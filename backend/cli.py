"""GuardAgent CLI — run the security gate from a terminal or CI pipeline.

    python -m backend.cli scan   <file>            # code / diff / Dockerfile / CI yaml
    python -m backend.cli scan   <file> --sarif    # emit SARIF 2.1.0 to stdout
    python -m backend.cli scan   <file> --ai       # add GPT-5.6 intent reasoning
    python -m backend.cli shield <file>            # screen content for prompt injection
    python -m backend.cli deps   requirements.txt  # supply-chain scan

Exit codes (so a pipeline can gate on them):
    0  Allow / PASS
    1  Review / SANITIZE      (warn — configurable to fail with --strict)
    2  Block / BLOCK
    3  Quarantine
    4  usage / IO error
"""
import argparse
import json
import sys

from . import analyzer, reasoner, shield, deps, sarif

# Exit-code contract shared by every subcommand.
_EXIT = {"Allow": 0, "PASS": 0, "Review": 1, "SANITIZE": 1,
         "Block": 2, "BLOCK": 2, "Quarantine": 3}

_SEV_COLOR = {"critical": "\033[91m", "high": "\033[93m",
              "medium": "\033[96m", "low": "\033[90m"}
_RESET = "\033[0m"


def _c(text: str, sev: str, color: bool) -> str:
    return f"{_SEV_COLOR.get(sev, '')}{text}{_RESET}" if color else text


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def cmd_scan(args) -> int:
    src = _read(args.file)
    analysis = analyzer.analyze(src)
    if args.sarif:
        json.dump(sarif.to_sarif(analysis, artifact_uri=args.file), sys.stdout, indent=2)
        print()
        return _EXIT.get(analysis["decision"], 0)

    decision = analysis["decision"]
    reasoning = reasoner.reason(src, analysis) if args.ai else None
    if args.json:
        json.dump({"analysis": analysis, "reasoning": reasoning}, sys.stdout, indent=2)
        print()
    else:
        color = not args.no_color
        print(f"\nGuardAgent scan · {args.file}")
        print(f"Decision: {decision}  (composite {analysis['composite']}/100)")
        print(f"{analysis['why']}\n")
        if analysis["findings"]:
            for f in analysis["findings"]:
                loc = f" (line {f['line']})" if f.get("line") else ""
                print(f"  {_c('●', f['sev'], color)} [{f['id']}] {f['name']} · {f['sev']}{loc}")
                print(f"      {f['desc']}")
        else:
            print("  No findings across all analysis layers.")
        if reasoning:
            print(f"\nGPT-5.6 intent: {reasoning.get('threat_class', '—')} "
                  f"({reasoning.get('engine', 'deterministic')})")
            print(f"  {reasoning.get('summary', '')}")
        print()
    if args.strict and decision in ("Review",):
        return 2
    return _EXIT.get(decision, 0)


def cmd_shield(args) -> int:
    content = _read(args.file)
    result = shield.inspect(content, args.source)
    if args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        color = not args.no_color
        rz = result["reasoning"]
        print(f"\nGuardAgent Shield · {args.file} · source={args.source}")
        print(f"Verdict: {result['verdict']}  "
              f"({len(result['screen']['hits'])} hits, composite {result['screen']['composite']}/100)")
        print(f"Attack class: {rz.get('attack_class', '—')}  ({rz.get('engine', 'deterministic')})")
        for h in result["screen"]["hits"]:
            print(f"  {_c('●', h['sev'], color)} [{h['id']}] {h['name']} · {h['cls']}")
        if result.get("sanitized") is not None:
            print("\nSanitized copy (safe to forward):")
            print(result["sanitized"])
        print()
    return _EXIT.get(result["verdict"], 0)


def cmd_deps(args) -> int:
    result = deps.scan(_read(args.file))
    if args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        color = not args.no_color
        print(f"\nGuardAgent supply-chain scan · {args.file}")
        print(f"Decision: {result['decision']}  ({result['packages']} packages)")
        for f in result["findings"]:
            print(f"  {_c('●', f['sev'], color)} [{f['id']}] {f['name']} · {f['issue']}")
            print(f"      fix: {f['fix']}")
        if not result["findings"]:
            print("  No supply-chain issues detected.")
        print()
    return _EXIT.get(result["decision"], 0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="guardagent", description="GuardAgent security gate — CLI")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan code / diff / Dockerfile / CI config")
    s.add_argument("file", help="path to scan, or - for stdin")
    s.add_argument("--ai", action="store_true", help="add GPT-5.6 intent reasoning")
    s.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0 to stdout")
    s.add_argument("--strict", action="store_true", help="fail (exit 2) on Review too")
    s.set_defaults(func=cmd_scan)

    sh = sub.add_parser("shield", help="screen content for prompt injection")
    sh.add_argument("file", help="path to screen, or - for stdin")
    sh.add_argument("--source", default="user-prompt",
                    choices=["user-prompt", "retrieved-doc", "tool-output"])
    sh.set_defaults(func=cmd_shield)

    d = sub.add_parser("deps", help="scan a dependency manifest")
    d.add_argument("file", help="requirements.txt / package.json, or - for stdin")
    d.set_defaults(func=cmd_deps)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
