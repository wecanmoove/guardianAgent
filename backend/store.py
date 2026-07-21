"""SQLite persistence layer.

Every scan, finding, agent action and audit record is persisted so the
platform can produce the execution evidence the XPRIZE judges ask for
("agent execution logs, API usage records"). Pure stdlib — no ORM.
"""
import json
import os
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = os.environ.get("GUARDAGENT_DB", os.path.join(os.path.dirname(__file__), "guardagent.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    sha TEXT, repo TEXT, branch TEXT, author TEXT,
    threat TEXT, sev TEXT, conf REAL, decision TEXT,
    engine TEXT, files TEXT, summary TEXT,
    rules TEXT, mitre TEXT, diff TEXT, composite INTEGER
);
CREATE TABLE IF NOT EXISTS agent_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    agent TEXT NOT NULL, action TEXT NOT NULL, tool TEXT NOT NULL,
    risk REAL, policy TEXT, outcome TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    trigger_kind TEXT, subject TEXT, policy TEXT,
    decision TEXT, approver TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS shield_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    source TEXT, verdict TEXT, attack_class TEXT,
    composite INTEGER, engine TEXT, detectors TEXT, excerpt TEXT
);
"""


@contextmanager
def _conn():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db():
    with _conn() as con:
        con.executescript(SCHEMA)


def _age(ts: float) -> str:
    d = max(0, time.time() - ts)
    if d < 90: return f"{int(d)} s"
    if d < 5400: return f"{int(d // 60)} min"
    if d < 172800: return f"{d / 3600:.0f} h"
    return f"{d / 86400:.0f} d"


def record_scan(**kw) -> int:
    with _conn() as con:
        cur = con.execute(
            "INSERT INTO scans (ts, sha, repo, branch, author, threat, sev, conf, decision,"
            " engine, files, summary, rules, mitre, diff, composite)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), kw.get("sha"), kw.get("repo"), kw.get("branch"), kw.get("author"),
             kw.get("threat"), kw.get("sev"), kw.get("conf"), kw.get("decision"),
             kw.get("engine"), json.dumps(kw.get("files", [])), kw.get("summary"),
             json.dumps(kw.get("rules", [])), json.dumps(kw.get("mitre", [])),
             kw.get("diff", ""), kw.get("composite", 0)))
        return cur.lastrowid


def list_scans(limit: int = 50) -> list[dict]:
    with _conn() as con:
        rows = con.execute("SELECT * FROM scans ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["files"] = json.loads(d.pop("files") or "[]")
        d["rules"] = json.loads(d.pop("rules") or "[]")
        d["mitre"] = json.loads(d.pop("mitre") or "[]")
        d["age"] = _age(d["ts"])
        out.append(d)
    return out


def record_agent_action(agent: str, action: str, tool: str, risk: float,
                        policy: str, outcome: str, detail: str = "") -> int:
    with _conn() as con:
        cur = con.execute(
            "INSERT INTO agent_actions (ts, agent, action, tool, risk, policy, outcome, detail)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), agent, action, tool, risk, policy, outcome, detail))
        return cur.lastrowid


def list_agent_actions(limit: int = 100) -> list[dict]:
    with _conn() as con:
        rows = con.execute("SELECT * FROM agent_actions ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) | {"age": _age(r["ts"])} for r in rows]


def record_audit(trigger_kind: str, subject: str, policy: str,
                 decision: str, approver: str = "— (automatic)") -> str:
    with _conn() as con:
        cur = con.execute(
            "INSERT INTO audit (ts, trigger_kind, subject, policy, decision, approver, evidence)"
            " VALUES (?,?,?,?,?,?,?)",
            (time.time(), trigger_kind, subject, policy, decision, approver, ""))
        ev = f"EV-{90000 + cur.lastrowid}"
        con.execute("UPDATE audit SET evidence=? WHERE id=?", (ev, cur.lastrowid))
        return ev


def list_audit(limit: int = 200) -> list[dict]:
    with _conn() as con:
        rows = con.execute("SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["ts_iso"] = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(d["ts"]))
        out.append(d)
    return out


def record_shield_check(source: str, verdict: str, attack_class: str, composite: int,
                        engine: str, detectors: list[str], excerpt: str) -> int:
    with _conn() as con:
        cur = con.execute(
            "INSERT INTO shield_checks (ts, source, verdict, attack_class, composite, engine, detectors, excerpt)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), source, verdict, attack_class, composite, engine,
             json.dumps(detectors), excerpt[:300]))
        return cur.lastrowid


def list_shield_checks(limit: int = 100) -> list[dict]:
    with _conn() as con:
        rows = con.execute("SELECT * FROM shield_checks ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["detectors"] = json.loads(d.pop("detectors") or "[]")
        d["age"] = _age(d["ts"])
        out.append(d)
    return out


def stats() -> dict:
    with _conn() as con:
        scans = con.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        blocked = con.execute("SELECT COUNT(*) c FROM scans WHERE decision IN ('Block','Quarantine')").fetchone()["c"]
        actions = con.execute("SELECT COUNT(*) c FROM agent_actions").fetchone()["c"]
        denied = con.execute("SELECT COUNT(*) c FROM agent_actions WHERE outcome='Denied'").fetchone()["c"]
        shield = con.execute("SELECT COUNT(*) c FROM shield_checks").fetchone()["c"]
        shield_blocked = con.execute("SELECT COUNT(*) c FROM shield_checks WHERE verdict='BLOCK'").fetchone()["c"]
    return {"scans": scans, "blocked": blocked, "agent_actions": actions, "denied": denied,
            "shield_checks": shield, "shield_blocked": shield_blocked}
