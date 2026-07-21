"""Live CISA KEV (Known Exploited Vulnerabilities) intelligence.

The Threat & Exposure Watch module is no longer simulated: it pulls the CISA
KEV catalog - the authoritative list of vulnerabilities confirmed exploited in
the wild, updated daily - server-side (no browser CORS proxy needed), then
classifies every entry by database engine and OS/hypervisor layer and flags
ransomware-linked and freshly-added CVEs.

Inspired by the standalone "DB Threat Watch" board, folded into the control
plane so exposure risk lands on the same posture score as code findings.

Pure stdlib fetch (urllib) with a truststore shim for Windows TLS, plus an
in-process TTL cache so we never hammer the feed.
"""
import json
import re
import ssl
import time
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_TTL = 6 * 3600  # 6h - CISA updates at most daily
_cache: dict = {"ts": 0, "data": None}

# Windows/corp-proxy TLS: prefer the OS trust store when available.
try:  # pragma: no cover - environment dependent
    import truststore
    truststore.inject_into_ssl()
except Exception:
    pass

DB_RX = {
    "mssql": re.compile(r"\b(sql server|mssql|microsoft sql)\b", re.I),
    "oracle": re.compile(r"\boracle\b.*\b(database|weblogic|goldengate|e-business|ebs|fusion middleware|access manager|identity)\b|\b(weblogic|goldengate)\b", re.I),
    "mysql": re.compile(r"\b(mysql|mariadb)\b", re.I),
    "pg": re.compile(r"\b(postgres|postgresql)\b", re.I),
    "generic": re.compile(r"\b(database|mongodb|redis|elasticsearch|couchdb|cassandra|db2|sqlite|sql injection|dbms)\b", re.I),
}
OS_RX = re.compile(r"\b(windows|linux kernel|linux|esxi|vmware|vcenter|hyper-v|hypervisor|ubuntu|red hat|rhel|suse|debian|centos|samba|sudo|openssl|glibc|macos|unix|aix|solaris|freebsd|active directory|kerberos|netlogon)\b", re.I)


def _classify(v: dict) -> tuple[str | None, str]:
    hay = " ".join(str(v.get(k, "")) for k in
                    ("vendorProject", "product", "vulnerabilityName", "shortDescription"))
    engine = None
    if DB_RX["mssql"].search(hay): engine = "mssql"
    elif DB_RX["mysql"].search(hay): engine = "mysql"
    elif DB_RX["pg"].search(hay): engine = "pg"
    elif DB_RX["oracle"].search(hay): engine = "oracle"
    is_db = bool(engine) or bool(DB_RX["generic"].search(hay))
    is_os = (not is_db) and bool(OS_RX.search(hay))
    return engine, ("db" if is_db else "os" if is_os else "other")


def _fetch_raw() -> dict:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "GuardAgent-ControlPlane/2.0"})
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _days_since(date_str: str) -> float:
    try:
        t = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
        return (time.time() - t) / 86400.0
    except Exception:
        return 9999.0


def get_kev(force: bool = False) -> dict:
    """Return classified KEV data (cached). Never raises - errors are reported
    in the payload so the UI can degrade gracefully."""
    now = time.time()
    if not force and _cache["data"] and (now - _cache["ts"] < _TTL):
        return _cache["data"]

    try:
        raw = _fetch_raw()
    except Exception as e:
        # Keep any stale cache; otherwise surface the error to the caller.
        if _cache["data"]:
            return {**_cache["data"], "stale": True}
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "entries": [],
                "counts": {}, "total": 0, "catalogVersion": None}

    vulns = raw.get("vulnerabilities", [])
    entries = []
    counts = {"mssql": 0, "oracle": 0, "mysql": 0, "pg": 0, "os": 0, "db": 0, "ransomware": 0}
    for v in vulns:
        engine, cat = _classify(v)
        age = _days_since(v.get("dateAdded", ""))
        # Field is exactly "Known" / "Unknown" - substring match would treat
        # "Unknown" as ransomware, so compare exactly.
        ransom = str(v.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"
        within_year = age <= 365
        if engine and within_year:
            counts[engine] += 1
        if cat == "db" and within_year:
            counts["db"] += 1
        if cat == "os" and within_year:
            counts["os"] += 1
        if ransom:
            counts["ransomware"] += 1
        entries.append({
            "cve": v.get("cveID"), "vendor": v.get("vendorProject"),
            "product": v.get("product"), "name": v.get("vulnerabilityName"),
            "desc": (v.get("shortDescription") or "")[:280],
            "dateAdded": v.get("dateAdded"), "dueDate": v.get("dueDate"),
            "engine": engine, "cat": cat, "ransomware": ransom,
            "fresh": age <= 7,
        })

    entries.sort(key=lambda e: e.get("dateAdded") or "", reverse=True)
    data = {"ok": True, "error": None, "total": len(entries),
            "catalogVersion": raw.get("catalogVersion"),
            "dateReleased": (raw.get("dateReleased") or "")[:10],
            "counts": counts, "entries": entries}
    _cache["ts"] = now
    _cache["data"] = data
    return data


def summary() -> dict:
    """Compact summary for the dashboard (no full entry list)."""
    d = get_kev()
    return {k: d[k] for k in ("ok", "error", "total", "catalogVersion", "counts")}
