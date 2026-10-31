# osv_client.py
# Asks OSV.dev (a free, public vulnerability database by Google) about library versions.
import re
from concurrent.futures import ThreadPoolExecutor

import requests
from packaging.version import InvalidVersion, Version

OSV = "https://api.osv.dev/v1"
TIMEOUT = 20

SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
                "MEDIUM": "medium", "LOW": "low"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_query_cache = {}  # (ecosystem, name, version) -> list of vulnerability IDs
_vuln_cache = {}   # vulnerability ID -> full details


class OSVError(Exception):
    """Friendly error when OSV.dev can't be reached."""


def _version(text):
    try:
        return Version(text)
    except (InvalidVersion, TypeError):
        return None


def _norm(name):
    return re.sub(r"[-_.]+", "-", name or "").lower()


def _get_vuln(vuln_id):
    if vuln_id not in _vuln_cache:
        try:
            r = requests.get(f"{OSV}/vulns/{vuln_id}", timeout=TIMEOUT)
        except requests.RequestException:
            raise OSVError("Could not reach the OSV.dev vulnerability database.")
        if r.status_code >= 400:
            raise OSVError(f"OSV.dev returned error {r.status_code}.")
        _vuln_cache[vuln_id] = r.json()
    return _vuln_cache[vuln_id]


def _severity(vuln):
    level = (vuln.get("database_specific") or {}).get("severity")
    if level and str(level).upper() in SEVERITY_MAP:
        return SEVERITY_MAP[str(level).upper()]
    for affected in vuln.get("affected", []):
        level = (affected.get("ecosystem_specific") or {}).get("severity")
        if level and str(level).upper() in SEVERITY_MAP:
            return SEVERITY_MAP[str(level).upper()]
    return "medium"  # unknown severity -> treat as medium


def _fixed_after(vuln, ecosystem, name, current):
    """Smallest version that fixes this vulnerability and is newer than ours."""
    current_v = _version(current)
    best = None
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != ecosystem or _norm(pkg.get("name")) != _norm(name):
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = _version(event.get("fixed"))
                if fixed and (current_v is None or fixed > current_v):
                    if best is None or fixed < best:
                        best = fixed
    return best


def check_packages(packages):
    """
    packages: list of (ecosystem, name, version)
    Returns {(ecosystem, name, version): summary} for vulnerable ones only.
    """
    unique = list(set(packages))
    todo = [p for p in unique if p not in _query_cache]

    # 1. Which vulnerabilities affect each package? (batched)
    for i in range(0, len(todo), 100):
        chunk = todo[i:i + 100]
        body = {"queries": [
            {"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk
        ]}
        try:
            r = requests.post(f"{OSV}/querybatch", json=body, timeout=TIMEOUT)
        except requests.RequestException:
            raise OSVError("Could not reach the OSV.dev vulnerability database.")
        if r.status_code >= 400:
            raise OSVError(f"OSV.dev returned error {r.status_code}.")
        for pkg, result in zip(chunk, r.json().get("results", [])):
            _query_cache[pkg] = [v["id"] for v in result.get("vulns", [])]

    # 2. Download details of every vulnerability (8 in parallel)
    all_ids = {vid for p in unique for vid in _query_cache.get(p, [])}
    missing = [vid for vid in all_ids if vid not in _vuln_cache]
    if missing:
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(_get_vuln, missing))

    # 3. One summary per package
    out = {}
    for pkg in unique:
        ids = _query_cache.get(pkg, [])
        if not ids:
            continue
        ecosystem, name, version = pkg

        # prefer GHSA records (they usually have severity); skip aliases of the same issue
        seen, vulns = set(), []
        for vid in sorted(ids, key=lambda x: (not x.startswith("GHSA"), x)):
            if vid in seen:
                continue
            vuln = _vuln_cache[vid]
            seen.add(vid)
            seen.update(vuln.get("aliases", []))
            vulns.append(vuln)

        worst = max(vulns, key=lambda v: SEVERITY_RANK[_severity(v)])
        fixes = [f for f in (_fixed_after(v, ecosystem, name, version) for v in vulns) if f]

        out[pkg] = {
            "severity": _severity(worst),
            "vulnCount": len(vulns),
            "vulnIds": [v["id"] for v in vulns][:20],
            "summary": (worst.get("summary") or worst.get("details") or "")[:200],
            "fixedVersion": str(max(fixes)) if fixes else None,
        }
    return out
