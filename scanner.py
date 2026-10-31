# scanner.py
# The manager: fetches commits, runs the checks, saves everything to MongoDB,
# then computes the verdict and (if it turned BLOCK) sends an alert.
import hashlib
import logging
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone

from pymongo.errors import DuplicateKeyError

import alerts
import detectors as det
import github_client as gh
import osv_client as osv
from db import get_db
from history import compute_verdict

log = logging.getLogger("releaseguard.scanner")

MAX_COMMITS = int(os.getenv("MAX_COMMITS", "30"))
SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
_scan_slots = threading.BoundedSemaphore(int(os.getenv("MAX_PARALLEL_SCANS", "3")))


class ScanError(Exception):
    """Friendly scan error."""


def now():
    return datetime.now(timezone.utc)


def stable_id(*parts):
    """Same inputs -> always the same ID (this is what makes duplicates detectable)."""
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


# ---------- Step A: prepare ----------

def prepare_scan(repo_input, trigger="manual"):
    """
    Validate the repo, save it, and create a 'running' scan.
    Returns (scan_id, repo_id, reused). If this repo already has a scan running,
    that scan is reused instead of starting a second one.
    """
    db = get_db()
    owner, name = gh.parse_repo_url(repo_input)
    info = gh.get_repo(owner, name)
    repo_id = info["fullName"].lower()

    db.repos.update_one(
        {"_id": repo_id},
        {"$set": {"owner": info["owner"], "name": info["name"], "url": info["url"],
                  "fullName": info["fullName"], "defaultBranch": info["defaultBranch"]},
         "$setOnInsert": {"createdAt": now()}},
        upsert=True,
    )

    running = db.scans.find_one({
        "repoId": repo_id, "status": "running",
        "startedAt": {"$gte": now() - timedelta(minutes=10)},
    })
    if running:
        return running["scanId"], repo_id, True

    scan_id = "scan-" + uuid.uuid4().hex[:12]
    db.scans.insert_one({
        "scanId": scan_id,
        "repoId": repo_id,
        "trigger": trigger,
        "status": "running",
        "startedAt": now(),
        "commitsFound": 0,
        "commitsScanned": 0,
        "commitsToScan": 0,
        "commitsSkipped": 0,
        "findingsAdded": 0,
        "verdict": None,
        "error": None,
    })
    return scan_id, repo_id, False


def start_scan_in_background(repo_input, trigger="manual"):
    """Used by the website and the webhook: returns immediately, scans in a thread."""
    scan_id, repo_id, reused = prepare_scan(repo_input, trigger)
    if not reused:
        threading.Thread(target=_background, args=(scan_id,), daemon=True).start()
    return scan_id, repo_id, reused


def _background(scan_id):
    with _scan_slots:  # at most N scans at the same time
        try:
            run_scan(scan_id, log=log.info)
        except Exception as e:  # already recorded on the scan document
            log.warning("scan %s failed: %s", scan_id, e)


def mark_stale_scans():
    """If the server restarted mid-scan, mark those scans as failed (they can be re-run)."""
    get_db().scans.update_many(
        {"status": "running", "startedAt": {"$lt": now() - timedelta(minutes=15)}},
        {"$set": {"status": "failed", "error": "Interrupted. Run the scan again.",
                  "finishedAt": now()}},
    )


# ---------- Step B: run ----------

def _fail(db, scan_id, message):
    db.scans.update_one(
        {"scanId": scan_id},
        {"$set": {"status": "failed", "error": message, "finishedAt": now()}},
    )


def run_scan(scan_id, log=print):
    db = get_db()
    scan = db.scans.find_one({"scanId": scan_id})
    if not scan:
        raise ScanError("Scan not found.")
    repo_id = scan["repoId"]
    owner, name = repo_id.split("/", 1)

    try:
        shas = gh.list_commits(owner, name, MAX_COMMITS)
        shas.reverse()  # oldest first, so "added" always comes before "removed"

        commit_ids = [f"{repo_id}@{sha}" for sha in shas]
        already_done = {
            d["sha"] for d in db.commits.find({"commitId": {"$in": commit_ids}}, {"sha": 1})
        }
        new_shas = [sha for sha in shas if sha not in already_done]

        db.scans.update_one({"scanId": scan_id}, {"$set": {
            "commitsFound": len(shas),
            "commitsToScan": len(new_shas),
            "commitsSkipped": len(shas) - len(new_shas),
        }})
        log(f"Found {len(shas)} commits: {len(new_shas)} new, "
            f"{len(shas) - len(new_shas)} already scanned (skipped).")

        total_added = 0
        for i, sha in enumerate(new_shas, start=1):
            commit = gh.get_commit(owner, name, sha)
            added, score = _scan_commit(db, repo_id, scan_id, commit)

            try:
                db.commits.insert_one({
                    "commitId": f"{repo_id}@{sha}",
                    "repoId": repo_id,
                    "sha": sha,
                    "message": commit["message"],
                    "author": commit["author"],
                    "authorLogin": commit["authorLogin"],
                    "committedAt": commit["committedAt"],
                    "url": commit["url"],
                    "partial": commit["partial"],
                    "riskScore": score,
                    "findingsAdded": added,
                    "scanId": scan_id,
                    "scannedAt": now(),
                })
            except DuplicateKeyError:
                pass  # saved by another scan at the same moment: fine

            total_added += added
            db.scans.update_one({"scanId": scan_id}, {"$set": {
                "commitsScanned": i,
                "findingsAdded": total_added,
                "currentCommit": sha,
            }})
            log(f"[{i}/{len(new_shas)}] {sha[:7]} {commit['message'][:50]} "
                f"-> {added} new finding(s)")

        previous = (db.repos.find_one({"_id": repo_id}, {"lastVerdict": 1}) or {}
                    ).get("lastVerdict")
        result = compute_verdict(repo_id)
        finished = now()
        db.repos.update_one({"_id": repo_id}, {"$set": {
            "lastVerdict": result["verdict"],
            "lastReasons": result["reasons"],
            "lastScanId": scan_id,
            "lastScanAt": finished,
        }})
        try:
            alert = alerts.maybe_alert(repo_id, scan_id, previous, result)
        except Exception as e:  # an alert problem must never break a scan
            alert = {"status": "failed", "error": str(e)}
        db.scans.update_one({"scanId": scan_id}, {"$set": {
            "status": "completed",
            "finishedAt": finished,
            "verdict": result["verdict"],
            "previousVerdict": previous,
            "verdictReasons": result["reasons"],
            "alertStatus": (alert or {}).get("status"),
        }})
        log(f"Verdict: {result['verdict']}")
        return result

    except (gh.GitHubError, osv.OSVError) as e:
        _fail(db, scan_id, str(e))
        raise ScanError(str(e))
    except Exception as e:
        _fail(db, scan_id, f"Unexpected error: {e}")
        raise


def _scan_commit(db, repo_id, scan_id, commit):
    """Run the 3 checks on one commit and save findings. Returns (added_count, risk_score)."""
    sha = commit["sha"]
    candidates = []
    packages_to_check = []

    for f in commit["files"]:
        filename = f["filename"]
        dep_parser = det.dependency_parser_for(filename)

        for action, line_no, text in det.parse_patch(f["patch"]):
            base = {"action": action, "file": filename, "line": line_no}

            # Check 1: secrets
            for s in det.find_secrets(text, filename):
                candidates.append({**base,
                    "type": "secret",
                    "severity": s["severity"],
                    "fingerprint": s["fingerprint"],
                    "title": f"{s['provider']} secret committed",
                    "details": {"provider": s["provider"], "rule": s["ruleId"],
                                "masked": s["masked"]},
                })

            # Check 2: risky settings
            for c in det.find_risky_config(text):
                candidates.append({**base,
                    "type": "risky_config",
                    "severity": c["severity"],
                    "fingerprint": f"config:{c['ruleId']}:{filename}",
                    "title": c["title"],
                    "details": {"rule": c["ruleId"], "snippet": text.strip()[:120]},
                })

            # Check 3: libraries
            if dep_parser:
                dep = dep_parser(text)
                if not dep:
                    continue
                eco, pkg = dep["ecosystem"], dep["name"]
                if dep["version"]:
                    candidates.append({**base,
                        "type": "vulnerable_dependency",
                        "fingerprint": f"dep:{eco}:{pkg}:{dep['version']}",
                        "dep": dep,
                    })
                    if action == "added":
                        packages_to_check.append((eco, pkg, dep["version"]))
                else:
                    candidates.append({**base,
                        "type": "unpinned_dependency",
                        "severity": "low",
                        "fingerprint": f"unpinned:{eco}:{pkg}",
                        "title": f"{pkg} has no pinned version",
                        "details": {"ecosystem": eco, "package": pkg, "spec": dep["spec"]},
                    })

    vuln_info = osv.check_packages(packages_to_check) if packages_to_check else {}

    added_count, risk_score = 0, 0
    for c in candidates:
        if c["action"] == "added":
            if c["type"] == "vulnerable_dependency":
                dep = c.pop("dep")
                info = vuln_info.get((dep["ecosystem"], dep["name"], dep["version"]))
                if not info:
                    continue  # this version is safe: not a finding
                n = info["vulnCount"]
                c["severity"] = info["severity"]
                c["title"] = (f"{dep['name']} {dep['version']} has {n} known "
                              f"vulnerabilit{'y' if n == 1 else 'ies'}")
                c["details"] = {
                    "ecosystem": dep["ecosystem"], "package": dep["name"],
                    "version": dep["version"], "fixedVersion": info["fixedVersion"],
                    "vulnCount": n, "vulnIds": info["vulnIds"], "summary": info["summary"],
                }
        else:
            # a "removed" event only matters if this exact risk was added before
            c.pop("dep", None)
            previous = db.findings.find_one(
                {"repoId": repo_id, "fingerprint": c["fingerprint"], "action": "added"},
                sort=[("committedAt", -1)],
            )
            if not previous:
                continue
            for key in ("type", "severity", "title", "details"):
                c[key] = previous[key]

        doc = {
            "findingId": stable_id(repo_id, sha, c["fingerprint"], c["action"],
                                   c["file"], c["line"]),
            "repoId": repo_id,
            "scanId": scan_id,
            "commitSha": sha,
            "committedAt": commit["committedAt"],
            "author": commit["author"],
            "type": c["type"],
            "severity": c["severity"],
            "action": c["action"],
            "fingerprint": c["fingerprint"],
            "file": c["file"],
            "line": c["line"],
            "title": c["title"],
            "details": c.get("details", {}),
            "detectedAt": now(),
        }
        try:
            db.findings.insert_one(doc)
            if c["action"] == "added":
                added_count += 1
                risk_score += SEVERITY_WEIGHT[c["severity"]]
        except DuplicateKeyError:
            pass  # saved by an earlier (interrupted) scan: safe to ignore

    return added_count, risk_score
