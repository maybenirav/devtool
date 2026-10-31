# history.py
# Turns saved finding events into answers using MongoDB aggregation pipelines:
# introduced-in, fixed-in, exposure, verdict, timeline and release comparison.
import re

from db import get_db

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}


def _weight_expr(path):
    """Aggregation expression: severity -> weight (critical=10, high=7, ...)."""
    return {"$switch": {
        "branches": [
            {"case": {"$eq": [path, sev]}, "then": w} for sev, w in SEVERITY_WEIGHT.items()
        ],
        "default": 1,
    }}


# ---------- 1. Risks: introduced-in, fixed-in, exposure ----------

def risks_pipeline(repo_id):
    return [
        # this repo's events, oldest first
        {"$match": {"repoId": repo_id}},
        {"$sort": {"committedAt": 1}},

        # all events of the same risk (same fingerprint) go into one group
        {"$group": {
            "_id": "$fingerprint",
            "type": {"$first": "$type"},
            "severity": {"$first": "$severity"},
            "title": {"$first": "$title"},
            "details": {"$first": "$details"},
            "file": {"$first": "$file"},
            "events": {"$push": {
                "action": "$action", "sha": "$commitSha", "at": "$committedAt",
                "author": "$author", "file": "$file", "line": "$line",
            }},
            "lastAddedAt": {"$max": {"$cond": [
                {"$eq": ["$action", "added"]}, "$committedAt", None]}},
            "lastRemovedAt": {"$max": {"$cond": [
                {"$eq": ["$action", "removed"]}, "$committedAt", None]}},
        }},

        # introduced = first "added"; fixed = last "removed" if it came after the last "added"
        {"$addFields": {
            "introduced": {"$first": {"$filter": {
                "input": "$events", "cond": {"$eq": ["$$this.action", "added"]}}}},
            "fixedEvent": {"$cond": [
                {"$gt": ["$lastRemovedAt", "$lastAddedAt"]},
                {"$last": {"$filter": {
                    "input": "$events", "cond": {"$eq": ["$$this.action", "removed"]}}}},
                None,
            ]},
        }},

        # status: active / fixed / in_history (a deleted secret is still in git history)
        {"$addFields": {
            "status": {"$cond": [
                {"$ne": ["$fixedEvent", None]},
                {"$cond": [{"$eq": ["$type", "secret"]}, "in_history", "fixed"]},
                "active",
            ]},
        }},

        # exposure ends when fixed; otherwise it is still going on (now)
        {"$addFields": {
            "exposureEnd": {"$cond": [
                {"$eq": ["$status", "fixed"]}, "$fixedEvent.at", "$$NOW"]},
        }},
        {"$addFields": {
            "exposureDays": {"$dateDiff": {
                "startDate": "$introduced.at", "endDate": "$exposureEnd", "unit": "day"}},
        }},

        # how many commits was it live for? (JOIN with commits)
        {"$lookup": {
            "from": "commits",
            "let": {"start": "$introduced.at", "end": "$exposureEnd"},
            "pipeline": [
                {"$match": {"repoId": repo_id, "$expr": {"$and": [
                    {"$gte": ["$committedAt", "$$start"]},
                    {"$lt": ["$committedAt", "$$end"]},
                ]}}},
                {"$count": "n"},
            ],
            "as": "liveCommits",
        }},

        # was it dismissed as a false positive? (JOIN with dismissals)
        {"$lookup": {
            "from": "dismissals",
            "let": {"fp": "$_id"},
            "pipeline": [
                {"$match": {"repoId": repo_id, "$expr": {"$eq": ["$fingerprint", "$$fp"]}}},
            ],
            "as": "dismissal",
        }},

        {"$addFields": {
            "liveForCommits": {"$ifNull": [{"$first": "$liveCommits.n"}, 0]},
            "dismissed": {"$gt": [{"$size": "$dismissal"}, 0]},
            "dismissReason": {"$first": "$dismissal.reason"},
            "sevRank": {"$indexOfArray": [SEVERITY_ORDER, "$severity"]},
            "statusRank": {"$cond": [{"$eq": ["$status", "fixed"]}, 1, 0]},  # open first
        }},
        {"$project": {"liveCommits": 0, "dismissal": 0}},

        # most urgent first
        {"$sort": {"dismissed": 1, "statusRank": 1, "sevRank": -1, "introduced.at": 1}},
    ]


def get_risks(repo_id):
    """One entry per unique risk with its full story."""
    return list(get_db().findings.aggregate(risks_pipeline(repo_id)))


# ---------- 2. Verdict ----------

def compute_verdict(repo_id, risks=None):
    """SAFE / RISKY / BLOCK with human-readable reasons."""
    if risks is None:
        risks = get_risks(repo_id)

    open_risks = [r for r in risks
                  if not r["dismissed"] and r["status"] in ("active", "in_history")]

    block, risky = [], []
    for r in open_risks:
        if r["type"] == "secret":
            block.append(r)  # active OR deleted-but-in-history: both must be rotated
        elif r["type"] == "vulnerable_dependency" and r["severity"] in ("critical", "high"):
            block.append(r)
        else:
            risky.append(r)

    verdict = "BLOCK" if block else ("RISKY" if risky else "SAFE")

    reasons = []
    for r in block + risky:
        where = r["introduced"]["sha"][:7] if r.get("introduced") else "?"
        if r["status"] == "in_history":
            reasons.append(f"{r['title']}: deleted in a later commit, but still in git "
                           f"history. Rotate it. (introduced in {where})")
        else:
            reasons.append(f"{r['title']} (introduced in {where})")

    return {
        "verdict": verdict,
        "reasons": reasons[:10],
        "counts": {
            "block": len(block),
            "risky": len(risky),
            "fixed": sum(1 for r in risks if r["status"] == "fixed" and not r["dismissed"]),
            "dismissed": sum(1 for r in risks if r["dismissed"]),
        },
    }


# ---------- 3. Timeline: risk level after each commit ----------

def timeline_pipeline(repo_id):
    return [
        {"$match": {"repoId": repo_id}},

        # JOIN each commit with its findings
        {"$lookup": {
            "from": "findings",
            "let": {"sha": "$sha"},
            "pipeline": [
                {"$match": {"repoId": repo_id, "$expr": {"$eq": ["$commitSha", "$$sha"]}}},
                {"$project": {"action": 1, "severity": 1, "type": 1, "title": 1}},
            ],
            "as": "f",
        }},

        # risk change in this commit: +weight when added, -weight when fixed
        # (a deleted secret does not lower the risk: it is still in history)
        {"$addFields": {
            "delta": {"$sum": {"$map": {
                "input": "$f", "as": "x",
                "in": {"$multiply": [
                    _weight_expr("$$x.severity"),
                    {"$cond": [
                        {"$eq": ["$$x.action", "added"]}, 1,
                        {"$cond": [{"$eq": ["$$x.type", "secret"]}, 0, -1]},
                    ]},
                ]},
            }}},
            "added": {"$size": {"$filter": {
                "input": "$f", "cond": {"$eq": ["$$this.action", "added"]}}}},
            "removed": {"$size": {"$filter": {
                "input": "$f", "cond": {"$eq": ["$$this.action", "removed"]}}}},
            "titles": "$f.title",
        }},

        # running total over time = open risk level after each commit
        {"$setWindowFields": {
            "sortBy": {"committedAt": 1},
            "output": {"openRisk": {
                "$sum": "$delta", "window": {"documents": ["unbounded", "current"]}}},
        }},

        {"$project": {"_id": 0, "sha": 1, "message": 1, "author": 1, "committedAt": 1,
                      "url": 1, "partial": 1, "delta": 1, "openRisk": 1,
                      "added": 1, "removed": 1, "titles": 1}},
    ]


def get_timeline(repo_id):
    return list(get_db().commits.aggregate(timeline_pipeline(repo_id)))


# ---------- 4. Compare two releases ----------

def _find_commit(repo_id, sha_prefix):
    commit = get_db().commits.find_one({
        "repoId": repo_id,
        "sha": {"$regex": "^" + re.escape((sha_prefix or "").strip().lower())},
    })
    if not commit:
        raise ValueError(f"Commit '{sha_prefix}' is not in the scanned history.")
    return commit


def _open_at(risks, when):
    """Risks that were open at a given moment."""
    result = {}
    for r in risks:
        if r["dismissed"] or not r.get("introduced") or r["introduced"]["at"] > when:
            continue
        fixed = r.get("fixedEvent")
        # secrets stay open forever (they live on in history)
        if r["type"] != "secret" and fixed and fixed["at"] <= when:
            continue
        result[r["_id"]] = r
    return result


def compare_commits(repo_id, sha_a, sha_b):
    """What changed in risk between release A and release B?"""
    a = _find_commit(repo_id, sha_a)
    b = _find_commit(repo_id, sha_b)
    if a["committedAt"] > b["committedAt"]:
        a, b = b, a  # always compare older -> newer
    if a["sha"] == b["sha"]:
        return {"identical": True, "a": a["sha"], "b": b["sha"],
                "new": [], "fixed": [], "unchanged": [], "scoreA": 0, "scoreB": 0,
                "trend": "same"}

    risks = get_risks(repo_id)
    open_a = _open_at(risks, a["committedAt"])
    open_b = _open_at(risks, b["committedAt"])

    new = [open_b[k] for k in open_b if k not in open_a]
    fixed = [open_a[k] for k in open_a if k not in open_b]
    unchanged = [open_b[k] for k in open_b if k in open_a]

    score_a = sum(SEVERITY_WEIGHT[r["severity"]] for r in open_a.values())
    score_b = sum(SEVERITY_WEIGHT[r["severity"]] for r in open_b.values())
    trend = "worse" if score_b > score_a else ("better" if score_b < score_a else "same")

    return {"identical": False, "a": a["sha"], "b": b["sha"], "new": new, "fixed": fixed,
            "unchanged": unchanged, "scoreA": score_a, "scoreB": score_b, "trend": trend}
