# setup_db.py
# Creates all collections with schema validation and indexes.
# Safe to run many times. The web app also runs this automatically on startup.
from pymongo import ASCENDING, DESCENDING

from db import get_db

VERDICTS = ["SAFE", "RISKY", "BLOCK", None]

VALIDATORS = {
    "repos": {"$jsonSchema": {
        "bsonType": "object",
        "required": ["_id", "owner", "name", "url", "createdAt"],
        "properties": {
            "_id": {"bsonType": "string", "description": "owner/name (lowercase)"},
            "owner": {"bsonType": "string"},
            "name": {"bsonType": "string"},
            "url": {"bsonType": "string"},
            "createdAt": {"bsonType": "date"},
            "lastVerdict": {"enum": VERDICTS},
        },
    }},
    "scans": {"$jsonSchema": {
        "bsonType": "object",
        "required": ["scanId", "repoId", "trigger", "status", "startedAt"],
        "properties": {
            "scanId": {"bsonType": "string"},
            "repoId": {"bsonType": "string"},
            "trigger": {"enum": ["manual", "webhook"]},
            "status": {"enum": ["running", "completed", "failed"]},
            "startedAt": {"bsonType": "date"},
            "verdict": {"enum": VERDICTS},
        },
    }},
    "commits": {"$jsonSchema": {
        "bsonType": "object",
        "required": ["commitId", "repoId", "sha", "committedAt", "scannedAt"],
        "properties": {
            "commitId": {"bsonType": "string", "description": "owner/name@sha"},
            "repoId": {"bsonType": "string"},
            "sha": {"bsonType": "string"},
            "committedAt": {"bsonType": "date"},
            "scannedAt": {"bsonType": "date"},
        },
    }},
    "findings": {"$jsonSchema": {
        "bsonType": "object",
        "required": [
            "findingId", "repoId", "scanId", "commitSha", "committedAt",
            "type", "severity", "action", "fingerprint", "file", "title", "detectedAt",
        ],
        "properties": {
            "findingId": {"bsonType": "string"},
            "repoId": {"bsonType": "string"},
            "scanId": {"bsonType": "string"},
            "commitSha": {"bsonType": "string"},
            "committedAt": {"bsonType": "date"},
            "type": {"enum": ["secret", "vulnerable_dependency",
                              "unpinned_dependency", "risky_config"]},
            "severity": {"enum": ["critical", "high", "medium", "low", "info"]},
            "action": {"enum": ["added", "removed"]},
            "fingerprint": {"bsonType": "string"},
            "file": {"bsonType": "string"},
            "title": {"bsonType": "string"},
            "details": {"bsonType": "object"},  # flexible part (Polymorphic Pattern)
            "detectedAt": {"bsonType": "date"},
        },
    }},
    "dismissals": {"$jsonSchema": {
        "bsonType": "object",
        "required": ["repoId", "fingerprint", "createdAt"],
        "properties": {
            "repoId": {"bsonType": "string"},
            "fingerprint": {"bsonType": "string"},
            "reason": {"bsonType": "string"},
            "createdAt": {"bsonType": "date"},
        },
    }},
    "webhook_deliveries": {"$jsonSchema": {
        "bsonType": "object",
        "required": ["deliveryId", "event", "receivedAt"],
        "properties": {
            "deliveryId": {"bsonType": "string"},
            "event": {"bsonType": "string"},
            "receivedAt": {"bsonType": "date"},
        },
    }},
    "alerts": {"$jsonSchema": {
        "bsonType": "object",
        "required": ["repoId", "scanId", "verdict", "status", "createdAt"],
        "properties": {
            "repoId": {"bsonType": "string"},
            "scanId": {"bsonType": "string"},
            "verdict": {"enum": ["SAFE", "RISKY", "BLOCK"]},
            "status": {"enum": ["sent", "failed", "skipped"]},
            "createdAt": {"bsonType": "date"},
        },
    }},
}


def setup_database(log=print):
    db = get_db()
    existing = set(db.list_collection_names())

    for name, validator in VALIDATORS.items():
        if name in existing:
            db.command("collMod", name, validator=validator,
                       validationLevel="strict", validationAction="error")
            log(f"  updated rules: {name}")
        else:
            db.create_collection(name, validator=validator,
                                 validationLevel="strict", validationAction="error")
            log(f"  created: {name}")

    # scans
    db.scans.create_index("scanId", unique=True, name="uniq_scanId")
    db.scans.create_index([("repoId", ASCENDING), ("startedAt", DESCENDING)],
                          name="repo_latest_scans")
    db.scans.create_index([("status", ASCENDING), ("startedAt", ASCENDING)],
                          name="running_scans")
    # commits
    db.commits.create_index("commitId", unique=True, name="uniq_commitId")
    db.commits.create_index([("repoId", ASCENDING), ("committedAt", DESCENDING)],
                            name="repo_latest_commits")
    # findings
    db.findings.create_index("findingId", unique=True, name="uniq_findingId")
    db.findings.create_index(
        [("repoId", ASCENDING), ("fingerprint", ASCENDING), ("committedAt", ASCENDING)],
        name="risk_history")
    db.findings.create_index([("scanId", ASCENDING), ("detectedAt", ASCENDING)],
                             name="scan_live_view")
    db.findings.create_index([("repoId", ASCENDING), ("commitSha", ASCENDING)],
                             name="findings_by_commit")
    # repos (home page: recently scanned)
    db.repos.create_index([("lastScanAt", DESCENDING)], name="recently_scanned")
    # dismissals: one decision per risk per repo
    db.dismissals.create_index([("repoId", ASCENDING), ("fingerprint", ASCENDING)],
                               unique=True, name="uniq_dismissal")
    # webhook deliveries: no duplicates + auto-delete after 7 days (TTL index)
    db.webhook_deliveries.create_index("deliveryId", unique=True, name="uniq_deliveryId")
    db.webhook_deliveries.create_index("receivedAt", expireAfterSeconds=7 * 24 * 3600,
                                       name="ttl_7_days")
    # alerts
    db.alerts.create_index([("repoId", ASCENDING), ("createdAt", DESCENDING)],
                           name="repo_latest_alerts")
    log("Database is ready.")


if __name__ == "__main__":
    print("Setting up collections, validation rules and indexes...")
    setup_database()
