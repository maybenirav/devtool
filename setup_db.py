# setup_db.py
# Creates all collections with schema validation and indexes.
# Safe to run many times: it updates existing rules instead of failing.
from pymongo import ASCENDING, DESCENDING
from db import get_db

db = get_db()

# ---------- 1. Validation rules (schema validation) ----------

VALIDATORS = {
    "repos": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["_id", "owner", "name", "url", "createdAt"],
            "properties": {
                "_id": {"bsonType": "string", "description": "owner/name"},
                "owner": {"bsonType": "string"},
                "name": {"bsonType": "string"},
                "url": {"bsonType": "string"},
                "createdAt": {"bsonType": "date"},
                "lastVerdict": {"enum": ["SAFE", "RISKY", "BLOCK", None]},
            },
        }
    },
    "scans": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["scanId", "repoId", "trigger", "status", "startedAt"],
            "properties": {
                "scanId": {"bsonType": "string"},
                "repoId": {"bsonType": "string"},
                "trigger": {"enum": ["manual", "webhook"]},
                "status": {"enum": ["running", "completed", "failed"]},
                "startedAt": {"bsonType": "date"},
                "verdict": {"enum": ["SAFE", "RISKY", "BLOCK", None]},
            },
        }
    },
    "commits": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["commitId", "repoId", "sha", "committedAt", "scannedAt"],
            "properties": {
                "commitId": {"bsonType": "string", "description": "owner/name@sha"},
                "repoId": {"bsonType": "string"},
                "sha": {"bsonType": "string"},
                "committedAt": {"bsonType": "date"},
                "scannedAt": {"bsonType": "date"},
            },
        }
    },
    "findings": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": [
                "findingId", "repoId", "scanId", "commitSha", "committedAt",
                "type", "severity", "action", "fingerprint", "file",
                "title", "detectedAt",
            ],
            "properties": {
                "findingId": {"bsonType": "string"},
                "repoId": {"bsonType": "string"},
                "scanId": {"bsonType": "string"},
                "commitSha": {"bsonType": "string"},
                "committedAt": {"bsonType": "date"},
                "type": {"enum": [
                    "secret", "vulnerable_dependency",
                    "unpinned_dependency", "risky_config",
                ]},
                "severity": {"enum": ["critical", "high", "medium", "low", "info"]},
                "action": {"enum": ["added", "removed"]},
                "fingerprint": {"bsonType": "string"},
                "file": {"bsonType": "string"},
                "title": {"bsonType": "string"},
                "details": {"bsonType": "object"},  # flexible part
                "detectedAt": {"bsonType": "date"},
            },
        }
    },
    "dismissals": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["repoId", "fingerprint", "createdAt"],
            "properties": {
                "repoId": {"bsonType": "string"},
                "fingerprint": {"bsonType": "string"},
                "reason": {"bsonType": "string"},
                "createdAt": {"bsonType": "date"},
            },
        }
    },
    "webhook_deliveries": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["deliveryId", "event", "receivedAt"],
            "properties": {
                "deliveryId": {"bsonType": "string"},
                "event": {"bsonType": "string"},
                "receivedAt": {"bsonType": "date"},
            },
        }
    },
    "alerts": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["repoId", "scanId", "verdict", "status", "createdAt"],
            "properties": {
                "repoId": {"bsonType": "string"},
                "scanId": {"bsonType": "string"},
                "verdict": {"enum": ["SAFE", "RISKY", "BLOCK"]},
                "status": {"enum": ["sent", "failed", "skipped"]},
                "createdAt": {"bsonType": "date"},
            },
        }
    },
}


def ensure_collection(name, validator):
    """Create the collection, or update its rules if it already exists."""
    if name in db.list_collection_names():
        db.command(
            "collMod", name,
            validator=validator,
            validationLevel="strict",
            validationAction="error",
        )
        print(f"  updated rules: {name}")
    else:
        db.create_collection(
            name,
            validator=validator,
            validationLevel="strict",
            validationAction="error",
        )
        print(f"  created: {name}")


print("Creating collections with validation rules...")
for name, validator in VALIDATORS.items():
    ensure_collection(name, validator)

# ---------- 2. Indexes ----------

print("Creating indexes...")

# scans
db.scans.create_index("scanId", unique=True, name="uniq_scanId")
db.scans.create_index([("repoId", ASCENDING), ("startedAt", DESCENDING)],
                      name="repo_latest_scans")

# commits
db.commits.create_index("commitId", unique=True, name="uniq_commitId")
db.commits.create_index([("repoId", ASCENDING), ("committedAt", DESCENDING)],
                        name="repo_latest_commits")

# findings
db.findings.create_index("findingId", unique=True, name="uniq_findingId")
db.findings.create_index(
    [("repoId", ASCENDING), ("fingerprint", ASCENDING), ("committedAt", ASCENDING)],
    name="risk_history",
)
db.findings.create_index([("scanId", ASCENDING), ("detectedAt", ASCENDING)],
                         name="scan_live_view")
db.findings.create_index([("repoId", ASCENDING), ("commitSha", ASCENDING)],
                         name="findings_by_commit")

# dismissals: one decision per risk per repo
db.dismissals.create_index([("repoId", ASCENDING), ("fingerprint", ASCENDING)],
                           unique=True, name="uniq_dismissal")

# webhook deliveries: no duplicates + auto-delete after 7 days (TTL)
db.webhook_deliveries.create_index("deliveryId", unique=True, name="uniq_deliveryId")
db.webhook_deliveries.create_index("receivedAt", expireAfterSeconds=7 * 24 * 3600,
                                   name="ttl_7_days")

# alerts
db.alerts.create_index([("repoId", ASCENDING), ("createdAt", DESCENDING)],
                       name="repo_latest_alerts")

print("Done! Database is ready.")