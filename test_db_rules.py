# test_db_rules.py
# Proves on your real Atlas database: (1) unique index blocks duplicates,
# (2) schema validation blocks broken data. Cleans up after itself.
from datetime import datetime, timezone

from pymongo.errors import DuplicateKeyError, WriteError

from db import get_db

db = get_db()
now = datetime.now(timezone.utc)
good = {
    "findingId": "test-finding-1", "repoId": "test/test-repo", "scanId": "test-scan-1",
    "commitSha": "abc123", "committedAt": now, "type": "secret", "severity": "critical",
    "action": "added", "fingerprint": "secret:test", "file": "config.py",
    "title": "Test AWS key", "details": {"provider": "AWS", "masked": "AKIA****TEST"},
    "detectedAt": now,
}
db.findings.delete_many({"repoId": "test/test-repo"})

db.findings.insert_one(dict(good))
print("OK  Test 1: valid finding saved")
try:
    db.findings.insert_one(dict(good))
    print("BAD Test 2: duplicate was saved")
except DuplicateKeyError:
    print("OK  Test 2: duplicate blocked by unique index")
try:
    db.findings.insert_one({"findingId": "test-finding-2", "repoId": "test/test-repo",
                            "type": "secret", "severity": "super bad"})
    print("BAD Test 3: broken finding was saved")
except WriteError:
    print("OK  Test 3: broken finding rejected by schema validation")

db.findings.delete_many({"repoId": "test/test-repo"})
print("Test data cleaned up.")
