# test_db_rules.py
# Proves: (1) unique index blocks duplicates, (2) validation blocks bad data.
from datetime import datetime, timezone
from pymongo.errors import DuplicateKeyError, WriteError
from db import get_db

db = get_db()
now = datetime.now(timezone.utc)

good_finding = {
    "findingId": "test-finding-1",
    "repoId": "test/test-repo",
    "scanId": "test-scan-1",
    "commitSha": "abc123",
    "committedAt": now,
    "type": "secret",
    "severity": "critical",
    "action": "added",
    "fingerprint": "secret:test",
    "file": "config.py",
    "title": "Test AWS key",
    "details": {"provider": "AWS", "masked": "AKIA****TEST"},
    "detectedAt": now,
}

db.findings.delete_many({"repoId": "test/test-repo"})  # clean old test data

# Test 1: a valid finding is accepted
db.findings.insert_one(dict(good_finding))
print("✅ Test 1: valid finding saved")

# Test 2: the same finding again is rejected (unique index)
try:
    db.findings.insert_one(dict(good_finding))
    print("❌ Test 2: duplicate was saved (should not happen!)")
except DuplicateKeyError:
    print("✅ Test 2: duplicate blocked by unique index")

# Test 3: a broken finding is rejected (schema validation)
bad_finding = {
    "findingId": "test-finding-2",
    "repoId": "test/test-repo",
    "type": "secret",
    "severity": "super bad",  # not an allowed value, and many fields missing
}
try:
    db.findings.insert_one(bad_finding)
    print("❌ Test 3: broken finding was saved (should not happen!)")
except WriteError:
    print("✅ Test 3: broken finding rejected by schema validation")

db.findings.delete_many({"repoId": "test/test-repo"})  # clean up
print("Test data cleaned up.")