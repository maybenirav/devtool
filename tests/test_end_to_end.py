# tests/test_end_to_end.py
# Full scan -> history -> verdict -> compare test, using a fake GitHub.
# Uses a SEPARATE database (releaseguard_test) so your real data is never touched.
#   python tests/test_end_to_end.py
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_NAME"] = "releaseguard_test"
os.environ.pop("N8N_WEBHOOK_URL", None)

from pymongo.errors import DuplicateKeyError, WriteError  # noqa: E402

import tests.fake_github as fake  # noqa: E402
from db import get_db  # noqa: E402

fake.install(setattr)

from history import compare_commits, compute_verdict, get_risks, get_timeline  # noqa: E402
from scanner import prepare_scan, run_scan  # noqa: E402
from setup_db import setup_database  # noqa: E402

REPO = "testowner/demo-app"
passed = 0


def check(condition, message):
    global passed
    if not condition:
        raise AssertionError("FAILED: " + message)
    passed += 1
    print("  ok -", message)


db = get_db()
for name in db.list_collection_names():
    db.drop_collection(name)
setup_database(log=lambda m: None)

print("1. First scan, only the first commit exists (should be SAFE)")
fake.visible = 1
scan_id, repo_id, _ = prepare_scan("https://github.com/TestOwner/demo-app")
check(repo_id == REPO, "repo id is lowercase owner/name")
result = run_scan(scan_id, log=lambda m: None)
check(result["verdict"] == "SAFE", "verdict SAFE")

print("2. New commits pushed, scan again (should be BLOCK)")
fake.visible = 4
scan_id2, _, _ = prepare_scan("TestOwner/demo-app")
result = run_scan(scan_id2, log=lambda m: None)
scan2 = db.scans.find_one({"scanId": scan_id2})
check(scan2["commitsSkipped"] == 1 and scan2["commitsScanned"] == 3,
      "old commit skipped, 3 new commits scanned")
check(result["verdict"] == "BLOCK", "verdict BLOCK")

risks = {r["title"]: r for r in get_risks(REPO)}
aws = risks["AWS secret committed"]
check(aws["status"] == "in_history", "deleted AWS key is 'in_history' (still dangerous)")
check(aws["introduced"]["sha"] == "c" * 40 and aws["fixedEvent"]["sha"] == "d" * 40,
      "AWS key introduced in commit c, removed in commit d")
check(aws["details"]["masked"] == "AKIA****PZTK", "secret is masked")
check(db.findings.count_documents({"details.masked": {"$regex": "QW2XLMN8"}}) == 0,
      "full secret is never stored")
django = risks["django 2.2.0 has 42 known vulnerabilities"]
check(django["status"] == "fixed", "django 2.2.0 marked fixed after the upgrade")
check(django["details"]["fixedVersion"] == "2.2.28", "upgrade suggestion stored")
check(django["liveForCommits"] == 2, "django was live for 2 commits")
check(risks["lodash 4.17.15 has 6 known vulnerabilities"]["status"] == "active", "lodash active")
check("requests has no pinned version" in risks, "unpinned requests detected")
check(len([r for r in risks.values() if r["type"] == "secret"]) == 2,
      "placeholder API key ignored (only AWS + DB_PASSWORD secrets)")

print("3. Timeline (running total with $setWindowFields)")
tl = get_timeline(REPO)
check([c["openRisk"] for c in tl] == [0, 19, 37, 27],
      f"open risk per commit {[c['openRisk'] for c in tl]}")

print("4. Compare releases")
cmp = compare_commits(REPO, "b", "d")
check({r["title"] for r in cmp["fixed"]} == {"django 2.2.0 has 42 known vulnerabilities"},
      "django listed as fixed between b and d")
check(len(cmp["new"]) == 3, "3 new risks between b and d (AWS, password, debug)")
check(compare_commits(REPO, "d", "d")["identical"], "same commit is identical")

print("5. Re-scan: nothing duplicated")
before = db.findings.count_documents({})
scan_id3, _, _ = prepare_scan("TestOwner/demo-app")
run_scan(scan_id3, log=lambda m: None)
check(db.findings.count_documents({}) == before, "no duplicate findings after re-scan")
check(db.scans.find_one({"scanId": scan_id3})["commitsSkipped"] == 4, "all 4 commits skipped")

print("6. Database rules")
f = db.findings.find_one({}, {"_id": 0})
try:
    db.findings.insert_one(dict(f))
    check(False, "duplicate rejected")
except DuplicateKeyError:
    check(True, "unique index rejects a duplicate finding")
try:
    db.findings.insert_one({"findingId": "bad", "repoId": REPO, "severity": "super bad"})
    check(False, "invalid rejected")
except WriteError:
    check(True, "schema validation rejects a broken finding")

print("7. Dismiss false positive")
pw = risks["Hardcoded credential (DB_PASSWORD) secret committed"]
db.dismissals.insert_one({"repoId": REPO, "fingerprint": pw["_id"], "reason": "test",
                          "createdAt": f["detectedAt"]})
v = compute_verdict(REPO)
check(v["counts"]["dismissed"] == 1 and v["verdict"] == "BLOCK",
      "dismissed one secret, still BLOCK because of the AWS key")

print("8. Alerts: only when the verdict changes to BLOCK")
alerts = list(db.alerts.find())
check(len(alerts) == 1 and alerts[0]["status"] == "skipped",
      "one alert record (skipped: no n8n URL in tests)")

print(f"\nAll {passed} checks passed.")
