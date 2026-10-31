# tests/fake_github.py
# A fake GitHub + OSV so the scanner can be tested offline (no internet, no tokens).
from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 10, 25, 10, 0, tzinfo=timezone.utc)


def _c(i, sha, message, files):
    return {"sha": sha, "message": message, "author": "Test Dev", "authorLogin": "testdev",
            "committedAt": T0 + timedelta(days=i), "url": f"https://github.com/x/{sha}",
            "files": files, "partial": False}


COMMITS = [
    _c(0, "a" * 40, "Initial app", [
        {"filename": "requirements.txt", "status": "added", "patch": "@@ -0,0 +1 @@\n+flask==3.0.3"},
    ]),
    _c(1, "b" * 40, "Add django and requests", [
        {"filename": "requirements.txt", "status": "modified",
         "patch": "@@ -1 +1,3 @@\n flask==3.0.3\n+django==2.2.0\n+requests"},
        {"filename": "package.json", "status": "added",
         "patch": '@@ -0,0 +1,7 @@\n+{\n+  "name": "demo",\n+  "version": "1.0.0",\n'
                  '+  "dependencies": {\n+    "lodash": "4.17.15"\n+  }\n+}'},
    ]),
    _c(2, "c" * 40, "Add config", [
        {"filename": "config.py", "status": "added",
         "patch": '@@ -0,0 +1,4 @@\n+DEBUG = True\n+AWS_ACCESS_KEY_ID = "AKIA4RG7QW2XLMN8PZTK"\n'
                  '+DB_PASSWORD = "Sup3rS3cretPass9"\n+API_KEY = "your_api_key_here"'},
    ]),
    _c(3, "d" * 40, "Remove AWS key, upgrade django", [
        {"filename": "config.py", "status": "modified",
         "patch": '@@ -1,4 +1,3 @@\n DEBUG = True\n-AWS_ACCESS_KEY_ID = "AKIA4RG7QW2XLMN8PZTK"\n'
                  ' DB_PASSWORD = "Sup3rS3cretPass9"\n API_KEY = "your_api_key_here"'},
        {"filename": "requirements.txt", "status": "modified",
         "patch": "@@ -1,3 +1,3 @@\n flask==3.0.3\n-django==2.2.0\n+django==4.2.16\n requests"},
    ]),
]

VULNS = {
    ("PyPI", "django", "2.2.0"): {"severity": "critical", "vulnCount": 42,
                                  "vulnIds": ["GHSA-x"], "summary": "SQL injection",
                                  "fixedVersion": "2.2.28"},
    ("npm", "lodash", "4.17.15"): {"severity": "high", "vulnCount": 6,
                                   "vulnIds": ["GHSA-y"], "summary": "Prototype pollution",
                                   "fixedVersion": "4.17.21"},
}

visible = len(COMMITS)  # how many commits "exist" right now (to simulate new pushes)


def install(monkey):
    import github_client as gh
    import osv_client as osv

    def get_repo(owner, name):
        return {"owner": "TestOwner", "name": "demo-app", "fullName": "TestOwner/demo-app",
                "url": "https://github.com/TestOwner/demo-app", "defaultBranch": "main"}

    def list_commits(owner, name, limit=30):
        import tests.fake_github as me
        return [c["sha"] for c in reversed(COMMITS[:me.visible])]

    def get_commit(owner, name, sha):
        return next(c for c in COMMITS if c["sha"] == sha)

    def check_packages(pkgs):
        return {p: VULNS[p] for p in set(pkgs) if p in VULNS}

    monkey(gh, "get_repo", get_repo)
    monkey(gh, "list_commits", list_commits)
    monkey(gh, "get_commit", get_commit)
    monkey(osv, "check_packages", check_packages)
