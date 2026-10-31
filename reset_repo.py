# reset_repo.py
# Deletes all saved data for one repo so it can be scanned fresh (use before a demo).
#   python reset_repo.py owner/repo
import sys

from db import get_db

if len(sys.argv) < 2:
    print("Usage: python reset_repo.py owner/repo")
    sys.exit(1)

repo_id = sys.argv[1].replace("https://github.com/", "").strip("/").lower()
db = get_db()
for name in ("findings", "commits", "scans", "alerts", "dismissals"):
    result = db[name].delete_many({"repoId": repo_id})
    print(f"{name}: deleted {result.deleted_count}")
db.repos.delete_one({"_id": repo_id})
print(f"Reset done for {repo_id}")
