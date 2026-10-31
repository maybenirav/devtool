# tools/make_demo_repo.py
# Builds the demo repo for your presentation, step by step, with real git commits.
#
#   python tools/make_demo_repo.py init     -> safe app (verdict: SAFE)
#   python tools/make_demo_repo.py break    -> vulnerable libs + secrets + debug (verdict: BLOCK)
#   python tools/make_demo_repo.py fix      -> deletes the AWS key, upgrades django
#
# The folder is created NEXT TO this project: ../releaseguard-demo
# All keys below are FAKE. They only look real so the scanner can find them.
import subprocess
import sys
from pathlib import Path

DEMO = Path(__file__).resolve().parent.parent.parent / "releaseguard-demo"

APP_PY = '''from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return "Hello from the ReleaseGuard demo app!"


if __name__ == "__main__":
    app.run()
'''

CONFIG_PY = '''import os

DEBUG = True
AWS_ACCESS_KEY_ID = "AKIA4RG7QW2XLMN8PZTK"
DB_PASSWORD = "Sup3rS3cretPass9"
API_KEY = "your_api_key_here"
SECRET_KEY = os.environ.get("SECRET_KEY")
'''

PACKAGE_JSON = '''{
  "name": "demo-frontend",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15"
  }
}
'''


def git(*args):
    print("  $ git " + " ".join(args))
    subprocess.run(["git", *args], cwd=DEMO, check=True)


def write(name, text):
    (DEMO / name).write_text(text, encoding="utf-8", newline="\n")


def commit(message, *files):
    git("add", *files)
    git("commit", "-m", message)


def push_if_remote():
    remotes = subprocess.run(["git", "remote"], cwd=DEMO, capture_output=True, text=True).stdout
    if "origin" in remotes.split():
        git("push", "-u", "origin", "main")
    else:
        print("\nNo GitHub remote yet. Connect it once with:")
        print(f"  cd {DEMO}")
        print("  git remote add origin https://github.com/YOUR-USERNAME/releaseguard-demo.git")
        print("  git push -u origin main")


def init():
    if (DEMO / ".git").exists():
        sys.exit(f"{DEMO} already exists. Delete that folder first if you want to start over.")
    DEMO.mkdir(parents=True, exist_ok=True)
    git("init", "-b", "main")
    write("README.md", "# ReleaseGuard demo app\n\nA tiny Flask app used to demo ReleaseGuard.\n")
    commit("Initial commit", "README.md")
    write("requirements.txt", "flask==3.1.3\n")
    write("app.py", APP_PY)
    commit("Add Flask app", "requirements.txt", "app.py")
    push_if_remote()
    print("\nDone. Scan it now: the verdict should be SAFE.")


def break_it():
    write("requirements.txt", "flask==3.1.3\ndjango==2.2.0\nrequests\n")
    commit("Add django and requests", "requirements.txt")
    write("package.json", PACKAGE_JSON)
    commit("Add frontend dependencies", "package.json")
    write("config.py", CONFIG_PY)
    commit("Add config", "config.py")
    push_if_remote()
    print("\nDone. Scan again: the verdict should be BLOCK.")


def fix():
    write("config.py", CONFIG_PY.replace('AWS_ACCESS_KEY_ID = "AKIA4RG7QW2XLMN8PZTK"\n', ""))
    commit("Remove AWS key", "config.py")
    write("requirements.txt", "flask==3.1.3\ndjango==4.2.16\nrequests\n")
    commit("Upgrade django", "requirements.txt")
    push_if_remote()
    print("\nDone. Scan again: django shows as FIXED, the AWS key stays 'still in git history'.")


if __name__ == "__main__":
    steps = {"init": init, "break": break_it, "fix": fix}
    if len(sys.argv) != 2 or sys.argv[1] not in steps:
        sys.exit("Usage: python tools/make_demo_repo.py init|break|fix")
    steps[sys.argv[1]]()
