# tests/dev_server.py
# Runs the website with a FAKE GitHub repo (no internet needed) for UI testing.
#   python tests/dev_server.py   ->  open http://localhost:8000
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DB_NAME", "releaseguard_dev")

import tests.fake_github as fake  # noqa: E402

fake.install(setattr)

# slow the fake GitHub down a little so the live updates are visible
import github_client as gh  # noqa: E402

_real_get_commit = gh.get_commit


def slow_get_commit(owner, name, sha):
    time.sleep(0.8)
    return _real_get_commit(owner, name, sha)


gh.get_commit = slow_get_commit

import uvicorn  # noqa: E402

from main import app  # noqa: E402

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
