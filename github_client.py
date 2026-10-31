# github_client.py
# Everything that talks to GitHub lives here.
import os
import re
from datetime import datetime

import requests
from dotenv import load_dotenv

load_dotenv()

API = "https://api.github.com"
TIMEOUT = 20  # seconds


class GitHubError(Exception):
    """An error with a friendly message we can show to the user."""


_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/.*)?$"
)
_SHORT_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$")


def parse_repo_url(text):
    """'https://github.com/owner/repo' or 'owner/repo' -> ('owner', 'repo')"""
    text = (text or "").strip().rstrip("/")
    match = _URL_RE.match(text) or _SHORT_RE.match(text)
    if not match:
        raise GitHubError(
            "Enter a GitHub repo link like https://github.com/owner/repo")
    owner, name = match.group(1), match.group(2)
    if name.endswith(".git"):
        name = name[:-4]
    return owner, name


def _headers():
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ReleaseGuard",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get(path, params=None):
    """Call the GitHub API and turn errors into friendly messages."""
    try:
        r = requests.get(API + path, headers=_headers(), params=params, timeout=TIMEOUT)
    except requests.RequestException:
        raise GitHubError("Could not reach GitHub. Check the internet connection.")

    if r.status_code == 404:
        raise GitHubError("Repo not found or private. ReleaseGuard scans public repos.")
    if r.status_code == 401:
        raise GitHubError("The GitHub token is invalid. Check GITHUB_TOKEN.")
    if r.status_code in (403, 429):
        if r.headers.get("X-RateLimit-Remaining") == "0":
            raise GitHubError("GitHub rate limit reached. Try again in a few minutes.")
        raise GitHubError("GitHub refused the request.")
    if r.status_code == 409:
        raise GitHubError("This repo is empty. Push a commit, then scan again.")
    if r.status_code >= 400:
        raise GitHubError(f"GitHub returned error {r.status_code}.")
    return r.json()


def parse_time(text):
    """GitHub time '2026-10-31T10:15:00Z' -> Python datetime (UTC)."""
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def get_repo(owner, name):
    data = _get(f"/repos/{owner}/{name}")
    return {
        "owner": data["owner"]["login"],
        "name": data["name"],
        "fullName": data["full_name"],
        "url": data["html_url"],
        "defaultBranch": data.get("default_branch", "main"),
    }


def list_commits(owner, name, limit=30):
    """Return commit SHAs of the default branch, newest first."""
    data = _get(f"/repos/{owner}/{name}/commits", params={"per_page": min(limit, 100)})
    return [c["sha"] for c in data]


def get_commit(owner, name, sha):
    """Return one commit with its changed files and their diffs."""
    data = _get(f"/repos/{owner}/{name}/commits/{sha}")
    info = data["commit"]
    author = info.get("author") or {}
    files = data.get("files") or []

    partial = len(files) >= 300  # GitHub returns at most 300 files per commit
    out_files = []
    for f in files:
        patch = f.get("patch")
        if patch is None and f.get("changes", 0) > 0:
            partial = True  # GitHub skipped this diff because it was too big
        out_files.append({
            "filename": f["filename"],
            "status": f.get("status"),
            "patch": patch or "",
        })

    return {
        "sha": data["sha"],
        "message": (info.get("message") or "").split("\n")[0][:200],
        "author": author.get("name") or "unknown",
        "authorLogin": (data.get("author") or {}).get("login"),
        "committedAt": parse_time(author.get("date") or info["committer"]["date"]),
        "url": data.get("html_url"),
        "files": out_files,
        "partial": partial,
    }
