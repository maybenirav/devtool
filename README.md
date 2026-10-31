# ReleaseGuard

**git blame for security risks.** Paste a GitHub repo and ReleaseGuard answers one question:
**is this release safe to ship, and if not, which commit made it unsafe?**

Built for UNCHARTED 2026 (NEXUS, SVNIT Surat), Track 3: Developer Tools for Production use cases.

## The problem

- **Deleted secrets are not gone.** A developer commits an API key, deletes it in the next commit
  and thinks it is fixed. Git keeps every old version, so the key is still readable. Only rotating it helps.
- **Vulnerable libraries hide in plain sight.** Old versions with public exploits keep working, so nobody notices.
- **Risky settings slip into releases:** `DEBUG = True`, `verify=False`, open CORS, wildcard hosts.

Existing tools mostly show what is wrong *right now*. They don't tell the story: when a risk entered,
which commit caused it, how long it was exposed, and whether this release is safer than the last one.

## What ReleaseGuard does

1. Fetches the recent commits of a public GitHub repo and reads each commit's diff.
2. Runs three checks on every added and removed line:
   - **Secrets:** AWS, GitHub, Stripe, Google, OpenAI, Anthropic, Slack, MongoDB URIs, private keys,
     hardcoded passwords. Placeholders like `your_api_key_here` are ignored.
   - **Vulnerable libraries:** `requirements.txt` and `package.json`, checked against
     [OSV.dev](https://osv.dev), with the version that fixes them.
   - **Risky settings:** debug mode, disabled TLS verification, open CORS, `ALLOWED_HOSTS = ['*']`.
3. Stores every finding as an **event** ("added in commit X", "removed in commit Y") in MongoDB.
4. Turns that history into answers with aggregation pipelines:
   - **Verdict:** SAFE / RISKY / BLOCK, with reasons
   - **Introduced in** which commit, by whom, when; **fixed in** which commit
   - **Exposure:** days and number of commits a risk was live
   - **"Still in git history":** a deleted secret keeps the release blocked until it is rotated
   - **History:** the risk level after every commit
   - **Compare** any two releases: what appeared, what was fixed
5. Developer workflow: live findings while scanning, GitHub webhook auto-scan on every push,
   n8n alerts when a release turns BLOCK, a README badge, "explain this risk" (Claude, with a
   built-in fallback), and dismissing false positives.

Secrets are **never stored**: only a one-way hash (to recognise the same secret across commits)
and a masked value like `AKIA****PZTK`. The AI explanation never receives secret values.

## How MongoDB is used

| Requirement | Implementation |
|---|---|
| Stable IDs, timestamps, project/version links | `commitId = owner/repo@sha`; `findingId` = hash of repo + commit + fingerprint + action + line; every document has `repoId`, `commitSha`, `committedAt` |
| Indexes for frequent questions | `risk_history (repoId, fingerprint, committedAt)`, `scan_live_view (scanId, detectedAt)`, `repo_latest_commits`, `repo_latest_scans`, `findings_by_commit`. The app shows `explain()` output proving which index each query uses |
| Aggregation pipelines | Risk story: `$group` by fingerprint, `$filter`/`$first`/`$last` for introduced/fixed, `$dateDiff` for exposure, `$lookup` into commits (live-for-N-commits) and dismissals. Timeline: `$lookup` + `$setWindowFields` running total |
| Schema validation | `$jsonSchema` on all 7 collections: required fields and enums (type, severity, action, status), while `details` stays flexible |
| Unique indexes / safe re-ingestion | `uniq_findingId`, `uniq_commitId`, `uniq_scanId`, `uniq_deliveryId`, `uniq_dismissal`. Re-scans skip known commits; an interrupted scan resumes without duplicates |
| Change streams | Live scan view: a database change stream on `findings` + `scans`, streamed to the browser with Server-Sent Events |
| Extra | TTL index (webhook deliveries expire after 7 days). Schema patterns: **Polymorphic** (one findings collection, different `details` shapes), **Computed** (latest verdict stored on the repo for the badge and home page), **event history** |

Collections: `repos`, `scans`, `commits`, `findings`, `dismissals`, `webhook_deliveries`, `alerts`.

## Architecture

```
Browser ──HTTP/SSE──> FastAPI (main.py) ──> scanner.py ──> GitHub API (commits, diffs)
                           │                    │──> detectors.py (secrets, settings, libraries)
                           │                    └──> osv_client.py ──> OSV.dev
                           │──> history.py (aggregation pipelines) ──┐
GitHub webhook ──────────> │                                         ├──> MongoDB Atlas
                           │──> alerts.py ──> n8n ──> Discord/email   │
                           └──> change stream ───────────────────────┘
```

## Run it locally

```bash
python -m venv venv
venv\Scripts\activate            # Windows  (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env           # then fill in MONGO_URI and GITHUB_TOKEN
uvicorn main:app --reload        # open http://localhost:8000
```

The database collections, validation rules and indexes are created automatically on startup
(or run `python setup_db.py`).

Command-line tools: `python scan_cli.py <repo-url>`, `python report_cli.py <repo-url> [shaA shaB]`,
`python reset_repo.py owner/repo`.

## Tests

```bash
python tests/test_detectors.py      # 30 offline checks for the three detectors
python tests/test_end_to_end.py     # 24 checks: scan, re-scan, history, verdict, compare, DB rules
```

The end-to-end test uses a simulated GitHub repo and a separate `releaseguard_test` database.

## Environment variables

| Name | Required | Purpose |
|---|---|---|
| `MONGO_URI` | yes | MongoDB Atlas connection string |
| `GITHUB_TOKEN` | yes | Fine-grained token, public repositories read-only (5,000 requests/hour) |
| `WEBHOOK_SECRET` | for webhooks | Shared secret used to verify GitHub webhook signatures |
| `N8N_WEBHOOK_URL` | for alerts | n8n Webhook node production URL |
| `ANTHROPIC_API_KEY` | no | AI explanations (built-in explanations otherwise) |
| `MAX_COMMITS` | no | Commits per scan (default 30) |

## Limitations and next steps

- Scans the latest 30 commits of the default branch of public repos.
- Libraries: Python `requirements.txt` and npm `package.json` (not lock files yet).
- Next: more ecosystems (Go, Maven, Cargo), secret validity checks, organisation-wide dashboards,
  GitHub Checks API to block pull requests.
