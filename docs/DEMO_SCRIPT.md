# Demo Script (video max 7 minutes, presentation 10 minutes)

This follows the 4-step demo flow from the Track 3 brief exactly.

## Before you record

1. `python reset_repo.py maybenirav/releaseguard-demo`
2. Rebuild the demo repo from scratch (SETUP_GUIDE Part 6, `init` only). Verdict should start as SAFE.
3. Open these tabs: your live ReleaseGuard URL, the `releaseguard-demo` repo on GitHub,
   MongoDB Atlas Data Explorer (`releaseguard` database), and your Discord channel (if n8n is set up).
4. Open the website once so Render is awake. Close anything that shows passwords.

## Script

**0:00 Problem (40 s)**
"A developer commits an API key by mistake, deletes it in the next commit and thinks it's fixed.
It isn't: Git keeps every version, and anyone can still read it. Old libraries with public
exploits and debug settings slip into releases the same way. Existing tools show what's wrong
now. ReleaseGuard answers: is this release safe to ship, and which commit made it unsafe?"

**0:40 Step 1: run the tool (50 s)**
Paste the demo repo, click **Scan repo**. Point at the live progress.
"Every recent commit is fetched from GitHub and its diff is checked for secrets, vulnerable
libraries and risky settings." The stamp lands: **SAFE**.

**1:30 Step 2: the data in MongoDB (50 s)**
Switch to Atlas Data Explorer. Show `scans`, `commits`, `findings`.
"Each commit has a stable ID: repo plus commit SHA. Findings are events: added or removed in a
commit." Back on the site, scroll to **Under the hood**: collections, required fields, indexes,
and the query plans showing each question uses its index.

**2:20 Step 3: a meaningful change (2 min)**
In the terminal: `python tools/make_demo_repo.py break` (adds django 2.2.0, lodash 4.17.15,
a fake AWS key, a hardcoded password and DEBUG = True, as 3 commits).
If the webhook is connected, the scan starts by itself; otherwise click **Scan again**.
- Findings stream in live (change stream). The stamp lands: **BLOCK**.
- Discord receives the n8n alert (verdict changed to BLOCK).
- Show a risk card: "introduced in commit X by Nirav", "upgrade lodash to 4.17.21".
- Run `python tools/make_demo_repo.py fix` (deletes the AWS key, upgrades django) and scan again.
- **Key moment:** django moves to **Fixed**, but the AWS key says
  **"deleted, but still readable in git history. Rotate this secret."** The verdict stays BLOCK.
- Show **History**: the risk level jumped at "Add config", dropped a bit when django was
  upgraded, but deleting the key did not lower it.
- **Compare** "Add Flask app" with the latest commit: riskier, with the new risks listed.
- Click **Explain** on the AWS key.

**4:20 Step 4: failure cases (1 min)**
In **Under the hood**, click the three buttons:
- "Try saving a duplicate": refused by the unique index. "That's why re-scans never double-count."
- "Try saving a broken finding": refused by schema validation, with MongoDB's exact reason.
- "Replay a delivery": GitHub sending the same webhook twice, the second one is ignored.
Then click **Scan again**: "4 already scanned, skipped" in the scan history.
Optional: paste `not a link` in the scan box to show the friendly error.

**5:20 Automation (40 s)**
**Automate it**: webhook auto-scan, n8n alerts only when the verdict changes, README badge.
Mark the DB_PASSWORD finding as a false positive to show dismissals.

**6:00 Close (40 s)**
"ReleaseGuard: git blame for security risks. MongoDB stores the full history: aggregation turns
events into introduced-in, fixed-in and exposure; unique indexes make re-scans safe; schema
validation keeps the data clean; change streams make it live. Try it yourself, no login needed."
Show the URL.
