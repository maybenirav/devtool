# ReleaseGuard: Your Step-by-Step Guide

Follow the parts in order. Each part ends with a check, so you always know it worked.
If something fails, send a screenshot of the error.

Time plan (deadline: code freeze **9:00 PM**, form closes **10:00 PM**):

| Part | What | Time |
|---|---|---|
| 1-4 | Put the code in place, install, run tests | 20 min |
| 5 | Run the website on your laptop | 10 min |
| 6 | Build the demo repo | 15 min |
| 7 | **Deploy online (Render)** | 30 min |
| 8-9 | Webhook + n8n alerts | 30 min |
| 10 | Demo video, PPT, submit | 2-3 hours |

---

## Part 1: Put the new code in your project

1. Unzip `releaseguard.zip`. You get a folder `releaseguard` with all the files.
2. Open your project folder `C:\hackathon\devtool`.
3. **Keep** these: `venv`, `.env`, `.git` (a hidden folder, you may not see it).
4. **Delete** your old Python files: `test_connection.py`, `watch.py`, `debug_commit.py`, and the
   old `db.py`, `setup_db.py`, `github_client.py`, `detectors.py`, `osv_client.py`, `scanner.py`,
   `history.py`, `scan_cli.py`, `report_cli.py`, `reset_repo.py`, `test_db_rules.py`.
5. Copy **everything inside** the unzipped `releaseguard` folder into `C:\hackathon\devtool`
   (including the hidden-looking `.gitignore` and `.env.example`). If Windows asks, choose **Replace**.

Check: `C:\hackathon\devtool` now contains `main.py`, a `static` folder, a `tests` folder, and your `.env`.

## Part 2: Install the libraries

In the VS Code terminal (with `(venv)` showing):

```
python -m pip install -r requirements.txt
```

Check: it ends with "Successfully installed ..." (or "Requirement already satisfied").
If it fails because of slow internet, just run it again.

## Part 3: Check your `.env`

Open `.env`. It should have at least these lines (your own values):

```
MONGO_URI=mongodb+srv://YOUR_DB_USER:YOUR_PASSWORD@your-cluster.xxxxx.mongodb.net/
DB_NAME=releaseguard
GITHUB_TOKEN=github_pat_xxxxxxxx
WEBHOOK_SECRET=pick-any-long-random-text-like-rg2026-k9x7q2m4v8
```

`WEBHOOK_SECRET` is just a password you invent. Write it down; you'll need it in Part 8.

## Part 4: Run the tests

```
python tests/test_detectors.py
python tests/test_end_to_end.py
```

Check: the first ends with **"All 30 checks passed."**, the second with **"All 24 checks passed."**
(The second test uses a separate database called `releaseguard_test`, so your real data is safe.)

Save your progress:

```
git add .
git commit -m "ReleaseGuard: full app"
git push
```

## Part 5: Run the website on your laptop

```
uvicorn main:app --reload
```

Open **http://localhost:8000** in your browser. You should see "Is this release safe to ship?".

Try it: paste `https://github.com/maybenirav/releaseguard-demo` and click **Scan repo**.
Findings appear live, then the stamp lands. (Your old demo repo still has the `requirements.txt.`
typo, so django won't show. Part 6 builds a clean one.)

Stop the server with **Ctrl + C** when you're done.

## Part 6: Build a clean demo repo

1. On GitHub, open your old `releaseguard-demo` repo, then **Settings**, scroll to the bottom,
   **Delete this repository**.
2. Create it again: **github.com/new**, name `releaseguard-demo`, **Public**,
   **do not** tick "Add a README". Click **Create repository**.
3. Clear the old scan data:
   ```
   python reset_repo.py maybenirav/releaseguard-demo
   ```
4. Create the safe starting version (the script makes the folder next to your project):
   ```
   python tools/make_demo_repo.py init
   ```
   It prints 3 commands at the end. Run them (they connect the folder to GitHub and push):
   ```
   cd ..\releaseguard-demo
   git remote add origin https://github.com/maybenirav/releaseguard-demo.git
   git push -u origin main
   cd ..\devtool
   ```

Check: the GitHub page shows `README.md`, `app.py`, `requirements.txt`.

**Do not run `break` and `fix` yet.** You will run them live during the demo (see `DEMO_SCRIPT.md`).
To rehearse, you can run them, then repeat Part 6 to start over.

**If GitHub blocks a push** saying a secret was detected: the keys are fake. Open the link in the
error message, choose "It's used in tests" (or "False positive"), allow it, then run `git push` again.

## Part 7: Deploy online with Render (compulsory!)

1. Make sure your code is pushed (`git push`) and check on GitHub that **`.env` is NOT in the file list**.
2. Make the `devtool` repo **Public** (Settings, Danger Zone, Change visibility). Judges need it anyway.
3. Go to **render.com**, sign up with your **GitHub** account.
4. Click **New +**, then **Blueprint**. Connect your `devtool` repo. Render reads `render.yaml`.
5. Render asks for the secret values. Fill in:
   - `MONGO_URI`: the same value as in your `.env`
   - `GITHUB_TOKEN`: the same value as in your `.env`
   - `N8N_WEBHOOK_URL` and `ANTHROPIC_API_KEY`: leave empty for now
   - `WEBHOOK_SECRET` is generated automatically
6. Click **Apply**. The first build takes 3-5 minutes.
7. Open your service. At the top you'll see the URL, like `https://releaseguard-xxxx.onrender.com`.

Check: open `https://YOUR-URL/api/health`. It must say `{"ok":true,"database":"connected"}`.
Then open the main URL and scan your demo repo. **This URL is what you submit.**

If the Blueprint option confuses you, use **New +, Web Service** instead: pick the repo,
Runtime **Python 3**, Build command `pip install -r requirements.txt`, Start command
`uvicorn main:app --host 0.0.0.0 --port $PORT`, Instance type **Free**, and add the environment
variables by hand (including `WEBHOOK_SECRET` with the text you invented).

**Keep it awake:** Render's free plan sleeps after 15 minutes without visitors, and waking up
takes about a minute. Judges might think it's broken. Fix: create a free account at
**cron-job.org** and add a job that opens `https://YOUR-URL/api/health` every 10 minutes.

## Part 8: Auto-scan on every push (GitHub webhook)

1. In Render, open your service, **Environment**, and copy the value of `WEBHOOK_SECRET`.
2. On GitHub, open `releaseguard-demo`, **Settings**, **Webhooks**, **Add webhook**:
   - Payload URL: `https://YOUR-URL/webhook/github`
   - Content type: **application/json**
   - Secret: paste the `WEBHOOK_SECRET` value
   - Which events: **Just the push event**
   - Click **Add webhook**.

Check: refresh the webhook page. The delivery shows a green tick (GitHub sends a "ping" first).
Scan the demo repo once on the website (webhooks only work for repos that were scanned once).
From then on, every push starts a scan by itself.

## Part 9: Alerts with n8n (sponsor bonus)

1. **Discord:** in a server you own, Server Settings, Integrations, Webhooks, New Webhook,
   pick a channel, **Copy Webhook URL**.
2. **n8n:** sign up at **n8n.io** (free trial). Create a new workflow, click the **...** menu,
   **Import from file**, and choose `n8n/releaseguard-alert-workflow.json` from this project.
3. Open the **Send to Discord** node and replace `PASTE_YOUR_DISCORD_WEBHOOK_URL_HERE` with your
   Discord webhook URL.
4. Open the **ReleaseGuard webhook** node and copy the **Production URL**.
5. Click **Save**, then switch the workflow to **Active**.
6. In Render, Environment, set `N8N_WEBHOOK_URL` to that Production URL. Save (Render redeploys).

Check: on your repo's report page, in "Automate it", click **Send test alert**.
A message appears in your Discord channel.

## Part 10 (optional): AI explanations

If you have an Anthropic API key with credits, add `ANTHROPIC_API_KEY` in Render.
Without it, the **Explain** button still works with built-in explanations.

## Part 11: Demo video, PPT, submission

- Rehearse with `docs/DEMO_SCRIPT.md`, then record the video (max 7 minutes).
- Build the PPT from `docs/PITCH.md`, using screenshots of your live site.
- Before recording: `python reset_repo.py maybenirav/releaseguard-demo` and rebuild the demo
  repo (Part 6) so you start from SAFE.
- Never show your `.env`, Atlas password or tokens on screen.
- The rulebook says AI coding assistants may be used per the organizers' AI policy, and teams must
  understand their code. Check that policy and disclose AI help if it asks you to.

**Submission checklist (form opens 9:00 PM, closes 10:00 PM):**

- [ ] Last `git push` **before 9:00 PM** (code freeze)
- [ ] Live URL works in a private/incognito browser window
- [ ] GitHub repo is public, README visible, `.env` not in it
- [ ] Demo video (max 7 min) uploaded and link is viewable by anyone
- [ ] PPT uploaded and link is viewable by anyone
- [ ] Access instructions: "No login needed. Open the URL and scan https://github.com/maybenirav/releaseguard-demo or any public repo."
- [ ] Every link in the form tested once more

## Troubleshooting

| Problem | Fix |
|---|---|
| `SSL handshake failed` | Atlas Network Access: allow `0.0.0.0/0`, wait 1 minute |
| `GitHub rate limit reached` | `GITHUB_TOKEN` missing or wrong in `.env` / Render |
| Render build fails | Check the log; usually a typo in an environment variable name |
| `/api/health` says error | `MONGO_URI` on Render is wrong, or Atlas blocks Render (allow `0.0.0.0/0`) |
| Webhook shows a red cross | Secret doesn't match `WEBHOOK_SECRET`, or content type isn't application/json |
| Live updates don't appear | The page falls back to refreshing every 2.5 seconds automatically |
| `python` not found | Activate the venv: `venv\Scripts\activate` |
