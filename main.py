# main.py
# The ReleaseGuard web app (FastAPI): website, JSON API, live updates,
# GitHub webhook, README badge and the "under the hood" MongoDB demos.
#
# Run locally:   uvicorn main:app --reload
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from pathlib import Path

from bson import ObjectId
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pymongo.errors import DuplicateKeyError, PyMongoError, WriteError
from starlette.concurrency import run_in_threadpool

import alerts
import github_client as gh
from db import get_db
from explain import explain
from history import compare_commits, compute_verdict, get_risks, get_timeline
from scanner import mark_stale_scans, start_scan_in_background
from setup_db import setup_database

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
logger = logging.getLogger("releaseguard")

STATIC = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app):
    try:
        await run_in_threadpool(setup_database, logger.info)
        await run_in_threadpool(mark_stale_scans)
    except Exception as e:  # the site still starts; /api/health will show the problem
        logger.error("Database setup failed: %s", e)
    yield


app = FastAPI(title="ReleaseGuard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ---------- helpers ----------

def clean(value):
    """Make MongoDB documents JSON-friendly (ObjectId -> str, dates -> ISO strings)."""
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()
                if not (k == "_id" and isinstance(v, ObjectId))}
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    return value


def repo_key(owner, name):
    return f"{owner}/{name}".lower()


def base_url(request: Request):
    return (os.getenv("PUBLIC_BASE_URL") or os.getenv("RENDER_EXTERNAL_URL")
            or str(request.base_url)).rstrip("/")


def now():
    return datetime.now(timezone.utc)


# ---------- pages ----------

@app.get("/", include_in_schema=False)
def home_page():
    return FileResponse(STATIC / "index.html")


@app.get("/repo/{owner}/{name}", include_in_schema=False)
def repo_page(owner: str, name: str):
    return FileResponse(STATIC / "index.html")


# ---------- API: health & repos ----------

@app.get("/api/health")
def health():
    try:
        get_db().command("ping")
        return {"ok": True, "database": "connected"}
    except Exception as e:
        return JSONResponse({"ok": False, "database": f"error: {type(e).__name__}"},
                            status_code=503)


@app.get("/api/repos")
def recent_repos():
    docs = get_db().repos.find(
        {"lastScanAt": {"$exists": True}},
        {"fullName": 1, "url": 1, "lastVerdict": 1, "lastScanAt": 1},
    ).sort("lastScanAt", -1).limit(12)
    return clean(list(docs))


# ---------- API: scanning ----------

@app.post("/api/scan")
def start_scan(payload: dict = Body(...)):
    repo = (payload or {}).get("repo", "")
    try:
        scan_id, repo_id, reused = start_scan_in_background(repo, trigger="manual")
    except gh.GitHubError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"scanId": scan_id, "repoId": repo_id, "reused": reused}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = get_db().scans.find_one({"scanId": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return clean(scan)


@app.get("/api/scans/{scan_id}/findings")
def get_scan_findings(scan_id: str):
    docs = get_db().findings.find({"scanId": scan_id}).sort("detectedAt", 1)
    return clean(list(docs))


def _sse(event, data):
    return f"event: {event}\ndata: {json.dumps(clean(data))}\n\n"


@app.get("/api/scans/{scan_id}/events")
def scan_events(scan_id: str):
    """Live updates with MongoDB change streams (Server-Sent Events)."""
    db = get_db()
    if not db.scans.find_one({"scanId": scan_id}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="Scan not found.")

    pipeline = [{"$match": {
        "ns.coll": {"$in": ["findings", "scans"]},
        "operationType": {"$in": ["insert", "update", "replace"]},
        "fullDocument.scanId": scan_id,
    }}]

    def stream():
        started = last_beat = time.time()
        try:
            # open the change stream FIRST, then send what already exists,
            # so nothing that happens in between is missed
            with db.watch(pipeline, full_document="updateLookup",
                          max_await_time_ms=1000) as changes:
                scan = db.scans.find_one({"scanId": scan_id})
                yield _sse("scan", scan)
                for f in db.findings.find({"scanId": scan_id}).sort("detectedAt", 1):
                    yield _sse("finding", f)
                if scan["status"] != "running":
                    yield _sse("done", scan)
                    return

                while changes.alive and time.time() - started < 600:
                    change = changes.try_next()
                    if change is None:
                        if time.time() - last_beat > 15:
                            last_beat = time.time()
                            yield ": keep-alive\n\n"
                        continue
                    doc = change.get("fullDocument") or {}
                    if change["ns"]["coll"] == "findings":
                        yield _sse("finding", doc)
                    else:
                        yield _sse("scan", doc)
                        if doc.get("status") != "running":
                            yield _sse("done", doc)
                            return
        except PyMongoError as e:
            logger.warning("change stream error: %s", e)
            yield _sse("stream-error", {"message": "Live updates paused. Refreshing..."})

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


# ---------- API: report ----------

@app.get("/api/repos/{owner}/{name}/report")
def repo_report(owner: str, name: str, request: Request):
    db = get_db()
    repo_id = repo_key(owner, name)
    repo = db.repos.find_one({"_id": repo_id})
    if not repo:
        raise HTTPException(status_code=404, detail="This repo has not been scanned yet.")

    risks = get_risks(repo_id)
    verdict = compute_verdict(repo_id, risks)
    scans = list(db.scans.find({"repoId": repo_id}).sort("startedAt", -1).limit(8))
    running = next((s for s in scans if s["status"] == "running"), None)

    # keep the stored verdict (Computed Pattern) in sync, e.g. after a dismissal
    if not running and repo.get("lastScanAt") and repo.get("lastVerdict") != verdict["verdict"]:
        db.repos.update_one({"_id": repo_id}, {"$set": {
            "lastVerdict": verdict["verdict"], "lastReasons": verdict["reasons"]}})

    base = base_url(request)
    return clean({
        "repo": repo,
        "verdict": verdict,
        "risks": risks,
        "timeline": get_timeline(repo_id),
        "scans": scans,
        "runningScanId": running["scanId"] if running else None,
        "alerts": list(db.alerts.find({"repoId": repo_id}).sort("createdAt", -1).limit(5)),
        "links": {
            "report": f"{base}/repo/{repo_id}",
            "badge": f"{base}/badge/{repo_id}.svg",
            "webhook": f"{base}/webhook/github",
        },
        "webhookConfigured": bool(os.getenv("WEBHOOK_SECRET")),
        "alertsConfigured": bool(os.getenv("N8N_WEBHOOK_URL")),
    })


@app.post("/api/repos/{owner}/{name}/compare")
def compare(owner: str, name: str, payload: dict = Body(...)):
    try:
        result = compare_commits(repo_key(owner, name), payload.get("a"), payload.get("b"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return clean(result)


def _find_risk(repo_id, fingerprint):
    for r in get_risks(repo_id):
        if r["_id"] == fingerprint:
            return r
    raise HTTPException(status_code=404, detail="Risk not found.")


@app.post("/api/repos/{owner}/{name}/explain")
def explain_risk(owner: str, name: str, payload: dict = Body(...)):
    risk = _find_risk(repo_key(owner, name), payload.get("fingerprint"))
    return explain(risk)


@app.post("/api/repos/{owner}/{name}/dismiss")
def dismiss(owner: str, name: str, payload: dict = Body(...)):
    repo_id = repo_key(owner, name)
    fingerprint = payload.get("fingerprint")
    _find_risk(repo_id, fingerprint)
    reason = (payload.get("reason") or "Marked as false positive").strip()[:200]
    get_db().dismissals.update_one(
        {"repoId": repo_id, "fingerprint": fingerprint},
        {"$set": {"reason": reason, "createdAt": now()}},
        upsert=True,
    )
    return {"ok": True}


@app.post("/api/repos/{owner}/{name}/undismiss")
def undismiss(owner: str, name: str, payload: dict = Body(...)):
    get_db().dismissals.delete_one(
        {"repoId": repo_key(owner, name), "fingerprint": payload.get("fingerprint")})
    return {"ok": True}


@app.post("/api/repos/{owner}/{name}/test-alert")
def test_alert(owner: str, name: str):
    repo_id = repo_key(owner, name)
    repo = get_db().repos.find_one({"_id": repo_id})
    if not repo:
        raise HTTPException(status_code=404, detail="This repo has not been scanned yet.")
    result = compute_verdict(repo_id)
    return clean(alerts.send_alert(repo_id, repo.get("lastScanId") or "test",
                                   result["verdict"], repo.get("lastVerdict"),
                                   result["reasons"], test=True))


# ---------- README badge ----------

BADGE_COLORS = {"SAFE": "#2e7d4f", "RISKY": "#b7791f", "BLOCK": "#c62828"}


@app.get("/badge/{owner}/{name}.svg", include_in_schema=False)
def badge(owner: str, name: str):
    repo = get_db().repos.find_one({"_id": repo_key(owner, name)}, {"lastVerdict": 1})
    verdict = (repo or {}).get("lastVerdict")
    label, value = "ReleaseGuard", (verdict or "not scanned")
    color = BADGE_COLORS.get(verdict, "#8a8f98")
    lw, vw = 7 * len(label) + 12, 7 * len(value) + 12
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{lw + vw}" height="20" role="img" aria-label="{label}: {value}">
<title>{label}: {value}</title>
<rect width="{lw}" height="20" fill="#3d4450"/><rect x="{lw}" width="{vw}" height="20" fill="{color}"/>
<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">
<text x="{lw / 2}" y="14">{label}</text><text x="{lw + vw / 2}" y="14">{value}</text></g></svg>"""
    return Response(svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "no-cache, max-age=0"})


# ---------- GitHub webhook ----------

def _handle_push(event, delivery_id, payload):
    db = get_db()
    repo_id = ((payload.get("repository") or {}).get("full_name") or "").lower()

    # unique index on deliveryId: GitHub re-sending the same delivery is ignored
    try:
        db.webhook_deliveries.insert_one({
            "deliveryId": delivery_id, "event": event, "repoId": repo_id,
            "receivedAt": now()})
    except DuplicateKeyError:
        return {"status": "duplicate_ignored", "deliveryId": delivery_id}

    if event == "ping":
        return {"status": "pong"}
    if event != "push":
        return {"status": "ignored", "reason": f"'{event}' events are not scanned"}

    repo = db.repos.find_one({"_id": repo_id})
    if not repo:
        return {"status": "ignored",
                "reason": "Repo not connected. Scan it once on the website first."}
    branch = repo.get("defaultBranch", "main")
    if payload.get("ref") != f"refs/heads/{branch}":
        return {"status": "ignored", "reason": f"Only pushes to '{branch}' are scanned"}

    scan_id, _, reused = start_scan_in_background(repo_id, trigger="webhook")
    db.webhook_deliveries.update_one({"deliveryId": delivery_id},
                                     {"$set": {"scanId": scan_id}})
    return {"status": "scan_started", "scanId": scan_id, "reused": reused}


@app.post("/webhook/github")
async def github_webhook(request: Request):
    secret = os.getenv("WEBHOOK_SECRET")
    if not secret:
        return JSONResponse({"error": "WEBHOOK_SECRET is not configured."}, status_code=503)

    body = await request.body()
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(request.headers.get("X-Hub-Signature-256", ""), expected):
        return JSONResponse({"error": "Invalid signature."}, status_code=401)

    delivery_id = request.headers.get("X-GitHub-Delivery")
    if not delivery_id:
        return JSONResponse({"error": "Missing X-GitHub-Delivery header."}, status_code=400)
    try:
        payload = json.loads(body or b"{}")
    except ValueError:
        return JSONResponse({"error": "Body is not valid JSON."}, status_code=400)

    event = request.headers.get("X-GitHub-Event", "")
    try:
        return await run_in_threadpool(_handle_push, event, delivery_id, payload)
    except gh.GitHubError as e:
        return JSONResponse({"error": str(e)}, status_code=502)


# ---------- "Under the hood": live MongoDB proofs for the demo ----------

def _index_names(plan):
    """Find every index name used in a query plan."""
    found = []
    if isinstance(plan, dict):
        if "indexName" in plan:
            found.append(plan["indexName"])
        for v in plan.values():
            found += _index_names(v)
    elif isinstance(plan, list):
        for v in plan:
            found += _index_names(v)
    return found


@app.get("/api/under-the-hood")
def under_the_hood(repo: str = ""):
    db = get_db()
    collections = []
    for info in db.list_collections():
        name = info["name"]
        if name.startswith("system."):
            continue
        schema = ((info.get("options") or {}).get("validator") or {}).get("$jsonSchema", {})
        indexes = []
        for idx_name, idx in db[name].index_information().items():
            indexes.append({
                "name": idx_name,
                "keys": [f"{k}:{v}" for k, v in idx["key"]],
                "unique": bool(idx.get("unique")) or idx_name == "_id_",
                "ttlSeconds": idx.get("expireAfterSeconds"),
            })
        collections.append({
            "name": name,
            "documents": db[name].estimated_document_count(),
            "requiredFields": schema.get("required", []),
            "indexes": indexes,
        })
    collections.sort(key=lambda c: c["name"])

    plans = []
    repo_id = repo.lower()
    if repo_id:
        questions = [
            ("Risk history of one finding", db.findings,
             {"repoId": repo_id, "fingerprint": "x"}, [("committedAt", 1)]),
            ("Latest commits of this repo", db.commits,
             {"repoId": repo_id}, [("committedAt", -1)]),
            ("Latest scans of this repo", db.scans,
             {"repoId": repo_id}, [("startedAt", -1)]),
        ]
        for label, coll, flt, sort in questions:
            try:
                plan = coll.find(flt).sort(sort).explain()["queryPlanner"]["winningPlan"]
                used = _index_names(plan)
            except PyMongoError:
                used = []
            plans.append({"question": label, "indexUsed": used[0] if used else "none"})

    return {"collections": collections, "queryPlans": plans}


@app.post("/api/demo/duplicate")
def demo_duplicate(payload: dict = Body(...)):
    """Try to save a finding that already exists. The unique index must refuse it."""
    db = get_db()
    repo_id = (payload.get("repo") or "").lower()
    original = db.findings.find_one({"repoId": repo_id}, sort=[("committedAt", -1)])
    if not original:
        raise HTTPException(status_code=400, detail="Scan this repo first.")
    copy = {k: v for k, v in original.items() if k != "_id"}
    try:
        db.findings.insert_one(copy)
        db.findings.delete_one({"_id": copy["_id"]})
        return {"blocked": False, "message": "Duplicate was saved. This should not happen."}
    except DuplicateKeyError as e:
        return {"blocked": True, "by": "unique index uniq_findingId",
                "findingId": original["findingId"], "title": original["title"],
                "message": (e.details or {}).get("errmsg", str(e))[:300]}


@app.post("/api/demo/invalid")
def demo_invalid(payload: dict = Body(...)):
    """Try to save a broken finding. Schema validation must refuse it."""
    db = get_db()
    broken = {
        "findingId": "demo-invalid-" + uuid.uuid4().hex[:8],
        "repoId": (payload.get("repo") or "demo/repo").lower(),
        "type": "secret",
        "severity": "super bad",
    }
    try:
        db.findings.insert_one(broken)
        db.findings.delete_one({"_id": broken["_id"]})
        return {"blocked": False, "message": "Broken document was saved. This should not happen."}
    except WriteError as e:
        info = (e.details or {}).get("errInfo", {})
        broken.pop("_id", None)
        return {"blocked": True, "by": "schema validation ($jsonSchema)",
                "attempted": broken, "code": e.code,
                "message": (e.details or {}).get("errmsg", str(e))[:200],
                "reason": info.get("details", {})}


@app.post("/api/demo/webhook-replay")
def demo_webhook_replay():
    """GitHub sometimes delivers the same event twice. Same delivery ID -> ignored."""
    db = get_db()
    delivery_id = "demo-" + uuid.uuid4().hex[:12]
    results = []
    for attempt in (1, 2):
        try:
            db.webhook_deliveries.insert_one({"deliveryId": delivery_id, "event": "push",
                                              "repoId": "demo/replay", "receivedAt": now()})
            results.append({"attempt": attempt, "result": "accepted"})
        except DuplicateKeyError:
            results.append({"attempt": attempt,
                            "result": "ignored: duplicate deliveryId (unique index)"})
    return {"deliveryId": delivery_id, "results": results,
            "note": "Delivery records expire automatically after 7 days (TTL index)."}
