# alerts.py
# Sends an alert to n8n when a repo's verdict CHANGES to BLOCK (no spam on every scan).
import os
from datetime import datetime, timezone

import requests

from db import get_db


def public_base_url():
    return (os.getenv("PUBLIC_BASE_URL") or os.getenv("RENDER_EXTERNAL_URL")
            or "http://localhost:8000").rstrip("/")


def send_alert(repo_id, scan_id, verdict, previous, reasons, test=False):
    """Post to the n8n webhook and record the attempt in the 'alerts' collection."""
    db = get_db()
    url = os.getenv("N8N_WEBHOOK_URL")
    report_url = f"{public_base_url()}/repo/{repo_id}"
    payload = {
        "repo": repo_id,
        "verdict": verdict,
        "previousVerdict": previous,
        "reasons": reasons[:5],
        "scanId": scan_id,
        "reportUrl": report_url,
        "test": test,
        "text": (f"{'[TEST] ' if test else ''}ReleaseGuard: {repo_id} is now {verdict}"
                 f" (was {previous or 'not scanned'}).\n"
                 + "\n".join(f"- {r}" for r in reasons[:5])
                 + f"\nReport: {report_url}"),
    }

    doc = {"repoId": repo_id, "scanId": scan_id, "verdict": verdict,
           "previousVerdict": previous, "test": test,
           "createdAt": datetime.now(timezone.utc)}

    if not url:
        doc.update(status="skipped", error="N8N_WEBHOOK_URL is not set")
    else:
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.ok:
                doc.update(status="sent")
            else:
                doc.update(status="failed", error=f"n8n answered {r.status_code}")
        except requests.RequestException as e:
            doc.update(status="failed", error=f"Could not reach n8n: {type(e).__name__}")

    db.alerts.insert_one(doc)
    doc.pop("_id", None)
    return doc


def maybe_alert(repo_id, scan_id, previous, result):
    """Alert only when the verdict changes to BLOCK."""
    if result["verdict"] == "BLOCK" and previous != "BLOCK":
        return send_alert(repo_id, scan_id, "BLOCK", previous, result["reasons"])
    return None
