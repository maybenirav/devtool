# scan_cli.py
# Usage: python scan_cli.py https://github.com/owner/repo
import sys

from db import get_db
from github_client import GitHubError
from scanner import ScanError, prepare_scan, run_scan


def main():
    if len(sys.argv) < 2:
        print("Usage: python scan_cli.py <github-repo-link>")
        return
    try:
        scan_id = prepare_scan(sys.argv[1])
        print(f"Scan started: {scan_id}")
        run_scan(scan_id)
    except (GitHubError, ScanError) as e:
        print(f"Scan failed: {e}")
        return

    print("\nFindings from this scan:")
    db = get_db()
    findings = list(db.findings.find({"scanId": scan_id}).sort("committedAt", 1))
    if not findings:
        print("  (no new findings)")
    for f in findings:
        print(f"  [{f['severity'].upper():8}] {f['action']:7} {f['commitSha'][:7]}  "
              f"{f['title']}  ({f['file']}:{f['line']})")
    print("\nScan finished!")


if __name__ == "__main__":
    main()