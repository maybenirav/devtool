# scan_cli.py
# Scan a repo from the terminal.
#   python scan_cli.py https://github.com/owner/repo
import sys

from db import get_db
from github_client import GitHubError
from scanner import ScanError, prepare_scan, run_scan


def main():
    if len(sys.argv) < 2:
        print("Usage: python scan_cli.py <github-repo-link>")
        return
    try:
        scan_id, repo_id, reused = prepare_scan(sys.argv[1])
        if reused:
            print(f"A scan for {repo_id} is already running ({scan_id}). Try again in a minute.")
            return
        print(f"Scan started: {scan_id}")
        run_scan(scan_id)
    except (GitHubError, ScanError) as e:
        print(f"Scan failed: {e}")
        return

    print("\nNew findings from this scan:")
    findings = list(get_db().findings.find({"scanId": scan_id}).sort("committedAt", 1))
    if not findings:
        print("  (none)")
    for f in findings:
        print(f"  [{f['severity'].upper():8}] {f['action']:7} {f['commitSha'][:7]}  "
              f"{f['title']}  ({f['file']}:{f['line']})")
    print(f"\nFull report: python report_cli.py {sys.argv[1]}")


if __name__ == "__main__":
    main()
