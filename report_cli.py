# report_cli.py
#   python report_cli.py <repo-link>                   -> verdict, risks, timeline
#   python report_cli.py <repo-link> <sha-A> <sha-B>   -> also compare two commits
import sys

from github_client import parse_repo_url
from history import compare_commits, compute_verdict, get_risks, get_timeline

if len(sys.argv) < 2:
    print("Usage: python report_cli.py <github-repo-link> [sha-A sha-B]")
    sys.exit(1)

owner, name = parse_repo_url(sys.argv[1])
repo_id = f"{owner}/{name}".lower()

risks = get_risks(repo_id)
verdict = compute_verdict(repo_id, risks)

print(f"\n===== VERDICT: {verdict['verdict']} =====")
for reason in verdict["reasons"]:
    print(f"  - {reason}")

print("\n===== RISKS =====")
for r in risks:
    intro = r["introduced"]
    line = (f"[{r['severity'].upper():8}] {r['title']}{'  (dismissed)' if r['dismissed'] else ''}\n"
            f"     status: {r['status']} | introduced in {intro['sha'][:7]} "
            f"by {intro['author']} on {intro['at']:%d %b %Y}")
    if r.get("fixedEvent"):
        line += f" | removed in {r['fixedEvent']['sha'][:7]}"
    line += f"\n     exposed {r['exposureDays']} day(s), live for {r['liveForCommits']} commit(s)"
    if r["details"].get("fixedVersion"):
        line += f"\n     fix: upgrade to {r['details']['fixedVersion']}"
    if r["details"].get("masked"):
        line += f"\n     value: {r['details']['masked']}"
    print(line)

print("\n===== TIMELINE =====")
for c in get_timeline(repo_id):
    print(f"  {c['sha'][:7]}  risk={c['openRisk']:>3}  (+{c['added']} / -{c['removed']})  "
          f"{c['message'][:45]}")

if len(sys.argv) == 4:
    result = compare_commits(repo_id, sys.argv[2], sys.argv[3])
    print(f"\n===== COMPARE {sys.argv[2]} -> {sys.argv[3]} =====")
    if result["identical"]:
        print("  Identical commits, no changes.")
    else:
        print(f"  Trend: {result['trend'].upper()} "
              f"(risk score {result['scoreA']} -> {result['scoreB']})")
        for r in result["new"]:
            print(f"  + NEW:   {r['title']}")
        for r in result["fixed"]:
            print(f"  - FIXED: {r['title']}")
