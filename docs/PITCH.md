# PPT Content (one section per slide)

Use screenshots from your live site. Keep text short on slides; say the rest out loud.
The rulebook asks for: problem, solution, implementation, technology choices, impact.

## Slide 1: Title
**ReleaseGuard**: git blame for security risks.
"Is this release safe to ship, and which commit made it unsafe?"
Your name, UNCHARTED 2026, Track 3. Live URL + GitHub link.

## Slide 2: The problem
- Deleted secrets are not gone: Git keeps every version. Only rotating the key helps.
- Vulnerable library versions keep working, so nobody notices them.
- Debug mode and disabled TLS checks slip into releases.
- Existing tools show today's state, not the story: when, which commit, how long exposed.

## Slide 3: The solution
Screenshot of a report with the BLOCK stamp.
One verdict per release (SAFE / RISKY / BLOCK) plus, for every risk: introduced in, fixed in,
exposure in days and commits, and the fix (rotate the key / upgrade to version X).

## Slide 4: How it works
The architecture diagram from the README: GitHub API → diffs → 3 detectors (+ OSV.dev) →
MongoDB events → aggregation → verdict, history, compare → website, webhook, n8n, badge.

## Slide 5: The key insight
Screenshot of the AWS key card: "deleted, but still readable in git history."
History screenshot: the risk level does not drop when a secret is deleted.

## Slide 6: MongoDB under the hood
| Feature | Used for |
|---|---|
| Stable IDs | `owner/repo@sha`, hashed finding IDs |
| Unique indexes | re-scans and duplicate webhooks never double-count |
| Schema validation | required fields + enums; flexible `details` |
| Aggregation | `$group` by fingerprint, `$lookup`, `$dateDiff`, `$setWindowFields` |
| Indexes | proven with `explain()` in the app |
| Change streams | live findings while scanning |
| TTL index | webhook deliveries expire after 7 days |
Patterns: Polymorphic, Computed, event history.

## Slide 7: Failure cases handled
Duplicate event, incomplete input, failed job, invalid configuration:
unique index, schema validation, scans marked failed and resumable, friendly errors for
bad links, private repos, empty repos, rate limits, fake webhook signatures.

## Slide 8: Developer workflow
Webhook auto-scan on push, n8n alert to Discord when a release turns BLOCK, README badge,
explain button (Claude with built-in fallback), false-positive dismissals.

## Slide 9: Security by design
Secrets are never stored: a one-way hash plus a masked value (`AKIA****PZTK`).
The AI never receives secret values. Read-only GitHub token. Webhook signatures verified.

## Slide 10: Impact and next steps
Catch leaked keys and vulnerable releases before they ship; know exactly which commit to fix.
Next: more ecosystems (Go, Maven, Cargo), blocking pull requests with GitHub Checks,
organisation-wide dashboards.

---

# Judges' Q&A: prepared answers

**Why not just use Dependabot or GitHub secret scanning?**
They focus on the current state. ReleaseGuard keeps the history: which commit introduced each
risk, how long it was exposed, whether it was really fixed, and one verdict per release.
It also flags secrets that were "deleted" but remain in history.

**Why MongoDB?**
Findings from different checks have different shapes (a secret vs a vulnerable library). One
collection stores them flexibly (Polymorphic Pattern) while `$jsonSchema` still enforces the
required fields. Aggregation computes the story inside the database, unique indexes make
re-ingestion safe, and change streams power the live view.

**How do you avoid duplicates?**
Stable IDs from real data: commit SHA, and a hash of repo + commit + fingerprint + action + line.
Unique indexes refuse a second copy. A re-scan skips commits already stored. An interrupted
scan resumes because a commit is only marked done after its findings are saved.

**How do you handle false positives?**
Only real key formats are matched, placeholders are ignored, and users can dismiss a finding.
The dismissal is stored and joined with `$lookup`, so it survives future scans.

**Do you store the secrets?**
No. Only a SHA-256 hash (to recognise the same secret across commits) and a masked value.

**What are the limitations?**
Latest 30 commits of the default branch, public repos, Python and npm libraries.

**What was the hardest part?**
Turning raw diffs into a reliable history: tracking the same risk across commits with
fingerprints, so a removal can be matched to the commit that introduced it.
