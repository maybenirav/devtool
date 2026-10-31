# detectors.py
# The three security checks: secrets, risky settings, and library lines.
import hashlib
import re

# ---------- Reading a diff ----------

_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_patch(patch):
    """Yield (action, line_number, text) for every added/removed line in a diff."""
    old_line = new_line = 0
    for raw in (patch or "").splitlines():
        hunk = _HUNK.match(raw)
        if hunk:
            old_line, new_line = int(hunk.group(1)), int(hunk.group(2))
            continue
        if raw.startswith("+"):
            yield "added", new_line, raw[1:]
            new_line += 1
        elif raw.startswith("-"):
            yield "removed", old_line, raw[1:]
            old_line += 1
        elif raw.startswith("\\"):
            continue  # "\ No newline at end of file"
        else:
            old_line += 1
            new_line += 1


# ---------- Check 1: Secrets ----------

# (rule id, provider, severity, pattern) - specific rules first
SECRET_RULES = [
    ("private_key", "Private key", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("aws_key", "AWS", "critical", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", "GitHub", "critical",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})")),
    ("stripe_live", "Stripe", "critical", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}")),
    ("anthropic_key", "Anthropic", "high", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key", "OpenAI", "high", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("google_api_key", "Google", "high", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("slack_token", "Slack", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("slack_webhook", "Slack", "medium",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}")),
    ("mongodb_uri", "MongoDB", "high",
     re.compile(r"mongodb(?:\+srv)?://[^\s:/@]+:[^\s@]+@[^\s'\"]+")),
    ("stripe_test", "Stripe (test key)", "low", re.compile(r"\bsk_test_[0-9a-zA-Z]{20,}")),
]

# e.g.  DB_PASSWORD = "Sup3rS3cret!"   or   "api_key": "abcd1234efgh"
GENERIC_SECRET = re.compile(
    r"(?i)([A-Za-z0-9_]*(?:password|passwd|pwd|secret|api_?key|access_?token|auth_?token)"
    r"[A-Za-z0-9_]*)[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
)

PLACEHOLDER_WORDS = (
    "example", "your", "xxxx", "changeme", "placeholder", "dummy", "sample",
    "<", ">", "${", "{{", "****", "redacted", "replace",
)


def looks_like_placeholder(value):
    v = value.lower()
    return any(word in v for word in PLACEHOLDER_WORDS)


def mask(value, rule_id):
    """Never show a full secret: AKIA****PZTK"""
    if rule_id == "private_key":
        return value + " (contents hidden)"
    if rule_id == "mongodb_uri":
        return re.sub(r"(://[^:/@\s]+:)[^@\s]+@", r"\1****@", value)
    if len(value) <= 10:
        return value[:2] + "****"
    return value[:4] + "****" + value[-4:]


def fingerprint_secret(value):
    """One-way hash: same secret -> same code, but the secret can't be recovered."""
    return "secret:" + hashlib.sha256(value.encode()).hexdigest()[:24]


def _overlaps(span, taken):
    start, end = span
    return any(start < t_end and t_start < end for t_start, t_end in taken)


def find_secrets(text, filename):
    """Return the secrets found in one line of code."""
    results, taken = [], []

    for rule_id, provider, severity, pattern in SECRET_RULES:
        for m in pattern.finditer(text):
            if _overlaps(m.span(), taken):
                continue
            value = m.group(0)
            if rule_id != "private_key" and looks_like_placeholder(value):
                continue
            taken.append(m.span())
            # every private key starts with the same header, so add the file name
            fp_source = value + "|" + filename if rule_id == "private_key" else value
            results.append({
                "ruleId": rule_id,
                "provider": provider,
                "severity": severity,
                "fingerprint": fingerprint_secret(fp_source),
                "masked": mask(value, rule_id),
            })

    for m in GENERIC_SECRET.finditer(text):
        if _overlaps(m.span(2), taken):
            continue
        value = m.group(2)
        if looks_like_placeholder(value):
            continue
        taken.append(m.span(2))
        results.append({
            "ruleId": "hardcoded_credential",
            "provider": f"Hardcoded credential ({m.group(1)})",
            "severity": "medium",
            "fingerprint": fingerprint_secret(value),
            "masked": mask(value, "hardcoded_credential"),
        })

    return results


# ---------- Check 2: Risky settings ----------

# (rule id, severity, title, pattern)
CONFIG_RULES = [
    ("debug_enabled", "medium", "Debug mode enabled",
     re.compile(r"\b(?i:debug)\s*=\s*True\b")),
    ("tls_verify_disabled", "high", "TLS certificate verification disabled",
     re.compile(r"\bverify\s*=\s*False\b")),
    ("unverified_ssl_context", "high", "Unverified SSL context used",
     re.compile(r"ssl\._create_unverified_context")),
    ("node_tls_disabled", "high", "TLS verification disabled (Node.js)",
     re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0")),
    ("allowed_hosts_any", "medium", "ALLOWED_HOSTS allows any host",
     re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]")),
    ("cors_allow_all", "medium", "CORS allows requests from any website",
     re.compile(r"CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True"
                r"|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]")),
]


def find_risky_config(text):
    stripped = text.strip()
    if stripped.startswith(("#", "//")):
        return []  # ignore comments
    return [
        {"ruleId": rule_id, "severity": severity, "title": title}
        for rule_id, severity, title, pattern in CONFIG_RULES
        if pattern.search(text)
    ]


# ---------- Check 3: Library files ----------

_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*"
    r"(===|==|~=|>=|<=|!=|>|<)?\s*([A-Za-z0-9.*+!_-]*)"
)


def normalize_pypi_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirement(line):
    """'django==2.2.0' -> {'ecosystem': 'PyPI', 'name': 'django', 'version': '2.2.0'}"""
    line = line.split("#", 1)[0].split(";", 1)[0].strip()
    if not line or line.startswith(("-", "git+", "http://", "https://")):
        return None
    m = _REQ_LINE.match(line)
    if not m:
        return None
    name, op, version = m.group(1), m.group(2), m.group(3)
    pinned = bool(op in ("==", "===") and version and "*" not in version)
    return {
        "ecosystem": "PyPI",
        "name": normalize_pypi_name(name),
        "version": version if pinned else None,
        "spec": line,
    }


_NPM_LINE = re.compile(
    r'^\s*"(@?[a-z0-9][a-z0-9._~-]*(?:/[a-z0-9][a-z0-9._~-]*)?)"\s*:\s*"([^"]*)"'
)
_NPM_SKIP_KEYS = {
    "name", "version", "description", "main", "module", "types", "license",
    "author", "homepage", "type", "private", "node", "npm",
}
_NPM_VERSION = re.compile(r"^[\^~=v]?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")


def parse_npm(line):
    """'"lodash": "4.17.15",' -> {'ecosystem': 'npm', 'name': 'lodash', 'version': '4.17.15'}"""
    m = _NPM_LINE.match(line)
    if not m:
        return None
    name, spec = m.group(1), m.group(2).strip()
    if name in _NPM_SKIP_KEYS:
        return None
    vm = _NPM_VERSION.match(spec)
    if vm:
        return {"ecosystem": "npm", "name": name, "version": vm.group(1), "spec": spec}
    if spec in ("*", "latest", "") or spec.startswith(">"):
        return {"ecosystem": "npm", "name": name, "version": None, "spec": spec}
    return None  # scripts, git links, etc.


def dependency_parser_for(filename):
    # tolerant of stray spaces / trailing dots, e.g. "requirements.txt."
    base = filename.rsplit("/", 1)[-1].lower().strip().rstrip(".")
    if base == "package.json":
        return parse_npm
    if base.startswith("requirements") and base.endswith(".txt"):
        return parse_requirement
    return None
