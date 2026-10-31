# explain.py
# "Explain this risk" button: uses Claude if ANTHROPIC_API_KEY is set,
# otherwise (or if the AI call fails) a built-in explanation. Never sends secret values.
import os

import requests

_cache = {}

BUILT_IN = {
    "secret": (
        "A credential was committed to the repository. Anyone who can read the repo, "
        "including its full git history, can copy it and use it as you. Deleting the line "
        "in a later commit does not help, because every old version of the file is still "
        "in git history.",
        "Revoke or rotate the key in the provider's dashboard now, then load it from an "
        "environment variable or a secrets manager instead of the code. Add the file to "
        ".gitignore. Rewriting git history is optional; rotating the key is not."),
    "vulnerable_dependency": (
        "This library version has publicly known security vulnerabilities. Attackers "
        "search for apps that still run these versions because the exploits are documented.",
        "Upgrade to the fixed version shown, run your tests, and pin the version so it "
        "doesn't drift back."),
    "unpinned_dependency": (
        "The library has no exact version, so every install can pull a different release. "
        "Builds stop being reproducible and ReleaseGuard cannot check the version for "
        "known vulnerabilities.",
        "Pin an exact, current version (for example name==1.2.3) and update it on purpose."),
    "debug_enabled": (
        "Debug mode shows detailed error pages, settings and sometimes source code to "
        "anyone who triggers an error. It is meant for local development only.",
        "Set DEBUG from an environment variable and keep it False in production."),
    "tls_verify_disabled": (
        "Turning off certificate verification means the app accepts any server, so an "
        "attacker on the network can intercept or change the traffic (man-in-the-middle).",
        "Remove verify=False. If you use a private certificate, pass its CA bundle path "
        "with verify='/path/to/ca.pem'."),
    "unverified_ssl_context": (
        "An unverified SSL context skips certificate checks, which allows "
        "man-in-the-middle attacks.",
        "Use ssl.create_default_context() and trust only the certificates you need."),
    "node_tls_disabled": (
        "Disabling rejectUnauthorized (or NODE_TLS_REJECT_UNAUTHORIZED=0) makes Node.js "
        "accept any certificate, allowing man-in-the-middle attacks.",
        "Remove the setting and provide the correct CA certificate instead."),
    "allowed_hosts_any": (
        "ALLOWED_HOSTS = ['*'] lets the app answer for any domain, which enables host "
        "header attacks such as poisoned password-reset links.",
        "List only your real domains in ALLOWED_HOSTS."),
    "cors_allow_all": (
        "Allowing every origin lets any website call your API from a visitor's browser.",
        "Allow only the frontend domains that really need access."),
}


def built_in_explanation(risk):
    key = risk.get("type")
    if key == "risky_config":
        key = (risk.get("details") or {}).get("rule", key)
    what, fix = BUILT_IN.get(key, (
        "This change was flagged as a security risk.",
        "Review the change and follow your team's security guidelines."))
    extra = ""
    fixed_version = (risk.get("details") or {}).get("fixedVersion")
    if fixed_version:
        extra = f" Suggested version: {fixed_version}."
    if risk.get("status") == "in_history":
        extra += " This one was deleted later, but it is still readable in git history."
    return f"Why it matters: {what}\n\nHow to fix: {fix}{extra}"


def _safe_facts(risk):
    """Only non-secret facts are ever sent to the AI (the masked value is not sent)."""
    d = risk.get("details") or {}
    facts = {
        "type": risk.get("type"),
        "title": risk.get("title"),
        "severity": risk.get("severity"),
        "status": risk.get("status"),
        "file": risk.get("file"),
        "provider": d.get("provider"),
        "rule": d.get("rule"),
        "package": d.get("package"),
        "version": d.get("version"),
        "fixedVersion": d.get("fixedVersion"),
        "vulnerabilitySummary": d.get("summary"),
    }
    return {k: v for k, v in facts.items() if v}


def explain(risk):
    cache_key = (risk.get("_id"), risk.get("status"))
    if cache_key in _cache:
        return _cache[cache_key]

    api_key = os.getenv("ANTHROPIC_API_KEY")
    result = None
    if api_key:
        prompt = (
            "You are a security reviewer. Explain this finding to a developer in plain "
            "English, in under 120 words, as two short paragraphs starting with "
            "'Why it matters:' and 'How to fix:'. Be concrete. Facts:\n"
            f"{_safe_facts(risk)}"
        )
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": os.getenv("AI_MODEL", "claude-haiku-5-5"),
                      "max_tokens": 400,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=20,
            )
            if r.ok:
                text = "".join(b.get("text", "") for b in r.json().get("content", []))
                if text.strip():
                    result = {"text": text.strip(), "source": "ai"}
        except requests.RequestException:
            result = None

    if result is None:
        result = {"text": built_in_explanation(risk), "source": "built-in"}
    _cache[cache_key] = result
    return result
