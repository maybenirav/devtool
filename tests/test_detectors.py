# tests/test_detectors.py
# Offline tests for the three checks (no database, no internet).
#   python tests/test_detectors.py
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detectors as d  # noqa: E402

passed = 0


def check(condition, message):
    global passed
    assert condition, "FAILED: " + message
    passed += 1
    print("  ok -", message)


print("Secrets")
s = d.find_secrets('AWS_ACCESS_KEY_ID = "AKIA4RG7QW2XLMN8PZTK"', "config.py")
check(len(s) == 1 and s[0]["ruleId"] == "aws_key" and s[0]["masked"] == "AKIA****PZTK", "AWS key found and masked")
check(d.find_secrets('KEY = "AKIAIOSFODNN7EXAMPLE"', "a.py") == [], "AWS documentation example key ignored")
check(d.find_secrets('token = "ghp_' + "a1B2" * 9 + '"', "a.py")[0]["provider"] == "GitHub", "GitHub token found")
check(d.find_secrets('k = "sk-ant-api03-' + "aB3dE5" * 5 + '"', "a.py")[0]["provider"] == "Anthropic",
      "Anthropic key is not double-reported as OpenAI")
check(len(d.find_secrets('k = "sk-ant-api03-' + "aB3dE5" * 5 + '"', "a.py")) == 1, "one secret per value")
check(d.find_secrets('DB_PASSWORD = "Sup3rS3cretPass9"', "a.py")[0]["ruleId"] == "hardcoded_credential",
      "hardcoded password found")
check(d.find_secrets('password = "changeme123"', "a.py") == [], "placeholder password ignored")
check(d.find_secrets('API_KEY = "your_api_key_here"', "a.py") == [], "placeholder API key ignored")
uri = d.find_secrets("MONGO_URI=mongodb+srv://user:hunter22@cluster0.abc.mongodb.net/", ".env")
check(uri and "hunter22" not in uri[0]["masked"] and "****" in uri[0]["masked"], "MongoDB URI password masked")
check(d.find_secrets("MONGO_URI=mongodb+srv://user:<db_password>@c.mongodb.net/", ".env") == [],
      "Atlas template URI ignored")
pk1 = d.find_secrets("-----BEGIN RSA PRIVATE KEY-----", "a.pem")[0]["fingerprint"]
pk2 = d.find_secrets("-----BEGIN RSA PRIVATE KEY-----", "b.pem")[0]["fingerprint"]
check(pk1 != pk2, "private keys in different files get different fingerprints")

print("Risky settings")
check(d.find_risky_config("DEBUG = True")[0]["ruleId"] == "debug_enabled", "DEBUG = True")
check(d.find_risky_config("app.run(debug=True)")[0]["ruleId"] == "debug_enabled", "debug=True")
check(d.find_risky_config("# DEBUG = True") == [], "commented-out line ignored")
check(d.find_risky_config("FLASK_DEBUG_TOOLBAR = True") == [], "other setting names ignored")
check(d.find_risky_config("requests.get(url, verify=False)")[0]["ruleId"] == "tls_verify_disabled", "verify=False")
check(d.find_risky_config("ALLOWED_HOSTS = ['*']")[0]["ruleId"] == "allowed_hosts_any", "ALLOWED_HOSTS *")
check(d.find_risky_config("rejectUnauthorized: false")[0]["ruleId"] == "node_tls_disabled", "Node TLS")

print("Libraries")
check(d.parse_requirement("django==2.2.0")["version"] == "2.2.0", "pinned PyPI version")
check(d.parse_requirement("   requests")["version"] is None, "unpinned PyPI (with leading spaces)")
check(d.parse_requirement("Flask_Login[extra]>=0.6 ; python_version>'3'")["name"] == "flask-login",
      "PyPI name normalised, extras and markers handled")
check(d.parse_requirement("# comment") is None and d.parse_requirement("-r base.txt") is None,
      "comments and includes skipped")
check(d.parse_npm('    "lodash": "4.17.15",')["version"] == "4.17.15", "npm exact version")
check(d.parse_npm('    "react": "^18.2.0",')["version"] == "18.2.0", "npm caret range uses base version")
check(d.parse_npm('    "left-pad": "*"')["version"] is None, "npm wildcard is unpinned")
check(d.parse_npm('  "name": "my-app",') is None and d.parse_npm('    "build": "tsc"') is None,
      "package name and scripts ignored")
check(d.dependency_parser_for("requirements.txt.") is d.parse_requirement, "tolerates 'requirements.txt.'")
check(d.dependency_parser_for("backend/requirements-dev.txt") is d.parse_requirement, "requirements-dev.txt")
check(d.dependency_parser_for("package-lock.json") is None, "lock file ignored")

print("Diff parsing")
lines = list(d.parse_patch("@@ -1,2 +1,2 @@\n keep\n-old\n+new\n\\ No newline at end of file"))
check(lines == [("removed", 2, "old"), ("added", 2, "new")], "added/removed lines with line numbers")

print(f"\nAll {passed} checks passed.")
