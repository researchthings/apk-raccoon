#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 2.0
# Script to scan source code or APK for potential secrets like API keys, private keys, etc.
# Why: Hardcoded secrets are common vulns; detection with locations enables removal or rotation.
#
# Improvements in v2.0:
# - Added more secret patterns (GitHub, Slack, Stripe, Firebase, JWT)
# - Context filtering to reduce false positives in comments/docs
# - Entropy checking for generic high-entropy strings
# - File extension filtering
# - Allowlist for known test/example patterns

import sys
import os
import re
import csv
import zipfile
import math
import traceback
from collections import Counter

# =============================================================================
# Secret patterns with descriptions
# Format: (RuleID, pattern, severity, description)
# =============================================================================
SECRET_PATTERNS = [
    # Cloud Provider Keys
    ("SECRET_AWS_ACCESS_KEY", r'AKIA[0-9A-Z]{16}', "High", "AWS Access Key ID"),
    ("SECRET_AWS_SECRET", r'(?i)(?:aws[_-]?)?secret[_-]?(?:access[_-]?)?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "High", "AWS Secret Access Key"),
    ("SECRET_GCP_API_KEY", r'AIza[0-9A-Za-z\-_]{35}', "Medium", "Google Cloud API Key"),
    ("SECRET_GCP_SERVICE_ACCOUNT", r'"type"\s*:\s*"service_account"', "High", "GCP Service Account JSON"),

    # Version Control & CI/CD
    ("SECRET_GITHUB_TOKEN", r'gh[pousr]_[A-Za-z0-9_]{36,}', "High", "GitHub Personal Access Token"),
    ("SECRET_GITHUB_OAUTH", r'gho_[A-Za-z0-9]{36}', "High", "GitHub OAuth Token"),
    ("SECRET_GITLAB_TOKEN", r'glpat-[A-Za-z0-9\-_]{20,}', "High", "GitLab Personal Access Token"),

    # Communication Platforms
    ("SECRET_SLACK_TOKEN", r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', "High", "Slack API Token"),
    ("SECRET_SLACK_WEBHOOK", r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}', "Medium", "Slack Webhook URL"),
    ("SECRET_DISCORD_TOKEN", r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}', "High", "Discord Bot Token"),
    ("SECRET_DISCORD_WEBHOOK", r'https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+', "Medium", "Discord Webhook URL"),

    # Payment Processors
    ("SECRET_STRIPE_KEY", r'sk_live_[0-9a-zA-Z]{24,}', "Critical", "Stripe Live Secret Key"),
    ("SECRET_STRIPE_RESTRICTED", r'rk_live_[0-9a-zA-Z]{24,}', "High", "Stripe Restricted Key"),
    ("SECRET_PAYPAL_TOKEN", r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}', "Critical", "PayPal Access Token"),

    # Firebase
    ("SECRET_FIREBASE_URL", r'https://[a-z0-9-]+\.firebaseio\.com', "Low", "Firebase Database URL"),
    ("SECRET_FIREBASE_KEY", r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', "High", "Firebase Cloud Messaging Key"),

    # Authentication
    ("SECRET_JWT", r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "Medium", "JSON Web Token"),
    ("SECRET_BASIC_AUTH", r'(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}', "Medium", "Basic Auth Header"),
    ("SECRET_BEARER_TOKEN", r'(?i)Authorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}', "Medium", "Bearer Token"),

    # Private Keys
    ("SECRET_RSA_PRIVATE", r'-----BEGIN RSA PRIVATE KEY-----', "Critical", "RSA Private Key"),
    ("SECRET_EC_PRIVATE", r'-----BEGIN EC PRIVATE KEY-----', "Critical", "EC Private Key"),
    ("SECRET_DSA_PRIVATE", r'-----BEGIN DSA PRIVATE KEY-----', "Critical", "DSA Private Key"),
    ("SECRET_OPENSSH_PRIVATE", r'-----BEGIN OPENSSH PRIVATE KEY-----', "Critical", "OpenSSH Private Key"),
    ("SECRET_PGP_PRIVATE", r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "Critical", "PGP Private Key"),

    # Database Connection Strings
    ("SECRET_MONGODB_URI", r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\']+', "High", "MongoDB Connection URI"),
    ("SECRET_POSTGRES_URI", r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\']+', "High", "PostgreSQL Connection URI"),
    ("SECRET_MYSQL_URI", r'mysql://[^:]+:[^@]+@[^\s"\']+', "High", "MySQL Connection URI"),

    # Generic Password Patterns (more specific to reduce FP)
    ("SECRET_PASSWORD_ASSIGN", r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,64})["\']', "Medium", "Hardcoded Password"),
    ("SECRET_API_KEY_ASSIGN", r'(?i)api[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_-]{16,64})["\']', "Medium", "API Key Assignment"),
]

# =============================================================================
# Context filters to reduce false positives
# =============================================================================

# File extensions to skip (non-code files)
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',  # Images
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv',  # Media
    '.ttf', '.otf', '.woff', '.woff2', '.eot',  # Fonts
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',  # Documents
    '.zip', '.tar', '.gz', '.rar', '.7z',  # Archives
    '.so', '.dll', '.dylib', '.a',  # Native libraries
    '.dex',  # Skip raw DEX (binary)
}

# Patterns that indicate the match is in a comment or documentation
COMMENT_PATTERNS = [
    r'^\s*(?://|#|\*|/\*)',  # Line starts with comment marker
    r'(?:example|sample|test|fake|dummy|placeholder|xxx|your[_-]?key)',  # Test/example indicators
    r'<YOUR[_-]?[A-Z_]+>',  # Placeholder pattern like <YOUR_API_KEY>
    r'\$\{[^}]+\}',  # Template variables like ${API_KEY}
    r'%\([^)]+\)s',  # Python format strings
]

# Known false positive values (exact match after extraction)
ALLOWLIST_VALUES = {
    # Common placeholder/example values
    'AKIAIOSFODNN7EXAMPLE',  # AWS example key
    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',  # AWS example secret
    'AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',  # Google example
    'your-api-key-here',
    'replace-with-your-key',
    'insert-key-here',
    'xxxxxxxxxxxxxxxx',
    'test_key_do_not_use',
}

# Minimum entropy threshold for generic secrets (to filter out non-random strings)
MIN_ENTROPY = 3.5


def calculate_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0
    prob = [float(c) / len(s) for c in Counter(s).values()]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def is_in_comment_context(text, match_start, match_end):
    """Check if the match appears to be in a comment or documentation context."""
    # Get the line containing the match
    line_start = text.rfind('\n', 0, match_start) + 1
    line_end = text.find('\n', match_end)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]

    # Check against comment patterns
    for pattern in COMMENT_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True

    return False


def is_allowlisted(matched_value):
    """Check if the matched value is in the allowlist."""
    # Normalize and check
    normalized = matched_value.strip().lower()
    for allowed in ALLOWLIST_VALUES:
        if allowed.lower() in normalized or normalized in allowed.lower():
            return True
    return False


def should_skip_file(filename):
    """Check if file should be skipped based on extension."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in SKIP_EXTENSIONS


def iter_text(src_dir, apk_path):
    """Iterate over code files yielding (path, content) tuples."""
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
                if should_skip_file(fn):
                    continue
                p = os.path.join(root, fn)
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        yield p, f.read()
                except Exception as e:
                    print(f"Warning: Failed to read {p}: {str(e)}", file=sys.stderr)
                    continue
    elif apk_path and os.path.isfile(apk_path):
        with zipfile.ZipFile(apk_path, 'r') as z:
            for zi in z.infolist():
                if zi.file_size > 0 and not zi.is_dir():
                    if should_skip_file(zi.filename):
                        continue
                    try:
                        yield zi.filename, z.read(zi.filename).decode("utf-8", errors="ignore")
                    except Exception as e:
                        print(f"Warning: Failed to read ZIP entry {zi.filename}: {str(e)}", file=sys.stderr)
                        continue


def main():
    try:
        if len(sys.argv) < 3:
            print("Usage: detect_secrets.py <src_dir> <out.csv> [apk_path]", file=sys.stderr)
            sys.exit(1)

        src_dir, out = sys.argv[1], sys.argv[2]
        apk_path = sys.argv[3] if len(sys.argv) > 3 else None

        rows = []
        files_scanned = 0
        secrets_found = 0
        filtered_out = 0

        for path, text in iter_text(src_dir, apk_path):
            files_scanned += 1

            for rid, rx, sev, desc in SECRET_PATTERNS:
                for m in re.finditer(rx, text):
                    matched_value = m.group(1) if m.lastindex else m.group(0)

                    # Filter 1: Skip if in comment/documentation context
                    if is_in_comment_context(text, m.start(), m.end()):
                        filtered_out += 1
                        continue

                    # Filter 2: Skip allowlisted values
                    if is_allowlisted(matched_value):
                        filtered_out += 1
                        continue

                    # Filter 3: For generic patterns, check entropy
                    if rid in ('SECRET_PASSWORD_ASSIGN', 'SECRET_API_KEY_ASSIGN'):
                        if calculate_entropy(matched_value) < MIN_ENTROPY:
                            filtered_out += 1
                            continue

                    # Extract context snippet (redact the actual secret)
                    snippet_start = max(0, m.start() - 30)
                    snippet_end = min(len(text), m.end() + 30)
                    snippet = text[snippet_start:snippet_end].replace("\n", " ")

                    # Partially redact the matched secret in evidence
                    if len(matched_value) > 8:
                        redacted = matched_value[:4] + '...' + matched_value[-4:]
                    else:
                        redacted = matched_value[:2] + '***'

                    rows.append({
                        "Source": "secrets",
                        "RuleID": rid,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": f"[REDACTED: {redacted}] Context: {snippet[:150]}",
                        "Severity": sev,
                        "HowFound": "Regex scan with context filtering"
                    })
                    secrets_found += 1

        # Write output
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        print(f"Wrote {out} ({len(rows)} findings, {files_scanned} files scanned, {filtered_out} filtered out)")

    except Exception as e:
        print(f"[!] Error in detect_secrets: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
