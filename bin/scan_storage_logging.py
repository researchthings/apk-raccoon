#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 2.0
# Script to scan for sensitive logging and weak storage practices in Android code
# Why: Identifies risks like leaked secrets in logs or insecure storage.
#
# Improvements in v2.0:
# - More specific sensitive logging detection (checks actual logged content)
# - Reduced false positives for SharedPreferences (context-aware)
# - Added file type filtering
# - Better evidence extraction

import sys
import os
import re
import csv
import zipfile
import traceback

# =============================================================================
# Logging patterns - more specific to actual sensitive data leaks
# =============================================================================

# Pattern to capture Android Log calls with their message
LOG_PATTERN = r'\bLog\.([dewivw]|wtf)\s*\(\s*[^,]+,\s*(.{0,200}?)\)'

# Patterns that indicate actually sensitive data being logged (not just field names)
SENSITIVE_LOG_PATTERNS = [
    # Actual credential/token values being logged
    (r'(?i)password\s*[:=]\s*["\'][^"\']+["\']', "High", "Password value logged"),
    (r'(?i)token\s*[:=]\s*["\'][^"\']+["\']', "High", "Token value logged"),
    (r'(?i)api[_-]?key\s*[:=]\s*["\'][^"\']+["\']', "High", "API key logged"),
    (r'(?i)secret\s*[:=]\s*["\'][^"\']+["\']', "High", "Secret value logged"),

    # Variable interpolation of sensitive data
    (r'(?i)\+\s*password\b', "High", "Password variable concatenated to log"),
    (r'(?i)\+\s*token\b', "High", "Token variable concatenated to log"),
    (r'(?i)\+\s*secret\b', "High", "Secret variable concatenated to log"),
    (r'(?i)\+\s*apiKey\b', "High", "API key variable concatenated to log"),

    # User credentials
    (r'(?i)credentials?\s*[:=]', "High", "Credentials logged"),
    (r'(?i)auth(?:entication)?[_-]?(?:header|token)', "Medium", "Auth header/token logged"),

    # PII
    (r'(?i)ssn|social[_-]?security', "High", "SSN potentially logged"),
    (r'(?i)credit[_-]?card|card[_-]?number', "High", "Credit card potentially logged"),
]

# =============================================================================
# Storage patterns
# =============================================================================

# World-readable preferences (deprecated and dangerous)
WORLD_READABLE_PATTERN = r'\b(MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)\b'

# External storage usage
EXTERNAL_STORAGE_PATTERN = r'Environment\.getExternalStorage(?:Directory|PublicDirectory)\s*\('

# Sensitive data in SharedPreferences without encryption context
SENSITIVE_PREFS_KEYS = [
    'password', 'token', 'secret', 'api_key', 'apiKey',
    'credential', 'auth', 'session', 'private_key', 'privateKey'
]


def check_encryption_context(text, match_start, match_end):
    """Check if encryption is used in the context of the match."""
    context_start = max(0, match_start - 300)
    context_end = min(len(text), match_end + 300)
    context = text[context_start:context_end].lower()

    encryption_indicators = [
        'encrypt', 'cipher', 'aes', 'rsa', 'keystore',
        'encryptedsharedpreferences', 'securepreferences',
        'masterkey', 'crypto', 'securely'
    ]

    return any(ind in context for ind in encryption_indicators)


def iter_text(src_dir, apk_path=None):
    """Iterate over source files."""
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
                # Only scan code files
                if not fn.endswith(('.java', '.kt', '.smali')):
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
                    try:
                        yield zi.filename, z.read(zi.filename).decode("utf-8", errors="ignore")
                    except Exception as e:
                        print(f"Warning: Failed to read ZIP entry {zi.filename}: {str(e)}", file=sys.stderr)
                        continue


def main():
    try:
        if len(sys.argv) < 3:
            print("Usage: scan_storage_logging.py <src_dir> <out.csv> [apk_path]", file=sys.stderr)
            sys.exit(1)

        src_dir, out = sys.argv[1], sys.argv[2]
        apk_path = sys.argv[3] if len(sys.argv) > 3 else None

        rows = []
        files_scanned = 0

        for path, text in iter_text(src_dir, apk_path):
            files_scanned += 1

            # Check for sensitive logging
            for log_match in re.finditer(LOG_PATTERN, text, re.DOTALL):
                log_level = log_match.group(1)
                log_content = log_match.group(2)

                for pattern, severity, desc in SENSITIVE_LOG_PATTERNS:
                    if re.search(pattern, log_content):
                        # Get broader context for evidence
                        start = max(0, log_match.start() - 20)
                        end = min(len(text), log_match.end() + 20)
                        snippet = text[start:end].replace("\n", " ")

                        rows.append({
                            "Source": "logging_storage",
                            "RuleID": "LOG_SENSITIVE",
                            "Title": desc,
                            "Location": str(path),
                            "Evidence": snippet[:200],
                            "Severity": severity,
                            "HowFound": "Regex scan"
                        })
                        break  # One finding per log call

            # Check for world-readable preferences
            for m in re.finditer(WORLD_READABLE_PATTERN, text):
                snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                rows.append({
                    "Source": "logging_storage",
                    "RuleID": "PREFS_WORLD_READABLE",
                    "Title": "World-readable/writable SharedPreferences (deprecated)",
                    "Location": str(path),
                    "Evidence": snippet[:200],
                    "Severity": "High",
                    "HowFound": "Regex scan"
                })

            # Check for sensitive SharedPreferences storage without encryption
            for key in SENSITIVE_PREFS_KEYS:
                pattern = rf'(?i)putString\s*\(\s*["\'](?:[^"\']*{key}[^"\']*)["\']'
                for m in re.finditer(pattern, text):
                    if not check_encryption_context(text, m.start(), m.end()):
                        snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                        rows.append({
                            "Source": "logging_storage",
                            "RuleID": "PREFS_SENSITIVE_PLAINTEXT",
                            "Title": f"Sensitive data '{key}' stored in SharedPreferences without encryption",
                            "Location": str(path),
                            "Evidence": snippet[:200],
                            "Severity": "High",
                            "HowFound": "Regex scan with context check"
                        })

            # Check for external storage usage
            for m in re.finditer(EXTERNAL_STORAGE_PATTERN, text):
                snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                rows.append({
                    "Source": "logging_storage",
                    "RuleID": "EXT_STORAGE_WRITE",
                    "Title": "External storage usage (publicly accessible)",
                    "Location": str(path),
                    "Evidence": snippet[:200],
                    "Severity": "Medium",
                    "HowFound": "Regex scan"
                })

        # Write output
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        print(f"Wrote {out} ({len(rows)} findings, {files_scanned} files scanned)")

    except Exception as e:
        print(f"[!] Error in scan_storage_logging: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
