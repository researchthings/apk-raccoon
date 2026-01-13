#!/usr/bin/env python3
"""Scan for sensitive data logging and insecure storage practices.

Detects credentials in logs, world-readable storage, unencrypted SharedPreferences,
external storage usage, and sensitive data in notifications/databases.

Features (v2.0):
    - Context-aware logging detection (checks actual logged content)
    - Encryption context checking to reduce false positives
    - External storage and database pattern detection

OWASP MASTG Coverage:
    - MASTG-TEST-0002: Sensitive data logging
    - MASTG-TEST-0004: Third-party data sharing
    - MASTG-TEST-0005: Notification data leakage
    - MASTG-TEST-0200-0207: External storage security
    - MASTG-TEST-0304-0306: Database security

Author: Randy Grant
Date: 11-07-2025
Version: 2.0
"""

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
# Notification patterns (MASTG-TEST-0005)
# =============================================================================

NOTIFICATION_SENSITIVE_PATTERNS = [
    # Notification with sensitive content
    (r'(?i)(?:setContentTitle|setContentText|setSubText)\s*\([^)]*(?:password|token|secret|ssn|credit|pin)[^)]*\)', "High", "Sensitive data in notification content"),
    (r'(?i)NotificationCompat\.Builder[^;]*(?:setContentTitle|setContentText)[^;]*(?:email|phone|ssn|address)', "High", "PII in notification"),
    (r'(?i)setTicker\s*\([^)]*(?:password|secret|token|key|credential)[^)]*\)', "High", "Secret value in notification ticker"),
    (r'(?i)Notification\s*\([^)]*(?:contentTitle|contentText)\s*[:=][^)]*(?:password|token|secret)', "High", "Sensitive data in Notification constructor"),
    (r'(?i)BigTextStyle\s*\(\)[^;]*bigText\s*\([^)]*(?:password|token|email|ssn)', "High", "Sensitive data in expanded notification"),
]

# =============================================================================
# Third-party data sharing patterns (MASTG-TEST-0004)
# =============================================================================

THIRDPARTY_DATA_PATTERNS = [
    # Sending sensitive data to third parties
    (r'(?i)(?:sendData|postData|uploadData|transmit)\s*\([^)]*(?:email|phone|ssn|location|userId|password)', "High", "User data sent to third party"),
    (r'(?i)(?:Firebase|Amplitude|Mixpanel|Analytics).*(?:log|track|send|set)\s*\([^)]*(?:email|phone|name|address)', "Medium", "Sensitive data sent to analytics"),
    (r'(?i)Gson\s*\(\)\s*\.toJson\s*\([^)]*(?:password|token|secret|ssn)', "High", "Sensitive data serialized with Gson"),
    (r'(?i)JSONObject[^;]*put\s*\([^)]*(?:password|token|secret|ssn|credit)', "High", "Sensitive data in JSON object"),
    (r'(?i)(?:retrofit|okhttp|HttpClient)[^;]*(?:POST|PUT)[^;]*(?:email|phone|ssn|password)', "Medium", "Potentially sensitive data in HTTP request"),
]

# =============================================================================
# Storage patterns
# =============================================================================

# World-readable preferences (deprecated and dangerous)
WORLD_READABLE_PATTERN = r'\b(MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)\b'

# External storage usage patterns (MASTG-TEST-0200-0207)
EXTERNAL_STORAGE_PATTERNS = [
    (r'Environment\.getExternalStorage(?:Directory|PublicDirectory)\s*\(', "Medium", "External storage directory access"),
    (r'(?i)getExternalFilesDir\s*\(', "Medium", "External files directory access"),
    (r'(?i)getExternalCacheDir\s*\(', "Medium", "External cache directory access"),
    (r'(?i)new\s+File\s*\(\s*["\'](?:/sdcard|/storage/emulated|/mnt/sdcard)', "High", "Hardcoded external storage path"),
    (r'(?i)FileOutputStream\s*\([^)]*(?:getExternalStorage|/sdcard|/storage)', "High", "Writing to external storage"),
    (r'(?i)FileWriter\s*\([^)]*(?:getExternalStorage|/sdcard|/storage)', "High", "Writing to external storage with FileWriter"),
    (r'(?i)requestLegacyExternalStorage\s*=\s*["\']?true', "Medium", "Requesting legacy external storage access"),
    (r'(?i)MANAGE_EXTERNAL_STORAGE', "Medium", "Requesting broad external storage permission"),
    (r'(?i)MediaStore\.(?:Images|Video|Audio)\.Media\.EXTERNAL_CONTENT_URI', "Low", "MediaStore external content access"),
]

# =============================================================================
# Database patterns (MASTG-TEST-0304-0306)
# =============================================================================

DATABASE_SENSITIVE_PATTERNS = [
    # SQLite with sensitive data
    (r'(?i)(?:insert|update|execSQL)\s*\([^)]*(?:password|token|secret|ssn|credit|pin)', "High", "Sensitive data in SQLite operation"),
    (r'(?i)rawQuery\s*\([^)]*SELECT[^)]*(?:password|token|secret|ssn)', "High", "Querying sensitive data from database"),
    (r'(?i)SQLiteDatabase\.(?:openDatabase|openOrCreateDatabase)\s*\([^)]*(?:password|key|secret)', "High", "Database opened with sensitive key in path"),
    # Room Database with sensitive entities
    (r'(?i)@(?:Entity|ColumnInfo)[^)]*(?:password|token|secret|ssn|credit)', "High", "Room entity storing sensitive field"),
    (r'(?i)@Query\s*\([^)]*SELECT[^)]*(?:password|token|secret|ssn)', "High", "Room query accessing sensitive columns"),
    # Realm with sensitive fields
    (r'(?i)RealmObject[^}]*(?:password|token|secret|ssn)', "High", "Realm object with sensitive field"),
]

# =============================================================================
# Temporary file patterns (MASTG-TEST-0304-0306)
# =============================================================================

TEMP_FILE_PATTERNS = [
    (r'(?i)File\.createTempFile\s*\([^)]*(?:password|token|secret|key|credential)', "High", "Temp file with sensitive name"),
    (r'(?i)File\.createTempFile\s*\(', "Low", "Temporary file creation (verify no sensitive data)"),
    (r'(?i)getCacheDir\s*\(\)[^;]*(?:password|token|secret|credential)', "High", "Sensitive data in cache directory"),
    (r'(?i)new\s+File\s*\([^)]*\.(?:tmp|temp|cache)["\']?\s*\)', "Low", "Temporary file pattern"),
    (r'(?i)BufferedWriter[^;]*createTempFile', "Medium", "Writing to temporary file"),
]

# Sensitive data in SharedPreferences without encryption context
SENSITIVE_PREFS_KEYS = [
    'password', 'token', 'secret', 'api_key', 'apiKey',
    'credential', 'auth', 'session', 'private_key', 'privateKey'
]


def check_encryption_context(text: str, match_start: int, match_end: int) -> bool:
    """Check if encryption is used in the context of the match.

    Args:
        text: Full file content.
        match_start: Start index of the match.
        match_end: End index of the match.

    Returns:
        True if encryption indicators found in surrounding context.
    """
    context_start = max(0, match_start - 300)
    context_end = min(len(text), match_end + 300)
    context = text[context_start:context_end].lower()

    encryption_indicators = [
        'encrypt', 'cipher', 'aes', 'rsa', 'keystore',
        'encryptedsharedpreferences', 'securepreferences',
        'masterkey', 'crypto', 'securely'
    ]

    return any(ind in context for ind in encryption_indicators)


def iter_text(src_dir: str, apk_path: str = None):
    """Iterate over source files yielding (path, content) tuples.

    Args:
        src_dir: Path to decompiled source directory.
        apk_path: Optional path to APK file for direct scanning.

    Yields:
        Tuple of (file_path, file_content) for each readable file.
    """
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


def main() -> None:
    """Scan for storage/logging issues and write findings to CSV.

    Command line args:
        sys.argv[1]: Path to decompiled source directory
        sys.argv[2]: Output CSV path
        sys.argv[3]: Optional path to APK file

    Raises:
        SystemExit: If arguments missing or scanning fails.
    """
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

            # Check for external storage usage (MASTG-TEST-0200-0207)
            for pattern, severity, desc in EXTERNAL_STORAGE_PATTERNS:
                for m in re.finditer(pattern, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "logging_storage",
                        "RuleID": "EXT_STORAGE_WRITE",
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": severity,
                        "HowFound": "Regex scan"
                    })

            # Check for notification sensitive data (MASTG-TEST-0005)
            for pattern, severity, desc in NOTIFICATION_SENSITIVE_PATTERNS:
                for m in re.finditer(pattern, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "logging_storage",
                        "RuleID": "NOTIF_SENSITIVE_DATA",
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": severity,
                        "HowFound": "Regex scan"
                    })

            # Check for third-party data sharing (MASTG-TEST-0004)
            for pattern, severity, desc in THIRDPARTY_DATA_PATTERNS:
                for m in re.finditer(pattern, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "logging_storage",
                        "RuleID": "THIRDPARTY_DATA_SHARE",
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": severity,
                        "HowFound": "Regex scan"
                    })

            # Check for database sensitive data (MASTG-TEST-0304-0306)
            for pattern, severity, desc in DATABASE_SENSITIVE_PATTERNS:
                for m in re.finditer(pattern, text):
                    if not check_encryption_context(text, m.start(), m.end()):
                        snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                        rows.append({
                            "Source": "logging_storage",
                            "RuleID": "DB_SENSITIVE_DATA",
                            "Title": desc,
                            "Location": str(path),
                            "Evidence": snippet[:200],
                            "Severity": severity,
                            "HowFound": "Regex scan with context check"
                        })

            # Check for temporary file issues (MASTG-TEST-0304-0306)
            for pattern, severity, desc in TEMP_FILE_PATTERNS:
                for m in re.finditer(pattern, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "logging_storage",
                        "RuleID": "TEMP_FILE_SENSITIVE",
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": severity,
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
