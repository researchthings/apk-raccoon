#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 2.0
# Script to scan for privacy control issues (e.g., PII handling, excessive permissions)
# Why: Addresses OWASP M6; inadequate privacy leads to data leaks.
#
# Improvements in v2.0:
# - Fixed broken negative lookahead patterns
# - Corrected permission classification (Android dangerous permissions)
# - Added context-aware PII detection
# - Fixed file handle leak

import sys
import os
import re
import csv
import zipfile
import traceback
from lxml import etree

# =============================================================================
# Android Dangerous Permissions (as defined by Android)
# These require runtime permission request in Android 6.0+
# =============================================================================
DANGEROUS_PERMISSIONS = {
    # Calendar
    'android.permission.READ_CALENDAR',
    'android.permission.WRITE_CALENDAR',
    # Call Log
    'android.permission.READ_CALL_LOG',
    'android.permission.WRITE_CALL_LOG',
    'android.permission.PROCESS_OUTGOING_CALLS',
    # Camera
    'android.permission.CAMERA',
    # Contacts
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.GET_ACCOUNTS',
    # Location
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.ACCESS_BACKGROUND_LOCATION',
    # Microphone
    'android.permission.RECORD_AUDIO',
    # Phone
    'android.permission.READ_PHONE_STATE',
    'android.permission.READ_PHONE_NUMBERS',
    'android.permission.CALL_PHONE',
    'android.permission.ANSWER_PHONE_CALLS',
    'android.permission.ADD_VOICEMAIL',
    'android.permission.USE_SIP',
    # Sensors
    'android.permission.BODY_SENSORS',
    'android.permission.BODY_SENSORS_BACKGROUND',
    # SMS
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_SMS',
    'android.permission.RECEIVE_WAP_PUSH',
    'android.permission.RECEIVE_MMS',
    # Storage
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.ACCESS_MEDIA_LOCATION',
    # Activity Recognition
    'android.permission.ACTIVITY_RECOGNITION',
    # Nearby Devices
    'android.permission.BLUETOOTH_ADVERTISE',
    'android.permission.BLUETOOTH_CONNECT',
    'android.permission.BLUETOOTH_SCAN',
    'android.permission.UWB_RANGING',
    'android.permission.NEARBY_WIFI_DEVICES',
}

# High-sensitivity permissions (warrant extra scrutiny)
HIGH_SENSITIVITY_PERMISSIONS = {
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_BACKGROUND_LOCATION',
    'android.permission.READ_CONTACTS',
    'android.permission.READ_CALL_LOG',
    'android.permission.READ_SMS',
    'android.permission.CAMERA',
    'android.permission.RECORD_AUDIO',
    'android.permission.BODY_SENSORS',
}

# =============================================================================
# PII patterns - more specific to reduce false positives
# =============================================================================
PII_PATTERNS = [
    # SSN patterns (US format)
    (
        "PRIV_SSN_HARDCODED",
        r'(?i)(?:ssn|social[_-]?security)[_-]?(?:number)?\s*[:=]\s*["\']?\d{3}[- ]?\d{2}[- ]?\d{4}',
        "Critical",
        "Hardcoded Social Security Number"
    ),
    # Credit card numbers
    (
        "PRIV_CC_HARDCODED",
        r'(?i)(?:credit[_-]?card|card[_-]?number|cc[_-]?num)\s*[:=]\s*["\']?\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}',
        "Critical",
        "Hardcoded Credit Card Number"
    ),
    # Bank account
    (
        "PRIV_BANK_HARDCODED",
        r'(?i)(?:bank[_-]?account|account[_-]?number|routing[_-]?number)\s*[:=]\s*["\']?\d{8,17}',
        "High",
        "Hardcoded Bank Account/Routing Number"
    ),
    # Email collection without context
    (
        "PRIV_EMAIL_COLLECT",
        r'(?i)(?:user[_-]?email|customer[_-]?email)\s*[:=]\s*(?:getText|getInput|getString)',
        "Low",
        "Email collection (verify consent)"
    ),
    # Phone collection
    (
        "PRIV_PHONE_COLLECT",
        r'(?i)(?:phone[_-]?number|mobile[_-]?number)\s*[:=]\s*(?:getText|getInput|getString)',
        "Low",
        "Phone number collection (verify consent)"
    ),
]

# Data sharing patterns
DATA_SHARING_PATTERNS = [
    (
        "PRIV_DATA_SHARE_ANALYTICS",
        r'(?i)(?:analytics|tracking|telemetry)\.(?:send|track|log)\s*\([^)]*(?:email|phone|location|userId)',
        "Medium",
        "PII sent to analytics (verify consent)"
    ),
    (
        "PRIV_DATA_SHARE_THIRDPARTY",
        r'(?i)(?:facebook|google|firebase|amplitude|mixpanel)\.(?:log|track|send)\s*\([^)]*(?:email|phone|name)',
        "Medium",
        "PII sent to third-party SDK (verify consent)"
    ),
]


def parse_manifest_for_perms(mani_path):
    """Parse manifest for permissions and categorize them."""
    permissions = {
        'dangerous': [],
        'high_sensitivity': [],
        'all': []
    }

    try:
        tree = etree.parse(mani_path)
        ns = '{http://schemas.android.com/apk/res/android}'

        for perm in tree.xpath('//uses-permission'):
            perm_name = perm.get(f'{ns}name')
            if perm_name:
                permissions['all'].append(perm_name)

                if perm_name in DANGEROUS_PERMISSIONS:
                    permissions['dangerous'].append(perm_name)

                if perm_name in HIGH_SENSITIVITY_PERMISSIONS:
                    permissions['high_sensitivity'].append(perm_name)

    except Exception as e:
        print(f"Warning: Manifest parse failed: {str(e)}", file=sys.stderr)

    return permissions


def check_encrypted_storage(text, pii_match_start, pii_match_end):
    """Check if PII storage appears to use encryption in the nearby context."""
    # Look for encryption indicators within 200 chars of the match
    context_start = max(0, pii_match_start - 200)
    context_end = min(len(text), pii_match_end + 200)
    context = text[context_start:context_end].lower()

    encryption_indicators = [
        'encrypt', 'cipher', 'aes', 'rsa', 'keystore',
        'encryptedsharedpreferences', 'securepreferences',
        'masterkey', 'crypto'
    ]

    return any(ind in context for ind in encryption_indicators)


def iter_text(src_dir, apk_path):
    """Iterate over source files."""
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
                # Skip non-code files
                if not fn.endswith(('.java', '.kt', '.smali', '.xml', '.json')):
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
            print("Usage: scan_privacy_issues.py <src_dir> <out.csv> [apk_path] [manifest.xml]", file=sys.stderr)
            sys.exit(1)

        src_dir, out = sys.argv[1], sys.argv[2]
        apk_path = sys.argv[3] if len(sys.argv) > 3 else None
        mani_path = sys.argv[4] if len(sys.argv) > 4 else None

        rows = []
        files_scanned = 0

        # Check manifest permissions
        if mani_path and os.path.isfile(mani_path):
            perms = parse_manifest_for_perms(mani_path)

            # Report high-sensitivity permissions
            for perm in perms['high_sensitivity']:
                rows.append({
                    "Source": "privacy",
                    "RuleID": "PRIV_HIGH_SENS_PERM",
                    "Title": "High-sensitivity permission requested",
                    "Location": mani_path,
                    "Evidence": perm,
                    "Severity": "Medium",
                    "HowFound": "XML parse"
                })

            # Report if many dangerous permissions (possible over-collection)
            if len(perms['dangerous']) > 5:
                rows.append({
                    "Source": "privacy",
                    "RuleID": "PRIV_EXCESSIVE_PERMS",
                    "Title": f"Many dangerous permissions ({len(perms['dangerous'])})",
                    "Location": mani_path,
                    "Evidence": ", ".join(perms['dangerous'][:5]) + "...",
                    "Severity": "Medium",
                    "HowFound": "XML parse"
                })

        # Scan source files
        for path, text in iter_text(src_dir, apk_path):
            files_scanned += 1

            # Check PII patterns
            for rid, rx, sev, desc in PII_PATTERNS:
                for m in re.finditer(rx, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "privacy",
                        "RuleID": rid,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": sev,
                        "HowFound": "Regex scan"
                    })

            # Check data sharing patterns
            for rid, rx, sev, desc in DATA_SHARING_PATTERNS:
                for m in re.finditer(rx, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "privacy",
                        "RuleID": rid,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": sev,
                        "HowFound": "Regex scan"
                    })

            # Check for unencrypted PII storage
            pii_storage_rx = r'(?i)(?:putString|put)\s*\(\s*["\'](?:email|phone|ssn|address)["\']'
            for m in re.finditer(pii_storage_rx, text):
                if not check_encrypted_storage(text, m.start(), m.end()):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "privacy",
                        "RuleID": "PRIV_PII_UNENCRYPTED",
                        "Title": "PII storage without encryption indicator",
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": "High",
                        "HowFound": "Regex scan with context check"
                    })

        # Write output
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        print(f"Wrote {out} ({len(rows)} findings, {files_scanned} files scanned)")

    except Exception as e:
        print(f"[!] Error in scan_privacy_issues: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
