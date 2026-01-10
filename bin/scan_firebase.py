#!/usr/bin/env python3
"""
Firebase Misconfiguration Scanner v1.0

Detects Firebase security misconfigurations that have led to massive data breaches:
- Exposed Firebase Realtime Database URLs
- Firebase Storage bucket URLs
- Firebase API keys (can be extracted and tested)
- Firestore project IDs
- google-services.json configuration files
- Firebase Cloud Messaging (FCM) server keys

References:
- https://zimperium.com/blog/mobile-threat-watch/misconfigured-firebase-apps-leave-sensitive-user-data-exposed/
- 125M+ user records exposed via misconfigured Firebase in 2024

OWASP Alignment: MASVS-STORAGE-1, MASVS-NETWORK-1
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
import zipfile
from pathlib import Path
from typing import Iterator

# CSV output schema
CSV_FIELDNAMES = ["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"]

# Firebase URL patterns
FIREBASE_PATTERNS = [
    # Firebase Realtime Database URLs
    (
        r"https://[a-z0-9-]+\.firebaseio\.com/?",
        "FIRE_REALTIME_DB",
        "Critical",
        "Firebase Realtime Database URL",
        "Firebase database URL exposed - may allow unauthenticated read/write if rules misconfigured",
    ),
    # Firebase Storage buckets
    (
        r"https://firebasestorage\.googleapis\.com/v0/b/[a-z0-9-]+\.appspot\.com",
        "FIRE_STORAGE_BUCKET",
        "High",
        "Firebase Storage Bucket URL",
        "Firebase storage bucket exposed - verify security rules restrict access",
    ),
    # Firebase Storage (gs:// format)
    (
        r"gs://[a-z0-9-]+\.appspot\.com",
        "FIRE_STORAGE_GS",
        "Medium",
        "Firebase Storage (gs://) Reference",
        "Firebase storage reference found - review storage security rules",
    ),
    # Firebase API Key (AIza prefix)
    (
        r"AIza[0-9A-Za-z_-]{35}",
        "FIRE_API_KEY",
        "High",
        "Firebase/Google API Key",
        "Firebase API key found - restrict in Google Cloud Console, verify app restrictions",
    ),
    # Firebase project ID patterns
    (
        r'"project_id"\s*:\s*"([a-z0-9-]+)"',
        "FIRE_PROJECT_ID",
        "Info",
        "Firebase Project ID",
        "Firebase project ID found - informational, used for enumeration",
    ),
    # Firebase messaging sender ID
    (
        r'"gcm_sender_id"\s*:\s*"(\d+)"',
        "FIRE_GCM_SENDER",
        "Low",
        "Firebase GCM Sender ID",
        "Firebase messaging sender ID - informational",
    ),
    # Firebase app ID
    (
        r'"mobilesdk_app_id"\s*:\s*"1:\d+:android:[a-f0-9]+"',
        "FIRE_APP_ID",
        "Info",
        "Firebase App ID",
        "Firebase app ID found - informational",
    ),
    # FCM Server Key (legacy format)
    (
        r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "FIRE_FCM_SERVER_KEY",
        "Critical",
        "Firebase Cloud Messaging Server Key",
        "FCM server key exposed - allows sending push notifications to any device. Regenerate immediately!",
    ),
    # Firestore database URL
    (
        r"https://firestore\.googleapis\.com/v1/projects/[a-z0-9-]+/databases",
        "FIRE_FIRESTORE_URL",
        "High",
        "Firestore Database URL",
        "Firestore URL found - verify security rules restrict access",
    ),
    # Firebase Auth domain
    (
        r"[a-z0-9-]+\.firebaseapp\.com",
        "FIRE_AUTH_DOMAIN",
        "Info",
        "Firebase Auth Domain",
        "Firebase auth domain found - informational, used for authentication",
    ),
    # Firebase database reference in code
    (
        r"FirebaseDatabase\.getInstance\(\)\.getReference\(",
        "FIRE_DB_REFERENCE",
        "Medium",
        "Firebase Database Reference Usage",
        "Direct Firebase database reference - ensure security rules are properly configured",
    ),
    # Firebase anonymous auth
    (
        r"signInAnonymously\(\)",
        "FIRE_ANON_AUTH",
        "Medium",
        "Firebase Anonymous Authentication",
        "Anonymous auth enabled - verify this is intentional and properly handled",
    ),
]

# Config file patterns to look for
CONFIG_FILES = [
    "google-services.json",
    "GoogleService-Info.plist",
]


def truncate(s: str, max_len: int = 150) -> str:
    """Truncate string for evidence field."""
    s = s.replace("\n", " ").replace("\r", "").strip()
    return s[:max_len] + "..." if len(s) > max_len else s


def iter_source_files(src_dir: str) -> Iterator[tuple[str, str]]:
    """Iterate over source files, yielding (path, content)."""
    src_path = Path(src_dir)
    if not src_path.exists():
        return

    extensions = {".java", ".kt", ".xml", ".json", ".properties", ".gradle", ".smali"}

    for p in src_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in extensions:
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                yield str(p), content
            except Exception:
                continue


def iter_apk_files(apk_path: str) -> Iterator[tuple[str, str]]:
    """Iterate over files inside APK, yielding (path, content)."""
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                # Look for config files and text files
                if name.endswith((".json", ".xml", ".properties")):
                    try:
                        content = zf.read(name).decode("utf-8", errors="ignore")
                        yield name, content
                    except Exception:
                        continue
    except Exception:
        return


def check_firebase_config(content: str, filepath: str, findings: list[dict]):
    """Check for Firebase configuration files with potentially sensitive data."""
    try:
        config = json.loads(content)

        # Check for google-services.json structure
        if "project_info" in config:
            project_id = config.get("project_info", {}).get("project_id", "")
            firebase_url = config.get("project_info", {}).get("firebase_url", "")
            storage_bucket = config.get("project_info", {}).get("storage_bucket", "")

            if firebase_url:
                findings.append({
                    "Source": "firebase",
                    "RuleID": "FIRE_CONFIG_DB_URL",
                    "Title": "Firebase Database URL in Config",
                    "Location": filepath,
                    "Evidence": truncate(firebase_url),
                    "Severity": "Critical",
                    "HowFound": "google-services.json analysis",
                })

            if storage_bucket:
                findings.append({
                    "Source": "firebase",
                    "RuleID": "FIRE_CONFIG_STORAGE",
                    "Title": "Firebase Storage Bucket in Config",
                    "Location": filepath,
                    "Evidence": truncate(storage_bucket),
                    "Severity": "High",
                    "HowFound": "google-services.json analysis",
                })

            # Check for API keys in client array
            for client in config.get("client", []):
                for api_key in client.get("api_key", []):
                    key = api_key.get("current_key", "")
                    if key:
                        findings.append({
                            "Source": "firebase",
                            "RuleID": "FIRE_CONFIG_API_KEY",
                            "Title": "Firebase API Key in Config",
                            "Location": filepath,
                            "Evidence": truncate(key[:20] + "..." + key[-10:] if len(key) > 30 else key),
                            "Severity": "High",
                            "HowFound": "google-services.json analysis",
                        })
    except json.JSONDecodeError:
        pass


def scan_for_firebase(src_dir: str, apk_path: str | None = None) -> list[dict]:
    """Scan source directory and APK for Firebase misconfigurations."""
    findings = []
    seen = set()  # Deduplicate findings

    # Compile patterns
    compiled_patterns = []
    for pattern, rule_id, severity, title, description in FIREBASE_PATTERNS:
        try:
            compiled_patterns.append((re.compile(pattern, re.IGNORECASE), rule_id, severity, title, description))
        except re.error:
            continue

    def process_file(filepath: str, content: str):
        # Check for google-services.json
        if filepath.endswith("google-services.json"):
            check_firebase_config(content, filepath, findings)

        # Check patterns
        for regex, rule_id, severity, title, description in compiled_patterns:
            for match in regex.finditer(content):
                evidence = match.group(0)
                key = (rule_id, filepath, evidence[:50])
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "Source": "firebase",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": f"Pattern match: {description}",
                    })

    # Scan source directory
    for filepath, content in iter_source_files(src_dir):
        process_file(filepath, content)

    # Scan APK if provided
    if apk_path and os.path.exists(apk_path):
        for filepath, content in iter_apk_files(apk_path):
            process_file(f"APK:{filepath}", content)

    # Add summary finding if Firebase detected but no critical issues
    firebase_detected = any(f["RuleID"].startswith("FIRE_") for f in findings)
    critical_found = any(f["Severity"] == "Critical" for f in findings)

    if firebase_detected and not critical_found:
        findings.append({
            "Source": "firebase",
            "RuleID": "FIRE_DETECTED",
            "Title": "Firebase Integration Detected",
            "Location": "Multiple locations",
            "Evidence": f"Found {len(findings)} Firebase-related items",
            "Severity": "Info",
            "HowFound": "Firebase usage analysis - verify security rules are properly configured",
        })

    return findings


def write_findings_csv(output_path: str, findings: list[dict]):
    """Write findings to CSV file."""
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(findings)

    print(f"Wrote {len(findings)} finding(s) to {output_path}")


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <src_dir> <output.csv> [apk_path]", file=sys.stderr)
        sys.exit(1)

    src_dir = sys.argv[1]
    output_path = sys.argv[2]
    apk_path = sys.argv[3] if len(sys.argv) > 3 else None

    findings = scan_for_firebase(src_dir, apk_path)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
