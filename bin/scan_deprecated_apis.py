#!/usr/bin/env python3
"""
Deprecated/Unsafe API Scanner v1.0

Detects usage of deprecated or security-sensitive Android APIs that may
indicate security vulnerabilities or compatibility issues.

Checks for:
- Deprecated crypto/security APIs
- Removed API usage above target SDK
- Known vulnerable library methods
- Insecure legacy patterns

References:
- https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0047/
- https://developer.android.com/reference/deprecated-list
- https://cwe.mitre.org/data/definitions/477.html

OWASP Alignment: MASVS-CODE-4
CWE: CWE-477 (Use of Obsolete Function)
"""

from __future__ import annotations

import csv
import os
import re
import sys
from pathlib import Path
from typing import Iterator

# CSV output schema
CSV_FIELDNAMES = ["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"]


def truncate(s: str, max_len: int = 150) -> str:
    """Truncate string for evidence field."""
    s = s.replace("\n", " ").replace("\r", "").strip()
    return s[:max_len] + "..." if len(s) > max_len else s


def iter_source_files(src_dir: str) -> Iterator[tuple[str, str]]:
    """Iterate over source files, yielding (path, content)."""
    src_path = Path(src_dir)
    if not src_path.exists():
        return

    extensions = {".java", ".kt", ".smali"}

    for p in src_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in extensions:
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                yield str(p), content
            except Exception:
                continue


# Deprecated/insecure API patterns
DEPRECATED_PATTERNS = [
    # Crypto deprecations
    (
        r"Cipher\.getInstance\s*\(\s*[\"']DES[\"']",
        "DEP_DES_CIPHER",
        "High",
        "DES Cipher (Deprecated/Insecure)",
        "DES is cryptographically broken - use AES",
    ),
    (
        r"MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']",
        "DEP_MD5_HASH",
        "High",
        "MD5 Hash (Deprecated/Insecure)",
        "MD5 is cryptographically weak - use SHA-256+",
    ),
    (
        r"MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']",
        "DEP_SHA1_HASH",
        "Medium",
        "SHA1 Hash (Deprecated)",
        "SHA1 is deprecated - use SHA-256+",
    ),
    (
        r"Cipher\.getInstance\s*\(\s*[\"']RC4[\"']",
        "DEP_RC4_CIPHER",
        "High",
        "RC4 Cipher (Deprecated/Insecure)",
        "RC4 is cryptographically broken - use AES-GCM",
    ),
    (
        r"Cipher\.getInstance\s*\(\s*[\"']Blowfish[\"']",
        "DEP_BLOWFISH",
        "Medium",
        "Blowfish Cipher (Deprecated)",
        "Blowfish is deprecated - use AES",
    ),

    # Network deprecations
    (
        r"HttpClient|DefaultHttpClient|AndroidHttpClient",
        "DEP_HTTP_CLIENT",
        "Medium",
        "Apache HttpClient (Deprecated)",
        "Apache HttpClient removed in API 23 - use HttpURLConnection or OkHttp",
    ),
    (
        r"org\.apache\.http",
        "DEP_APACHE_HTTP",
        "Medium",
        "Apache HTTP Library (Deprecated)",
        "Apache HTTP removed from SDK - use modern networking",
    ),
    (
        r"SSLCertificateSocketFactory",
        "DEP_SSL_SOCKET_FACTORY",
        "High",
        "SSLCertificateSocketFactory (Insecure)",
        "SSLCertificateSocketFactory can bypass certificate validation",
    ),

    # Storage deprecations
    (
        r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE",
        "DEP_WORLD_ACCESSIBLE",
        "High",
        "MODE_WORLD_READABLE/WRITEABLE (Deprecated)",
        "World-accessible files removed in API 24 - use ContentProvider",
    ),
    (
        r"getExternalStorageDirectory\s*\(",
        "DEP_EXTERNAL_STORAGE",
        "Medium",
        "getExternalStorageDirectory (Deprecated)",
        "Deprecated in API 29 - use getExternalFilesDir or MediaStore",
    ),
    (
        r"Environment\.getExternalStoragePublicDirectory",
        "DEP_PUBLIC_STORAGE",
        "Medium",
        "getExternalStoragePublicDirectory (Deprecated)",
        "Deprecated in API 29 - use MediaStore APIs",
    ),

    # Service deprecations
    (
        r"startService\s*\(\s*new\s+Intent\s*\(\s*[\"']",
        "DEP_IMPLICIT_SERVICE",
        "High",
        "Implicit Service Start (Deprecated)",
        "Implicit service intents illegal since API 21",
    ),
    (
        r"getRunningTasks|getRecentTasks",
        "DEP_RUNNING_TASKS",
        "Medium",
        "getRunningTasks (Deprecated)",
        "Deprecated for privacy - only returns own tasks since API 21",
    ),

    # Telephony deprecations
    (
        r"TelephonyManager.*getDeviceId\s*\(",
        "DEP_GET_DEVICE_ID",
        "High",
        "getDeviceId (Deprecated)",
        "Deprecated in API 26, removed in 29 - use Android ID or instance ID",
    ),
    (
        r"Settings\.Secure.*ANDROID_ID",
        "DEP_ANDROID_ID",
        "Low",
        "ANDROID_ID Usage",
        "ANDROID_ID behavior changed in API 26 - verify identifier strategy",
    ),

    # WebView deprecations
    (
        r"@SuppressWarnings\s*\(\s*[\"']deprecation[\"']\s*\)[^}]*WebView",
        "DEP_WEBVIEW_SUPPRESSED",
        "Medium",
        "Suppressed WebView Deprecation",
        "Deprecated WebView methods with suppressed warning - review",
    ),
    (
        r"WebSettings.*setJavaScriptEnabled\s*\(\s*true\s*\)",
        "DEP_JS_ENABLED",
        "Low",
        "JavaScript Enabled in WebView",
        "JavaScript in WebView - ensure proper security settings",
    ),

    # Broadcast deprecations
    (
        r"sendStickyBroadcast|sendStickyOrderedBroadcast",
        "DEP_STICKY_BROADCAST",
        "High",
        "Sticky Broadcast (Deprecated)",
        "Sticky broadcasts deprecated API 21 - use regular broadcasts",
    ),
    (
        r"LocalBroadcastManager",
        "DEP_LOCAL_BROADCAST",
        "Low",
        "LocalBroadcastManager (Deprecated)",
        "Deprecated - use LiveData or similar reactive patterns",
    ),

    # Fragment deprecations
    (
        r"android\.app\.Fragment|getFragmentManager\(\)",
        "DEP_PLATFORM_FRAGMENT",
        "Medium",
        "Platform Fragment (Deprecated)",
        "Platform fragments deprecated - use AndroidX Fragment",
    ),

    # AsyncTask deprecation
    (
        r"extends\s+AsyncTask|new\s+AsyncTask",
        "DEP_ASYNC_TASK",
        "Low",
        "AsyncTask (Deprecated)",
        "AsyncTask deprecated in API 30 - use java.util.concurrent or Kotlin coroutines",
    ),

    # Loader deprecation
    (
        r"extends\s+(?:Async)?Loader|LoaderManager",
        "DEP_LOADER",
        "Low",
        "Loader Pattern (Deprecated)",
        "Loaders deprecated - use ViewModel with LiveData",
    ),

    # Permission deprecations
    (
        r"WRITE_EXTERNAL_STORAGE|READ_EXTERNAL_STORAGE",
        "DEP_STORAGE_PERMISSION",
        "Low",
        "Storage Permissions (Changing)",
        "Storage permissions behavior changed in API 29+ - use scoped storage",
    ),

    # Reflection usage (security concern)
    (
        r"setAccessible\s*\(\s*true\s*\)",
        "DEP_SET_ACCESSIBLE",
        "Medium",
        "setAccessible(true) Usage",
        "Bypassing access controls - review security implications",
    ),

    # Unsafe methods
    (
        r"Runtime\.getRuntime\(\)\.exec",
        "DEP_RUNTIME_EXEC",
        "Medium",
        "Runtime.exec() Usage",
        "Shell execution - verify input sanitization",
    ),
    (
        r"ProcessBuilder[^;]*\.start\s*\(",
        "DEP_PROCESS_BUILDER",
        "Medium",
        "ProcessBuilder Usage",
        "Process execution - verify input sanitization",
    ),
]

# Smali patterns
SMALI_PATTERNS = [
    # DES in smali
    (
        r"const-string[^;]*\"DES\"",
        "DEP_SMALI_DES",
        "High",
        "DES String Constant (Smali)",
        "DES cipher referenced in smali - insecure",
    ),
    # MD5 in smali
    (
        r"const-string[^;]*\"MD5\"",
        "DEP_SMALI_MD5",
        "High",
        "MD5 String Constant (Smali)",
        "MD5 hash referenced in smali - weak",
    ),
]


def scan_for_deprecated_apis(src_dir: str) -> list[dict]:
    """Scan source code for deprecated API usage."""
    findings = []
    seen = set()

    # Compile patterns
    compiled_patterns = []
    for pattern, rule_id, severity, title, description in DEPRECATED_PATTERNS:
        try:
            compiled_patterns.append(
                (re.compile(pattern, re.IGNORECASE | re.MULTILINE), rule_id, severity, title, description)
            )
        except re.error:
            continue

    compiled_smali = []
    for pattern, rule_id, severity, title, description in SMALI_PATTERNS:
        try:
            compiled_smali.append(
                (re.compile(pattern, re.IGNORECASE), rule_id, severity, title, description)
            )
        except re.error:
            continue

    for filepath, content in iter_source_files(src_dir):
        is_smali = filepath.endswith(".smali")
        patterns_to_use = compiled_smali if is_smali else compiled_patterns

        for regex, rule_id, severity, title, description in patterns_to_use:
            for match in regex.finditer(content):
                evidence = match.group(0)
                key = (rule_id, filepath, evidence[:50])

                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "Source": "deprecated_apis",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    # Summary
    high_count = sum(1 for f in findings if f["Severity"] == "High")
    medium_count = sum(1 for f in findings if f["Severity"] == "Medium")

    if findings:
        findings.append({
            "Source": "deprecated_apis",
            "RuleID": "DEP_SUMMARY",
            "Title": "Deprecated API Analysis Summary",
            "Location": "Application",
            "Evidence": f"{high_count} high, {medium_count} medium severity findings",
            "Severity": "Info",
            "HowFound": "Review deprecated APIs for security and compatibility",
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
        print(f"Usage: {sys.argv[0]} <src_dir> <output.csv>", file=sys.stderr)
        sys.exit(1)

    src_dir = sys.argv[1]
    output_path = sys.argv[2]

    findings = scan_for_deprecated_apis(src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
