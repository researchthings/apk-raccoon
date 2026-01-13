#!/usr/bin/env python3
"""Scan for PendingIntent security vulnerabilities.

Detects PendingIntent misuse that enables intent redirection attacks.
Android 12+ requires explicit mutability flags (FLAG_IMMUTABLE/FLAG_MUTABLE).

Checks:
    - Missing FLAG_IMMUTABLE/FLAG_MUTABLE (Android 12+ requirement)
    - Implicit intents in PendingIntent (hijackable)
    - Mutable PendingIntents with implicit base intent
    - Empty base intent (can be filled by attacker)
    - Broadcast PendingIntents without explicit receiver

OWASP MASTG Coverage:
    - MASTG-TEST-0028: Testing for Vulnerable PendingIntent
    - MASTG-TEST-0029: Testing for Intent Redirection

Author: Randy Grant
Date: 01-09-2026
Version: 1.0
"""

import csv
import os
import re
import sys
import traceback
import zipfile

from lxml import etree

# =============================================================================
# PendingIntent patterns
# =============================================================================

# Methods that create PendingIntent
PENDING_INTENT_METHODS = [
    'PendingIntent.getActivity',
    'PendingIntent.getActivities',
    'PendingIntent.getBroadcast',
    'PendingIntent.getService',
    'PendingIntent.getForegroundService',
]

# Pattern to find PendingIntent creation
PENDING_INTENT_PATTERN = r'PendingIntent\.(?:getActivity|getActivities|getBroadcast|getService|getForegroundService)\s*\('

# Pattern to check for immutability flags
FLAG_IMMUTABLE_PATTERN = r'FLAG_IMMUTABLE|PendingIntent\.FLAG_IMMUTABLE'
FLAG_MUTABLE_PATTERN = r'FLAG_MUTABLE|PendingIntent\.FLAG_MUTABLE'

# Pattern for empty intent
EMPTY_INTENT_PATTERN = r'new\s+Intent\s*\(\s*\)'

# Pattern for implicit intent (no explicit component)
IMPLICIT_INTENT_INDICATORS = [
    r'new\s+Intent\s*\(\s*["\'][^"\']+["\']\s*\)',  # Intent with action string only
    r'new\s+Intent\s*\(\s*Intent\.[A-Z_]+\s*\)',   # Intent with Intent.ACTION_*
    r'setAction\s*\(\s*["\'][^"\']+["\']\s*\)',    # setAction without setComponent
]

# Pattern for explicit intent (has component set)
EXPLICIT_INTENT_INDICATORS = [
    r'setComponent\s*\(',
    r'setClass\s*\(',
    r'setClassName\s*\(',
    r'setPackage\s*\(',
    r'new\s+Intent\s*\(\s*\w+\s*,\s*\w+\.class\s*\)',  # Intent(context, Activity.class)
    r'new\s+Intent\s*\(\s*this\s*,',
    r'new\s+Intent\s*\(\s*context\s*,',
    r'new\s+ComponentName\s*\(',
]


def extract_pending_intent_context(text: str, match_start: int, match_end: int) -> str:
    """Extract the context around a PendingIntent creation for analysis.

    Args:
        text: The source code text to extract context from.
        match_start: Starting position of the PendingIntent match.
        match_end: Ending position of the PendingIntent match.

    Returns:
        A string containing the relevant context surrounding the PendingIntent
        creation, including balanced parentheses.
    """
    # Look back to find the start of the statement (max 500 chars)
    context_start = max(0, match_start - 500)
    # Look forward to find the closing parenthesis (max 300 chars)
    context_end = min(len(text), match_end + 300)

    # Find balanced parentheses
    paren_count = 0
    actual_end = match_end
    for i in range(match_end, context_end):
        if text[i] == '(':
            paren_count += 1
        elif text[i] == ')':
            if paren_count == 0:
                actual_end = i + 1
                break
            paren_count -= 1

    return text[context_start:actual_end]


def analyze_pending_intent(context: str, full_text: str, match_start: int) -> list[dict]:
    """Analyze a PendingIntent creation for security issues.

    Args:
        context: The extracted context string around the PendingIntent.
        full_text: The full source code text for additional analysis.
        match_start: Starting position of the match in full_text.

    Returns:
        A list of finding dictionaries, each containing RuleID, Title,
        Severity, and Description keys.
    """
    findings = []

    # Check for FLAG_IMMUTABLE or FLAG_MUTABLE
    has_immutable = bool(re.search(FLAG_IMMUTABLE_PATTERN, context))
    has_mutable = bool(re.search(FLAG_MUTABLE_PATTERN, context))

    if not has_immutable and not has_mutable:
        findings.append({
            "RuleID": "PI_MISSING_FLAG",
            "Title": "PendingIntent without FLAG_IMMUTABLE/FLAG_MUTABLE",
            "Severity": "High",
            "Description": "Android 12+ requires explicit mutability flag"
        })

    # Check for empty intent
    if re.search(EMPTY_INTENT_PATTERN, context):
        severity = "Critical" if has_mutable else "High"
        findings.append({
            "RuleID": "PI_EMPTY_INTENT",
            "Title": "PendingIntent with empty base Intent",
            "Severity": severity,
            "Description": "Empty intent can be filled by attacker"
        })

    # Check for implicit vs explicit intent
    is_implicit = any(re.search(pattern, context) for pattern in IMPLICIT_INTENT_INDICATORS)
    is_explicit = any(re.search(pattern, context) for pattern in EXPLICIT_INTENT_INDICATORS)

    if is_implicit and not is_explicit:
        severity = "Critical" if has_mutable else "High"
        findings.append({
            "RuleID": "PI_IMPLICIT_INTENT",
            "Title": "PendingIntent with implicit Intent",
            "Severity": severity,
            "Description": "Implicit intent can be intercepted by malicious app"
        })

    # Check for mutable PendingIntent with implicit intent (worst case)
    if has_mutable and is_implicit and not is_explicit:
        findings.append({
            "RuleID": "PI_MUTABLE_IMPLICIT",
            "Title": "Mutable PendingIntent with implicit Intent (critical)",
            "Severity": "Critical",
            "Description": "Mutable + implicit = intent redirection attack vector"
        })

    # Check for broadcast PendingIntent (higher risk)
    if 'getBroadcast' in context:
        if is_implicit and not is_explicit:
            findings.append({
                "RuleID": "PI_BROADCAST_IMPLICIT",
                "Title": "Broadcast PendingIntent without explicit receiver",
                "Severity": "High",
                "Description": "Broadcast can be received by any app with matching filter"
            })

    return findings


def check_target_sdk(mani_path: str) -> int:
    """Check targetSdkVersion from AndroidManifest.xml.

    Args:
        mani_path: Path to the AndroidManifest.xml file.

    Returns:
        The targetSdkVersion as an integer, or 0 if not found or on error.
    """
    try:
        tree = etree.parse(mani_path)
        ns = '{http://schemas.android.com/apk/res/android}'

        # Check uses-sdk element
        uses_sdk = tree.xpath('//uses-sdk')
        if uses_sdk:
            target_sdk = uses_sdk[0].get(f'{ns}targetSdkVersion', '0')
            return int(target_sdk) if target_sdk.isdigit() else 0
    except Exception:
        pass
    return 0


def iter_text(src_dir: str, apk_path: str | None = None):
    """Iterate over source files, yielding path and content.

    Args:
        src_dir: Directory containing decompiled source files.
        apk_path: Optional path to APK file for direct scanning.

    Yields:
        Tuples of (file_path, file_content) for each source file.
    """
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
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
    """Scan for PendingIntent vulnerabilities and write findings to CSV.

    Command line args:
        sys.argv[1]: Path to source directory
        sys.argv[2]: Output CSV path
        sys.argv[3]: Optional path to APK file
        sys.argv[4]: Optional path to AndroidManifest.xml

    Raises:
        SystemExit: If arguments missing or scanning fails.
    """
    try:
        if len(sys.argv) < 3:
            print("Usage: scan_pending_intents.py <src_dir> <out.csv> [apk_path] [manifest.xml]", file=sys.stderr)
            sys.exit(1)

        src_dir, out = sys.argv[1], sys.argv[2]
        apk_path = sys.argv[3] if len(sys.argv) > 3 else None
        mani_path = sys.argv[4] if len(sys.argv) > 4 else None

        rows = []
        files_scanned = 0
        pending_intents_found = 0

        # Check target SDK version
        target_sdk = 0
        if mani_path and os.path.isfile(mani_path):
            target_sdk = check_target_sdk(mani_path)
            if target_sdk >= 31:
                # Android 12+ requires explicit flags
                rows.append({
                    "Source": "pending_intent",
                    "RuleID": "PI_TARGET_SDK_31",
                    "Title": "App targets Android 12+ (SDK 31+)",
                    "Location": mani_path,
                    "Evidence": f"targetSdkVersion={target_sdk}, FLAG_IMMUTABLE/MUTABLE required",
                    "Severity": "Info",
                    "HowFound": "XML parse"
                })

        # Scan source files
        for path, text in iter_text(src_dir, apk_path):
            files_scanned += 1

            # Find all PendingIntent creations
            for m in re.finditer(PENDING_INTENT_PATTERN, text):
                pending_intents_found += 1

                # Get extended context for analysis
                context = extract_pending_intent_context(text, m.start(), m.end())

                # Analyze the PendingIntent
                findings = analyze_pending_intent(context, text, m.start())

                for finding in findings:
                    # Adjust severity based on target SDK
                    severity = finding["Severity"]
                    if target_sdk >= 31 and finding["RuleID"] == "PI_MISSING_FLAG":
                        severity = "Critical"  # Will crash on Android 12+

                    snippet = context.replace("\n", " ")[:200]
                    rows.append({
                        "Source": "pending_intent",
                        "RuleID": finding["RuleID"],
                        "Title": finding["Title"],
                        "Location": str(path),
                        "Evidence": snippet,
                        "Severity": severity,
                        "HowFound": "Regex scan with context analysis"
                    })

            # Check for unsafe intent handling that could lead to PendingIntent issues
            unsafe_patterns = [
                (
                    "PI_GETPARCELABLE_INTENT",
                    r'getParcelableExtra\s*\([^)]*\)\s*(?:as\s+Intent|\.getAction)',
                    "Medium",
                    "Intent extracted from extras (potential hijack if passed to PendingIntent)"
                ),
                (
                    "PI_INTENT_SETDATA_EXTRA",
                    r'(?:intent|Intent)\s*\.\s*setData\s*\(\s*(?:getIntent|intent)\.get',
                    "Medium",
                    "Setting intent data from another intent (potential redirect)"
                ),
            ]

            for rid, rx, sev, desc in unsafe_patterns:
                for m in re.finditer(rx, text, re.IGNORECASE):
                    snippet = text[max(0, m.start() - 30):m.end() + 50].replace("\n", " ")
                    rows.append({
                        "Source": "pending_intent",
                        "RuleID": rid,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": sev,
                        "HowFound": "Regex scan"
                    })

        # Summary finding
        if pending_intents_found > 0:
            rows.append({
                "Source": "pending_intent",
                "RuleID": "PI_SUMMARY",
                "Title": f"Found {pending_intents_found} PendingIntent creation(s)",
                "Location": "Codebase-wide",
                "Evidence": f"Manual review recommended for all PendingIntent usages",
                "Severity": "Info",
                "HowFound": "Count"
            })

        # Write output
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        print(f"Wrote {out} ({len(rows)} findings, {files_scanned} files scanned, {pending_intents_found} PendingIntents analyzed)")

    except Exception as e:
        print(f"[!] Error in scan_pending_intents: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
