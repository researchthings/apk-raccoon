#!/usr/bin/env python3
"""
Implicit Intent Leakage Scanner v1.0

Detects insecure use of implicit intents that can lead to:
- Sensitive data leakage to malicious apps
- Intent interception by rogue receivers
- Man-in-the-middle attacks on IPC
- Information disclosure via broadcast sniffing

Checks for:
- sendBroadcast() without permission or explicit receiver
- startActivity/startService with implicit intents
- Sensitive data in broadcast extras
- Missing setPackage() on intents with sensitive data

References:
- https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0009/
- https://developer.android.com/privacy-and-security/risks/implicit-intent
- https://cwe.mitre.org/data/definitions/927.html

OWASP Alignment: MASVS-PLATFORM-1, MASVS-PLATFORM-3
CWE: CWE-927 (Use of Implicit Intent for Sensitive Communication)
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

# Sensitive data keywords
SENSITIVE_KEYWORDS = [
    "password", "passwd", "pwd", "secret", "token", "auth", "api_key",
    "apikey", "credential", "session", "cookie", "user", "email",
    "phone", "ssn", "credit", "card", "account", "pin", "otp",
    "private", "key", "cert", "license", "payment"
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

    extensions = {".java", ".kt", ".smali"}

    for p in src_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in extensions:
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                yield str(p), content
            except Exception:
                continue


# Implicit intent patterns
IMPLICIT_INTENT_PATTERNS = [
    # High: sendBroadcast without permission (implicit)
    (
        r"sendBroadcast\s*\(\s*\w+\s*\)(?!\s*,)",
        "IMPL_BROADCAST_NO_PERM",
        "High",
        "sendBroadcast() Without Permission",
        "Implicit broadcast without permission - any app can receive",
    ),
    # High: sendOrderedBroadcast without permission
    (
        r"sendOrderedBroadcast\s*\(\s*\w+\s*,\s*null",
        "IMPL_ORDERED_NO_PERM",
        "High",
        "sendOrderedBroadcast() Without Permission",
        "Ordered broadcast with null permission - can be intercepted",
    ),
    # High: Intent without explicit component
    (
        r"new\s+Intent\s*\(\s*[\"'][^\"']+[\"']\s*\)(?![\s\S]{0,100}\.setComponent|\.setClass|\.setPackage)",
        "IMPL_INTENT_ACTION_ONLY",
        "Medium",
        "Intent with Action Only (No Component)",
        "Intent created with action only - may be intercepted by other apps",
    ),
    # High: startActivity with implicit intent
    (
        r"startActivity(?:ForResult)?\s*\(\s*new\s+Intent\s*\(\s*[\"']",
        "IMPL_START_ACTIVITY_IMPLICIT",
        "Medium",
        "startActivity() with Implicit Intent",
        "Starting activity with implicit intent - verify target app",
    ),
    # High: startService with implicit intent (deprecated)
    (
        r"startService\s*\(\s*new\s+Intent\s*\(\s*[\"']",
        "IMPL_START_SERVICE_IMPLICIT",
        "High",
        "startService() with Implicit Intent",
        "Implicit service start is insecure - use explicit intents",
    ),
    # High: bindService with implicit intent
    (
        r"bindService\s*\(\s*new\s+Intent\s*\(\s*[\"']",
        "IMPL_BIND_SERVICE_IMPLICIT",
        "High",
        "bindService() with Implicit Intent",
        "Implicit service binding is insecure - use explicit intents",
    ),
    # Medium: Intent.setAction without setPackage/setComponent
    (
        r"\.setAction\s*\([^)]+\)(?![\s\S]{0,100}\.setPackage|\.setComponent)",
        "IMPL_SETACTION_NO_PACKAGE",
        "Medium",
        "setAction() Without setPackage()",
        "Intent action set without package restriction",
    ),
    # High: sendBroadcast with putExtra containing sensitive data
    (
        r"\.putExtra\s*\([^)]*(?:" + "|".join(SENSITIVE_KEYWORDS) + r")[^)]*\)[^;]*sendBroadcast",
        "IMPL_SENSITIVE_BROADCAST",
        "Critical",
        "Sensitive Data in Broadcast",
        "Sensitive data sent via broadcast - can be intercepted",
    ),
    # High: Sensitive data in intent extras for implicit intent
    (
        r"Intent\s*\([^)]*\)[^;]*\.putExtra\s*\([^)]*(?:" + "|".join(SENSITIVE_KEYWORDS[:10]) + r")",
        "IMPL_SENSITIVE_EXTRA",
        "High",
        "Sensitive Data in Intent Extra",
        "Sensitive data in intent extra - verify recipient",
    ),
    # Good: Explicit intent creation
    (
        r"new\s+Intent\s*\(\s*\w+\s*,\s*\w+\.class\s*\)",
        "IMPL_EXPLICIT_INTENT",
        "Info",
        "Explicit Intent Creation",
        "Good: Explicit intent with target class",
    ),
    # Good: setPackage used
    (
        r"\.setPackage\s*\(\s*[\"'][^\"']+[\"']\s*\)",
        "IMPL_SET_PACKAGE",
        "Info",
        "Intent setPackage() Used",
        "Good: Intent package explicitly set",
    ),
    # Good: LocalBroadcastManager
    (
        r"LocalBroadcastManager[^;]*\.sendBroadcast",
        "IMPL_LOCAL_BROADCAST",
        "Info",
        "LocalBroadcastManager Used",
        "Good: LocalBroadcastManager is secure for internal broadcasts",
    ),
]

# Intent chooser patterns (may expose data to multiple apps)
CHOOSER_PATTERNS = [
    # Medium: Intent chooser with sensitive data
    (
        r"Intent\.createChooser\s*\([^)]+(?:" + "|".join(SENSITIVE_KEYWORDS[:5]) + r")",
        "IMPL_CHOOSER_SENSITIVE",
        "Medium",
        "Intent Chooser with Sensitive Data",
        "Chooser may expose data to multiple apps - user chooses target",
    ),
    # Info: Intent chooser (general)
    (
        r"Intent\.createChooser\s*\(",
        "IMPL_CHOOSER",
        "Low",
        "Intent Chooser Used",
        "Intent chooser presents multiple app options to user",
    ),
]

# Smali patterns
SMALI_PATTERNS = [
    # sendBroadcast in smali
    (
        r"invoke-virtual\s*\{[^}]+\},\s*Landroid/content/Context;->sendBroadcast\(Landroid/content/Intent;\)V",
        "IMPL_SMALI_BROADCAST",
        "High",
        "sendBroadcast() Without Permission (Smali)",
        "Implicit broadcast in smali - verify permission requirement",
    ),
    # startService in smali with Intent
    (
        r"invoke-virtual\s*\{[^}]+\},\s*Landroid/content/Context;->startService\(Landroid/content/Intent;\)",
        "IMPL_SMALI_START_SERVICE",
        "Medium",
        "startService() (Smali)",
        "Service start in smali - verify explicit intent usage",
    ),
]


def analyze_intent_context(content: str, match_pos: int) -> str:
    """Analyze the context around an intent usage to determine risk."""
    # Look for nearby setPackage/setComponent/setClass calls
    context_before = content[max(0, match_pos - 300):match_pos]
    context_after = content[match_pos:match_pos + 300]

    protections = []
    if re.search(r"\.setPackage\s*\(", context_before + context_after):
        protections.append("setPackage")
    if re.search(r"\.setComponent\s*\(", context_before + context_after):
        protections.append("setComponent")
    if re.search(r"\.setClass\s*\(", context_before + context_after):
        protections.append("setClass")
    if re.search(r",\s*[\"'][^\"']+[\"']\s*\)", context_after):
        protections.append("permission")

    return ", ".join(protections) if protections else "none"


def scan_for_implicit_intents(src_dir: str) -> list[dict]:
    """Scan source code for implicit intent vulnerabilities."""
    findings = []
    seen = set()

    # Track patterns
    implicit_count = 0
    explicit_count = 0

    all_patterns = IMPLICIT_INTENT_PATTERNS + CHOOSER_PATTERNS

    # Compile patterns
    compiled_patterns = []
    for pattern, rule_id, severity, title, description in all_patterns:
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

                    # Track explicit vs implicit
                    if rule_id in ("IMPL_EXPLICIT_INTENT", "IMPL_SET_PACKAGE", "IMPL_LOCAL_BROADCAST"):
                        explicit_count += 1
                    elif severity in ("Critical", "High", "Medium"):
                        implicit_count += 1

                    # Add protection context for high/critical findings
                    how_found = description
                    if severity in ("Critical", "High") and not is_smali:
                        protections = analyze_intent_context(content, match.start())
                        if protections != "none":
                            how_found = f"{description} (protections nearby: {protections})"
                            # Downgrade severity if protection found
                            if "setPackage" in protections or "setComponent" in protections:
                                severity = "Low"

                    findings.append({
                        "Source": "implicit_intents",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": how_found,
                    })

    # Summary
    critical_count = sum(1 for f in findings if f["Severity"] == "Critical")
    high_count = sum(1 for f in findings if f["Severity"] == "High")

    if implicit_count > 0:
        findings.append({
            "Source": "implicit_intents",
            "RuleID": "IMPL_SUMMARY",
            "Title": "Implicit Intent Analysis Summary",
            "Location": "Application",
            "Evidence": f"{critical_count} critical, {high_count} high severity findings",
            "Severity": "Info",
            "HowFound": f"Implicit: {implicit_count}, Explicit: {explicit_count} - Use explicit intents for sensitive data",
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

    findings = scan_for_implicit_intents(src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
