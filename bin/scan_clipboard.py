#!/usr/bin/env python3
"""
Clipboard Security Scanner v1.0

Detects insecure clipboard usage that can leak sensitive data to malicious apps.
On Android < 10, any app can read clipboard content. On Android 10+, only the
foreground app or default input method can access clipboard.

Checks for:
- Sensitive data copied to clipboard
- ClipboardManager.setPrimaryClip() with passwords/tokens
- Missing EXTRA_IS_SENSITIVE flag
- Clipboard data access patterns

References:
- https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0005/
- https://developer.android.com/develop/ui/views/touch-and-input/copy-paste
- https://cwe.mitre.org/data/definitions/200.html

OWASP Alignment: MASVS-STORAGE-2
CWE: CWE-200 (Information Exposure)
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
    "password", "passwd", "pwd", "secret", "token", "auth", "key",
    "credential", "session", "cookie", "pin", "otp", "code",
    "ssn", "credit", "card", "cvv", "account", "private"
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


# Clipboard patterns
CLIPBOARD_PATTERNS = [
    # High: setPrimaryClip with sensitive data
    (
        r"(?:" + "|".join(SENSITIVE_KEYWORDS) + r")[^;]*setPrimaryClip\s*\(",
        "CLIP_SENSITIVE_SET",
        "High",
        "Sensitive Data Copied to Clipboard",
        "Sensitive data copied to clipboard - accessible by other apps on Android < 10",
    ),
    # High: ClipData.newPlainText with sensitive variable
    (
        r"ClipData\.newPlainText\s*\([^)]*(?:" + "|".join(SENSITIVE_KEYWORDS[:10]) + r")",
        "CLIP_PLAINTEXT_SENSITIVE",
        "High",
        "Sensitive PlainText in ClipData",
        "Sensitive data in ClipData.newPlainText() - use secure alternatives",
    ),
    # High: setPrimaryClip without EXTRA_IS_SENSITIVE
    (
        r"setPrimaryClip\s*\([^)]+\)(?![\s\S]{0,200}EXTRA_IS_SENSITIVE)",
        "CLIP_NO_SENSITIVE_FLAG",
        "Medium",
        "setPrimaryClip() Without Sensitive Flag",
        "Missing ClipDescription.EXTRA_IS_SENSITIVE for sensitive data",
    ),
    # Medium: General clipboard write
    (
        r"ClipboardManager[^;]*\.setPrimaryClip\s*\(",
        "CLIP_SET_PRIMARY",
        "Low",
        "ClipboardManager.setPrimaryClip() Usage",
        "Clipboard write detected - verify no sensitive data",
    ),
    # Medium: ClipData creation
    (
        r"ClipData\.(?:newPlainText|newHtmlText|newUri|newIntent)\s*\(",
        "CLIP_DATA_CREATE",
        "Low",
        "ClipData Creation",
        "ClipData created - review content for sensitive data",
    ),
    # Medium: Clipboard read (may indicate sensitive data handling)
    (
        r"ClipboardManager[^;]*\.getPrimaryClip\s*\(\s*\)",
        "CLIP_GET_PRIMARY",
        "Low",
        "ClipboardManager.getPrimaryClip() Usage",
        "Clipboard read detected - data may come from other apps",
    ),
    # High: Clipboard with Intent (can contain sensitive extras)
    (
        r"ClipData\.newIntent\s*\([^)]+Intent",
        "CLIP_INTENT_DATA",
        "Medium",
        "Intent Data in Clipboard",
        "Intent copied to clipboard - may contain sensitive extras",
    ),
    # Good: EXTRA_IS_SENSITIVE used
    (
        r"EXTRA_IS_SENSITIVE|ClipDescription\.EXTRA_IS_SENSITIVE",
        "CLIP_SENSITIVE_FLAG",
        "Info",
        "EXTRA_IS_SENSITIVE Flag Used",
        "Good: Clipboard marked as sensitive (Android 13+)",
    ),
    # High: Clipboard listener (can monitor clipboard changes)
    (
        r"addPrimaryClipChangedListener\s*\(",
        "CLIP_LISTENER",
        "Medium",
        "Clipboard Change Listener",
        "App monitors clipboard changes - privacy concern",
    ),
]

# Smali patterns
SMALI_PATTERNS = [
    # setPrimaryClip in smali
    (
        r"invoke-virtual\s*\{[^}]+\},\s*Landroid/content/ClipboardManager;->setPrimaryClip",
        "CLIP_SMALI_SET",
        "Medium",
        "ClipboardManager.setPrimaryClip() (Smali)",
        "Clipboard write in smali - review data content",
    ),
    # getPrimaryClip in smali
    (
        r"invoke-virtual\s*\{[^}]+\},\s*Landroid/content/ClipboardManager;->getPrimaryClip",
        "CLIP_SMALI_GET",
        "Low",
        "ClipboardManager.getPrimaryClip() (Smali)",
        "Clipboard read in smali",
    ),
]


def scan_for_clipboard_issues(src_dir: str) -> list[dict]:
    """Scan source code for clipboard security issues."""
    findings = []
    seen = set()

    has_sensitive_flag = False
    clipboard_writes = 0

    # Compile patterns
    compiled_patterns = []
    for pattern, rule_id, severity, title, description in CLIPBOARD_PATTERNS:
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

                    if rule_id == "CLIP_SENSITIVE_FLAG":
                        has_sensitive_flag = True
                    elif "SET" in rule_id:
                        clipboard_writes += 1

                    findings.append({
                        "Source": "clipboard",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    # Summary
    if clipboard_writes > 0:
        high_count = sum(1 for f in findings if f["Severity"] == "High")
        findings.append({
            "Source": "clipboard",
            "RuleID": "CLIP_SUMMARY",
            "Title": "Clipboard Analysis Summary",
            "Location": "Application",
            "Evidence": f"{clipboard_writes} clipboard writes, {high_count} high severity findings",
            "Severity": "Info",
            "HowFound": f"EXTRA_IS_SENSITIVE used: {has_sensitive_flag}",
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

    findings = scan_for_clipboard_issues(src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
