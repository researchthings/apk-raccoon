#!/usr/bin/env python3
"""
Keyboard Cache Security Scanner v1.0

Detects input fields that may cache sensitive data in keyboard dictionaries.
Keyboards often cache typed text for autocomplete/prediction, which can leak
sensitive data like passwords, credit cards, or PII.

Checks for:
- Password fields without textNoSuggestions flag
- Sensitive EditText without proper inputType
- Missing android:inputType attributes on sensitive fields
- Custom keyboard usage patterns

References:
- https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0006/
- https://developer.android.com/reference/android/text/InputType
- https://cwe.mitre.org/data/definitions/524.html

OWASP Alignment: MASVS-STORAGE-2
CWE: CWE-524 (Use of Cache Containing Sensitive Information)
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


def iter_source_files(src_dir: str, extensions: set[str]) -> Iterator[tuple[str, str]]:
    """Iterate over source files, yielding (path, content)."""
    src_path = Path(src_dir)
    if not src_path.exists():
        return

    for p in src_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in extensions:
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                yield str(p), content
            except Exception:
                continue


# Sensitive field identifiers
SENSITIVE_IDS = [
    "password", "passwd", "pwd", "pin", "otp", "secret",
    "ssn", "social", "credit", "card", "cvv", "ccv",
    "account", "routing", "bank", "token", "auth"
]

# Layout XML patterns
LAYOUT_PATTERNS = [
    # High: Password field without textNoSuggestions
    (
        r"<EditText[^>]*android:inputType=\"[^\"]*textPassword[^\"]*\"[^>]*(?!textNoSuggestions)",
        "KEY_PASSWORD_NO_SUGGESTIONS",
        "Medium",
        "Password Field Without textNoSuggestions",
        "Password field may cache input - add textNoSuggestions flag",
    ),
    # High: Sensitive ID without proper inputType
    (
        r"<EditText[^>]*android:id=\"[^\"]*(?:" + "|".join(SENSITIVE_IDS[:8]) + r")[^\"]*\"[^>]*(?!android:inputType)",
        "KEY_SENSITIVE_NO_INPUTTYPE",
        "High",
        "Sensitive Field Without inputType",
        "Sensitive field without inputType - keyboard may cache input",
    ),
    # Medium: Number field (may be PIN/card) without flag
    (
        r"<EditText[^>]*android:inputType=\"number[^\"]*\"[^>]*android:id=\"[^\"]*(?:pin|otp|cvv|card)",
        "KEY_NUMBER_SENSITIVE",
        "Medium",
        "Numeric Sensitive Field",
        "Numeric field with sensitive ID - verify no keyboard caching",
    ),
    # Good: textNoSuggestions flag present
    (
        r"android:inputType=\"[^\"]*textNoSuggestions[^\"]*\"",
        "KEY_NO_SUGGESTIONS",
        "Info",
        "textNoSuggestions Flag Present",
        "Good: textNoSuggestions prevents keyboard caching",
    ),
    # Good: textVisiblePassword (no suggestions by default)
    (
        r"android:inputType=\"[^\"]*textVisiblePassword[^\"]*\"",
        "KEY_VISIBLE_PASSWORD",
        "Info",
        "textVisiblePassword Used",
        "textVisiblePassword typically disables suggestions",
    ),
    # High: Autocomplete hint on sensitive field
    (
        r"<EditText[^>]*android:autofillHints=\"(?:password|creditCardNumber)[^\"]*\"[^>]*(?!textNoSuggestions)",
        "KEY_AUTOFILL_SENSITIVE",
        "Low",
        "Sensitive Autofill Without Suggestions Flag",
        "Autofill hints present - ensure keyboard caching disabled",
    ),
]

# Java/Kotlin code patterns
CODE_PATTERNS = [
    # High: setInputType without NO_SUGGESTIONS for sensitive
    (
        r"(?:password|pin|otp|secret)[^;]*\.setInputType\s*\([^)]*TYPE_TEXT[^)]*\)(?!.*TYPE_TEXT_FLAG_NO_SUGGESTIONS)",
        "KEY_CODE_NO_SUGGESTIONS",
        "High",
        "Sensitive Field setInputType Without NO_SUGGESTIONS",
        "Add InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS to prevent caching",
    ),
    # Medium: EditText with sensitive hint but no inputType restriction
    (
        r"\.setHint\s*\([^)]*(?:password|pin|secret|card)[^)]*\)(?![\s\S]{0,200}setInputType)",
        "KEY_HINT_NO_INPUTTYPE",
        "Medium",
        "Sensitive Hint Without InputType",
        "Sensitive hint text but no inputType set - may cache input",
    ),
    # Good: TYPE_TEXT_FLAG_NO_SUGGESTIONS used
    (
        r"TYPE_TEXT_FLAG_NO_SUGGESTIONS|InputType\.TYPE_TEXT_FLAG_NO_SUGGESTIONS",
        "KEY_FLAG_NO_SUGGESTIONS",
        "Info",
        "NO_SUGGESTIONS Flag in Code",
        "Good: TYPE_TEXT_FLAG_NO_SUGGESTIONS used",
    ),
    # Medium: setRawInputType without suggestions check
    (
        r"setRawInputType\s*\([^)]*(?:password|number)",
        "KEY_RAW_INPUT_SENSITIVE",
        "Medium",
        "setRawInputType with Sensitive Type",
        "Raw input type set - verify suggestions disabled",
    ),
    # Info: Custom IME connection (advanced usage)
    (
        r"onCreateInputConnection|InputConnection",
        "KEY_CUSTOM_IME",
        "Low",
        "Custom Input Connection",
        "Custom IME handling - review for secure input",
    ),
]

# Smali patterns
SMALI_PATTERNS = [
    # setInputType in smali
    (
        r"invoke-virtual\s*\{[^}]+\},\s*Landroid/widget/EditText;->setInputType\(I\)V",
        "KEY_SMALI_INPUTTYPE",
        "Low",
        "EditText.setInputType() (Smali)",
        "InputType set in smali - verify NO_SUGGESTIONS flag",
    ),
]


def scan_for_keyboard_cache(src_dir: str) -> list[dict]:
    """Scan for keyboard cache vulnerabilities."""
    findings = []
    seen = set()

    has_no_suggestions = False
    sensitive_fields = 0

    # Scan layout XMLs
    compiled_layout = []
    for pattern, rule_id, severity, title, description in LAYOUT_PATTERNS:
        try:
            compiled_layout.append(
                (re.compile(pattern, re.IGNORECASE | re.DOTALL), rule_id, severity, title, description)
            )
        except re.error:
            continue

    for filepath, content in iter_source_files(src_dir, {".xml"}):
        if "/layout" not in filepath and "\\layout" not in filepath:
            continue

        for regex, rule_id, severity, title, description in compiled_layout:
            for match in regex.finditer(content):
                evidence = match.group(0)
                key = (rule_id, filepath, evidence[:50])

                if key not in seen:
                    seen.add(key)

                    if rule_id in ("KEY_NO_SUGGESTIONS", "KEY_VISIBLE_PASSWORD"):
                        has_no_suggestions = True
                    elif severity in ("High", "Medium"):
                        sensitive_fields += 1

                    findings.append({
                        "Source": "keyboard_cache",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    # Scan Java/Kotlin code
    compiled_code = []
    for pattern, rule_id, severity, title, description in CODE_PATTERNS:
        try:
            compiled_code.append(
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

    for filepath, content in iter_source_files(src_dir, {".java", ".kt", ".smali"}):
        is_smali = filepath.endswith(".smali")
        patterns_to_use = compiled_smali if is_smali else compiled_code

        for regex, rule_id, severity, title, description in patterns_to_use:
            for match in regex.finditer(content):
                evidence = match.group(0)
                key = (rule_id, filepath, evidence[:50])

                if key not in seen:
                    seen.add(key)

                    if rule_id == "KEY_FLAG_NO_SUGGESTIONS":
                        has_no_suggestions = True
                    elif severity in ("High", "Medium"):
                        sensitive_fields += 1

                    findings.append({
                        "Source": "keyboard_cache",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    # Summary
    if sensitive_fields > 0:
        high_count = sum(1 for f in findings if f["Severity"] == "High")
        findings.append({
            "Source": "keyboard_cache",
            "RuleID": "KEY_SUMMARY",
            "Title": "Keyboard Cache Analysis Summary",
            "Location": "Application",
            "Evidence": f"{sensitive_fields} sensitive fields, {high_count} high severity findings",
            "Severity": "Info",
            "HowFound": f"NO_SUGGESTIONS protection found: {has_no_suggestions}",
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

    findings = scan_for_keyboard_cache(src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
