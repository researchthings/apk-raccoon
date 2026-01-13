#!/usr/bin/env python3
"""Scan for Fragment Injection vulnerabilities.

Detects fragment injection vulnerabilities where malicious apps can inject
arbitrary fragments into exported PreferenceActivity or similar activities.

Checks:
    - PreferenceActivity without isValidFragment() override (CVE-2014-8609)
    - Fragment.instantiate() with untrusted input
    - getIntent().getStringExtra() used for fragment class names
    - Exported activities accepting fragment parameters

OWASP MASTG Coverage:
    - MASTG-TEST-0029: Testing for Fragment Injection

Author: Randy Grant
Date: 01-09-2026
Version: 1.0
"""

from __future__ import annotations

import csv
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

# CSV output schema
CSV_FIELDNAMES = ["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"]

# Android namespace
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def truncate(s: str, max_len: int = 150) -> str:
    """Truncate string for CSV evidence field.

    Args:
        s: The string to truncate.
        max_len: Maximum length before truncation.

    Returns:
        Truncated string with ellipsis if needed, newlines removed.
    """
    s = s.replace("\n", " ").replace("\r", "").strip()
    return s[:max_len] + "..." if len(s) > max_len else s


def get_android_attr(elem: ET.Element, attr: str) -> str | None:
    """Get Android namespace attribute value from XML element.

    Args:
        elem: XML element to query.
        attr: Attribute name without namespace prefix.

    Returns:
        Attribute value if found, None otherwise.
    """
    return elem.get(f"{{{ANDROID_NS}}}{attr}")


def iter_source_files(src_dir: str) -> Iterator[tuple[str, str]]:
    """Iterate over source files, yielding path and content.

    Args:
        src_dir: Directory containing source files to scan.

    Yields:
        Tuples of (file_path, file_content) for each matching file.
    """
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


def parse_manifest(manifest_path: str) -> ET.Element | None:
    """Parse AndroidManifest.xml and return root element.

    Args:
        manifest_path: Path to AndroidManifest.xml file.

    Returns:
        Root XML element if parsing succeeds, None on failure.
    """
    try:
        ET.register_namespace("android", ANDROID_NS)
        tree = ET.parse(manifest_path)
        return tree.getroot()
    except Exception as e:
        print(f"[!] Warning: Could not parse manifest: {e}", file=sys.stderr)
        return None


# Fragment injection patterns in code
FRAGMENT_PATTERNS = [
    # Critical: PreferenceActivity without isValidFragment
    (
        r"class\s+\w+\s+extends\s+PreferenceActivity(?![\s\S]*isValidFragment)",
        "FRAG_PREF_ACTIVITY_VULNERABLE",
        "High",
        "PreferenceActivity Without isValidFragment()",
        "PreferenceActivity must override isValidFragment() to prevent injection (API 19+)",
    ),
    # High: isValidFragment returning true for all
    (
        r"(?:protected|public)\s+boolean\s+isValidFragment\s*\([^)]*\)\s*\{[^}]*return\s+true\s*;",
        "FRAG_ISVALID_ALWAYS_TRUE",
        "High",
        "isValidFragment() Always Returns True",
        "isValidFragment() should validate fragment class names against allowlist",
    ),
    # High: Fragment.instantiate with dynamic class name
    (
        r"Fragment\.instantiate\s*\([^,]+,\s*(?:getIntent\(\)|intent)\.[^,]+",
        "FRAG_INSTANTIATE_INTENT",
        "High",
        "Fragment.instantiate() with Intent Data",
        "Fragment class from Intent can be controlled by attacker",
    ),
    # High: getFragmentManager with dynamic fragment
    (
        r"getIntent\s*\(\s*\)\s*\.\s*get(?:String|Parcelable)Extra\s*\([^)]*fragment",
        "FRAG_INTENT_FRAGMENT_EXTRA",
        "High",
        "Fragment Class from Intent Extra",
        "Fragment name from Intent extra - validate against allowlist",
    ),
    # High: FragmentTransaction with class from string
    (
        r"Class\.forName\s*\([^)]+\)[^;]*\.asSubclass\s*\(\s*Fragment\.class",
        "FRAG_CLASS_FORNAME",
        "High",
        "Fragment from Class.forName()",
        "Dynamic fragment loading via reflection - validate class name",
    ),
    # Medium: instantiate with string variable
    (
        r"Fragment\.instantiate\s*\([^,]+,\s*[a-zA-Z_]\w*\s*[,)]",
        "FRAG_INSTANTIATE_VARIABLE",
        "Medium",
        "Fragment.instantiate() with Variable",
        "Review source of fragment class name variable",
    ),
    # Medium: getFragment from FragmentManager
    (
        r"getFragmentManager\s*\(\s*\)\s*\.findFragmentByTag\s*\(\s*getIntent",
        "FRAG_FIND_BY_INTENT",
        "Medium",
        "findFragmentByTag() with Intent Data",
        "Fragment tag from Intent - review validation",
    ),
    # Info: AppCompatPreferenceActivity (also affected)
    (
        r"class\s+\w+\s+extends\s+AppCompatPreferenceActivity(?![\s\S]*isValidFragment)",
        "FRAG_APPCOMPAT_PREF",
        "High",
        "AppCompatPreferenceActivity Without isValidFragment()",
        "AppCompatPreferenceActivity also vulnerable to fragment injection",
    ),
    # Good: Proper isValidFragment implementation
    (
        r"isValidFragment\s*\([^)]*\)\s*\{[^}]*\.equals\s*\(\s*[^)]+\.class\.getName",
        "FRAG_ISVALID_PROPER",
        "Info",
        "Proper isValidFragment() Implementation",
        "Good: isValidFragment validates against specific fragment classes",
    ),
]

# Smali patterns
SMALI_PATTERNS = [
    # PreferenceActivity in smali
    (
        r"\.super\s+Landroid/preference/PreferenceActivity;",
        "FRAG_SMALI_PREF_ACTIVITY",
        "Medium",
        "PreferenceActivity Subclass (Smali)",
        "PreferenceActivity in smali - check for isValidFragment override",
    ),
    # Fragment.instantiate in smali
    (
        r"invoke-static\s*\{[^}]+\},\s*Landroid/(?:app|support/v4/app)/Fragment;->instantiate",
        "FRAG_SMALI_INSTANTIATE",
        "Medium",
        "Fragment.instantiate() Call (Smali)",
        "Fragment instantiation in smali - review class name source",
    ),
]


def check_manifest_for_fragment_activities(manifest_path: str) -> list[dict]:
    """Check manifest for exported activities that might be vulnerable.

    Args:
        manifest_path: Path to AndroidManifest.xml file.

    Returns:
        List of finding dictionaries for preference-like exported activities.
    """
    findings = []

    root = parse_manifest(manifest_path)
    if root is None:
        return findings

    app_elem = root.find("application")
    if app_elem is None:
        return findings

    for activity in app_elem.findall("activity"):
        name = get_android_attr(activity, "name") or "Unknown"
        exported = get_android_attr(activity, "exported")

        # Check for intent filters (implicitly exported)
        has_intent_filter = len(activity.findall("intent-filter")) > 0

        # Check name for preference/settings activities
        name_lower = name.lower()
        is_likely_preference = any(kw in name_lower for kw in [
            "preference", "settings", "config", "option"
        ])

        if is_likely_preference:
            if exported == "true" or has_intent_filter:
                findings.append({
                    "Source": "fragment_injection",
                    "RuleID": "FRAG_EXPORTED_PREFERENCE",
                    "Title": f"Exported Preference-like Activity: {name}",
                    "Location": name,
                    "Evidence": f"exported={exported}, intent-filters={has_intent_filter}",
                    "Severity": "High",
                    "HowFound": "Exported preference activities may be vulnerable to fragment injection",
                })

    return findings


def scan_for_fragment_injection(src_dir: str, manifest_path: str | None = None) -> list[dict]:
    """Scan source code for fragment injection vulnerabilities.

    Args:
        src_dir: Directory containing decompiled source files.
        manifest_path: Optional path to AndroidManifest.xml file.

    Returns:
        List of finding dictionaries with vulnerability details.
    """
    findings = []
    seen = set()

    # Check manifest if provided
    if manifest_path:
        manifest_findings = check_manifest_for_fragment_activities(manifest_path)
        findings.extend(manifest_findings)

    # Compile patterns
    compiled_patterns = []
    for pattern, rule_id, severity, title, description in FRAGMENT_PATTERNS:
        try:
            compiled_patterns.append(
                (re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL), rule_id, severity, title, description)
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

    # Track vulnerable activities for cross-reference
    preference_activities = []
    has_isvalid_fragment = False

    for filepath, content in iter_source_files(src_dir):
        is_smali = filepath.endswith(".smali")
        patterns_to_use = compiled_smali if is_smali else compiled_patterns

        # Check if this file extends PreferenceActivity
        if not is_smali:
            if re.search(r"extends\s+(?:AppCompat)?PreferenceActivity", content, re.IGNORECASE):
                preference_activities.append(filepath)
                if re.search(r"isValidFragment\s*\(", content):
                    has_isvalid_fragment = True

        for regex, rule_id, severity, title, description in patterns_to_use:
            for match in regex.finditer(content):
                evidence = match.group(0)
                key = (rule_id, filepath, evidence[:50])

                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "Source": "fragment_injection",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    # Add summary if PreferenceActivity found without protection
    if preference_activities and not has_isvalid_fragment:
        findings.append({
            "Source": "fragment_injection",
            "RuleID": "FRAG_NO_VALIDATION",
            "Title": f"PreferenceActivity Without Fragment Validation ({len(preference_activities)} found)",
            "Location": ", ".join(Path(p).name for p in preference_activities[:3]),
            "Evidence": "No isValidFragment() override found in PreferenceActivity subclasses",
            "Severity": "High",
            "HowFound": "Override isValidFragment() and validate fragment class against allowlist",
        })

    # Summary
    critical_count = sum(1 for f in findings if f["Severity"] == "Critical")
    high_count = sum(1 for f in findings if f["Severity"] == "High")

    if findings:
        findings.append({
            "Source": "fragment_injection",
            "RuleID": "FRAG_SUMMARY",
            "Title": "Fragment Injection Analysis Summary",
            "Location": "Application",
            "Evidence": f"{critical_count} critical, {high_count} high severity findings",
            "Severity": "Info",
            "HowFound": f"PreferenceActivity count: {len(preference_activities)}, isValidFragment present: {has_isvalid_fragment}",
        })

    return findings


def write_findings_csv(output_path: str, findings: list[dict]) -> None:
    """Write findings to CSV file.

    Args:
        output_path: Path for the output CSV file.
        findings: List of finding dictionaries to write.
    """
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(findings)

    print(f"Wrote {len(findings)} finding(s) to {output_path}")


def main() -> None:
    """Scan for fragment injection vulnerabilities and write findings to CSV.

    Command line args:
        sys.argv[1]: Path to source directory
        sys.argv[2]: Output CSV path
        sys.argv[3]: Optional path to AndroidManifest.xml

    Raises:
        SystemExit: If required arguments are missing.
    """
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <src_dir> <output.csv> [manifest.xml]", file=sys.stderr)
        sys.exit(1)

    src_dir = sys.argv[1]
    output_path = sys.argv[2]
    manifest_path = sys.argv[3] if len(sys.argv) > 3 else None

    findings = scan_for_fragment_injection(src_dir, manifest_path)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
