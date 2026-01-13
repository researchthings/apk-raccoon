#!/usr/bin/env python3
"""Scan for Tapjacking (Overlay Attack) vulnerabilities.

Detects susceptibility to tapjacking attacks where malicious apps display
transparent overlays to capture user taps intended for legitimate apps.

Checks:
    - Missing filterTouchesWhenObscured on sensitive views
    - Missing FLAG_SECURE on sensitive activities
    - SYSTEM_ALERT_WINDOW permission usage
    - Overlay detection implementations

OWASP MASTG Coverage:
    - MASTG-TEST-0062: Testing for Tapjacking

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

# Sensitive activity keywords that should have tapjacking protection
SENSITIVE_ACTIVITY_KEYWORDS = [
    "login", "auth", "password", "payment", "checkout", "transfer",
    "confirm", "verify", "otp", "pin", "biometric", "fingerprint",
    "bank", "wallet", "settings", "permission", "consent", "grant",
]


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


def get_android_attr(elem: ET.Element, attr: str) -> str | None:
    """Get Android namespace attribute value from XML element.

    Args:
        elem: XML element to query.
        attr: Attribute name without namespace prefix.

    Returns:
        Attribute value if found, None otherwise.
    """
    return elem.get(f"{{{ANDROID_NS}}}{attr}")


def iter_source_files(src_dir: str, extensions: set[str]) -> Iterator[tuple[str, str]]:
    """Iterate over source files, yielding path and content.

    Args:
        src_dir: Directory containing source files to scan.
        extensions: Set of file extensions to include (e.g., {'.java', '.xml'}).

    Yields:
        Tuples of (file_path, file_content) for each matching file.
    """
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


def is_sensitive_activity(name: str) -> bool:
    """Check if activity name suggests sensitive functionality.

    Args:
        name: Activity class name to check.

    Returns:
        True if the activity name contains sensitive keywords.
    """
    name_lower = name.lower()
    return any(keyword in name_lower for keyword in SENSITIVE_ACTIVITY_KEYWORDS)


def check_manifest_permissions(root: ET.Element, findings: list[dict]) -> None:
    """Check for overlay-related permissions.

    Args:
        root: Root XML element of AndroidManifest.xml.
        findings: List to append findings to (modified in place).
    """
    for uses_perm in root.findall("uses-permission"):
        perm_name = get_android_attr(uses_perm, "name")
        if perm_name == "android.permission.SYSTEM_ALERT_WINDOW":
            findings.append({
                "Source": "tapjacking",
                "RuleID": "TAP_OVERLAY_PERMISSION",
                "Title": "App Requests Overlay Permission",
                "Location": "AndroidManifest.xml",
                "Evidence": "SYSTEM_ALERT_WINDOW permission requested",
                "Severity": "Medium",
                "HowFound": "App can draw over other apps - review usage context",
            })


def check_activities_for_tapjacking(root: ET.Element, findings: list[dict]) -> None:
    """Check activities for tapjacking vulnerability indicators.

    Args:
        root: Root XML element of AndroidManifest.xml.
        findings: List to append findings to (modified in place).
    """
    app_elem = root.find("application")
    if app_elem is None:
        return

    sensitive_activities = []

    for activity in app_elem.findall("activity"):
        name = get_android_attr(activity, "name") or "Unknown"
        exported = get_android_attr(activity, "exported")

        # Track sensitive activities
        if is_sensitive_activity(name):
            sensitive_activities.append(name)

            # Exported sensitive activities are higher risk
            if exported == "true":
                findings.append({
                    "Source": "tapjacking",
                    "RuleID": "TAP_SENSITIVE_EXPORTED",
                    "Title": f"Sensitive Exported Activity: {name}",
                    "Location": name,
                    "Evidence": f"Activity appears sensitive and is exported=true",
                    "Severity": "High",
                    "HowFound": "Sensitive exported activity - ensure tapjacking protection",
                })

    if sensitive_activities:
        findings.append({
            "Source": "tapjacking",
            "RuleID": "TAP_SENSITIVE_ACTIVITIES",
            "Title": f"Found {len(sensitive_activities)} Potentially Sensitive Activities",
            "Location": "AndroidManifest.xml",
            "Evidence": truncate(", ".join(sensitive_activities)),
            "Severity": "Info",
            "HowFound": "These activities should implement tapjacking protections",
        })


# Code patterns for tapjacking protection and vulnerability
TAPJACKING_PATTERNS = [
    # Good: filterTouchesWhenObscured protection
    (
        r"filterTouchesWhenObscured\s*=\s*[\"']?true",
        "TAP_FILTER_TOUCHES_ENABLED",
        "Info",
        "Tapjacking Protection: filterTouchesWhenObscured",
        "Good: View protected against tapjacking with filterTouchesWhenObscured",
    ),
    # Good: setFilterTouchesWhenObscured in code
    (
        r"\.setFilterTouchesWhenObscured\s*\(\s*true\s*\)",
        "TAP_FILTER_TOUCHES_CODE",
        "Info",
        "Tapjacking Protection: setFilterTouchesWhenObscured()",
        "Good: Programmatic tapjacking protection enabled",
    ),
    # Good: FLAG_SECURE usage
    (
        r"FLAG_SECURE|WindowManager\.LayoutParams\.FLAG_SECURE",
        "TAP_FLAG_SECURE",
        "Info",
        "Screen Capture Protection: FLAG_SECURE",
        "Good: Activity protected against screen capture/overlay",
    ),
    # Good: Overlay detection
    (
        r"onFilterTouchEventForSecurity|FLAG_WINDOW_IS_OBSCURED",
        "TAP_OVERLAY_DETECTION",
        "Info",
        "Overlay Detection Implementation",
        "Good: App implements overlay/obscured touch detection",
    ),
    # Bad: Explicitly disabling filter touches
    (
        r"\.setFilterTouchesWhenObscured\s*\(\s*false\s*\)",
        "TAP_FILTER_DISABLED",
        "High",
        "Tapjacking Protection Explicitly Disabled",
        "filterTouchesWhenObscured explicitly set to false",
    ),
    # Potential: Touch handling without security check
    (
        r"onTouchEvent\s*\([^)]*\)(?!.*onFilterTouchEventForSecurity)",
        "TAP_UNPROTECTED_TOUCH",
        "Low",
        "Touch Handler Without Security Filter",
        "onTouchEvent without overlay security check - review for sensitive operations",
    ),
]

# Layout patterns to check
LAYOUT_PATTERNS = [
    # Sensitive button without tapjacking protection
    (
        r"<Button[^>]*android:text=\"[^\"]*(?:confirm|submit|pay|login|transfer|authorize)[^\"]*\"[^>]*(?!filterTouchesWhenObscured)",
        "TAP_SENSITIVE_BUTTON",
        "Medium",
        "Sensitive Button Without filterTouchesWhenObscured",
        "Sensitive button should have filterTouchesWhenObscured=true",
    ),
    # EditText for password without protection
    (
        r"<EditText[^>]*android:inputType=\"[^\"]*(?:textPassword|numberPassword)[^\"]*\"[^>]*(?!filterTouchesWhenObscured)",
        "TAP_PASSWORD_FIELD",
        "Medium",
        "Password Field Without Tapjacking Protection",
        "Password input should have filterTouchesWhenObscured=true",
    ),
]


def scan_code_for_tapjacking(src_dir: str) -> list[dict]:
    """Scan source code for tapjacking patterns.

    Args:
        src_dir: Directory containing decompiled source files.

    Returns:
        List of finding dictionaries for tapjacking patterns.
    """
    findings = []
    seen = set()

    # Compile code patterns
    compiled_code = []
    for pattern, rule_id, severity, title, description in TAPJACKING_PATTERNS:
        try:
            compiled_code.append(
                (re.compile(pattern, re.IGNORECASE | re.MULTILINE), rule_id, severity, title, description)
            )
        except re.error:
            continue

    # Scan Java/Kotlin files
    for filepath, content in iter_source_files(src_dir, {".java", ".kt", ".smali"}):
        for regex, rule_id, severity, title, description in compiled_code:
            for match in regex.finditer(content):
                evidence = match.group(0)
                key = (rule_id, filepath, evidence[:30])
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "Source": "tapjacking",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    return findings


def scan_layouts_for_tapjacking(src_dir: str) -> list[dict]:
    """Scan layout XML files for tapjacking vulnerabilities.

    Args:
        src_dir: Directory containing layout XML files.

    Returns:
        List of finding dictionaries for layout vulnerabilities.
    """
    findings = []
    seen = set()

    # Compile layout patterns
    compiled_layout = []
    for pattern, rule_id, severity, title, description in LAYOUT_PATTERNS:
        try:
            compiled_layout.append(
                (re.compile(pattern, re.IGNORECASE | re.DOTALL), rule_id, severity, title, description)
            )
        except re.error:
            continue

    # Scan XML layout files
    for filepath, content in iter_source_files(src_dir, {".xml"}):
        # Only check layout files
        if "/layout" not in filepath and "\\layout" not in filepath:
            continue

        for regex, rule_id, severity, title, description in compiled_layout:
            for match in regex.finditer(content):
                evidence = match.group(0)
                key = (rule_id, filepath, evidence[:30])
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "Source": "tapjacking",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    return findings


def check_target_sdk(root: ET.Element, findings: list[dict]) -> None:
    """Check target SDK for tapjacking-related behavior changes.

    Args:
        root: Root XML element of AndroidManifest.xml.
        findings: List to append findings to (modified in place).
    """
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        target_sdk = get_android_attr(uses_sdk, "targetSdkVersion")
        if target_sdk:
            try:
                sdk = int(target_sdk)
                # Android 12 (API 31) added stricter overlay restrictions
                if sdk < 31:
                    findings.append({
                        "Source": "tapjacking",
                        "RuleID": "TAP_OLD_TARGET_SDK",
                        "Title": f"Target SDK < 31 (targetSdk={sdk})",
                        "Location": "AndroidManifest.xml",
                        "Evidence": f"targetSdkVersion={sdk}",
                        "Severity": "Low",
                        "HowFound": "Android 12+ has stricter overlay restrictions - consider upgrading",
                    })
            except ValueError:
                pass


def scan_for_tapjacking(manifest_path: str, src_dir: str | None = None) -> list[dict]:
    """Scan for tapjacking vulnerabilities.

    Args:
        manifest_path: Path to AndroidManifest.xml file.
        src_dir: Optional path to source directory for code analysis.

    Returns:
        List of finding dictionaries with vulnerability details.
    """
    findings = []

    # Parse manifest
    root = parse_manifest(manifest_path)
    if root is None:
        findings.append({
            "Source": "tapjacking",
            "RuleID": "TAP_MANIFEST_PARSE_ERROR",
            "Title": "Could Not Parse Manifest",
            "Location": manifest_path,
            "Evidence": "Failed to parse AndroidManifest.xml",
            "Severity": "Info",
            "HowFound": "Manifest parsing failed",
        })
        return findings

    # Check manifest
    check_manifest_permissions(root, findings)
    check_activities_for_tapjacking(root, findings)
    check_target_sdk(root, findings)

    # Scan code
    if src_dir:
        code_findings = scan_code_for_tapjacking(src_dir)
        findings.extend(code_findings)

        layout_findings = scan_layouts_for_tapjacking(src_dir)
        findings.extend(layout_findings)

    # Analyze protection status
    has_filter_touches = any(f["RuleID"] in ("TAP_FILTER_TOUCHES_ENABLED", "TAP_FILTER_TOUCHES_CODE") for f in findings)
    has_flag_secure = any(f["RuleID"] == "TAP_FLAG_SECURE" for f in findings)
    has_sensitive = any(f["RuleID"] == "TAP_SENSITIVE_ACTIVITIES" for f in findings)

    if has_sensitive and not has_filter_touches and not has_flag_secure:
        findings.append({
            "Source": "tapjacking",
            "RuleID": "TAP_NO_PROTECTION",
            "Title": "No Tapjacking Protection Found",
            "Location": "Application",
            "Evidence": "Sensitive activities detected but no filterTouchesWhenObscured or FLAG_SECURE found",
            "Severity": "High",
            "HowFound": "Add filterTouchesWhenObscured=true to sensitive views and FLAG_SECURE to sensitive activities",
        })

    # Summary
    high_count = sum(1 for f in findings if f["Severity"] == "High")
    medium_count = sum(1 for f in findings if f["Severity"] == "Medium")

    findings.append({
        "Source": "tapjacking",
        "RuleID": "TAP_SUMMARY",
        "Title": "Tapjacking Analysis Summary",
        "Location": "Application",
        "Evidence": f"{high_count} high, {medium_count} medium severity issues",
        "Severity": "Info",
        "HowFound": f"Protection status: filterTouches={has_filter_touches}, FLAG_SECURE={has_flag_secure}",
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
    """Scan for tapjacking vulnerabilities and write findings to CSV.

    Command line args:
        sys.argv[1]: Path to AndroidManifest.xml
        sys.argv[2]: Output CSV path
        sys.argv[3]: Optional path to source directory

    Raises:
        SystemExit: If required arguments are missing.
    """
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <manifest.xml> <output.csv> [src_dir]", file=sys.stderr)
        sys.exit(1)

    manifest_path = sys.argv[1]
    output_path = sys.argv[2]
    src_dir = sys.argv[3] if len(sys.argv) > 3 else None

    findings = scan_for_tapjacking(manifest_path, src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
