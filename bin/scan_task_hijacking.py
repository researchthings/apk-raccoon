#!/usr/bin/env python3
"""Scan for Task Hijacking (StrandHogg) vulnerabilities.

Detects Android task hijacking vulnerabilities (StrandHogg 1.0 and 2.0)
that allow malicious apps to hijack legitimate app tasks and present
counterfeit screens, tricking users into divulging sensitive information.

Checks:
    - Dangerous taskAffinity + launchMode combinations
    - Activities vulnerable to task injection
    - minSdkVersion < 30 without mitigations
    - allowTaskReparenting enabled

OWASP MASTG Coverage:
    - MASTG-TEST-0028: Testing for Task Hijacking
    - MASTG-TEST-0029: Testing for StrandHogg

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

# Dangerous launch modes for StrandHogg
DANGEROUS_LAUNCH_MODES = {"singleTask", "singleInstance"}


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
        manifest_path: Path to the AndroidManifest.xml file.

    Returns:
        Root Element of the parsed manifest, or None on error.
    """
    try:
        # Handle namespace
        ET.register_namespace("android", ANDROID_NS)
        tree = ET.parse(manifest_path)
        return tree.getroot()
    except Exception as e:
        print(f"[!] Warning: Could not parse manifest: {e}", file=sys.stderr)
        return None


def get_android_attr(elem: ET.Element, attr: str) -> str | None:
    """Get Android namespace attribute value from element.

    Args:
        elem: The XML element to query.
        attr: The attribute name without namespace prefix.

    Returns:
        The attribute value, or None if not found.
    """
    return elem.get(f"{{{ANDROID_NS}}}{attr}")


def get_min_sdk(root: ET.Element) -> int:
    """Extract minSdkVersion from manifest.

    Args:
        root: Root element of the parsed manifest.

    Returns:
        The minSdkVersion as integer, or 1 if not found.
    """
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        min_sdk = get_android_attr(uses_sdk, "minSdkVersion")
        if min_sdk:
            try:
                return int(min_sdk)
            except ValueError:
                pass
    return 1  # Default to very low


def get_target_sdk(root: ET.Element) -> int:
    """Extract targetSdkVersion from manifest.

    Args:
        root: Root element of the parsed manifest.

    Returns:
        The targetSdkVersion as integer, or 1 if not found.
    """
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        target_sdk = get_android_attr(uses_sdk, "targetSdkVersion")
        if target_sdk:
            try:
                return int(target_sdk)
            except ValueError:
                pass
    return 1


def check_activity_task_hijacking(activity: ET.Element, min_sdk: int, findings: list[dict]) -> None:
    """Check an activity element for task hijacking vulnerabilities.

    Args:
        activity: The activity XML element to analyze.
        min_sdk: The app's minimum SDK version.
        findings: List to append findings to (modified in place).
    """
    name = get_android_attr(activity, "name") or "Unknown"
    task_affinity = get_android_attr(activity, "taskAffinity")
    launch_mode = get_android_attr(activity, "launchMode")
    exported = get_android_attr(activity, "exported")
    allow_task_reparenting = get_android_attr(activity, "allowTaskReparenting")

    # Check for StrandHogg 1.0 vulnerability
    # Vulnerable if: taskAffinity is set (not empty) AND launchMode is singleTask/singleInstance
    if launch_mode in DANGEROUS_LAUNCH_MODES:
        # If taskAffinity is not explicitly empty, it inherits package name or custom value
        if task_affinity is None:
            # Default - inherits package name, still vulnerable with singleTask
            if min_sdk < 30:
                findings.append({
                    "Source": "task_hijacking",
                    "RuleID": "TASK_STRANDHOGG_V1",
                    "Title": f"StrandHogg 1.0 Vulnerable Activity: {name}",
                    "Location": name,
                    "Evidence": f"launchMode={launch_mode}, taskAffinity=default (inherits package)",
                    "Severity": "High",
                    "HowFound": "Activity uses singleTask/singleInstance without empty taskAffinity",
                })
        elif task_affinity != "":
            # Explicit non-empty taskAffinity - definitely vulnerable
            findings.append({
                "Source": "task_hijacking",
                "RuleID": "TASK_STRANDHOGG_V1_EXPLICIT",
                "Title": f"StrandHogg 1.0 Vulnerable Activity (Explicit Affinity): {name}",
                "Location": name,
                "Evidence": f"launchMode={launch_mode}, taskAffinity={task_affinity}",
                "Severity": "Critical",
                "HowFound": "Activity has explicit taskAffinity with dangerous launchMode",
            })

    # Check for allowTaskReparenting (can also enable task hijacking)
    if allow_task_reparenting == "true":
        findings.append({
            "Source": "task_hijacking",
            "RuleID": "TASK_REPARENTING",
            "Title": f"Task Reparenting Enabled: {name}",
            "Location": name,
            "Evidence": "allowTaskReparenting=true",
            "Severity": "Medium",
            "HowFound": "Activity can be moved to different task, enabling hijacking scenarios",
        })

    # Check exported activities with dangerous launch modes
    if exported == "true" and launch_mode in DANGEROUS_LAUNCH_MODES:
        findings.append({
            "Source": "task_hijacking",
            "RuleID": "TASK_EXPORTED_DANGEROUS",
            "Title": f"Exported Activity with Dangerous LaunchMode: {name}",
            "Location": name,
            "Evidence": f"exported=true, launchMode={launch_mode}",
            "Severity": "High",
            "HowFound": "Exported activity with singleTask/singleInstance is easier to exploit",
        })


def check_application_attributes(app_elem: ET.Element, findings: list[dict]) -> None:
    """Check application-level task affinity settings.

    Args:
        app_elem: The application XML element to analyze.
        findings: List to append findings to (modified in place).
    """
    task_affinity = get_android_attr(app_elem, "taskAffinity")
    allow_task_reparenting = get_android_attr(app_elem, "allowTaskReparenting")

    if allow_task_reparenting == "true":
        findings.append({
            "Source": "task_hijacking",
            "RuleID": "TASK_APP_REPARENTING",
            "Title": "Application-Level Task Reparenting Enabled",
            "Location": "AndroidManifest.xml",
            "Evidence": "application android:allowTaskReparenting=true",
            "Severity": "Medium",
            "HowFound": "All activities inherit task reparenting capability",
        })

    # If app-level taskAffinity is empty string, that's a good mitigation
    if task_affinity == "":
        findings.append({
            "Source": "task_hijacking",
            "RuleID": "TASK_AFFINITY_MITIGATION",
            "Title": "StrandHogg Mitigation: Empty TaskAffinity",
            "Location": "AndroidManifest.xml",
            "Evidence": "application android:taskAffinity=\"\"",
            "Severity": "Info",
            "HowFound": "Empty taskAffinity at application level mitigates StrandHogg",
        })


def scan_code_for_context_startactivities(src_dir: str) -> list[dict]:
    """Scan for StrandHogg 2.0 pattern: Context.startActivities() abuse.

    Args:
        src_dir: Directory containing decompiled source files.

    Returns:
        List of finding dictionaries for startActivities usage patterns.
    """
    findings = []
    seen = set()

    # Pattern for startActivities - StrandHogg 2.0 attack vector
    pattern = re.compile(r"startActivities\s*\(\s*[^)]+\)", re.IGNORECASE)

    src_path = Path(src_dir)
    if not src_path.exists():
        return findings

    for p in src_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".java", ".kt", ".smali"}:
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                for match in pattern.finditer(content):
                    evidence = match.group(0)
                    key = (str(p), evidence[:30])
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "Source": "task_hijacking",
                            "RuleID": "TASK_STRANDHOGG_V2_PATTERN",
                            "Title": "Potential StrandHogg 2.0 Vector: startActivities()",
                            "Location": str(p),
                            "Evidence": truncate(evidence),
                            "Severity": "Medium",
                            "HowFound": "startActivities() can be exploited for StrandHogg 2.0 if not carefully validated",
                        })
            except Exception:
                continue

    return findings


def scan_for_task_hijacking(manifest_path: str, src_dir: str | None = None) -> list[dict]:
    """Scan for task hijacking (StrandHogg) vulnerabilities.

    Args:
        manifest_path: Path to AndroidManifest.xml file.
        src_dir: Optional directory containing decompiled source files.

    Returns:
        List of finding dictionaries with vulnerability details.
    """
    findings = []

    # Parse manifest
    root = parse_manifest(manifest_path)
    if root is None:
        findings.append({
            "Source": "task_hijacking",
            "RuleID": "TASK_MANIFEST_PARSE_ERROR",
            "Title": "Could Not Parse Manifest",
            "Location": manifest_path,
            "Evidence": "Failed to parse AndroidManifest.xml",
            "Severity": "Info",
            "HowFound": "Manifest parsing failed",
        })
        return findings

    # Get SDK versions
    min_sdk = get_min_sdk(root)
    target_sdk = get_target_sdk(root)

    # Check if app targets pre-Android 11 (vulnerable to StrandHogg)
    if min_sdk < 30:
        findings.append({
            "Source": "task_hijacking",
            "RuleID": "TASK_MIN_SDK_VULNERABLE",
            "Title": f"App Supports Vulnerable Android Versions (minSdk={min_sdk})",
            "Location": "AndroidManifest.xml",
            "Evidence": f"minSdkVersion={min_sdk} (Android 11/API 30 added StrandHogg mitigations)",
            "Severity": "Medium",
            "HowFound": "App runs on Android versions without built-in StrandHogg protection",
        })

    # Check application element
    app_elem = root.find("application")
    if app_elem is not None:
        check_application_attributes(app_elem, findings)

        # Check each activity
        for activity in app_elem.findall("activity"):
            check_activity_task_hijacking(activity, min_sdk, findings)

        # Also check activity-alias
        for alias in app_elem.findall("activity-alias"):
            check_activity_task_hijacking(alias, min_sdk, findings)

    # Scan code for StrandHogg 2.0 patterns
    if src_dir:
        code_findings = scan_code_for_context_startactivities(src_dir)
        findings.extend(code_findings)

    # Summary finding
    critical_count = sum(1 for f in findings if f["Severity"] == "Critical")
    high_count = sum(1 for f in findings if f["Severity"] == "High")

    if critical_count > 0 or high_count > 0:
        findings.append({
            "Source": "task_hijacking",
            "RuleID": "TASK_SUMMARY",
            "Title": "Task Hijacking Vulnerability Summary",
            "Location": "AndroidManifest.xml",
            "Evidence": f"Found {critical_count} critical, {high_count} high severity task hijacking issues",
            "Severity": "Info",
            "HowFound": f"Summary: Set android:taskAffinity=\"\" on application to mitigate",
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
    """Scan for task hijacking vulnerabilities and write findings to CSV.

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

    findings = scan_for_task_hijacking(manifest_path, src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
