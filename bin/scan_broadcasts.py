#!/usr/bin/env python3
"""
Broadcast Receiver Security Scanner v1.0

Detects insecure broadcast receiver configurations that can lead to:
- Information disclosure via exported receivers
- Denial of service attacks
- Privilege escalation via sticky broadcasts
- Ordered broadcast hijacking

References:
- https://developer.android.com/privacy-and-security/risks/insecure-broadcast-receiver
- https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/
- https://developer.android.com/develop/background-work/background-tasks/broadcasts

OWASP Alignment: MASVS-PLATFORM-1, MASVS-PLATFORM-2
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

# Sensitive broadcast actions that should be protected
SENSITIVE_BROADCAST_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED": ("Boot receiver", "Medium"),
    "android.intent.action.PACKAGE_ADDED": ("Package install receiver", "Medium"),
    "android.intent.action.PACKAGE_REMOVED": ("Package removal receiver", "Medium"),
    "android.intent.action.NEW_OUTGOING_CALL": ("Call intercept receiver", "High"),
    "android.provider.Telephony.SMS_RECEIVED": ("SMS receiver", "Critical"),
    "android.provider.Telephony.WAP_PUSH_RECEIVED": ("WAP push receiver", "High"),
    "android.intent.action.BATTERY_LOW": ("Battery receiver", "Low"),
    "android.net.conn.CONNECTIVITY_CHANGE": ("Network change receiver", "Medium"),
    "android.intent.action.PHONE_STATE": ("Phone state receiver", "High"),
    "android.intent.action.USER_PRESENT": ("User unlock receiver", "Medium"),
}

# Dangerous permissions that can be associated with receivers
DANGEROUS_RECEIVER_PERMISSIONS = {
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.READ_PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALL_LOG",
}


def truncate(s: str, max_len: int = 150) -> str:
    """Truncate string for evidence field."""
    s = s.replace("\n", " ").replace("\r", "").strip()
    return s[:max_len] + "..." if len(s) > max_len else s


def parse_manifest(manifest_path: str) -> ET.Element | None:
    """Parse AndroidManifest.xml and return root element."""
    try:
        ET.register_namespace("android", ANDROID_NS)
        tree = ET.parse(manifest_path)
        return tree.getroot()
    except Exception as e:
        print(f"[!] Warning: Could not parse manifest: {e}", file=sys.stderr)
        return None


def get_android_attr(elem: ET.Element, attr: str) -> str | None:
    """Get Android namespace attribute value."""
    return elem.get(f"{{{ANDROID_NS}}}{attr}")


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


def check_receiver_security(receiver: ET.Element, findings: list[dict]):
    """Check a broadcast receiver for security issues."""
    name = get_android_attr(receiver, "name") or "Unknown"
    exported = get_android_attr(receiver, "exported")
    permission = get_android_attr(receiver, "permission")
    enabled = get_android_attr(receiver, "enabled")

    # Collect intent filter actions
    actions = []
    has_intent_filter = False
    for intent_filter in receiver.findall("intent-filter"):
        has_intent_filter = True
        priority = get_android_attr(intent_filter, "priority")

        # Check for high priority (ordered broadcast hijacking)
        if priority:
            try:
                prio_val = int(priority)
                if prio_val > 100:
                    findings.append({
                        "Source": "broadcasts",
                        "RuleID": "BCAST_HIGH_PRIORITY",
                        "Title": f"High Priority Receiver: {name}",
                        "Location": name,
                        "Evidence": f"priority={priority}",
                        "Severity": "Medium",
                        "HowFound": "High priority can hijack ordered broadcasts from other apps",
                    })
            except ValueError:
                pass

        for action in intent_filter.findall("action"):
            action_name = get_android_attr(action, "name")
            if action_name:
                actions.append(action_name)

                # Check for sensitive broadcast actions
                if action_name in SENSITIVE_BROADCAST_ACTIONS:
                    desc, severity = SENSITIVE_BROADCAST_ACTIONS[action_name]
                    findings.append({
                        "Source": "broadcasts",
                        "RuleID": "BCAST_SENSITIVE_ACTION",
                        "Title": f"Sensitive Broadcast Receiver ({desc}): {name}",
                        "Location": name,
                        "Evidence": f"action={action_name}",
                        "Severity": severity,
                        "HowFound": f"Receiver handles sensitive system broadcast: {desc}",
                    })

    # Determine if exported (explicit or implicit via intent-filter)
    is_exported = exported == "true" or (has_intent_filter and exported != "false")

    # Exported receiver without permission protection
    if is_exported and not permission:
        findings.append({
            "Source": "broadcasts",
            "RuleID": "BCAST_EXPORTED_NO_PERM",
            "Title": f"Exported Receiver Without Permission: {name}",
            "Location": name,
            "Evidence": f"exported={exported}, permission=none, actions={actions[:3]}",
            "Severity": "High",
            "HowFound": "Any app can send broadcasts to this receiver - add permission protection",
        })

    # Exported receiver with weak permission
    if is_exported and permission:
        # Check if permission is a custom permission (might be weak)
        if not permission.startswith("android.permission."):
            findings.append({
                "Source": "broadcasts",
                "RuleID": "BCAST_CUSTOM_PERMISSION",
                "Title": f"Exported Receiver With Custom Permission: {name}",
                "Location": name,
                "Evidence": f"permission={permission}",
                "Severity": "Low",
                "HowFound": "Verify custom permission has appropriate protection level",
            })

    # Check for common vulnerable patterns in receiver names
    if is_exported:
        name_lower = name.lower()
        if any(kw in name_lower for kw in ["debug", "test", "dev", "admin"]):
            findings.append({
                "Source": "broadcasts",
                "RuleID": "BCAST_DEBUG_RECEIVER",
                "Title": f"Potentially Debug/Test Receiver Exported: {name}",
                "Location": name,
                "Evidence": f"Suspicious name pattern, exported={exported}",
                "Severity": "Medium",
                "HowFound": "Debug/test receivers should not be exported in production",
            })


def check_permissions_for_broadcasts(root: ET.Element, findings: list[dict]):
    """Check for dangerous broadcast-related permissions."""
    for uses_perm in root.findall("uses-permission"):
        perm_name = get_android_attr(uses_perm, "name")
        if perm_name in DANGEROUS_RECEIVER_PERMISSIONS:
            findings.append({
                "Source": "broadcasts",
                "RuleID": "BCAST_DANGEROUS_PERM",
                "Title": f"Dangerous Broadcast Permission: {perm_name}",
                "Location": "AndroidManifest.xml",
                "Evidence": perm_name,
                "Severity": "Medium",
                "HowFound": "App can receive sensitive system broadcasts",
            })


# Code patterns for broadcast security issues
BROADCAST_CODE_PATTERNS = [
    # Sticky broadcasts (deprecated and insecure)
    (
        r"sendStickyBroadcast\s*\(",
        "BCAST_STICKY_SEND",
        "High",
        "Sticky Broadcast Sent",
        "sendStickyBroadcast is deprecated and insecure - any app can read it",
    ),
    (
        r"sendStickyOrderedBroadcast\s*\(",
        "BCAST_STICKY_ORDERED",
        "High",
        "Sticky Ordered Broadcast Sent",
        "Sticky ordered broadcasts are insecure - any app can intercept",
    ),
    # Implicit broadcasts without permission
    (
        r"sendBroadcast\s*\(\s*[^,)]+\s*\)(?!\s*,)",
        "BCAST_IMPLICIT_NO_PERM",
        "Medium",
        "Broadcast Without Permission Parameter",
        "Broadcast sent without permission - any app can receive it",
    ),
    # Dynamic receiver registration without permission
    (
        r"registerReceiver\s*\([^,]+,\s*[^,]+\s*\)(?!\s*,)",
        "BCAST_REGISTER_NO_PERM",
        "Medium",
        "Receiver Registered Without Permission",
        "Dynamic receiver registered without permission filter",
    ),
    # Ordered broadcast with result data
    (
        r"setResultData\s*\(|setResultCode\s*\(|setResult\s*\(",
        "BCAST_ORDERED_RESULT",
        "Low",
        "Ordered Broadcast Result Modification",
        "Result data set in ordered broadcast - ensure proper priority handling",
    ),
    # LocalBroadcastManager (good practice, deprecated but still used)
    (
        r"LocalBroadcastManager",
        "BCAST_LOCAL_BROADCAST",
        "Info",
        "LocalBroadcastManager Usage",
        "Good: Using local broadcasts - not vulnerable to external interception",
    ),
    # Exported flag explicitly set in dynamic registration (API 33+)
    (
        r"RECEIVER_EXPORTED|RECEIVER_NOT_EXPORTED",
        "BCAST_EXPLICIT_EXPORT_FLAG",
        "Info",
        "Explicit Receiver Export Flag (API 33+)",
        "Good: Explicit export flag set for dynamic receiver registration",
    ),
    # getResultData in receiver (potential data exposure)
    (
        r"getResultData\s*\(\)|getResultCode\s*\(\)",
        "BCAST_RESULT_ACCESS",
        "Low",
        "Ordered Broadcast Result Access",
        "Accessing ordered broadcast result data - review for sensitive info",
    ),
    # PendingIntent with broadcast
    (
        r"PendingIntent\.getBroadcast\s*\(",
        "BCAST_PENDING_INTENT",
        "Low",
        "PendingIntent with Broadcast",
        "PendingIntent created for broadcast - ensure proper flags",
    ),
    # abortBroadcast (ordered broadcast interception)
    (
        r"abortBroadcast\s*\(\)",
        "BCAST_ABORT",
        "Medium",
        "Broadcast Abortion",
        "Ordered broadcast being aborted - potential denial of service to lower priority receivers",
    ),
]


def scan_code_for_broadcast_issues(src_dir: str) -> list[dict]:
    """Scan source code for broadcast security issues."""
    findings = []
    seen = set()

    compiled_patterns = []
    for pattern, rule_id, severity, title, description in BROADCAST_CODE_PATTERNS:
        try:
            compiled_patterns.append(
                (re.compile(pattern, re.IGNORECASE), rule_id, severity, title, description)
            )
        except re.error:
            continue

    for filepath, content in iter_source_files(src_dir):
        for regex, rule_id, severity, title, description in compiled_patterns:
            for match in regex.finditer(content):
                evidence = match.group(0)
                key = (rule_id, filepath, evidence[:30])
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "Source": "broadcasts",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    return findings


def check_target_sdk_broadcast(root: ET.Element, findings: list[dict]):
    """Check target SDK for broadcast-related behavior changes."""
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        target_sdk = get_android_attr(uses_sdk, "targetSdkVersion")
        if target_sdk:
            try:
                sdk = int(target_sdk)
                # Android 13 (API 33) requires explicit export flag for dynamic receivers
                if sdk >= 33:
                    findings.append({
                        "Source": "broadcasts",
                        "RuleID": "BCAST_API33_REQUIREMENTS",
                        "Title": "API 33+ Broadcast Requirements",
                        "Location": "AndroidManifest.xml",
                        "Evidence": f"targetSdkVersion={sdk}",
                        "Severity": "Info",
                        "HowFound": "API 33+ requires RECEIVER_EXPORTED/NOT_EXPORTED flag for dynamic receivers",
                    })
                # Android 8 (API 26) limited implicit broadcast receivers
                if sdk >= 26:
                    findings.append({
                        "Source": "broadcasts",
                        "RuleID": "BCAST_API26_LIMITS",
                        "Title": "API 26+ Implicit Broadcast Limits",
                        "Location": "AndroidManifest.xml",
                        "Evidence": f"targetSdkVersion={sdk}",
                        "Severity": "Info",
                        "HowFound": "API 26+ restricts many implicit broadcasts - some receivers may not work",
                    })
            except ValueError:
                pass


def scan_for_broadcasts(manifest_path: str, src_dir: str | None = None) -> list[dict]:
    """Main scanning function for broadcast receiver security."""
    findings = []

    # Parse manifest
    root = parse_manifest(manifest_path)
    if root is None:
        findings.append({
            "Source": "broadcasts",
            "RuleID": "BCAST_MANIFEST_PARSE_ERROR",
            "Title": "Could Not Parse Manifest",
            "Location": manifest_path,
            "Evidence": "Failed to parse AndroidManifest.xml",
            "Severity": "Info",
            "HowFound": "Manifest parsing failed",
        })
        return findings

    # Check permissions
    check_permissions_for_broadcasts(root, findings)

    # Check target SDK
    check_target_sdk_broadcast(root, findings)

    # Find application element
    app_elem = root.find("application")
    if app_elem is not None:
        # Check each receiver
        receiver_count = 0
        exported_count = 0
        for receiver in app_elem.findall("receiver"):
            receiver_count += 1
            exported = get_android_attr(receiver, "exported")
            has_intent_filter = receiver.find("intent-filter") is not None
            if exported == "true" or (has_intent_filter and exported != "false"):
                exported_count += 1
            check_receiver_security(receiver, findings)

        if receiver_count > 0:
            findings.append({
                "Source": "broadcasts",
                "RuleID": "BCAST_RECEIVER_COUNT",
                "Title": f"Broadcast Receivers: {receiver_count} total, {exported_count} exported",
                "Location": "AndroidManifest.xml",
                "Evidence": f"{receiver_count} receivers, {exported_count} exported",
                "Severity": "Info",
                "HowFound": "Receiver count summary",
            })

    # Scan code
    if src_dir:
        code_findings = scan_code_for_broadcast_issues(src_dir)
        findings.extend(code_findings)

    # Summary
    critical_count = sum(1 for f in findings if f["Severity"] == "Critical")
    high_count = sum(1 for f in findings if f["Severity"] == "High")

    findings.append({
        "Source": "broadcasts",
        "RuleID": "BCAST_SUMMARY",
        "Title": "Broadcast Security Analysis Summary",
        "Location": "Application",
        "Evidence": f"{critical_count} critical, {high_count} high severity issues",
        "Severity": "Info",
        "HowFound": "Protect exported receivers with permissions, avoid sticky broadcasts",
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
        print(f"Usage: {sys.argv[0]} <manifest.xml> <output.csv> [src_dir]", file=sys.stderr)
        sys.exit(1)

    manifest_path = sys.argv[1]
    output_path = sys.argv[2]
    src_dir = sys.argv[3] if len(sys.argv) > 3 else None

    findings = scan_for_broadcasts(manifest_path, src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
