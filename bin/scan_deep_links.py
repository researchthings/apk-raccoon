#!/usr/bin/env python3
"""Scan for Deep Link security vulnerabilities.

Detects insecure deep link / App Link configurations that can lead to
phishing attacks, intent injection, WebView injection, and credential theft.

Checks:
    - Unverified deep links missing autoVerify
    - Custom URL schemes vulnerable to hijacking
    - HTTP-only deep links (no HTTPS)
    - Wildcard host patterns
    - Unsafe deep link data handling in code

OWASP MASTG Coverage:
    - MASTG-TEST-0028: Testing Deep Links
    - MASTG-TEST-0029: Testing Custom URL Schemes

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


def parse_manifest(manifest_path: str) -> ET.Element | None:
    """Parse AndroidManifest.xml and return root element.

    Args:
        manifest_path: Path to the AndroidManifest.xml file.

    Returns:
        Root Element of the parsed manifest, or None on error.
    """
    try:
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


def check_intent_filter_deep_links(activity: ET.Element, findings: list[dict]) -> None:
    """Check activity's intent filters for deep link security issues.

    Args:
        activity: The activity XML element to analyze.
        findings: List to append findings to (modified in place).
    """
    activity_name = get_android_attr(activity, "name") or "Unknown"
    exported = get_android_attr(activity, "exported")

    for intent_filter in activity.findall("intent-filter"):
        # Check for VIEW action (deep link handler)
        has_view_action = False
        for action in intent_filter.findall("action"):
            action_name = get_android_attr(action, "name")
            if action_name == "android.intent.action.VIEW":
                has_view_action = True
                break

        if not has_view_action:
            continue

        # Check for BROWSABLE category (web-clickable deep link)
        has_browsable = False
        for category in intent_filter.findall("category"):
            cat_name = get_android_attr(category, "name")
            if cat_name == "android.intent.category.BROWSABLE":
                has_browsable = True
                break

        if not has_browsable:
            continue

        # This is a deep link handler - check security
        auto_verify = get_android_attr(intent_filter, "autoVerify")

        # Collect schemes and hosts
        schemes = []
        hosts = []
        for data in intent_filter.findall("data"):
            scheme = get_android_attr(data, "scheme")
            host = get_android_attr(data, "host")
            if scheme:
                schemes.append(scheme)
            if host:
                hosts.append(host)

        schemes = list(set(schemes))
        hosts = list(set(hosts))

        # Check for custom schemes (not https)
        custom_schemes = [s for s in schemes if s not in ("http", "https")]
        if custom_schemes:
            findings.append({
                "Source": "deep_links",
                "RuleID": "DEEP_CUSTOM_SCHEME",
                "Title": f"Custom URL Scheme Handler: {activity_name}",
                "Location": activity_name,
                "Evidence": f"schemes={custom_schemes}, hosts={hosts}",
                "Severity": "Medium",
                "HowFound": "Custom schemes can be registered by malicious apps for phishing",
            })

        # Check for http (not https)
        if "http" in schemes and "https" not in schemes:
            findings.append({
                "Source": "deep_links",
                "RuleID": "DEEP_HTTP_ONLY",
                "Title": f"HTTP-Only Deep Link (No HTTPS): {activity_name}",
                "Location": activity_name,
                "Evidence": f"schemes={schemes}",
                "Severity": "High",
                "HowFound": "HTTP deep links can be intercepted on the network",
            })

        # Check for missing autoVerify (App Links)
        if "https" in schemes and auto_verify != "true":
            findings.append({
                "Source": "deep_links",
                "RuleID": "DEEP_NO_AUTO_VERIFY",
                "Title": f"HTTPS Deep Link Without autoVerify: {activity_name}",
                "Location": activity_name,
                "Evidence": f"schemes={schemes}, hosts={hosts}, autoVerify={auto_verify}",
                "Severity": "High",
                "HowFound": "Without autoVerify, any app can claim this deep link (link hijacking)",
            })

        # Check for wildcard hosts
        wildcard_hosts = [h for h in hosts if h and (h.startswith("*") or h == "*")]
        if wildcard_hosts:
            findings.append({
                "Source": "deep_links",
                "RuleID": "DEEP_WILDCARD_HOST",
                "Title": f"Wildcard Host in Deep Link: {activity_name}",
                "Location": activity_name,
                "Evidence": f"hosts={wildcard_hosts}",
                "Severity": "High",
                "HowFound": "Wildcard hosts allow phishing from any domain",
            })

        # Check exported status
        if exported == "true":
            findings.append({
                "Source": "deep_links",
                "RuleID": "DEEP_EXPORTED_HANDLER",
                "Title": f"Exported Deep Link Handler: {activity_name}",
                "Location": activity_name,
                "Evidence": f"exported=true, schemes={schemes}",
                "Severity": "Info",
                "HowFound": "Deep link handler is exported (expected for deep links)",
            })

        # No host specified (catches all URLs with scheme)
        if schemes and not hosts:
            findings.append({
                "Source": "deep_links",
                "RuleID": "DEEP_NO_HOST_FILTER",
                "Title": f"Deep Link Without Host Filter: {activity_name}",
                "Location": activity_name,
                "Evidence": f"schemes={schemes}, no host restriction",
                "Severity": "High",
                "HowFound": "Without host filter, any URL with this scheme is handled",
            })


# Code patterns for unsafe deep link handling
UNSAFE_DEEPLINK_PATTERNS = [
    # Loading deep link URL directly in WebView
    (
        r"getIntent\(\)\.getData\(\).*loadUrl\(",
        "DEEP_WEBVIEW_INJECTION",
        "Critical",
        "Deep Link URL Loaded in WebView",
        "Deep link data loaded directly in WebView - potential XSS/injection",
    ),
    # Using deep link data without validation
    (
        r"getIntent\(\)\.getData\(\)\.toString\(\)",
        "DEEP_UNVALIDATED_DATA",
        "Medium",
        "Deep Link Data Used Without Validation",
        "Deep link data used directly - validate before use",
    ),
    # SQL query with deep link data
    (
        r"getIntent\(\)\.getData\(\).*rawQuery|execSQL",
        "DEEP_SQL_INJECTION",
        "Critical",
        "Deep Link Data in SQL Query",
        "Deep link data in SQL query - potential SQL injection",
    ),
    # Intent created from deep link data
    (
        r"Intent\.parseUri\(.*getIntent\(\)\.getData\(\)",
        "DEEP_INTENT_INJECTION",
        "Critical",
        "Intent Created From Deep Link Data",
        "Deep link data used to create intent - intent injection vulnerability",
    ),
    # File operations with deep link path
    (
        r"getIntent\(\)\.getData\(\)\.getPath\(\).*File\(",
        "DEEP_PATH_TRAVERSAL",
        "High",
        "Deep Link Path in File Operation",
        "Deep link path used in file operation - potential path traversal",
    ),
    # getQueryParameter without validation
    (
        r"\.getQueryParameter\([\"'][^\"']+[\"']\)(?!.*(?:isEmpty|isNull|matches|Pattern))",
        "DEEP_QUERY_PARAM",
        "Low",
        "Query Parameter Extraction",
        "Query parameter extracted from deep link - ensure validation",
    ),
    # JavaScript enabled WebView loading external content
    (
        r"setJavaScriptEnabled\(true\).*loadUrl\(.*getIntent",
        "DEEP_JS_WEBVIEW",
        "Critical",
        "JavaScript WebView Loading Deep Link",
        "JavaScript-enabled WebView loading deep link content",
    ),
]


def scan_code_for_unsafe_deeplink_handling(src_dir: str) -> list[dict]:
    """Scan source code for unsafe deep link handling patterns.

    Args:
        src_dir: Directory containing decompiled source files.

    Returns:
        List of finding dictionaries for unsafe deep link handling.
    """
    findings = []
    seen = set()

    compiled_patterns = []
    for pattern, rule_id, severity, title, description in UNSAFE_DEEPLINK_PATTERNS:
        try:
            compiled_patterns.append(
                (re.compile(pattern, re.IGNORECASE | re.DOTALL), rule_id, severity, title, description)
            )
        except re.error:
            continue

    for filepath, content in iter_source_files(src_dir):
        for regex, rule_id, severity, title, description in compiled_patterns:
            for match in regex.finditer(content):
                evidence = match.group(0)
                key = (rule_id, filepath, evidence[:50])
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "Source": "deep_links",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    return findings


def scan_for_deep_links(manifest_path: str, src_dir: str | None = None) -> list[dict]:
    """Scan for deep link security vulnerabilities.

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
            "Source": "deep_links",
            "RuleID": "DEEP_MANIFEST_PARSE_ERROR",
            "Title": "Could Not Parse Manifest",
            "Location": manifest_path,
            "Evidence": "Failed to parse AndroidManifest.xml",
            "Severity": "Info",
            "HowFound": "Manifest parsing failed",
        })
        return findings

    # Find application element
    app_elem = root.find("application")
    if app_elem is None:
        return findings

    # Check each activity for deep link handlers
    deep_link_count = 0
    for activity in app_elem.findall("activity"):
        before_count = len(findings)
        check_intent_filter_deep_links(activity, findings)
        if len(findings) > before_count:
            deep_link_count += 1

    # Also check activity-alias
    for alias in app_elem.findall("activity-alias"):
        check_intent_filter_deep_links(alias, findings)

    # Scan code for unsafe handling
    if src_dir:
        code_findings = scan_code_for_unsafe_deeplink_handling(src_dir)
        findings.extend(code_findings)

    # Summary
    critical_count = sum(1 for f in findings if f["Severity"] == "Critical")
    high_count = sum(1 for f in findings if f["Severity"] == "High")

    if deep_link_count > 0:
        findings.append({
            "Source": "deep_links",
            "RuleID": "DEEP_SUMMARY",
            "Title": f"Deep Link Analysis Summary ({deep_link_count} handlers found)",
            "Location": "AndroidManifest.xml",
            "Evidence": f"{critical_count} critical, {high_count} high severity issues",
            "Severity": "Info",
            "HowFound": "Use autoVerify=true for HTTPS App Links, validate all deep link data",
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
    """Scan for deep link vulnerabilities and write findings to CSV.

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

    findings = scan_for_deep_links(manifest_path, src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
