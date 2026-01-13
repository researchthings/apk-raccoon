#!/usr/bin/env python3
"""Scan for authentication and authorization vulnerabilities.

Detects weak password configurations, insecure session handling, hardcoded
credentials, IDOR risks, and exported components without permissions.

Features (v2.0):
    - Context-aware regex patterns to reduce false positives
    - IDOR detection for user-controlled IDs
    - Manifest analysis for unprotected exports

OWASP MASTG Coverage:
    - MASTG-TEST-0003: Authentication bypass detection
    - MASTG-TEST-0018: IDOR vulnerability detection
    - MASTG-TEST-0016: Exported component analysis

Author: Randy Grant
Date: 11-07-2025
Version: 2.0
"""

import sys
import os
import re
import csv
import zipfile
import xml.etree.ElementTree as ET
import traceback

# =============================================================================
# Authentication issue patterns - refined for lower false positives
# Format: (RuleID, pattern, severity, description, context_required)
# context_required: if True, match must be in security-relevant context
# =============================================================================
AUTH_PATTERNS = [
    # Weak password configuration
    (
        "AUTH_WEAK_PASSWORD_LITERAL",
        r'(?i)(?:password|passwd|pwd)\s*=\s*["\']([^"\']{1,6})["\']',
        "High",
        "Hardcoded weak password (6 chars or less)",
        False
    ),
    (
        "AUTH_WEAK_PASSWORD_LENGTH",
        r'(?i)setMinLength\s*\(\s*([1-5])\s*\)',
        "Medium",
        "Password minimum length set too short",
        False
    ),

    # Insecure session handling - more specific patterns
    (
        "AUTH_SESSION_NULL_CHECK",
        r'(?i)(?:session|sessionId|session_id)\s*(?:==|!=|\.equals)\s*(?:null|"")',
        "Medium",
        "Session null/empty check (verify proper handling)",
        False
    ),
    (
        "AUTH_TOKEN_HARDCODED",
        r'(?i)(?:auth|access|refresh)[_-]?token\s*=\s*["\'][A-Za-z0-9._-]{20,}["\']',
        "High",
        "Hardcoded authentication token",
        False
    ),

    # HTTP for authentication - more specific
    (
        "AUTH_HTTP_LOGIN_URL",
        r'(?i)(?:login|auth|signin|authenticate)[_-]?url\s*=\s*["\']http://',
        "Critical",
        "Authentication endpoint using HTTP",
        False
    ),
    (
        "AUTH_HTTP_CREDENTIAL_SEND",
        r'(?i)\.(?:post|send|submit)\s*\([^)]*http://[^)]*(?:password|credential|token)',
        "Critical",
        "Credentials sent over HTTP",
        False
    ),

    # IDOR-related patterns - more specific to actual vulnerabilities
    (
        "AUTH_IDOR_DIRECT_OBJECT",
        r'(?i)(?:user|account|profile|order|document)[_-]?id\s*=\s*(?:request\.getParameter|intent\.get\w*Extra|getIntent\(\)\.get)',
        "High",
        "User-controlled ID used for object access",
        False
    ),
    (
        "AUTH_IDOR_PATH_PARAM",
        r'(?i)/(?:user|account|profile|order|document)s?/\s*["\']?\s*\+\s*(?:id|userId|accountId)',
        "High",
        "User ID concatenated into URL path",
        False
    ),

    # Missing authorization checks
    (
        "AUTH_NO_PERMISSION_CHECK",
        r'(?i)(?:isAdmin|hasPermission|checkPermission|isAuthorized)\s*\(\s*\)\s*(?:;|$)',
        "Low",
        "Permission check with no parameters (verify logic)",
        True
    ),

    # Credential storage issues
    (
        "AUTH_PLAINTEXT_CRED_STORAGE",
        r'(?i)(?:SharedPreferences|putString)\s*\([^)]*(?:password|credential|secret)',
        "High",
        "Credentials stored in SharedPreferences (may be plaintext)",
        False
    ),

    # Biometric bypass
    (
        "AUTH_BIOMETRIC_BYPASS",
        r'(?i)(?:setNegativeButton|setCancelable\s*\(\s*true)',
        "Medium",
        "Biometric dialog may allow bypass (verify implementation)",
        True  # Only flag in biometric context
    ),
]

# Context patterns that must be present for context_required rules
SECURITY_CONTEXTS = {
    "AUTH_NO_PERMISSION_CHECK": [r'(?i)admin|permission|authorize|privilege'],
    "AUTH_BIOMETRIC_BYPASS": [r'(?i)biometric|fingerprint|faceId|BiometricPrompt'],
}


def parse_manifest(mani_path: str) -> list:
    """Parse manifest to find exported components without permissions.

    Args:
        mani_path: Path to AndroidManifest.xml file.

    Returns:
        List of dicts with component info for each unprotected export.
    """
    results = []
    try:
        tree = ET.parse(mani_path)
        root = tree.getroot()
        ns = '{http://schemas.android.com/apk/res/android}'

        # Components that can be exported
        component_tags = ['activity', 'service', 'receiver', 'provider']

        for tag in component_tags:
            for elem in root.iter(tag):
                exported = elem.get(f'{ns}exported')
                permission = elem.get(f'{ns}permission')
                name = elem.get(f'{ns}name', 'unknown')

                # Check if explicitly exported without permission
                if exported == 'true' and not permission:
                    # Check for intent-filter (implicit export in older Android)
                    has_intent_filter = elem.find('intent-filter') is not None

                    results.append({
                        'component_type': tag,
                        'name': name,
                        'exported': exported,
                        'has_intent_filter': has_intent_filter,
                        'xml': ET.tostring(elem, encoding="unicode")[:300]
                    })

    except Exception as e:
        print(f"Warning: Manifest parse failed: {str(e)}", file=sys.stderr)

    return results


def iter_text(src_dir: str, apk_path: str, mani_path: str):
    """Iterate over source files yielding (path, content) tuples.

    Args:
        src_dir: Path to decompiled source directory.
        apk_path: Optional path to APK file for direct scanning.
        mani_path: Path to AndroidManifest.xml.

    Yields:
        Tuple of (file_path, file_content) for each readable file.
    """
    # Yield manifest content
    if mani_path and os.path.isfile(mani_path):
        with open(mani_path, "r", encoding="utf-8") as f:
            yield "manifest", f.read()

    # Iterate source directory
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
                # Skip non-code files
                if not fn.endswith(('.java', '.kt', '.smali', '.xml', '.json')):
                    continue
                p = os.path.join(root, fn)
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        yield p, f.read()
                except Exception as e:
                    print(f"Warning: Failed to read {p}: {str(e)}", file=sys.stderr)
                    continue

    # Fallback to APK
    elif apk_path and os.path.isfile(apk_path):
        with zipfile.ZipFile(apk_path, 'r') as z:
            for zi in z.infolist():
                if zi.file_size > 0 and not zi.is_dir():
                    try:
                        yield zi.filename, z.read(zi.filename).decode("utf-8", errors="ignore")
                    except Exception as e:
                        print(f"Warning: Failed to read ZIP entry {zi.filename}: {str(e)}", file=sys.stderr)
                        continue


def check_context(text: str, rule_id: str) -> bool:
    """Check if required security context is present for context-dependent rules.

    Args:
        text: File content to check.
        rule_id: The rule ID to check context for.

    Returns:
        True if context matches or no context required.
    """
    if rule_id not in SECURITY_CONTEXTS:
        return True  # No context required

    for pattern in SECURITY_CONTEXTS[rule_id]:
        if re.search(pattern, text):
            return True
    return False


def main() -> None:
    """Scan for auth issues and write findings to CSV.

    Command line args:
        sys.argv[1]: Path to decompiled source directory
        sys.argv[2]: Path to AndroidManifest.xml
        sys.argv[3]: Output CSV path
        sys.argv[4]: Optional path to APK file

    Raises:
        SystemExit: If arguments missing or scanning fails.
    """
    try:
        if len(sys.argv) < 4:
            print("Usage: scan_auth_issues.py <src_dir> <manifest.xml> <out.csv> [apk_path]", file=sys.stderr)
            sys.exit(1)

        src_dir, mani_path, out = sys.argv[1], sys.argv[2], sys.argv[3]
        apk_path = sys.argv[4] if len(sys.argv) > 4 else None

        rows = []
        files_scanned = 0

        # First, check manifest for exported components
        exported_components = parse_manifest(mani_path)
        for comp in exported_components:
            rows.append({
                "Source": "auth",
                "RuleID": "AUTH_EXPORTED_NO_PERM",
                "Title": f"Exported {comp['component_type']} without permission",
                "Location": f"{mani_path}:{comp['name']}",
                "Evidence": comp['xml'][:200],
                "Severity": "High",
                "HowFound": "XML parse"
            })

        # Scan source files
        for path, text in iter_text(src_dir, apk_path, mani_path):
            files_scanned += 1

            for rid, rx, sev, desc, context_required in AUTH_PATTERNS:
                # Skip context-dependent patterns if context not present
                if context_required and not check_context(text, rid):
                    continue

                for m in re.finditer(rx, text):
                    # Get context around match
                    start = max(0, m.start() - 40)
                    end = min(len(text), m.end() + 40)
                    snippet = text[start:end].replace("\n", " ")

                    rows.append({
                        "Source": "auth",
                        "RuleID": rid,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": sev,
                        "HowFound": "Regex scan"
                    })

        # Write output
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        print(f"Wrote {out} ({len(rows)} findings, {files_scanned} files scanned)")

    except Exception as e:
        print(f"[!] Error in scan_auth_issues: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
