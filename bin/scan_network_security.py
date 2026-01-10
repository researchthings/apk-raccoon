#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 2.0
# Script to scan for network security issues in Android code/manifest/APK
# Why: Network vulns like cleartext traffic are common; covers MASVS-NETWORK.
#
# Improvements in v2.0:
# - Filter out documentation/comment URLs
# - More specific cleartext detection
# - Distinguish between legitimate and suspicious TrustManager usage
# - Skip localhost/development URLs

import sys
import os
import re
import csv
import zipfile
import traceback
from lxml import etree

# =============================================================================
# URL patterns to ignore (documentation, localhost, comments)
# =============================================================================
SAFE_URL_PATTERNS = [
    r'http://localhost',
    r'http://127\.0\.0\.1',
    r'http://10\.\d+\.\d+\.\d+',  # Private network
    r'http://192\.168\.\d+\.\d+',  # Private network
    r'http://schemas\.android\.com',  # Android schema
    r'http://www\.w3\.org',  # W3C schemas
    r'http://ns\.adobe\.com',  # Adobe namespace
    r'http://example\.com',  # Example domain
    r'http://example\.org',
    r'http://test\.',  # Test domains
]

# Patterns indicating the URL is in a comment
COMMENT_INDICATORS = [
    r'^\s*//',  # Java single-line comment
    r'^\s*\*',  # Java multi-line comment
    r'^\s*#',   # Properties file comment
    r'<!--',    # XML comment
]


def is_safe_url(url):
    """Check if URL is a safe/ignorable pattern."""
    for pattern in SAFE_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False


def is_in_comment(text, match_start):
    """Check if match appears to be in a comment."""
    # Get the line containing the match
    line_start = text.rfind('\n', 0, match_start) + 1
    line = text[line_start:match_start + 50]

    for pattern in COMMENT_INDICATORS:
        if re.match(pattern, line):
            return True
    return False


def parse_manifest_cleartext(mani_path):
    """Parse manifest for cleartext traffic configuration."""
    try:
        tree = etree.parse(mani_path)
        ns = {'android': 'http://schemas.android.com/apk/res/android'}

        # Check application-level setting
        app_cleartext = tree.xpath('//application/@android:usesCleartextTraffic', namespaces=ns)
        if app_cleartext and app_cleartext[0] == 'true':
            return True, "android:usesCleartextTraffic=true"

        # Check for network security config that might allow cleartext
        network_config = tree.xpath('//application/@android:networkSecurityConfig', namespaces=ns)
        if network_config:
            return None, f"Uses networkSecurityConfig: {network_config[0]} (check config file)"

        return False, None

    except Exception as e:
        print(f"Warning: Manifest parse failed: {str(e)}", file=sys.stderr)
        return None, None


def iter_text(src_dir, apk_path):
    """Iterate over source files."""
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
                # Only scan relevant files
                if not fn.endswith(('.java', '.kt', '.smali', '.xml', '.json')):
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


def main():
    try:
        if len(sys.argv) < 4:
            print("Usage: scan_network_security.py <src_dir> <manifest.xml> <out.csv> [apk_path]", file=sys.stderr)
            sys.exit(1)

        src_dir, mani_path, out = sys.argv[1], sys.argv[2], sys.argv[3]
        apk_path = sys.argv[4] if len(sys.argv) > 4 else None

        rows = []
        files_scanned = 0

        # Check manifest for cleartext configuration
        if mani_path and os.path.isfile(mani_path):
            cleartext_enabled, evidence = parse_manifest_cleartext(mani_path)
            if cleartext_enabled:
                rows.append({
                    "Source": "network",
                    "RuleID": "NET_CLEARTEXT_ENABLED",
                    "Title": "Cleartext traffic enabled in manifest",
                    "Location": mani_path,
                    "Evidence": evidence,
                    "Severity": "High",
                    "HowFound": "XML parse"
                })
            elif evidence:  # Has network security config
                rows.append({
                    "Source": "network",
                    "RuleID": "NET_SECURITY_CONFIG",
                    "Title": "Custom network security configuration",
                    "Location": mani_path,
                    "Evidence": evidence,
                    "Severity": "Info",
                    "HowFound": "XML parse"
                })

        # Scan source files
        for path, text in iter_text(src_dir, apk_path):
            files_scanned += 1

            # Check for HTTP URLs in code (not comments, not safe URLs)
            http_pattern = r'http://[^\s"\'<>)}\]]+[^\s"\'<>)}\]\.,;]'
            for m in re.finditer(http_pattern, text):
                url = m.group(0)

                # Skip if safe URL
                if is_safe_url(url):
                    continue

                # Skip if in comment
                if is_in_comment(text, m.start()):
                    continue

                snippet = text[max(0, m.start() - 20):m.end() + 20].replace("\n", " ")
                rows.append({
                    "Source": "network",
                    "RuleID": "NET_HTTP_URL",
                    "Title": "HTTP URL in code (cleartext)",
                    "Location": str(path),
                    "Evidence": snippet[:200],
                    "Severity": "High",
                    "HowFound": "Regex scan"
                })

            # Check for custom TrustManager (potential cert validation bypass)
            # Look for implementations that accept all certificates
            trust_manager_pattern = r'class\s+\w+\s+implements\s+X509TrustManager'
            for m in re.finditer(trust_manager_pattern, text):
                # Check if it has an empty checkServerTrusted
                context_end = min(len(text), m.end() + 500)
                context = text[m.start():context_end]

                # Look for suspicious patterns
                if re.search(r'checkServerTrusted[^}]*\{\s*\}', context) or \
                   re.search(r'checkServerTrusted[^}]*\{\s*//\s*\}', context) or \
                   re.search(r'checkServerTrusted[^}]*\{\s*return\s*;\s*\}', context):
                    snippet = text[m.start():min(len(text), m.end() + 100)].replace("\n", " ")
                    rows.append({
                        "Source": "network",
                        "RuleID": "NET_TRUST_ALL_CERTS",
                        "Title": "TrustManager that accepts all certificates",
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": "Critical",
                        "HowFound": "Regex scan"
                    })

            # Check for HostnameVerifier that accepts all hosts
            hostname_pattern = r'class\s+\w+\s+implements\s+HostnameVerifier'
            for m in re.finditer(hostname_pattern, text):
                context_end = min(len(text), m.end() + 300)
                context = text[m.start():context_end]

                if re.search(r'verify[^}]*return\s+true\s*;', context):
                    snippet = text[m.start():min(len(text), m.end() + 100)].replace("\n", " ")
                    rows.append({
                        "Source": "network",
                        "RuleID": "NET_HOSTNAME_BYPASS",
                        "Title": "HostnameVerifier that accepts all hostnames",
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": "Critical",
                        "HowFound": "Regex scan"
                    })

            # Check for SSL error handler that proceeds anyway
            ssl_error_pattern = r'onReceivedSslError[^}]*handler\.proceed\s*\(\s*\)'
            for m in re.finditer(ssl_error_pattern, text, re.DOTALL):
                snippet = text[max(0, m.start() - 20):m.end() + 20].replace("\n", " ")
                rows.append({
                    "Source": "network",
                    "RuleID": "NET_SSL_ERROR_BYPASS",
                    "Title": "SSL error handler that proceeds anyway",
                    "Location": str(path),
                    "Evidence": snippet[:200],
                    "Severity": "Critical",
                    "HowFound": "Regex scan"
                })

            # Check for missing certificate pinning (info level)
            if 'OkHttpClient' in text or 'HttpsURLConnection' in text:
                if 'CertificatePinner' not in text and 'sslSocketFactory' not in text.lower():
                    # Only report once per file
                    rows.append({
                        "Source": "network",
                        "RuleID": "NET_NO_CERT_PINNING",
                        "Title": "HTTPS client without certificate pinning",
                        "Location": str(path),
                        "Evidence": "Uses OkHttpClient/HttpsURLConnection without CertificatePinner",
                        "Severity": "Low",
                        "HowFound": "Heuristic"
                    })

        # Write output
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        print(f"Wrote {out} ({len(rows)} findings, {files_scanned} files scanned)")

    except Exception as e:
        print(f"[!] Error in scan_network_security: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
