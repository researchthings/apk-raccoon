#!/usr/bin/env python3
"""Scan for network security vulnerabilities.

Detects cleartext traffic, certificate validation bypass, hostname verification
bypass, WebSocket insecurity, and missing certificate pinning.

Features (v2.0):
    - Filters documentation/comment/localhost URLs
    - Distinguishes legitimate vs suspicious TrustManager usage
    - WebSocket security analysis

OWASP MASTG Coverage:
    - MASTG-TEST-0242: Certificate validation bypass
    - MASTG-TEST-0243: Hostname verification bypass
    - MASTG-TEST-0295: WebSocket security
    - MASTG-TEST-0021: Cleartext traffic detection

Author: Randy Grant
Date: 11-07-2025
Version: 2.0
"""

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

# =============================================================================
# Certificate Validation Bypass Patterns (MASTG-TEST-0242)
# =============================================================================

CERT_VALIDATION_PATTERNS = [
    # Empty checkClientTrusted method
    (r'checkClientTrusted\s*\([^)]*\)\s*\{[^}]*\}', "NET_CERT_BYPASS_CLIENT", "Critical", "Empty checkClientTrusted - accepts all client certs"),
    # Empty checkServerTrusted (checked separately with context)
    (r'getAcceptedIssuers\s*\([^)]*\)\s*\{\s*return\s+null\s*;?\s*\}', "NET_CERT_BYPASS_ISSUERS", "Critical", "getAcceptedIssuers returns null"),
    # TrustAllCerts pattern
    (r'(?i)TrustAll(?:Certs?|Manager|SSLContext)', "NET_CERT_BYPASS_TRUSTALL", "Critical", "TrustAll pattern detected"),
    # SSLContext with null TrustManager
    (r'sslContext\.init\s*\(\s*null\s*,\s*(?:null|new\s+TrustManager)', "NET_CERT_BYPASS_INIT", "Critical", "SSLContext initialized with permissive TrustManager"),
    # Debug-only bypass (still risky)
    (r'(?i)if\s*\(\s*(?:BuildConfig\.)?DEBUG\s*\)[^;]*(?:TrustManager|acceptAll|skipVerif)', "NET_CERT_BYPASS_DEBUG", "High", "Certificate validation bypassed in debug mode"),
]

# =============================================================================
# Hostname Verification Bypass Patterns (MASTG-TEST-0243)
# =============================================================================

HOSTNAME_BYPASS_PATTERNS = [
    # HostnameVerifier always returns true
    (r'verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;?\s*\}', "NET_HOSTNAME_ALWAYS_TRUE", "Critical", "HostnameVerifier always returns true"),
    # AllowAllHostnameVerifier (deprecated but still used)
    (r'(?i)AllowAllHostnameVerifier', "NET_HOSTNAME_ALLOWALL", "Critical", "Using deprecated AllowAllHostnameVerifier"),
    (r'(?i)SSLSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER', "NET_HOSTNAME_ALLOWALL", "Critical", "Using ALLOW_ALL_HOSTNAME_VERIFIER"),
    # Null hostname verifier
    (r'setHostnameVerifier\s*\(\s*null\s*\)', "NET_HOSTNAME_NULL", "Critical", "HostnameVerifier set to null"),
    # NoopHostnameVerifier
    (r'(?i)NoopHostnameVerifier|NOOP_HOSTNAME_VERIFIER', "NET_HOSTNAME_NOOP", "Critical", "Using NoopHostnameVerifier"),
    # OkHttp hostname verifier disabled
    (r'\.hostnameVerifier\s*\([^)]*return\s+true', "NET_HOSTNAME_OKHTTP_BYPASS", "Critical", "OkHttp hostname verification disabled"),
]

# =============================================================================
# WebSocket Security Patterns (MASTG-TEST-0295)
# =============================================================================

WEBSOCKET_PATTERNS = [
    # Insecure WebSocket (ws://) instead of wss://
    (r'["\']ws://(?!localhost|127\.0\.0\.1|10\.|192\.168\.)[^"\']+["\']', "NET_WEBSOCKET_INSECURE", "High", "Insecure WebSocket (ws:// instead of wss://)"),
    # WebSocket without certificate validation
    (r'(?i)WebSocket[^;]*TrustManager', "NET_WEBSOCKET_NO_CERT", "Critical", "WebSocket with custom TrustManager"),
    # OkHttp WebSocket with permissive SSL
    (r'(?i)OkHttpClient\.Builder[^}]*WebSocket[^}]*sslSocketFactory', "NET_WEBSOCKET_PERMISSIVE_SSL", "High", "WebSocket with custom SSL configuration"),
    # WebSocket with hostname verifier disabled
    (r'(?i)WebSocket[^;]*(?:setHostnameVerifier|hostnameVerifier)\s*\([^)]*(?:null|true)', "NET_WEBSOCKET_NO_HOSTNAME", "Critical", "WebSocket without hostname verification"),
    # Raw Socket.IO or similar with ws://
    (r'(?i)(?:socket\.io|sockjs|websocket)[^;]*ws://', "NET_WEBSOCKET_INSECURE_LIB", "High", "WebSocket library using insecure ws://"),
]


def is_safe_url(url: str) -> bool:
    """Check if URL is a safe/ignorable pattern.

    Args:
        url: URL string to check.

    Returns:
        True if URL matches a safe pattern (localhost, schemas, etc).
    """
    for pattern in SAFE_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False


def is_in_comment(text: str, match_start: int) -> bool:
    """Check if match appears to be in a comment.

    Args:
        text: Full file content.
        match_start: Start index of the match.

    Returns:
        True if match is within a comment block.
    """
    # Get the line containing the match
    line_start = text.rfind('\n', 0, match_start) + 1
    line = text[line_start:match_start + 50]

    for pattern in COMMENT_INDICATORS:
        if re.match(pattern, line):
            return True
    return False


def parse_manifest_cleartext(mani_path: str) -> tuple:
    """Parse manifest for cleartext traffic configuration.

    Args:
        mani_path: Path to AndroidManifest.xml.

    Returns:
        Tuple of (cleartext_enabled: bool|None, evidence: str|None).
    """
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


def iter_text(src_dir: str, apk_path: str):
    """Iterate over source files yielding (path, content) tuples.

    Args:
        src_dir: Path to decompiled source directory.
        apk_path: Optional path to APK file for direct scanning.

    Yields:
        Tuple of (file_path, file_content) for each readable file.
    """
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


def main() -> None:
    """Scan for network security issues and write findings to CSV.

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

            # Check for certificate validation bypass patterns (MASTG-TEST-0242)
            for pattern, rule_id, severity, desc in CERT_VALIDATION_PATTERNS:
                for m in re.finditer(pattern, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "network",
                        "RuleID": rule_id,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": severity,
                        "HowFound": "Regex scan"
                    })

            # Check for hostname verification bypass patterns (MASTG-TEST-0243)
            for pattern, rule_id, severity, desc in HOSTNAME_BYPASS_PATTERNS:
                for m in re.finditer(pattern, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "network",
                        "RuleID": rule_id,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": severity,
                        "HowFound": "Regex scan"
                    })

            # Check for WebSocket security issues (MASTG-TEST-0295)
            for pattern, rule_id, severity, desc in WEBSOCKET_PATTERNS:
                for m in re.finditer(pattern, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "network",
                        "RuleID": rule_id,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": severity,
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
        print(f"[!] Error in scan_network_security: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
