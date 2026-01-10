#!/usr/bin/env python3

# Author: Randy Grant
# Date: 01-09-2026
# Version: 1.0
# Script to scan for certificate pinning implementation and bypasses
# Why: Certificate pinning prevents MITM attacks; its absence or bypass is critical.
#
# Checks:
# - Network Security Config pinning declarations
# - OkHttp CertificatePinner usage
# - TrustManagerFactory customizations
# - Common pinning bypass techniques
# - Missing pinning on sensitive endpoints

import sys
import os
import re
import csv
import zipfile
import traceback
from lxml import etree

# =============================================================================
# Pinning implementation patterns (positive indicators)
# =============================================================================
PINNING_IMPLEMENTATIONS = {
    "okhttp_pinner": {
        "pattern": r'CertificatePinner\.Builder\(\)',
        "description": "OkHttp CertificatePinner"
    },
    "okhttp_add_pin": {
        "pattern": r'\.add\s*\(\s*["\'][^"\']+["\']\s*,\s*["\']sha256/',
        "description": "OkHttp pin configuration"
    },
    "trustkit": {
        "pattern": r'TrustKit\.initializeWithNetworkSecurityConfiguration',
        "description": "TrustKit pinning library"
    },
    "appcenter_pinning": {
        "pattern": r'CertificateTrustManager|PublicKeyManager',
        "description": "Custom certificate trust manager"
    },
    "retrofit_pinner": {
        "pattern": r'certificatePinner\s*\(',
        "description": "Retrofit certificate pinner"
    },
}

# =============================================================================
# Pinning bypass patterns (negative indicators - vulnerabilities)
# =============================================================================
PINNING_BYPASS_PATTERNS = [
    (
        "PIN_BYPASS_TRUSTMANAGER",
        r'TrustManagerFactory\.getInstance[^;]+init\s*\(\s*\(KeyStore\)\s*null\s*\)',
        "Critical",
        "TrustManager initialized with null KeyStore (bypasses pinning)"
    ),
    (
        "PIN_BYPASS_EMPTY_PINS",
        r'CertificatePinner\.Builder\(\)\.build\(\)',
        "High",
        "Empty CertificatePinner (no pins configured)"
    ),
    (
        "PIN_BYPASS_REFLECTION",
        r'(?i)(?:setField|getDeclaredField)\s*\([^)]*(?:certificatePinner|trustManager|sslSocketFactory)',
        "Critical",
        "Reflection used to modify SSL/pinning components"
    ),
    (
        "PIN_BYPASS_UNSAFE_HOSTNAME",
        r'ALLOW_ALL_HOSTNAME_VERIFIER|NullHostnameVerifier',
        "Critical",
        "Hostname verification disabled"
    ),
    (
        "PIN_DEBUG_BYPASS",
        r'(?i)if\s*\(\s*(?:BuildConfig\.)?DEBUG\s*\)\s*[^}]*(?:certificatePinner|trustManager|ssl)',
        "High",
        "Pinning bypassed in debug builds (check production)"
    ),
    (
        "PIN_XPOSED_BYPASS",
        r'(?i)de\.robv\.android\.xposed|XposedBridge|XC_MethodHook',
        "Info",
        "Xposed framework references (potential bypass mechanism)"
    ),
    (
        "PIN_FRIDA_BYPASS",
        r'(?i)frida|com\.sensepost\.mallet',
        "Info",
        "Frida references (potential bypass mechanism)"
    ),
]

# =============================================================================
# Sensitive endpoints that should have pinning
# =============================================================================
SENSITIVE_ENDPOINT_PATTERNS = [
    r'(?i)/api/(?:v\d+/)?(?:auth|login|token|oauth)',
    r'(?i)/api/(?:v\d+/)?(?:payment|checkout|transaction)',
    r'(?i)/api/(?:v\d+/)?(?:user|account|profile)',
    r'(?i)(?:stripe|braintree|paypal|adyen)\.com',
    r'(?i)(?:cognito|auth0|okta|firebase)\.(?:com|amazonaws)',
]


def parse_network_security_config(config_path):
    """Parse network_security_config.xml for pinning declarations."""
    findings = []
    pinned_domains = []

    try:
        tree = etree.parse(config_path)

        # Check for pin-set declarations
        pin_sets = tree.xpath('//pin-set')
        for pin_set in pin_sets:
            expiration = pin_set.get('expiration')
            pins = pin_set.xpath('.//pin')

            if not pins:
                findings.append({
                    "RuleID": "PIN_CONFIG_EMPTY",
                    "Title": "Empty pin-set in network security config",
                    "Evidence": f"pin-set has no pins defined",
                    "Severity": "High"
                })
            elif expiration:
                # Check if pins are expired or expiring soon
                findings.append({
                    "RuleID": "PIN_CONFIG_EXPIRATION",
                    "Title": "Certificate pins have expiration date",
                    "Evidence": f"Expiration: {expiration} - verify not expired",
                    "Severity": "Info"
                })

        # Check domain-config for pinning
        domain_configs = tree.xpath('//domain-config')
        for dc in domain_configs:
            domains = dc.xpath('.//domain/text()')
            has_pins = dc.xpath('.//pin-set//pin')

            for domain in domains:
                if has_pins:
                    pinned_domains.append(domain)
                else:
                    # Check if this is a sensitive domain without pinning
                    for sensitive_pattern in SENSITIVE_ENDPOINT_PATTERNS:
                        if re.search(sensitive_pattern, domain):
                            findings.append({
                                "RuleID": "PIN_MISSING_SENSITIVE",
                                "Title": f"Sensitive domain without pinning: {domain}",
                                "Evidence": f"Domain {domain} matches sensitive pattern but has no pins",
                                "Severity": "Medium"
                            })
                            break

        # Check for debug-overrides that disable pinning
        debug_overrides = tree.xpath('//debug-overrides')
        for override in debug_overrides:
            trust_anchors = override.xpath('.//certificates[@src="user"]')
            if trust_anchors:
                findings.append({
                    "RuleID": "PIN_DEBUG_USER_CERTS",
                    "Title": "Debug builds trust user certificates",
                    "Evidence": "debug-overrides allows user certificates (check release builds)",
                    "Severity": "Info"
                })

        # Check base-config for cleartext or missing pins
        base_config = tree.xpath('//base-config')
        for bc in base_config:
            cleartext = bc.get('cleartextTrafficPermitted', 'false')
            if cleartext.lower() == 'true':
                findings.append({
                    "RuleID": "PIN_BASE_CLEARTEXT",
                    "Title": "Base config permits cleartext traffic",
                    "Evidence": "cleartextTrafficPermitted=true in base-config",
                    "Severity": "High"
                })

    except Exception as e:
        findings.append({
            "RuleID": "PIN_CONFIG_PARSE_ERROR",
            "Title": "Failed to parse network security config",
            "Evidence": str(e)[:100],
            "Severity": "Info"
        })

    return findings, pinned_domains


def find_network_security_config(src_dir):
    """Find network_security_config.xml in the source directory."""
    for root, _, files in os.walk(src_dir):
        for fn in files:
            if fn == 'network_security_config.xml':
                return os.path.join(root, fn)
    return None


def iter_text(src_dir, apk_path=None):
    """Iterate over source files."""
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
                if not fn.endswith(('.java', '.kt', '.smali')):
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
        if len(sys.argv) < 3:
            print("Usage: scan_cert_pinning.py <src_dir> <out.csv> [apk_path]", file=sys.stderr)
            sys.exit(1)

        src_dir, out = sys.argv[1], sys.argv[2]
        apk_path = sys.argv[3] if len(sys.argv) > 3 else None

        rows = []
        files_scanned = 0

        # Track pinning implementation status
        pinning_found = {
            "implementation": False,
            "config_file": False,
            "pinned_domains": [],
            "sensitive_endpoints": []
        }

        # Check for network security config
        config_path = find_network_security_config(src_dir)
        if config_path:
            pinning_found["config_file"] = True
            config_findings, pinned_domains = parse_network_security_config(config_path)
            pinning_found["pinned_domains"] = pinned_domains

            for finding in config_findings:
                rows.append({
                    "Source": "cert_pinning",
                    "RuleID": finding["RuleID"],
                    "Title": finding["Title"],
                    "Location": config_path,
                    "Evidence": finding["Evidence"],
                    "Severity": finding["Severity"],
                    "HowFound": "XML parse"
                })

        # Scan source files
        for path, text in iter_text(src_dir, apk_path):
            files_scanned += 1

            # Check for pinning implementations
            for impl_name, impl_info in PINNING_IMPLEMENTATIONS.items():
                if re.search(impl_info["pattern"], text):
                    pinning_found["implementation"] = True
                    # This is informational - pinning is present
                    rows.append({
                        "Source": "cert_pinning",
                        "RuleID": "PIN_IMPLEMENTATION_FOUND",
                        "Title": f"Certificate pinning implementation: {impl_info['description']}",
                        "Location": str(path),
                        "Evidence": impl_info["description"],
                        "Severity": "Info",
                        "HowFound": "Regex scan"
                    })

            # Check for bypass patterns
            for rid, rx, sev, desc in PINNING_BYPASS_PATTERNS:
                for m in re.finditer(rx, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "cert_pinning",
                        "RuleID": rid,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": sev,
                        "HowFound": "Regex scan"
                    })

            # Track sensitive endpoints
            for pattern in SENSITIVE_ENDPOINT_PATTERNS:
                for m in re.finditer(pattern, text):
                    endpoint = m.group(0)
                    if endpoint not in pinning_found["sensitive_endpoints"]:
                        pinning_found["sensitive_endpoints"].append(endpoint)

        # Final analysis: report if sensitive endpoints exist without pinning
        if pinning_found["sensitive_endpoints"] and not pinning_found["implementation"]:
            rows.append({
                "Source": "cert_pinning",
                "RuleID": "PIN_MISSING_FOR_SENSITIVE",
                "Title": "Sensitive endpoints without certificate pinning",
                "Location": "Codebase-wide",
                "Evidence": f"Found {len(pinning_found['sensitive_endpoints'])} sensitive endpoints: {', '.join(pinning_found['sensitive_endpoints'][:3])}...",
                "Severity": "High",
                "HowFound": "Heuristic analysis"
            })

        # Report if no pinning at all
        if not pinning_found["implementation"] and not pinning_found["config_file"]:
            rows.append({
                "Source": "cert_pinning",
                "RuleID": "PIN_NONE_FOUND",
                "Title": "No certificate pinning implementation detected",
                "Location": "Codebase-wide",
                "Evidence": f"Scanned {files_scanned} files, no pinning patterns found",
                "Severity": "Medium",
                "HowFound": "Absence detection"
            })

        # Write output
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        print(f"Wrote {out} ({len(rows)} findings, {files_scanned} files scanned)")

    except Exception as e:
        print(f"[!] Error in scan_cert_pinning: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
