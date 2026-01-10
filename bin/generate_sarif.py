#!/usr/bin/env python3
"""
SARIF Report Generator for APK Raccoon

Generates SARIF 2.1.0 (Static Analysis Results Interchange Format) output
for integration with GitHub Security, GitLab, Azure DevOps, and other CI/CD tools.

SARIF Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/

Usage:
    python generate_sarif.py <findings.csv> <output.sarif> [--tool-version VERSION]
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Tool metadata
TOOL_NAME = "APK Raccoon"
TOOL_INFORMATION_URI = "https://github.com/anthropics/claude-code"
TOOL_VERSION = "2.0.0"

# SARIF schema
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

# Severity to SARIF level mapping
SEVERITY_TO_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "none",
}

# Severity to SARIF security-severity score (CVSS-like 0-10)
SEVERITY_TO_SCORE = {
    "Critical": "9.0",
    "High": "7.5",
    "Medium": "5.0",
    "Low": "3.0",
    "Info": "0.0",
}

# OWASP MASVS mapping
OWASP_MAPPING = {
    "MAN_": ("MASVS-PLATFORM-1", "Platform Security - Component Configuration"),
    "COMP_": ("MASVS-PLATFORM-1", "Platform Security - Exported Components"),
    "SEC_": ("MASVS-STORAGE-1", "Storage Security - Sensitive Data"),
    "API_KEY": ("MASVS-STORAGE-1", "Storage Security - API Keys"),
    "CRYPTO_": ("MASVS-CRYPTO-1", "Cryptography - Algorithm Security"),
    "WEAK_": ("MASVS-CRYPTO-1", "Cryptography - Weak Algorithms"),
    "WEB_": ("MASVS-PLATFORM-2", "Platform Security - WebView"),
    "WEBVIEW_": ("MASVS-PLATFORM-2", "Platform Security - WebView"),
    "LOG_": ("MASVS-STORAGE-2", "Storage Security - Logging"),
    "STORAGE_": ("MASVS-STORAGE-1", "Storage Security - Data Protection"),
    "NET_": ("MASVS-NETWORK-1", "Network Security - Transport"),
    "SSL_": ("MASVS-NETWORK-2", "Network Security - Certificate Validation"),
    "TLS_": ("MASVS-NETWORK-2", "Network Security - TLS Configuration"),
    "CERT_": ("MASVS-NETWORK-2", "Network Security - Certificate Pinning"),
    "AUTH_": ("MASVS-AUTH-1", "Authentication - Local Auth"),
    "BIOMETRIC_": ("MASVS-AUTH-2", "Authentication - Biometric"),
    "SQL_": ("MASVS-CODE-4", "Code Security - SQL Injection"),
    "CMD_": ("MASVS-CODE-4", "Code Security - Command Injection"),
    "INJ_": ("MASVS-CODE-4", "Code Security - Injection"),
    "BIN_": ("MASVS-RESILIENCE-1", "Resilience - Binary Protection"),
    "ROOT_": ("MASVS-RESILIENCE-2", "Resilience - Root Detection"),
    "PRIV_": ("MASVS-PRIVACY-1", "Privacy - Data Collection"),
    "PII_": ("MASVS-PRIVACY-1", "Privacy - PII Exposure"),
    "PROV_": ("MASVS-PLATFORM-1", "Platform Security - Content Providers"),
    "PEND_": ("MASVS-PLATFORM-1", "Platform Security - PendingIntent"),
    "FIRE_": ("MASVS-STORAGE-1", "Storage Security - Firebase"),
    "TASK_": ("MASVS-PLATFORM-1", "Platform Security - Task Hijacking"),
    "DEEP_": ("MASVS-PLATFORM-1", "Platform Security - Deep Links"),
    "LINK_": ("MASVS-PLATFORM-1", "Platform Security - URL Handling"),
    "TAP_": ("MASVS-PLATFORM-3", "Platform Security - Tapjacking"),
    "BCAST_": ("MASVS-PLATFORM-1", "Platform Security - Broadcasts"),
    "NATIVE_": ("MASVS-CODE-3", "Code Security - Native Code"),
    "ELF_": ("MASVS-CODE-3", "Code Security - Binary Protections"),
    "DYN_": ("MASVS-CODE-4", "Code Security - Dynamic Loading"),
    "LOAD_": ("MASVS-CODE-4", "Code Security - Code Loading"),
    "ZIP_": ("MASVS-CODE-4", "Code Security - Path Traversal"),
    "SER_": ("MASVS-CODE-4", "Code Security - Deserialization"),
    "FRAG_": ("MASVS-PLATFORM-1", "Platform Security - Fragment Injection"),
    "XXE_": ("MASVS-CODE-4", "Code Security - XML Injection"),
    "IMPL_": ("MASVS-PLATFORM-1", "Platform Security - Intent Handling"),
    "CLIP_": ("MASVS-STORAGE-2", "Storage Security - Clipboard"),
    "KEY_": ("MASVS-STORAGE-2", "Storage Security - Keyboard Cache"),
    "RAND_": ("MASVS-CRYPTO-1", "Cryptography - Random Number Generation"),
    "SIG_": ("MASVS-RESILIENCE-3", "Resilience - Code Signing"),
    "DEP_": ("MASVS-CODE-4", "Code Security - Deprecated APIs"),
}

# CWE mapping with full descriptions
CWE_MAPPING = {
    "ZIP_": ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"),
    "SER_": ("CWE-502", "Deserialization of Untrusted Data"),
    "FRAG_": ("CWE-470", "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')"),
    "XXE_": ("CWE-611", "Improper Restriction of XML External Entity Reference"),
    "IMPL_": ("CWE-927", "Use of Implicit Intent for Sensitive Communication"),
    "CLIP_": ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
    "KEY_": ("CWE-524", "Use of Cache Containing Sensitive Information"),
    "RAND_": ("CWE-338", "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)"),
    "SIG_": ("CWE-347", "Improper Verification of Cryptographic Signature"),
    "DEP_": ("CWE-477", "Use of Obsolete Function"),
    "SQL_": ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"),
    "CMD_": ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"),
    "CRYPTO_": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "NET_HTTP": ("CWE-319", "Cleartext Transmission of Sensitive Information"),
    "SSL_": ("CWE-295", "Improper Certificate Validation"),
    "LOG_": ("CWE-532", "Insertion of Sensitive Information into Log File"),
    "SEC_": ("CWE-798", "Use of Hard-coded Credentials"),
    "API_KEY": ("CWE-798", "Use of Hard-coded Credentials"),
    "MAN_DEBUG": ("CWE-489", "Active Debug Code"),
    "MAN_BACKUP": ("CWE-919", "Weaknesses in Mobile Applications"),
    "WEB_JS": ("CWE-749", "Exposed Dangerous Method or Function"),
    "PROV_": ("CWE-926", "Improper Export of Android Application Components"),
    "PEND_": ("CWE-927", "Use of Implicit Intent for Sensitive Communication"),
    "TASK_": ("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
    "TAP_": ("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
    "ROOT_": ("CWE-656", "Reliance on Security Through Obscurity"),
}


def get_owasp_info(rule_id: str) -> tuple[str, str]:
    """Get OWASP MASVS category and description for a rule ID."""
    for prefix, info in OWASP_MAPPING.items():
        if rule_id.startswith(prefix):
            return info
    return ("MASVS-CODE-4", "Code Security")


def get_cwe_info(rule_id: str) -> tuple[str, str] | None:
    """Get CWE ID and description for a rule ID."""
    for prefix, info in CWE_MAPPING.items():
        if rule_id.startswith(prefix):
            return info
    return None


def generate_rule_id_hash(rule_id: str) -> str:
    """Generate a stable hash for a rule ID (for SARIF fingerprint)."""
    return hashlib.sha256(rule_id.encode()).hexdigest()[:16]


def read_findings(csv_path: str) -> list[dict]:
    """Read findings from CSV file."""
    findings = []
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Skip summary rows
                if row.get("RuleID", "").endswith("_SUMMARY"):
                    continue
                findings.append(row)
    except Exception as e:
        print(f"Error reading CSV: {e}", file=sys.stderr)
        sys.exit(1)
    return findings


def build_rules(findings: list[dict]) -> list[dict]:
    """Build SARIF rules array from findings."""
    rules = {}

    for finding in findings:
        rule_id = finding.get("RuleID", "UNKNOWN")
        if rule_id in rules:
            continue

        severity = finding.get("Severity", "Medium")
        title = finding.get("Title", rule_id)
        how_found = finding.get("HowFound", "")
        source = finding.get("Source", "")

        owasp_id, owasp_desc = get_owasp_info(rule_id)
        cwe_info = get_cwe_info(rule_id)

        rule: dict[str, Any] = {
            "id": rule_id,
            "name": title.replace(" ", ""),
            "shortDescription": {
                "text": title
            },
            "fullDescription": {
                "text": how_found or title
            },
            "helpUri": f"https://mas.owasp.org/MASTG/",
            "properties": {
                "security-severity": SEVERITY_TO_SCORE.get(severity, "5.0"),
                "tags": [
                    "security",
                    f"scanner/{source}",
                    f"owasp/{owasp_id}",
                ]
            }
        }

        # Add CWE relationship if available
        if cwe_info:
            cwe_id, cwe_desc = cwe_info
            rule["relationships"] = [{
                "target": {
                    "id": cwe_id,
                    "guid": f"cwe-{cwe_id.split('-')[1]}",
                    "toolComponent": {
                        "name": "CWE",
                        "guid": "cwe-taxonomy"
                    }
                },
                "kinds": ["superset"]
            }]
            rule["properties"]["tags"].append(f"external/cwe/{cwe_id}")

        # Add OWASP tag
        rule["properties"]["tags"].append(f"external/owasp/{owasp_id}")

        rules[rule_id] = rule

    return list(rules.values())


def build_results(findings: list[dict]) -> list[dict]:
    """Build SARIF results array from findings."""
    results = []

    for i, finding in enumerate(findings):
        rule_id = finding.get("RuleID", "UNKNOWN")
        severity = finding.get("Severity", "Medium")
        location = finding.get("Location", "Unknown")
        evidence = finding.get("Evidence", "")
        how_found = finding.get("HowFound", "")

        # Build location
        artifact_location = {
            "uri": location,
            "uriBaseId": "%SRCROOT%"
        }

        # If location looks like a file path, try to extract it
        if "/" in location or "\\" in location:
            # Normalize path
            artifact_location["uri"] = location.replace("\\", "/")

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": i,
            "level": SEVERITY_TO_LEVEL.get(severity, "warning"),
            "message": {
                "text": f"{finding.get('Title', rule_id)}: {how_found}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": artifact_location
                }
            }],
            "fingerprints": {
                "primaryLocationLineHash": generate_rule_id_hash(f"{rule_id}:{location}:{evidence[:50]}")
            }
        }

        # Add code flow for evidence
        if evidence:
            result["codeFlows"] = [{
                "threadFlows": [{
                    "locations": [{
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": artifact_location
                            },
                            "message": {
                                "text": evidence[:500]  # Truncate evidence
                            }
                        }
                    }]
                }]
            }]

        results.append(result)

    return results


def generate_sarif_report(
    findings: list[dict],
    output_path: str,
    tool_version: str = TOOL_VERSION
):
    """Generate SARIF 2.1.0 report from findings."""

    rules = build_rules(findings)
    results = build_results(findings)

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": tool_version,
                    "informationUri": TOOL_INFORMATION_URI,
                    "rules": rules,
                    "supportedTaxonomies": [
                        {
                            "name": "CWE",
                            "guid": "cwe-taxonomy",
                            "informationUri": "https://cwe.mitre.org/"
                        },
                        {
                            "name": "OWASP MASVS",
                            "guid": "owasp-masvs",
                            "informationUri": "https://mas.owasp.org/MASVS/"
                        }
                    ]
                }
            },
            "taxonomies": [
                {
                    "name": "CWE",
                    "guid": "cwe-taxonomy",
                    "version": "4.12",
                    "informationUri": "https://cwe.mitre.org/",
                    "downloadUri": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
                    "organization": "MITRE",
                    "shortDescription": {
                        "text": "Common Weakness Enumeration"
                    }
                }
            ],
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat()
            }]
        }]
    }

    # Write SARIF file
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    # Summary
    severity_counts = {}
    for finding in findings:
        sev = finding.get("Severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"Generated SARIF report: {output_path}")
    print(f"  SARIF version: {SARIF_VERSION}")
    print(f"  Total results: {len(results)}")
    print(f"  Unique rules: {len(rules)}")
    print(f"  Severity breakdown:")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev in severity_counts:
            print(f"    {sev}: {severity_counts[sev]}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate SARIF report from APK Raccoon findings"
    )
    parser.add_argument("csv_file", help="Input CSV file with findings")
    parser.add_argument("output_file", help="Output SARIF file path")
    parser.add_argument(
        "--tool-version",
        default=TOOL_VERSION,
        help=f"Tool version for SARIF (default: {TOOL_VERSION})"
    )

    args = parser.parse_args()

    if not os.path.exists(args.csv_file):
        print(f"Error: CSV file not found: {args.csv_file}", file=sys.stderr)
        sys.exit(1)

    findings = read_findings(args.csv_file)
    generate_sarif_report(findings, args.output_file, args.tool_version)


if __name__ == "__main__":
    main()
