#!/usr/bin/env python3
"""
APK Signature Security Scanner v1.0

Analyzes APK signing configuration for security weaknesses including:
- Signature scheme versions (v1/v2/v3/v4)
- Certificate algorithm strength
- Signature verification in code
- Debug certificate detection

References:
- https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038/
- https://developer.android.com/about/versions/pie/android-9.0#apk-key-rotation
- https://cwe.mitre.org/data/definitions/347.html

OWASP Alignment: MASVS-RESILIENCE-3
CWE: CWE-347 (Improper Verification of Cryptographic Signature)
"""

from __future__ import annotations

import csv
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Iterator

# CSV output schema
CSV_FIELDNAMES = ["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"]


def truncate(s: str, max_len: int = 150) -> str:
    """Truncate string for evidence field."""
    s = s.replace("\n", " ").replace("\r", "").strip()
    return s[:max_len] + "..." if len(s) > max_len else s


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


def check_apk_signature(apk_path: str) -> list[dict]:
    """Check APK signature using apksigner if available."""
    findings = []

    if not os.path.exists(apk_path):
        return findings

    # Try apksigner verify
    try:
        result = subprocess.run(
            ["apksigner", "verify", "--print-certs", "-v", apk_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout + result.stderr

        # Check for signature schemes
        has_v1 = "v1 scheme (JAR signing): true" in output.lower() or "verified using v1" in output.lower()
        has_v2 = "v2 scheme (APK Signature Scheme v2): true" in output.lower() or "verified using v2" in output.lower()
        has_v3 = "v3 scheme (APK Signature Scheme v3): true" in output.lower() or "verified using v3" in output.lower()

        if has_v1 and not has_v2 and not has_v3:
            findings.append({
                "Source": "apk_signature",
                "RuleID": "SIG_V1_ONLY",
                "Title": "APK Uses v1 Signature Only",
                "Location": apk_path,
                "Evidence": "Only JAR signing (v1) present",
                "Severity": "Medium",
                "HowFound": "v1 signatures can be modified without breaking verification - use v2+",
            })
        elif has_v2 and not has_v3:
            findings.append({
                "Source": "apk_signature",
                "RuleID": "SIG_V2_NO_V3",
                "Title": "APK Missing v3 Signature",
                "Location": apk_path,
                "Evidence": "v2 present, v3 missing",
                "Severity": "Low",
                "HowFound": "v3 enables key rotation - consider upgrading",
            })

        # Check for SHA1 (weak)
        if "SHA1" in output or "sha1" in output.lower():
            if "SHA256" not in output and "sha256" not in output.lower():
                findings.append({
                    "Source": "apk_signature",
                    "RuleID": "SIG_SHA1_ONLY",
                    "Title": "APK Signed with SHA1 Only",
                    "Location": apk_path,
                    "Evidence": "Certificate uses SHA1 algorithm",
                    "Severity": "High",
                    "HowFound": "SHA1 is cryptographically weak - resign with SHA256+",
                })

        # Check for debug certificate
        if "debug" in output.lower() or "CN=Android Debug" in output:
            findings.append({
                "Source": "apk_signature",
                "RuleID": "SIG_DEBUG_CERT",
                "Title": "APK Signed with Debug Certificate",
                "Location": apk_path,
                "Evidence": "Debug certificate detected",
                "Severity": "Critical",
                "HowFound": "Debug certificates should not be used in production",
            })

        # Check for weak RSA key
        if re.search(r"RSA,?\s*1024", output, re.IGNORECASE):
            findings.append({
                "Source": "apk_signature",
                "RuleID": "SIG_WEAK_RSA",
                "Title": "Weak RSA Key Size (1024-bit)",
                "Location": apk_path,
                "Evidence": "RSA 1024-bit key detected",
                "Severity": "High",
                "HowFound": "Use RSA 2048-bit or higher",
            })

        if has_v2 or has_v3:
            findings.append({
                "Source": "apk_signature",
                "RuleID": "SIG_MODERN_SCHEME",
                "Title": "Modern Signature Scheme Present",
                "Location": apk_path,
                "Evidence": f"v2: {has_v2}, v3: {has_v3}",
                "Severity": "Info",
                "HowFound": "Good: Modern APK signature scheme in use",
            })

    except FileNotFoundError:
        # apksigner not available, check META-INF manually
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    # Fallback: Check META-INF in APK
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            meta_inf_files = [n for n in zf.namelist() if n.startswith("META-INF/")]

            has_sf = any(n.endswith(".SF") for n in meta_inf_files)
            has_rsa = any(n.endswith(".RSA") for n in meta_inf_files)
            has_dsa = any(n.endswith(".DSA") for n in meta_inf_files)
            has_ec = any(n.endswith(".EC") for n in meta_inf_files)

            if has_dsa:
                findings.append({
                    "Source": "apk_signature",
                    "RuleID": "SIG_DSA_USED",
                    "Title": "DSA Signature Algorithm",
                    "Location": apk_path,
                    "Evidence": "DSA signature file in META-INF",
                    "Severity": "Medium",
                    "HowFound": "DSA is deprecated - use RSA or ECDSA",
                })

            if not has_sf:
                findings.append({
                    "Source": "apk_signature",
                    "RuleID": "SIG_MISSING_SF",
                    "Title": "Missing Signature File",
                    "Location": apk_path,
                    "Evidence": "No .SF file in META-INF",
                    "Severity": "Critical",
                    "HowFound": "APK may not be properly signed",
                })

    except zipfile.BadZipFile:
        findings.append({
            "Source": "apk_signature",
            "RuleID": "SIG_INVALID_APK",
            "Title": "Invalid APK File",
            "Location": apk_path,
            "Evidence": "Could not read as ZIP",
            "Severity": "Critical",
            "HowFound": "APK file is corrupted or invalid",
        })
    except Exception:
        pass

    return findings


# Code patterns for signature verification
CODE_PATTERNS = [
    # Good: Signature verification in code
    (
        r"PackageManager[^;]*\.getPackageInfo[^)]*GET_SIGNATURES",
        "SIG_VERIFY_CODE",
        "Info",
        "Package Signature Verification",
        "Good: App verifies its own signature",
    ),
    # Good: Signature check with specific hash
    (
        r"\.getSignatures\s*\(\s*\)[^;]*(?:equals|contains|compare)",
        "SIG_HASH_CHECK",
        "Info",
        "Signature Hash Comparison",
        "Good: Signature hash is verified",
    ),
    # Medium: Signature check without comparison
    (
        r"packageInfo\.signatures(?![\s\S]{0,100}(?:equals|compare|hash))",
        "SIG_NO_COMPARISON",
        "Medium",
        "Signature Retrieved Without Comparison",
        "Signature retrieved but not compared - verify usage",
    ),
    # High: Disabled signature verification
    (
        r"(?:SKIP|DISABLE|BYPASS).*(?:SIGNATURE|VERIFY|CHECK)",
        "SIG_DISABLED",
        "High",
        "Signature Verification Disabled",
        "Signature verification appears disabled",
    ),
]


def scan_code_for_signature(src_dir: str) -> list[dict]:
    """Scan source code for signature-related patterns."""
    findings = []
    seen = set()

    compiled_patterns = []
    for pattern, rule_id, severity, title, description in CODE_PATTERNS:
        try:
            compiled_patterns.append(
                (re.compile(pattern, re.IGNORECASE | re.MULTILINE), rule_id, severity, title, description)
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
                        "Source": "apk_signature",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    return findings


def scan_for_signature_issues(apk_path: str | None = None, src_dir: str | None = None) -> list[dict]:
    """Main scanning function."""
    findings = []

    if apk_path:
        findings.extend(check_apk_signature(apk_path))

    if src_dir:
        findings.extend(scan_code_for_signature(src_dir))

    # Summary
    critical_count = sum(1 for f in findings if f["Severity"] == "Critical")
    high_count = sum(1 for f in findings if f["Severity"] == "High")

    if findings:
        findings.append({
            "Source": "apk_signature",
            "RuleID": "SIG_SUMMARY",
            "Title": "APK Signature Analysis Summary",
            "Location": "Application",
            "Evidence": f"{critical_count} critical, {high_count} high severity findings",
            "Severity": "Info",
            "HowFound": "Use v2+ signature scheme with SHA256+ and RSA 2048+",
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
        print(f"Usage: {sys.argv[0]} <output.csv> [apk_path] [src_dir]", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    apk_path = sys.argv[2] if len(sys.argv) > 2 else None
    src_dir = sys.argv[3] if len(sys.argv) > 3 else None

    findings = scan_for_signature_issues(apk_path, src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
