#!/usr/bin/env python3
"""Scan for Zip Slip path traversal vulnerabilities.

Detects Zip Slip vulnerabilities (CVE-2018-1000001) where archive extraction
can write files outside the target directory via path traversal sequences.

Checks:
    - ZipEntry.getName() used without path validation
    - ZipInputStream extraction without canonicalization
    - Missing "../" checks in archive handling
    - Unsafe file path construction from archive entries

OWASP MASTG Coverage:
    - MASTG-TEST-0025: Testing for Path Traversal

Author: Randy Grant
Date: 01-09-2026
Version: 1.0
"""

from __future__ import annotations

import csv
import os
import re
import sys
from pathlib import Path
from typing import Iterator

# CSV output schema
CSV_FIELDNAMES = ["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"]


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


# Zip Slip vulnerability patterns
ZIP_SLIP_PATTERNS = [
    # Critical: ZipEntry.getName() without validation used in File constructor
    (
        r"ZipEntry[^;]*\.getName\s*\(\s*\)[^;]*new\s+File\s*\(",
        "ZIP_ENTRY_TO_FILE",
        "Critical",
        "ZipEntry Name Used Directly in File Path",
        "ZipEntry.getName() used to create File without path validation - Zip Slip vulnerable",
    ),
    # Critical: ZipEntry extraction pattern without canonicalization
    (
        r"new\s+File\s*\([^)]*\.getName\s*\(\s*\)",
        "ZIP_FILE_FROM_NAME",
        "Critical",
        "File Created from Archive Entry Name",
        "File created directly from archive entry name - validate path before extraction",
    ),
    # High: ZipInputStream getNextEntry without validation
    (
        r"ZipInputStream[^}]*getNextEntry\s*\(\s*\)[^}]*(?!getCanonicalPath|startsWith|contains\s*\(\s*\"\.\./)",
        "ZIP_UNVALIDATED_ENTRY",
        "High",
        "ZipInputStream Extraction Without Path Check",
        "Zip extraction without apparent path validation",
    ),
    # High: JarEntry/JarInputStream patterns
    (
        r"JarEntry[^;]*\.getName\s*\(\s*\)[^;]*new\s+File",
        "JAR_ENTRY_TO_FILE",
        "Critical",
        "JarEntry Name Used in File Path",
        "JarEntry.getName() used to create File - same vulnerability as Zip Slip",
    ),
    # Medium: TarEntry patterns (Apache Commons Compress)
    (
        r"TarArchiveEntry[^;]*\.getName\s*\(\s*\)[^;]*new\s+File",
        "TAR_ENTRY_TO_FILE",
        "Critical",
        "TarArchiveEntry Name Used in File Path",
        "Tar entry name used to create File - path traversal vulnerable",
    ),
    # High: Missing path traversal check
    (
        r"\.getName\s*\(\s*\)[^;]*(?:FileOutputStream|FileWriter|Files\.copy)",
        "ZIP_NAME_TO_STREAM",
        "High",
        "Archive Entry Name Used in Output Stream",
        "Entry name flows to file output without validation",
    ),
    # Medium: ZipFile usage (potential extraction)
    (
        r"ZipFile\s*\([^)]+\)[^}]*getInputStream\s*\([^)]*\)[^}]*new\s+File",
        "ZIPFILE_EXTRACTION",
        "Medium",
        "ZipFile Extraction Pattern",
        "ZipFile extraction pattern - review for path validation",
    ),
    # Good: Canonicalization check (informational)
    (
        r"getCanonicalPath\s*\(\s*\)[^;]*startsWith",
        "ZIP_CANONICAL_CHECK",
        "Info",
        "Path Canonicalization Check Present",
        "Good: Canonical path validation detected",
    ),
    # Good: Path traversal check (informational)
    (
        r"(?:contains|indexOf)\s*\(\s*\"\.\./?\"|\.startsWith\s*\(\s*destDir",
        "ZIP_TRAVERSAL_CHECK",
        "Info",
        "Path Traversal Check Present",
        "Good: Path traversal validation detected",
    ),
]

# Smali-specific patterns
SMALI_PATTERNS = [
    # ZipEntry->getName in smali
    (
        r"invoke-virtual\s*\{[^}]+\},\s*Ljava/util/zip/ZipEntry;->getName\(\)Ljava/lang/String;",
        "ZIP_SMALI_GETNAME",
        "Medium",
        "ZipEntry.getName() Call (Smali)",
        "ZipEntry.getName() in smali - review extraction logic",
    ),
    # ZipInputStream->getNextEntry in smali
    (
        r"invoke-virtual\s*\{[^}]+\},\s*Ljava/util/zip/ZipInputStream;->getNextEntry\(\)Ljava/util/zip/ZipEntry;",
        "ZIP_SMALI_NEXTENTRY",
        "Medium",
        "ZipInputStream.getNextEntry() Call (Smali)",
        "Zip extraction in smali - review for path validation",
    ),
]


def scan_for_zip_slip(src_dir: str) -> list[dict]:
    """Scan source code for Zip Slip path traversal vulnerabilities.

    Args:
        src_dir: Directory containing decompiled source files.

    Returns:
        List of finding dictionaries with vulnerability details.
    """
    findings = []
    seen = set()

    # Track if we found any extraction with validation
    has_validation = False
    extraction_locations = []

    # Compile patterns
    compiled_patterns = []
    for pattern, rule_id, severity, title, description in ZIP_SLIP_PATTERNS:
        try:
            compiled_patterns.append(
                (re.compile(pattern, re.IGNORECASE | re.DOTALL), rule_id, severity, title, description)
            )
        except re.error:
            continue

    compiled_smali = []
    for pattern, rule_id, severity, title, description in SMALI_PATTERNS:
        try:
            compiled_smali.append(
                (re.compile(pattern, re.IGNORECASE), rule_id, severity, title, description)
            )
        except re.error:
            continue

    for filepath, content in iter_source_files(src_dir):
        is_smali = filepath.endswith(".smali")
        patterns_to_use = compiled_smali if is_smali else compiled_patterns

        for regex, rule_id, severity, title, description in patterns_to_use:
            for match in regex.finditer(content):
                evidence = match.group(0)
                key = (rule_id, filepath, evidence[:50])

                if key not in seen:
                    seen.add(key)

                    # Track validation patterns
                    if rule_id in ("ZIP_CANONICAL_CHECK", "ZIP_TRAVERSAL_CHECK"):
                        has_validation = True
                    elif severity in ("Critical", "High"):
                        extraction_locations.append(filepath)

                    findings.append({
                        "Source": "zip_slip",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    # If we found extraction without validation, add summary finding
    critical_count = sum(1 for f in findings if f["Severity"] == "Critical")
    high_count = sum(1 for f in findings if f["Severity"] == "High")

    if (critical_count > 0 or high_count > 0) and not has_validation:
        findings.append({
            "Source": "zip_slip",
            "RuleID": "ZIP_NO_VALIDATION",
            "Title": "Archive Extraction Without Path Validation",
            "Location": "Multiple files",
            "Evidence": f"{critical_count} critical, {high_count} high severity extractions without validation",
            "Severity": "Critical",
            "HowFound": "Add canonical path check: destFile.getCanonicalPath().startsWith(destDir.getCanonicalPath())",
        })

    # Summary
    if findings:
        findings.append({
            "Source": "zip_slip",
            "RuleID": "ZIP_SUMMARY",
            "Title": "Zip Slip Analysis Summary",
            "Location": "Application",
            "Evidence": f"{critical_count} critical, {high_count} high severity findings",
            "Severity": "Info",
            "HowFound": f"Validation patterns found: {has_validation}",
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
    """Scan for Zip Slip vulnerabilities and write findings to CSV.

    Command line args:
        sys.argv[1]: Path to source directory
        sys.argv[2]: Output CSV path

    Raises:
        SystemExit: If required arguments are missing.
    """
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <src_dir> <output.csv>", file=sys.stderr)
        sys.exit(1)

    src_dir = sys.argv[1]
    output_path = sys.argv[2]

    findings = scan_for_zip_slip(src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
