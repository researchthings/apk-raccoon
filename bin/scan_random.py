#!/usr/bin/env python3
"""Scan for Insecure Random Number Generation vulnerabilities.

Detects insecure random number generation that can lead to predictable
tokens, keys, IVs, and other security-sensitive values.

Checks:
    - java.util.Random instead of SecureRandom for crypto
    - Weak seeding of random generators (time-based, constant)
    - Predictable random sources (Math.random, ThreadLocalRandom)
    - Missing SecureRandom for security operations

OWASP MASTG Coverage:
    - MASTG-TEST-0015: Testing for Insecure Random Number Generation

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


# Security-sensitive contexts where Random is dangerous
SECURITY_CONTEXTS = [
    "key", "token", "secret", "password", "salt", "iv", "nonce",
    "session", "auth", "cipher", "crypt", "hash", "signature"
]

# PRNG patterns
RANDOM_PATTERNS = [
    # Critical: java.util.Random for security purposes
    (
        r"(?:" + "|".join(SECURITY_CONTEXTS) + r")[^;]*new\s+Random\s*\(",
        "RAND_INSECURE_SECURITY",
        "Critical",
        "java.util.Random for Security Purpose",
        "java.util.Random is predictable - use SecureRandom for tokens/keys",
    ),
    # High: new Random() general usage
    (
        r"new\s+Random\s*\(\s*\)",
        "RAND_WEAK_UNSEEDED",
        "Medium",
        "java.util.Random() Without Seed",
        "Unseeded Random - if used for security, switch to SecureRandom",
    ),
    # High: Random seeded with time (predictable)
    (
        r"new\s+Random\s*\(\s*(?:System\.currentTimeMillis|System\.nanoTime)",
        "RAND_TIME_SEED",
        "High",
        "Random Seeded with Time",
        "Time-based seed is predictable - use SecureRandom",
    ),
    # High: Random seeded with constant
    (
        r"new\s+Random\s*\(\s*\d+\s*\)",
        "RAND_CONSTANT_SEED",
        "High",
        "Random Seeded with Constant",
        "Constant seed makes output predictable - use SecureRandom",
    ),
    # Medium: Math.random() for security
    (
        r"(?:" + "|".join(SECURITY_CONTEXTS[:5]) + r")[^;]*Math\.random\s*\(",
        "RAND_MATH_SECURITY",
        "High",
        "Math.random() for Security Purpose",
        "Math.random() uses weak PRNG - use SecureRandom",
    ),
    # Medium: General Math.random()
    (
        r"Math\.random\s*\(\s*\)",
        "RAND_MATH_RANDOM",
        "Low",
        "Math.random() Usage",
        "Math.random() is weak - verify not used for security",
    ),
    # High: ThreadLocalRandom for security
    (
        r"(?:" + "|".join(SECURITY_CONTEXTS[:5]) + r")[^;]*ThreadLocalRandom",
        "RAND_THREADLOCAL_SECURITY",
        "High",
        "ThreadLocalRandom for Security",
        "ThreadLocalRandom is not cryptographically secure",
    ),
    # Medium: kotlin.random for security
    (
        r"(?:" + "|".join(SECURITY_CONTEXTS[:5]) + r")[^;]*Random\.(?:nextInt|nextBytes|nextDouble)",
        "RAND_KOTLIN_SECURITY",
        "High",
        "Kotlin Random for Security",
        "Kotlin Random is not cryptographically secure",
    ),
    # Good: SecureRandom usage
    (
        r"new\s+SecureRandom\s*\(",
        "RAND_SECURE_RANDOM",
        "Info",
        "SecureRandom Usage",
        "Good: SecureRandom is cryptographically secure",
    ),
    # Good: SecureRandom.getInstance
    (
        r"SecureRandom\.getInstance\s*\(",
        "RAND_SECURE_INSTANCE",
        "Info",
        "SecureRandom.getInstance() Usage",
        "Good: SecureRandom provider instantiation",
    ),
    # Good: SecureRandom.getInstanceStrong (Java 8+)
    (
        r"SecureRandom\.getInstanceStrong\s*\(",
        "RAND_SECURE_STRONG",
        "Info",
        "SecureRandom.getInstanceStrong() Usage",
        "Good: Strong SecureRandom instance",
    ),
    # High: UUID for security without SecureRandom
    (
        r"UUID\.randomUUID\s*\(\s*\)(?![\s\S]{0,100}SecureRandom)",
        "RAND_UUID_DEFAULT",
        "Low",
        "UUID.randomUUID() Default Generator",
        "UUID.randomUUID() uses SecureRandom by default - OK for most uses",
    ),
]

# Smali patterns
SMALI_PATTERNS = [
    # java.util.Random in smali
    (
        r"new-instance\s+v\d+,\s*Ljava/util/Random;",
        "RAND_SMALI_UTIL_RANDOM",
        "Medium",
        "java.util.Random Instance (Smali)",
        "java.util.Random in smali - verify not for security",
    ),
    # SecureRandom in smali
    (
        r"new-instance\s+v\d+,\s*Ljava/security/SecureRandom;",
        "RAND_SMALI_SECURE",
        "Info",
        "SecureRandom Instance (Smali)",
        "Good: SecureRandom used in smali",
    ),
]


def scan_for_random_issues(src_dir: str) -> list[dict]:
    """Scan source code for insecure random number generation.

    Args:
        src_dir: Directory containing decompiled source files.

    Returns:
        List of finding dictionaries with vulnerability details.
    """
    findings = []
    seen = set()

    has_secure_random = False
    insecure_count = 0

    # Compile patterns
    compiled_patterns = []
    for pattern, rule_id, severity, title, description in RANDOM_PATTERNS:
        try:
            compiled_patterns.append(
                (re.compile(pattern, re.IGNORECASE | re.MULTILINE), rule_id, severity, title, description)
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

                    if "SECURE" in rule_id:
                        has_secure_random = True
                    elif severity in ("Critical", "High"):
                        insecure_count += 1

                    findings.append({
                        "Source": "random",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    # Summary
    critical_count = sum(1 for f in findings if f["Severity"] == "Critical")
    high_count = sum(1 for f in findings if f["Severity"] == "High")

    if insecure_count > 0:
        findings.append({
            "Source": "random",
            "RuleID": "RAND_SUMMARY",
            "Title": "Random Number Generator Analysis",
            "Location": "Application",
            "Evidence": f"{critical_count} critical, {high_count} high severity findings",
            "Severity": "Info",
            "HowFound": f"SecureRandom present: {has_secure_random}",
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
    """Scan for insecure random generation and write findings to CSV.

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

    findings = scan_for_random_issues(src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
