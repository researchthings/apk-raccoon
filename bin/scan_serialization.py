#!/usr/bin/env python3
"""Scan for Unsafe Deserialization vulnerabilities.

Detects insecure deserialization patterns that can lead to remote code
execution, denial of service, privilege escalation, and data tampering.

Checks:
    - ObjectInputStream.readObject() usage
    - Custom Serializable/Externalizable classes
    - Parcelable deserialization from untrusted sources
    - JSON/XML deserialization vulnerabilities (Jackson, Gson, XStream)

OWASP MASTG Coverage:
    - MASTG-TEST-0025: Testing for Insecure Deserialization

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


# Java Object Serialization patterns (most critical)
JAVA_SERIALIZATION_PATTERNS = [
    # Critical: ObjectInputStream.readObject()
    (
        r"ObjectInputStream[^;]*\.readObject\s*\(\s*\)",
        "SER_READ_OBJECT",
        "High",
        "ObjectInputStream.readObject() Usage",
        "Deserializing Java objects - vulnerable to gadget chain attacks if data is untrusted",
    ),
    # Critical: readUnshared (same risk as readObject)
    (
        r"ObjectInputStream[^;]*\.readUnshared\s*\(\s*\)",
        "SER_READ_UNSHARED",
        "High",
        "ObjectInputStream.readUnshared() Usage",
        "readUnshared has same deserialization risks as readObject",
    ),
    # Critical: ObjectInputStream from network/file
    (
        r"new\s+ObjectInputStream\s*\(\s*(?:socket|connection|url|http|input|file|stream)",
        "SER_OIS_FROM_NETWORK",
        "Critical",
        "ObjectInputStream from External Source",
        "Deserializing from network/file source - high RCE risk",
    ),
    # High: ObjectInputStream creation
    (
        r"new\s+ObjectInputStream\s*\(",
        "SER_OIS_CREATE",
        "Medium",
        "ObjectInputStream Creation",
        "ObjectInputStream instantiated - review data source",
    ),
    # High: ObjectOutputStream (indicates serialization usage)
    (
        r"ObjectOutputStream[^;]*\.writeObject\s*\(",
        "SER_WRITE_OBJECT",
        "Low",
        "ObjectOutputStream.writeObject() Usage",
        "Serialization used - review corresponding deserialization",
    ),
    # High: Custom readObject method (potential gadget)
    (
        r"private\s+void\s+readObject\s*\(\s*ObjectInputStream",
        "SER_CUSTOM_READOBJECT",
        "Medium",
        "Custom readObject() Method",
        "Custom deserialization logic - review for command execution",
    ),
    # High: Custom readResolve method
    (
        r"(?:private|protected)\s+Object\s+readResolve\s*\(",
        "SER_READ_RESOLVE",
        "Low",
        "Custom readResolve() Method",
        "Custom deserialization resolver - review for security",
    ),
]

# Android Parcelable patterns
PARCELABLE_PATTERNS = [
    # High: Parcel.readParcelable from Intent
    (
        r"getIntent\s*\(\s*\)[^;]*\.getParcelable(?:Extra|ArrayListExtra)?\s*\(",
        "SER_INTENT_PARCELABLE",
        "Medium",
        "Parcelable from Intent Extra",
        "Parcelable deserialized from Intent - validate before use",
    ),
    # High: Bundle.getParcelable
    (
        r"\.getParcelable(?:ArrayList)?\s*\(\s*[\"'][^\"']+[\"']\s*\)",
        "SER_BUNDLE_PARCELABLE",
        "Low",
        "Parcelable from Bundle",
        "Parcelable extraction - ensure data source is trusted",
    ),
    # High: Parcel.readValue (can deserialize arbitrary objects)
    (
        r"Parcel[^;]*\.readValue\s*\(\s*(?:null|getClassLoader)",
        "SER_PARCEL_READVALUE",
        "Medium",
        "Parcel.readValue() Usage",
        "readValue can deserialize arbitrary Parcelables",
    ),
    # Medium: Direct Parcel reading
    (
        r"Parcel[^;]*\.(?:readSerializable|readParcelable)\s*\(",
        "SER_PARCEL_DIRECT",
        "Medium",
        "Direct Parcel Deserialization",
        "Direct Parcel deserialization - verify data source",
    ),
    # High: createFromParcel (CREATOR pattern)
    (
        r"createFromParcel\s*\(\s*(?:Parcel|in|source)\s*\)",
        "SER_CREATE_FROM_PARCEL",
        "Low",
        "Parcelable CREATOR Pattern",
        "Parcelable deserialization - data should be from trusted source",
    ),
]

# JSON deserialization patterns
JSON_PATTERNS = [
    # High: Gson with type token (can deserialize complex types)
    (
        r"Gson\s*\(\s*\)[^;]*\.fromJson\s*\([^,]+,\s*new\s+TypeToken",
        "SER_GSON_TYPETOKEN",
        "Medium",
        "Gson TypeToken Deserialization",
        "Complex type deserialization with Gson - review type safety",
    ),
    # High: Jackson ObjectMapper with untrusted data
    (
        r"ObjectMapper[^;]*\.readValue\s*\(",
        "SER_JACKSON_READ",
        "Medium",
        "Jackson ObjectMapper.readValue()",
        "Jackson deserialization - ensure polymorphic types are restricted",
    ),
    # High: Jackson enableDefaultTyping (dangerous)
    (
        r"enableDefaultTyping|activateDefaultTyping|DefaultTyping",
        "SER_JACKSON_DEFAULT_TYPING",
        "Critical",
        "Jackson Default Typing Enabled",
        "Default typing enables polymorphic deserialization - RCE risk",
    ),
    # High: JsonParser.readValueAs
    (
        r"JsonParser[^;]*\.readValueAs\s*\(",
        "SER_JACKSON_PARSER",
        "Medium",
        "Jackson JsonParser.readValueAs()",
        "Jackson parser deserialization - review type restrictions",
    ),
]

# XML deserialization patterns
XML_PATTERNS = [
    # High: XMLDecoder (known dangerous)
    (
        r"XMLDecoder[^;]*\.readObject\s*\(",
        "SER_XML_DECODER",
        "Critical",
        "XMLDecoder.readObject() Usage",
        "XMLDecoder is inherently insecure - avoid entirely",
    ),
    # Medium: XStream deserialization
    (
        r"XStream[^;]*\.fromXML\s*\(",
        "SER_XSTREAM",
        "High",
        "XStream.fromXML() Usage",
        "XStream deserialization - requires proper security config",
    ),
    # Medium: JAXB unmarshalling
    (
        r"Unmarshaller[^;]*\.unmarshal\s*\(",
        "SER_JAXB_UNMARSHAL",
        "Low",
        "JAXB Unmarshaller Usage",
        "JAXB unmarshalling - generally safer than other XML deserializers",
    ),
]

# Serializable class declaration patterns
CLASS_PATTERNS = [
    # Info: Serializable class without serialVersionUID
    (
        r"class\s+\w+[^{]*implements[^{]*Serializable(?!.*serialVersionUID)",
        "SER_NO_SERIAL_UID",
        "Low",
        "Serializable Without serialVersionUID",
        "Missing serialVersionUID - may cause deserialization issues",
    ),
    # Info: Externalizable class
    (
        r"class\s+\w+[^{]*implements[^{]*Externalizable",
        "SER_EXTERNALIZABLE",
        "Low",
        "Externalizable Class",
        "Externalizable requires manual serialization - review readExternal()",
    ),
]

# Smali patterns
SMALI_PATTERNS = [
    # ObjectInputStream.readObject in smali
    (
        r"invoke-virtual\s*\{[^}]+\},\s*Ljava/io/ObjectInputStream;->readObject\(\)Ljava/lang/Object;",
        "SER_SMALI_READOBJECT",
        "High",
        "ObjectInputStream.readObject() (Smali)",
        "Java deserialization in smali - high risk if data is untrusted",
    ),
    # Parcel.readParcelable in smali
    (
        r"invoke-virtual\s*\{[^}]+\},\s*Landroid/os/Parcel;->readParcelable",
        "SER_SMALI_PARCEL",
        "Medium",
        "Parcel.readParcelable() (Smali)",
        "Parcelable deserialization in smali",
    ),
]


def scan_for_serialization(src_dir: str) -> list[dict]:
    """Scan source code for unsafe deserialization vulnerabilities.

    Args:
        src_dir: Directory containing decompiled source files.

    Returns:
        List of finding dictionaries with vulnerability details.
    """
    findings = []
    seen = set()

    all_patterns = (
        JAVA_SERIALIZATION_PATTERNS +
        PARCELABLE_PATTERNS +
        JSON_PATTERNS +
        XML_PATTERNS +
        CLASS_PATTERNS
    )

    # Compile patterns
    compiled_patterns = []
    for pattern, rule_id, severity, title, description in all_patterns:
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
                    findings.append({
                        "Source": "serialization",
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

    if critical_count > 0 or high_count > 0:
        findings.append({
            "Source": "serialization",
            "RuleID": "SER_SUMMARY",
            "Title": "Deserialization Analysis Summary",
            "Location": "Application",
            "Evidence": f"{critical_count} critical, {high_count} high severity findings",
            "Severity": "Info",
            "HowFound": "Review all deserialization for untrusted data sources",
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
    """Scan for deserialization vulnerabilities and write findings to CSV.

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

    findings = scan_for_serialization(src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
