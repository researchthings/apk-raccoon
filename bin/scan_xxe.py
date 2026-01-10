#!/usr/bin/env python3
"""
XXE (XML External Entity) Injection Scanner v1.0

Detects XML parser configurations vulnerable to XXE attacks that can lead to:
- Local file disclosure
- Server-side request forgery (SSRF)
- Denial of service (billion laughs attack)
- Remote code execution (in some environments)

Checks for:
- SAXParser without feature restrictions
- DocumentBuilder without secure configuration
- XMLReader without disabled external entities
- XPath injection vulnerabilities
- Missing FEATURE_SECURE_PROCESSING

References:
- https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0025/
- https://cwe.mitre.org/data/definitions/611.html
- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

OWASP Alignment: MASVS-CODE-4
CWE: CWE-611 (Improper Restriction of XML External Entity Reference)
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


# XXE vulnerability patterns
XXE_PATTERNS = [
    # Critical: SAXParserFactory without feature restrictions
    (
        r"SAXParserFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,500}setFeature)",
        "XXE_SAX_NO_FEATURE",
        "High",
        "SAXParserFactory Without Security Features",
        "SAXParserFactory should disable external entities with setFeature()",
    ),
    # Critical: DocumentBuilderFactory without feature restrictions
    (
        r"DocumentBuilderFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,500}setFeature)",
        "XXE_DOM_NO_FEATURE",
        "High",
        "DocumentBuilderFactory Without Security Features",
        "DocumentBuilderFactory should disable DTDs and external entities",
    ),
    # Critical: XMLInputFactory without restrictions
    (
        r"XMLInputFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,500}setProperty)",
        "XXE_STAX_NO_PROPERTY",
        "High",
        "XMLInputFactory Without Security Properties",
        "XMLInputFactory should disable DTD and external entities",
    ),
    # Critical: XMLReader without feature restrictions
    (
        r"XMLReader[^;]*(?:getXMLReader|newXMLReader)\s*\(\s*\)(?![\s\S]{0,500}setFeature)",
        "XXE_XMLREADER_NO_FEATURE",
        "High",
        "XMLReader Without Security Features",
        "XMLReader should disable external entities",
    ),
    # High: XPathFactory (potential XXE via input)
    (
        r"XPathFactory\.newInstance\s*\(\s*\)[^;]*\.newXPath",
        "XXE_XPATH_FACTORY",
        "Medium",
        "XPathFactory Usage",
        "XPath with untrusted input can enable XXE - review XML source",
    ),
    # High: TransformerFactory (potential XXE)
    (
        r"TransformerFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,500}setFeature|setAttribute)",
        "XXE_TRANSFORMER_NO_FEATURE",
        "High",
        "TransformerFactory Without Security Features",
        "TransformerFactory can be vulnerable to XXE",
    ),
    # High: SchemaFactory (potential XXE)
    (
        r"SchemaFactory\.newInstance\s*\([^)]+\)(?![\s\S]{0,500}setFeature|setProperty)",
        "XXE_SCHEMA_NO_FEATURE",
        "Medium",
        "SchemaFactory Without Security Features",
        "SchemaFactory should disable external entities",
    ),
    # Medium: Unmarshaller (JAXB XXE)
    (
        r"JAXBContext[^;]*\.createUnmarshaller\s*\(\s*\)(?![\s\S]{0,300}setProperty)",
        "XXE_JAXB_UNMARSHALLER",
        "Medium",
        "JAXB Unmarshaller Without Properties",
        "JAXB unmarshalling can be vulnerable to XXE",
    ),
    # High: XmlPullParser with external entity
    (
        r"XmlPullParser[^;]*setFeature\s*\([^)]*PROCESS_DOCDECL",
        "XXE_PULLPARSER_DOCTYPE",
        "High",
        "XmlPullParser DOCTYPE Processing Enabled",
        "DOCTYPE processing can enable XXE attacks",
    ),
    # Good: Proper XXE prevention (informational)
    (
        r"setFeature\s*\([^)]*(?:FEATURE_SECURE_PROCESSING|disallow-doctype-decl)[^)]*,\s*true",
        "XXE_SECURE_FEATURE",
        "Info",
        "Secure Processing Feature Enabled",
        "Good: Secure processing feature is enabled",
    ),
    # Good: External entities disabled
    (
        r"setFeature\s*\([^)]*external-(?:general|parameter)-entities[^)]*,\s*false",
        "XXE_EXTERNAL_DISABLED",
        "Info",
        "External Entities Disabled",
        "Good: External entities are disabled",
    ),
    # Good: DTD loading disabled
    (
        r"setFeature\s*\([^)]*load-external-dtd[^)]*,\s*false",
        "XXE_DTD_DISABLED",
        "Info",
        "External DTD Loading Disabled",
        "Good: External DTD loading is disabled",
    ),
    # High: Validator with untrusted input
    (
        r"Validator[^;]*\.validate\s*\(\s*new\s+(?:Stream|DOM)Source\s*\(",
        "XXE_VALIDATOR_SOURCE",
        "Medium",
        "Validator with External Source",
        "Validation with external source - ensure XXE protection",
    ),
]

# Dangerous configurations (explicitly enabling external entities)
DANGEROUS_PATTERNS = [
    # Critical: Explicitly enabling external entities
    (
        r"setFeature\s*\([^)]*external-(?:general|parameter)-entities[^)]*,\s*true",
        "XXE_EXTERNAL_ENABLED",
        "Critical",
        "External Entities Explicitly Enabled",
        "External entities are explicitly enabled - HIGH XXE risk",
    ),
    # Critical: Enabling DTD processing
    (
        r"setFeature\s*\([^)]*(?:load-external-dtd|http://apache\.org/xml/features/nonvalidating/load-dtd-grammar)[^)]*,\s*true",
        "XXE_DTD_ENABLED",
        "Critical",
        "External DTD Loading Enabled",
        "External DTD loading enabled - XXE and SSRF risk",
    ),
    # High: setExpandEntityReferences(true)
    (
        r"setExpandEntityReferences\s*\(\s*true\s*\)",
        "XXE_EXPAND_ENTITIES",
        "High",
        "Entity Expansion Enabled",
        "Entity expansion enabled - denial of service risk",
    ),
]

# Network/file operations following XML parsing
DATA_FLOW_PATTERNS = [
    # High: URL from XML content
    (
        r"(?:getText|getNodeValue|getTextContent)\s*\(\s*\)[^;]*(?:URL|openConnection|HttpURLConnection)",
        "XXE_XML_TO_URL",
        "High",
        "XML Content Used in URL",
        "XML content flows to network operation - potential SSRF",
    ),
    # High: File from XML content
    (
        r"(?:getText|getNodeValue|getTextContent)\s*\(\s*\)[^;]*new\s+File",
        "XXE_XML_TO_FILE",
        "High",
        "XML Content Used in File Path",
        "XML content flows to file operation - potential file disclosure",
    ),
]

# Smali patterns
SMALI_PATTERNS = [
    # SAXParserFactory in smali
    (
        r"invoke-static\s*\{[^}]*\},\s*Ljavax/xml/parsers/SAXParserFactory;->newInstance",
        "XXE_SMALI_SAX",
        "Medium",
        "SAXParserFactory.newInstance() (Smali)",
        "SAX parser in smali - review for XXE protection",
    ),
    # DocumentBuilderFactory in smali
    (
        r"invoke-static\s*\{[^}]*\},\s*Ljavax/xml/parsers/DocumentBuilderFactory;->newInstance",
        "XXE_SMALI_DOM",
        "Medium",
        "DocumentBuilderFactory.newInstance() (Smali)",
        "DOM parser in smali - review for XXE protection",
    ),
]


def scan_for_xxe(src_dir: str) -> list[dict]:
    """Scan source code for XXE vulnerabilities."""
    findings = []
    seen = set()

    # Track security measures
    has_secure_config = False
    parser_count = 0

    all_patterns = XXE_PATTERNS + DANGEROUS_PATTERNS + DATA_FLOW_PATTERNS

    # Compile patterns
    compiled_patterns = []
    for pattern, rule_id, severity, title, description in all_patterns:
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

                    # Track security measures
                    if rule_id in ("XXE_SECURE_FEATURE", "XXE_EXTERNAL_DISABLED", "XXE_DTD_DISABLED"):
                        has_secure_config = True
                    elif "NO_FEATURE" in rule_id or "NO_PROPERTY" in rule_id:
                        parser_count += 1

                    findings.append({
                        "Source": "xxe",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    # Add summary if parsers found without protection
    if parser_count > 0 and not has_secure_config:
        findings.append({
            "Source": "xxe",
            "RuleID": "XXE_NO_PROTECTION",
            "Title": f"XML Parsers Without XXE Protection ({parser_count} found)",
            "Location": "Multiple files",
            "Evidence": f"{parser_count} XML parser(s) without apparent security configuration",
            "Severity": "High",
            "HowFound": "Add: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
        })

    # Summary
    critical_count = sum(1 for f in findings if f["Severity"] == "Critical")
    high_count = sum(1 for f in findings if f["Severity"] == "High")

    if findings:
        findings.append({
            "Source": "xxe",
            "RuleID": "XXE_SUMMARY",
            "Title": "XXE Analysis Summary",
            "Location": "Application",
            "Evidence": f"{critical_count} critical, {high_count} high severity findings",
            "Severity": "Info",
            "HowFound": f"Secure configurations found: {has_secure_config}",
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
        print(f"Usage: {sys.argv[0]} <src_dir> <output.csv>", file=sys.stderr)
        sys.exit(1)

    src_dir = sys.argv[1]
    output_path = sys.argv[2]

    findings = scan_for_xxe(src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
