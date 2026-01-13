#!/usr/bin/env python3
"""Scan for Dynamic Code Loading vulnerabilities.

Detects insecure dynamic code loading patterns that can lead to code
injection, remote code execution, and arbitrary code execution.

Checks:
    - DexClassLoader usage and patterns
    - Code loading from external storage
    - Downloaded DEX file patterns
    - Reflection-based code execution
    - Missing integrity verification

OWASP MASTG Coverage:
    - MASTG-TEST-0038: Testing for Dynamic Code Loading
    - MASTG-TEST-0039: Testing for Code Injection

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


# Dynamic code loading patterns
DYNAMIC_LOADING_PATTERNS = [
    # DexClassLoader - primary code loading mechanism
    (
        r"DexClassLoader\s*\(",
        "DYN_DEX_CLASSLOADER",
        "High",
        "DexClassLoader Usage",
        "DexClassLoader found - can load arbitrary DEX code at runtime",
    ),
    # PathClassLoader
    (
        r"PathClassLoader\s*\(",
        "DYN_PATH_CLASSLOADER",
        "Medium",
        "PathClassLoader Usage",
        "PathClassLoader found - review source of loaded classes",
    ),
    # BaseDexClassLoader
    (
        r"BaseDexClassLoader\s*\(",
        "DYN_BASE_CLASSLOADER",
        "Medium",
        "BaseDexClassLoader Usage",
        "Custom class loader extending BaseDexClassLoader",
    ),
    # InMemoryDexClassLoader (Android 8.0+)
    (
        r"InMemoryDexClassLoader\s*\(",
        "DYN_INMEMORY_CLASSLOADER",
        "High",
        "InMemoryDexClassLoader Usage",
        "Loading DEX directly from memory - review data source",
    ),
    # DelegateLastClassLoader
    (
        r"DelegateLastClassLoader\s*\(",
        "DYN_DELEGATE_CLASSLOADER",
        "Medium",
        "DelegateLastClassLoader Usage",
        "Custom class loading order - review for security implications",
    ),
    # Class.forName with dynamic string
    (
        r"Class\.forName\s*\([^\"'\)]+\)",
        "DYN_CLASS_FORNAME",
        "Medium",
        "Dynamic Class.forName",
        "Class loaded by dynamic name - potential for class injection",
    ),
    # loadClass method
    (
        r"\.loadClass\s*\([^)]+\)",
        "DYN_LOAD_CLASS",
        "Medium",
        "Dynamic loadClass",
        "Dynamic class loading - review class name source",
    ),
    # defineClass (custom class definition)
    (
        r"defineClass\s*\(",
        "DYN_DEFINE_CLASS",
        "High",
        "Custom Class Definition",
        "Defining class from raw bytes - high risk of code injection",
    ),
    # External storage paths in class loading context
    (
        r"getExternalStorageDirectory\(\).*(?:DexClassLoader|PathClassLoader|loadClass)",
        "DYN_EXTERNAL_STORAGE_LOAD",
        "Critical",
        "Loading Code from External Storage",
        "Code loaded from external storage - any app can modify these files",
    ),
    # Download and execute pattern
    (
        r"(?:download|fetch|get).*\.dex|\.dex.*(?:download|fetch|get)",
        "DYN_DOWNLOAD_DEX",
        "Critical",
        "DEX File Download Pattern",
        "Pattern suggests downloading DEX files - remote code execution risk",
    ),
    # Reflection with invoke
    (
        r"Method\.invoke\s*\(",
        "DYN_METHOD_INVOKE",
        "Low",
        "Reflection Method.invoke",
        "Reflective method invocation - review for dynamic class usage",
    ),
    # Constructor.newInstance
    (
        r"Constructor\.newInstance\s*\(",
        "DYN_CONSTRUCTOR_NEWINSTANCE",
        "Low",
        "Reflective Constructor Instantiation",
        "Reflective instantiation - review class source",
    ),
    # Runtime.exec with downloaded content
    (
        r"Runtime\.getRuntime\(\)\.exec\s*\(",
        "DYN_RUNTIME_EXEC",
        "High",
        "Runtime.exec Call",
        "Command execution - review for dynamic command construction",
    ),
    # ProcessBuilder
    (
        r"ProcessBuilder\s*\(",
        "DYN_PROCESS_BUILDER",
        "Medium",
        "ProcessBuilder Usage",
        "Process creation - review command source",
    ),
    # ScriptEngine (JavaScript, Groovy, etc.)
    (
        r"ScriptEngine(?:Manager)?|\.eval\s*\(",
        "DYN_SCRIPT_ENGINE",
        "High",
        "Script Engine Usage",
        "Script evaluation engine - potential code injection vector",
    ),
    # Rhino JavaScript engine
    (
        r"org\.mozilla\.javascript|Rhino",
        "DYN_RHINO",
        "High",
        "Rhino JavaScript Engine",
        "Rhino JS engine detected - review script sources",
    ),
    # Smali: invoke-virtual DexClassLoader
    (
        r"invoke-virtual.*Ldalvik/system/DexClassLoader",
        "DYN_SMALI_DEXLOADER",
        "High",
        "DexClassLoader in Smali",
        "DexClassLoader invocation in bytecode",
    ),
    # Smali: loadDex
    (
        r"invoke.*loadDex",
        "DYN_SMALI_LOADDEX",
        "High",
        "loadDex in Smali",
        "DEX loading operation in bytecode",
    ),
    # Asset-based DEX loading
    (
        r"getAssets\(\).*\.dex|\.dex.*getAssets\(\)",
        "DYN_ASSET_DEX",
        "Medium",
        "DEX Loaded from Assets",
        "DEX file loaded from assets - verify file integrity",
    ),
    # Cache directory DEX loading
    (
        r"getCacheDir\(\).*(?:DexClassLoader|PathClassLoader)|(?:DexClassLoader|PathClassLoader).*getCacheDir\(\)",
        "DYN_CACHE_DEX",
        "Medium",
        "DEX Loaded from Cache",
        "DEX loaded from cache directory - verify file source",
    ),
    # Files directory DEX loading
    (
        r"getFilesDir\(\).*(?:DexClassLoader|PathClassLoader)|(?:DexClassLoader|PathClassLoader).*getFilesDir\(\)",
        "DYN_FILES_DEX",
        "Low",
        "DEX Loaded from Internal Files",
        "DEX loaded from internal files - lower risk but verify source",
    ),
]

# Patterns indicating safer practices
SAFE_LOADING_PATTERNS = [
    # Signature verification before loading
    (
        r"(?:verify|check).*(?:signature|certificate|hash).*(?:DexClassLoader|load)",
        "DYN_SIGNATURE_CHECK",
        "Info",
        "Signature Verification Detected",
        "Good: Signature verification before code loading",
    ),
    # Hash verification
    (
        r"(?:MD5|SHA|hash|digest).*(?:DexClassLoader|PathClassLoader)",
        "DYN_HASH_CHECK",
        "Info",
        "Hash Verification Detected",
        "Good: Hash verification pattern found for code loading",
    ),
]

# DEX file patterns in various contexts
DEX_FILE_PATTERNS = [
    # .dex file references
    (
        r"[\"'][^\"']*\.dex[\"']",
        "DYN_DEX_REFERENCE",
        "Medium",
        "DEX File Reference",
        "Reference to .dex file found",
    ),
    # .jar file references (can contain DEX)
    (
        r"[\"'][^\"']*\.jar[\"'].*(?:ClassLoader|loadClass)",
        "DYN_JAR_CLASSLOADER",
        "Medium",
        "JAR File with ClassLoader",
        "JAR file loaded via ClassLoader - may contain DEX",
    ),
    # .apk file references for loading
    (
        r"[\"'][^\"']*\.apk[\"'].*(?:ClassLoader|loadClass)",
        "DYN_APK_CLASSLOADER",
        "Medium",
        "APK File with ClassLoader",
        "APK file used with ClassLoader",
    ),
]


def scan_code_for_dynamic_loading(src_dir: str) -> list[dict]:
    """Scan source code for dynamic code loading patterns.

    Args:
        src_dir: Directory containing decompiled source files.

    Returns:
        List of finding dictionaries for dynamic loading patterns.
    """
    findings = []
    seen = set()

    # Compile all patterns
    all_patterns = DYNAMIC_LOADING_PATTERNS + SAFE_LOADING_PATTERNS + DEX_FILE_PATTERNS
    compiled_patterns = []
    for pattern, rule_id, severity, title, description in all_patterns:
        try:
            compiled_patterns.append(
                (re.compile(pattern, re.IGNORECASE | re.DOTALL), rule_id, severity, title, description)
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
                        "Source": "dynamic_loading",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    return findings


def analyze_loading_context(findings: list[dict]) -> list[dict]:
    """Analyze patterns to provide context-aware findings.

    Args:
        findings: List of finding dictionaries from initial scan.

    Returns:
        List of additional findings based on pattern analysis.
    """
    analysis_findings = []

    # Check for high-risk combinations
    rule_ids = {f["RuleID"] for f in findings}

    # Critical: External storage + class loading
    if "DYN_EXTERNAL_STORAGE_LOAD" in rule_ids:
        analysis_findings.append({
            "Source": "dynamic_loading",
            "RuleID": "DYN_CRITICAL_EXTERNAL",
            "Title": "CRITICAL: Code Loaded from World-Writable Location",
            "Location": "Application",
            "Evidence": "External storage + class loading detected",
            "Severity": "Critical",
            "HowFound": "Any app can place malicious code in external storage - never load code from there",
        })

    # Critical: Download + DEX pattern
    if "DYN_DOWNLOAD_DEX" in rule_ids:
        analysis_findings.append({
            "Source": "dynamic_loading",
            "RuleID": "DYN_CRITICAL_DOWNLOAD",
            "Title": "CRITICAL: Remote Code Loading Pattern",
            "Location": "Application",
            "Evidence": "DEX download pattern detected",
            "Severity": "Critical",
            "HowFound": "Downloading and loading code enables remote code execution attacks",
        })

    # High: DexClassLoader without verification
    has_dex_loader = any(r.startswith("DYN_DEX_CLASSLOADER") or r == "DYN_SMALI_DEXLOADER" for r in rule_ids)
    has_verification = "DYN_SIGNATURE_CHECK" in rule_ids or "DYN_HASH_CHECK" in rule_ids

    if has_dex_loader and not has_verification:
        analysis_findings.append({
            "Source": "dynamic_loading",
            "RuleID": "DYN_NO_VERIFICATION",
            "Title": "DexClassLoader Without Integrity Verification",
            "Location": "Application",
            "Evidence": "DexClassLoader found but no signature/hash verification detected",
            "Severity": "High",
            "HowFound": "Always verify integrity of dynamically loaded code",
        })

    # Medium: Multiple class loading mechanisms
    loader_count = sum(1 for r in rule_ids if r in (
        "DYN_DEX_CLASSLOADER", "DYN_PATH_CLASSLOADER", "DYN_BASE_CLASSLOADER",
        "DYN_INMEMORY_CLASSLOADER", "DYN_DELEGATE_CLASSLOADER"
    ))
    if loader_count >= 2:
        analysis_findings.append({
            "Source": "dynamic_loading",
            "RuleID": "DYN_MULTIPLE_LOADERS",
            "Title": f"Multiple Class Loading Mechanisms ({loader_count} types)",
            "Location": "Application",
            "Evidence": f"{loader_count} different class loader types detected",
            "Severity": "Medium",
            "HowFound": "Complex class loading architecture - review all loading paths",
        })

    # Good: Has verification
    if has_verification:
        analysis_findings.append({
            "Source": "dynamic_loading",
            "RuleID": "DYN_HAS_VERIFICATION",
            "Title": "Code Integrity Verification Present",
            "Location": "Application",
            "Evidence": "Signature or hash verification detected",
            "Severity": "Info",
            "HowFound": "Good: App appears to verify code before loading",
        })

    return analysis_findings


def scan_for_dynamic_loading(src_dir: str) -> list[dict]:
    """Scan for dynamic code loading vulnerabilities.

    Args:
        src_dir: Directory containing decompiled source files.

    Returns:
        List of finding dictionaries with vulnerability details.
    """
    findings = []

    if not src_dir or not os.path.exists(src_dir):
        findings.append({
            "Source": "dynamic_loading",
            "RuleID": "DYN_NO_SOURCE",
            "Title": "No Source Directory Provided",
            "Location": "N/A",
            "Evidence": "Source directory required for dynamic loading analysis",
            "Severity": "Info",
            "HowFound": "Provide decompiled source directory",
        })
        return findings

    # Scan code
    code_findings = scan_code_for_dynamic_loading(src_dir)
    findings.extend(code_findings)

    # Analyze context
    analysis_findings = analyze_loading_context(code_findings)
    findings.extend(analysis_findings)

    # Summary
    critical_count = sum(1 for f in findings if f["Severity"] == "Critical")
    high_count = sum(1 for f in findings if f["Severity"] == "High")
    has_dex_loader = any(f["RuleID"].startswith("DYN_DEX") or f["RuleID"].startswith("DYN_SMALI") for f in findings)

    if has_dex_loader:
        findings.append({
            "Source": "dynamic_loading",
            "RuleID": "DYN_SUMMARY",
            "Title": "Dynamic Code Loading Analysis Summary",
            "Location": "Application",
            "Evidence": f"{critical_count} critical, {high_count} high severity issues",
            "Severity": "Info",
            "HowFound": "Dynamic code loading detected - requires careful security review",
        })
    else:
        findings.append({
            "Source": "dynamic_loading",
            "RuleID": "DYN_SUMMARY",
            "Title": "Dynamic Code Loading Analysis Summary",
            "Location": "Application",
            "Evidence": "No significant dynamic code loading detected",
            "Severity": "Info",
            "HowFound": "No DexClassLoader or similar patterns found",
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
    """Scan for dynamic code loading and write findings to CSV.

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

    findings = scan_for_dynamic_loading(src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
