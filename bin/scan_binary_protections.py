#!/usr/bin/env python3
"""Scan for insufficient binary protections and debug code.

Detects absence of root detection, anti-debug, emulator detection, tampering
checks, and code obfuscation. Also identifies debug code left in production.

Note: This scanner reports ABSENCE of protections as findings. It scans the
entire codebase for protection indicators and reports if none are found.

OWASP MASTG Coverage:
    - MASTG-TEST-0038: Root detection
    - MASTG-TEST-0039: Anti-debug protections
    - MASTG-TEST-0040: Emulator detection
    - MASTG-TEST-0041: Debug code detection
    - MASTG-TEST-0042: Code obfuscation

Author: Randy Grant
Date: 11-07-2025
Version: 2.0
"""

import csv
import os
import re
import sys
import traceback
import zipfile
from collections import defaultdict

# Protection categories with patterns that INDICATE protection is present
# If ANY pattern in a category matches, that protection is considered present
PROTECTION_INDICATORS = {
    "BIN_NO_ROOT_DETECT": {
        "title": "No Root Detection Found",
        "severity": "High",
        "patterns": [
            r'\bRootBeer\b',
            r'\bisRooted\b',
            r'\bcheckRoot\b',
            r'\bRootTools\b',
            r'\bSafetyNet\b',
            r'\bcheckForSuBinary\b',
            r'\bcheckSuExists\b',
            r'\bdetectRootManagementApps\b',
            r'\bdetectPotentiallyDangerousApps\b',
            r'\bcheckForDangerousProps\b',
            r'\bcheckForBusyBoxBinary\b',
            r'\bisDeviceRooted\b',
            r'com\.scottyab\.rootbeer',
            r'eu\.chainfire\.libsuperuser',
        ],
    },
    "BIN_NO_ANTI_DEBUG": {
        "title": "No Anti-Debug Protection Found",
        "severity": "Medium",
        "patterns": [
            r'\bDebug\.isDebuggerConnected\b',
            r'\bisDebuggerConnected\b',
            r'\bptrace\b',
            r'\banti.?debug\b',
            r'\bdetectDebugger\b',
            r'\bTracerPid\b',
            r'\bandroid\.os\.Debug\b',
            r'\bwaitForDebugger\b',
        ],
    },
    "BIN_NO_EMULATOR_DETECT": {
        "title": "No Emulator Detection Found",
        "severity": "Medium",
        "patterns": [
            r'\bisEmulator\b',
            r'Build\.FINGERPRINT.*generic',
            r'Build\.MODEL.*Emulator',
            r'Build\.MANUFACTURER.*Genymotion',
            r'\bgoldfish\b',
            r'\branchu\b',
            r'\bvbox86\b',
            r'\bdetectEmulator\b',
            r'\bcheckEmulator\b',
            r'ro\.kernel\.qemu',
            r'ro\.hardware\.goldfish',
        ],
    },
    "BIN_NO_TAMPERING_DETECT": {
        "title": "No Tampering/Integrity Check Found",
        "severity": "Medium",
        "patterns": [
            r'\bverifySignature\b',
            r'\bcheckSignature\b',
            r'\bPackageManager\.GET_SIGNATURES\b',
            r'\bGET_SIGNING_CERTIFICATES\b',
            r'\bverifyInstaller\b',
            r'\bcheckInstallSource\b',
            r'\bgetInstallerPackageName\b',
            r'\bcheckIntegrity\b',
            r'\bPlayIntegrity\b',
        ],
    },
}

# Obfuscation is detected differently - we look for signs of LACK of obfuscation
OBFUSCATION_CHECK = {
    "rule_id": "BIN_NO_OBFUSCATION",
    "title": "Code Appears Unobfuscated",
    "severity": "Low",
    # Threshold: if more than this percentage of class names are readable, likely not obfuscated
    "readable_threshold": 0.7,
}

# =============================================================================
# Debug Code Detection (MASTG-TEST-0041)
# Unlike PROTECTION_INDICATORS, these patterns indicate PRESENCE of debug code (bad)
# =============================================================================

DEBUG_CODE_PATTERNS = [
    # BuildConfig.DEBUG checks left in production
    (r'\bBuildConfig\.DEBUG\b', "Medium", "BuildConfig.DEBUG check in code (should be removed in production)"),
    (r'if\s*\(\s*BuildConfig\.DEBUG\s*\)', "Medium", "Debug conditional check"),

    # Verbose/Debug logging (should use Timber or be stripped in release)
    (r'\bLog\.(v|d)\s*\(', "Low", "Verbose/Debug log statement (consider stripping in release)"),
    (r'\bLog\.wtf\s*\(', "Medium", "Log.wtf (What a Terrible Failure) - debug logging"),

    # Stack trace printing (security/info disclosure)
    (r'\.printStackTrace\s*\(\s*\)', "Medium", "printStackTrace() exposes stack trace to logs"),
    (r'(?i)e\.printStackTrace', "Medium", "Exception stack trace printed"),

    # StrictMode (development tool left in production)
    (r'\bStrictMode\.setThreadPolicy\b', "Medium", "StrictMode enabled (development tool)"),
    (r'\bStrictMode\.setVmPolicy\b', "Medium", "StrictMode VM policy (development tool)"),
    (r'\bStrictMode\.enableDefaults\b', "Medium", "StrictMode defaults enabled"),

    # System.out/err (typically debug code)
    (r'\bSystem\.out\.print(?:ln)?\s*\(', "Low", "System.out print statement (debug code)"),
    (r'\bSystem\.err\.print(?:ln)?\s*\(', "Low", "System.err print statement (debug code)"),

    # Debug flags/constants
    (r'(?i)\bDEBUG\s*=\s*true\b', "Medium", "DEBUG flag set to true"),
    (r'(?i)\bIS_DEBUG\s*=\s*true\b', "Medium", "IS_DEBUG flag set to true"),
    (r'(?i)\bDEBUG_MODE\s*=\s*true\b', "Medium", "DEBUG_MODE flag set to true"),

    # Toast for debugging
    (r'Toast\.makeText\s*\([^)]*(?:debug|test|todo)', "Low", "Debug/test Toast message"),

    # Stetho (debug bridge)
    (r'\bStetho\.initialize', "Medium", "Stetho debug bridge initialized"),

    # LeakCanary (memory debugging)
    (r'\bLeakCanary\b', "Low", "LeakCanary (memory debugging tool)"),
]


def iter_text(src_dir: str, apk_path: str):
    """Iterate over code files yielding (path, content) tuples.

    Args:
        src_dir: Path to decompiled source directory.
        apk_path: Path to APK file for direct scanning.

    Yields:
        Tuple of (file_path, file_content) for each readable file.
    """
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
                if fn.endswith(".java") or fn.endswith(".smali"):
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
                if zi.filename.endswith(".dex") or zi.filename.endswith(".smali"):
                    try:
                        yield zi.filename, z.read(zi.filename).decode("utf-8", errors="ignore")
                    except Exception as e:
                        print(f"Warning: Failed to read ZIP entry {zi.filename}: {str(e)}", file=sys.stderr)
                        continue


def check_obfuscation(src_dir: str) -> tuple:
    """Heuristic check for obfuscation by analyzing class/file names.

    Args:
        src_dir: Path to decompiled source directory.

    Returns:
        Tuple of (is_unobfuscated: bool, evidence: str).
    """
    if not os.path.isdir(src_dir):
        return False, "N/A"

    class_names = []
    # Pattern for Java class declarations
    class_pattern = re.compile(r'\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b')

    for root, _, files in os.walk(src_dir):
        for fn in files:
            if fn.endswith(".java"):
                # Use filename as class name indicator
                name = fn.replace(".java", "")
                class_names.append(name)

                # Also check class declarations in file
                try:
                    p = os.path.join(root, fn)
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for match in class_pattern.finditer(content):
                            class_names.append(match.group(1))
                except:
                    pass

    if not class_names:
        return False, "No classes found"

    # Count "readable" class names (more than 3 chars, not just letters/numbers pattern)
    def is_readable(name):
        # Obfuscated names are typically: a, b, aa, ab, aB, etc.
        # Readable names are: MainActivity, UserService, etc.
        if len(name) <= 2:
            return False
        # Check if it looks like a real word (has vowels, reasonable length)
        has_vowel = bool(re.search(r'[aeiouAEIOU]', name))
        return len(name) > 3 and has_vowel

    readable_count = sum(1 for n in class_names if is_readable(n))
    total = len(class_names)
    ratio = readable_count / total if total > 0 else 0

    return ratio > OBFUSCATION_CHECK["readable_threshold"], f"{readable_count}/{total} readable names ({ratio:.0%})"


def main() -> None:
    """Scan for missing binary protections and write findings to CSV.

    Command line args:
        sys.argv[1]: Path to decompiled source directory
        sys.argv[2]: Path to APK file
        sys.argv[3]: Output CSV path

    Raises:
        SystemExit: If arguments missing or scanning fails.
    """
    try:
        if len(sys.argv) < 4:
            print("Usage: scan_binary_protections.py <src_dir> <apk_path> <out.csv>", file=sys.stderr)
            sys.exit(1)

        src_dir, apk_path, out = sys.argv[1], sys.argv[2], sys.argv[3]

        # Track which protections are found
        protections_found = defaultdict(list)
        files_scanned = 0

        # Track debug code findings
        debug_code_findings = []

        # Scan all files for protection indicators and debug code
        for path, text in iter_text(src_dir, apk_path):
            files_scanned += 1

            # Check for protection indicators (absence is bad)
            for rule_id, config in PROTECTION_INDICATORS.items():
                for pattern in config["patterns"]:
                    if re.search(pattern, text, re.IGNORECASE):
                        protections_found[rule_id].append((path, pattern))
                        break  # One match per category per file is enough

            # Check for debug code (presence is bad) - MASTG-TEST-0041
            for pattern, severity, desc in DEBUG_CODE_PATTERNS:
                for m in re.finditer(pattern, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    debug_code_findings.append({
                        "Source": "binary_prot",
                        "RuleID": "BIN_DEBUG_CODE",
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": severity,
                        "HowFound": "Regex scan"
                    })
                    break  # One finding per pattern per file

        # Generate findings for MISSING protections
        rows = []

        # Add debug code findings (limit to avoid noise)
        # Group by description and limit per type
        debug_by_type = defaultdict(list)
        for finding in debug_code_findings:
            debug_by_type[finding["Title"]].append(finding)

        for desc, findings in debug_by_type.items():
            # Report first 5 of each type to avoid noise
            for finding in findings[:5]:
                rows.append(finding)
            if len(findings) > 5:
                # Add summary for remaining
                rows.append({
                    "Source": "binary_prot",
                    "RuleID": "BIN_DEBUG_CODE",
                    "Title": f"{desc} (and {len(findings) - 5} more)",
                    "Location": "Multiple files",
                    "Evidence": f"Found in {len(findings)} locations total",
                    "Severity": findings[0]["Severity"],
                    "HowFound": "Regex scan (summary)"
                })

        for rule_id, config in PROTECTION_INDICATORS.items():
            if rule_id not in protections_found:
                # Protection NOT found - this is a finding
                rows.append({
                    "Source": "binary_prot",
                    "RuleID": rule_id,
                    "Title": config["title"],
                    "Location": f"Entire codebase ({files_scanned} files scanned)",
                    "Evidence": f"No indicators found for patterns: {', '.join(config['patterns'][:3])}...",
                    "Severity": config["severity"],
                    "HowFound": "Absence detection (scanned all files, no protection indicators found)"
                })
            else:
                # Protection found - log for debugging but don't report as finding
                locations = protections_found[rule_id][:3]  # First 3 locations
                print(f"[+] {rule_id}: Protection found in {len(protections_found[rule_id])} location(s): {[l[0] for l in locations]}", file=sys.stderr)

        # Check obfuscation separately (different heuristic)
        is_unobfuscated, evidence = check_obfuscation(src_dir)
        if is_unobfuscated:
            rows.append({
                "Source": "binary_prot",
                "RuleID": OBFUSCATION_CHECK["rule_id"],
                "Title": OBFUSCATION_CHECK["title"],
                "Location": src_dir,
                "Evidence": evidence,
                "Severity": OBFUSCATION_CHECK["severity"],
                "HowFound": "Heuristic (class name readability analysis)"
            })

        # Write output
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        print(f"Wrote {out} ({len(rows)} findings, {files_scanned} files scanned)")

    except Exception as e:
        print(f"[!] Error in scan_binary_protections: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
