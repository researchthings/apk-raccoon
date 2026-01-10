#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 2.0
# Script to scan for insufficient binary protections in APK (e.g., lack of anti-debug, obfuscation)
# Why: Addresses OWASP M7; weak protections allow reverse engineering. Flags absence of safeguards for adding them in remediation.
#
# IMPORTANT: This scanner detects ABSENCE of protections.
# It scans the entire codebase for protection indicators and reports
# a finding only if NO indicators are found for a given protection category.

import sys, os, re, csv, zipfile
import traceback
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


def iter_text(src_dir, apk_path):
    """Iterate over code files yielding (path, content) tuples."""
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


def check_obfuscation(src_dir):
    """
    Heuristic check for obfuscation by analyzing class/file names.
    Returns True if code appears unobfuscated (finding should be raised).
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


def main():
    try:
        if len(sys.argv) < 4:
            print("Usage: scan_binary_protections.py <src_dir> <apk_path> <out.csv>", file=sys.stderr)
            sys.exit(1)

        src_dir, apk_path, out = sys.argv[1], sys.argv[2], sys.argv[3]

        # Track which protections are found
        protections_found = defaultdict(list)
        files_scanned = 0

        # Scan all files for protection indicators
        for path, text in iter_text(src_dir, apk_path):
            files_scanned += 1
            for rule_id, config in PROTECTION_INDICATORS.items():
                for pattern in config["patterns"]:
                    if re.search(pattern, text, re.IGNORECASE):
                        protections_found[rule_id].append((path, pattern))
                        break  # One match per category per file is enough

        # Generate findings for MISSING protections
        rows = []

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
