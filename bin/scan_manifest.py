#!/usr/bin/env python3
"""Analyze AndroidManifest.xml for security issues.

Scans the Android manifest for debuggable flags, exported components,
and dangerous permissions that could expose sensitive data or functionality.

OWASP MASTG Coverage:
    - MASTG-TEST-0001: Debuggable flag detection
    - MASTG-TEST-0016: Exported component analysis
    - MASTG-TEST-0029: Permission analysis

Author: Randy Grant
Date: 11-07-2025
Version: 1.0
"""

import csv
import sys
import traceback
import xml.etree.ElementTree as ET


def main() -> None:
    """Parse manifest and write security findings to CSV.

    Reads AndroidManifest.xml, checks for debuggable flag, exported
    components, and dangerous permissions, then outputs findings in
    CSV format for aggregation with other scanners.

    Command line args:
        sys.argv[1]: Path to AndroidManifest.xml
        sys.argv[2]: Output CSV path

    Raises:
        SystemExit: If arguments missing or parsing fails.
    """
    try:
        if len(sys.argv) < 3:
            raise ValueError("Usage: analyze_manifest.py <manifest.xml> <out.csv>")
        mani_path, out = sys.argv[1], sys.argv[2]
        tree = ET.parse(mani_path)
        root = tree.getroot()
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        rows = []
        # Debuggable
        if root.find(".//application", ns).get("{http://schemas.android.com/apk/res/android}debuggable") == "true":
            rows.append(dict(Source="manifest", RuleID="MANI_DEBUGGABLE", Title="App is debuggable", Location=mani_path,
                             Evidence="android:debuggable=true", Severity="High", HowFound="XML parse"))
        # Exported components
        for elem in root.findall(".//*[@android:exported='true']", ns):
            tag = elem.tag.split('}')[-1]
            name = elem.get("{http://schemas.android.com/apk/res/android}name", "unknown")
            rows.append(dict(Source="manifest", RuleID="MANI_EXPORTED", Title=f"Exported {tag}", Location=mani_path,
                             Evidence=f"{tag}: {name}", Severity="Medium", HowFound="XML parse"))
        # Dangerous permissions
        dangerous_perms = ["WRITE_EXTERNAL_STORAGE", "READ_SMS", "CAMERA"]  # Example list; expand
        for perm in root.findall(".//uses-permission", ns):
            name = perm.get("{http://schemas.android.com/apk/res/android}name", "").split(".")[-1]
            if name in dangerous_perms:
                rows.append(dict(Source="manifest", RuleID="MANI_DANGEROUS_PERM", Title="Dangerous permission", Location=mani_path,
                                 Evidence=name, Severity="Medium", HowFound="XML parse"))
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source","RuleID","Title","Location","Evidence","Severity","HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(f"Wrote {out} ({len(rows)} rows)")
    except Exception as e:
        print(f"[!] Error in analyze_manifest: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()