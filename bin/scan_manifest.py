#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 1.0
# Script to analyze AndroidManifest.xml for issues
# Why: Manifest declares permissions/components; flags over-permissions, exported, debuggable for security risks.

import sys, xml.etree.ElementTree as ET, csv
import traceback

def main():
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