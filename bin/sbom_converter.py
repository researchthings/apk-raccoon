#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 1.0
# Script to convert grype JSON SBOM findings into a flat CSV format
# Why: Flattens complex JSON for easy aggregation and review; aligns with other CSV outputs for consistency.

import sys, json, csv, os
import traceback

def main():
    try:
        if len(sys.argv) < 3:
            raise ValueError("Usage: convert_sbom.py <grype.json> <out.csv>")
        jpath, out = sys.argv[1], sys.argv[2]
        rows = []
        if os.path.isfile(jpath):
            j = json.load(open(jpath, "r", encoding="utf-8"))
            matches = j.get("matches", [])
            for m in matches:
                vuln = m.get("vulnerability", {})
                art = m.get("artifact", {})
                sev = (vuln.get("severity") or "Info").title()
                rid = f"SBOM_{vuln.get('id','UNKNOWN')}"
                title = f"{vuln.get('id','UNKNOWN')} in {art.get('name','?')}:{art.get('version','?')}"
                ev = vuln.get("dataSource","")
                loc = art.get("name","")
                rows.append(dict(Source="sbom", RuleID=rid, Title=title, Location=loc,
                                 Evidence=ev, Severity=sev, HowFound="grype JSON"))
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source","RuleID","Title","Location","Evidence","Severity","HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(f"Wrote {out} ({len(rows)} rows)")
    except Exception as e:
        print(f"[!] Error in convert_sbom: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()