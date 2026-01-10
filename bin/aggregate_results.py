#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 1.0
# Script to aggregate all CSV findings into one and generate stats.json
# Why: Centralizes outputs from multiple scanners for unified report; stats for quick summary.

import sys, os, pandas as pd, json
import traceback

def main():
    try:
        if len(sys.argv) < 2:
            raise ValueError("Usage: aggregate_results.py <audit_dir>")
        audit_dir = sys.argv[1]
        csv_paths = []
        for sub in ["30_scans", "40_sbom", "60_dynamic"]:
            d = os.path.join(audit_dir, sub)
            if os.path.isdir(d):
                for f in os.listdir(d):
                    if f.endswith(".csv"):
                        csv_paths.append(os.path.join(d, f))
        dfs = []
        for p in csv_paths:
            if os.path.getsize(p) > 0:
                df = pd.read_csv(p)
                dfs.append(df)
        if dfs:
            all_findings = pd.concat(dfs, ignore_index=True)
            all_findings.to_csv(sys.stdout, index=False)
            # Generate stats
            stats = {"total": len(all_findings), "counts_by_severity": all_findings["Severity"].value_counts().to_dict()}
            with open(os.path.join(audit_dir, "stats.json"), "w", encoding="utf-8") as f:
                json.dump(stats, f, indent=2)
        else:
            print("No findings CSVs found.")
    except Exception as e:
        print(f"[!] Error in aggregate_results: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()