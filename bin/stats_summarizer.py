#!/usr/bin/env python3
"""Print findings summary from stats.json.

Reads stats.json and outputs a one-line summary with findings count by severity
to help prioritize remediation efforts.

Author: Randy Grant
Date: 11-07-2025
Version: 1.0
"""

import json
import os
import sys
import traceback


def main() -> None:
    """Print findings summary to stdout.

    Command line args:
        sys.argv[1]: Path to stats.json

    Raises:
        SystemExit: If stats.json missing or invalid.
    """
    try:
        if len(sys.argv) < 2:
            raise ValueError("Usage: summarize_stats.py <stats.json>")
        p = sys.argv[1]
        if not os.path.isfile(p):
            raise FileNotFoundError(f"stats.json not found at {p}")
        s = json.load(open(p,"r",encoding="utf-8"))
        by_sev = s.get("counts_by_severity",{})
        order = ["Critical","High","Medium","Low","Info"]
        parts = [f"{k}={by_sev.get(k,0)}" for k in order]
        total = s.get("total",0)
        print("Findings:", ", ".join(parts), f"| Total={total}")
    except Exception as e:
        print(f"[!] Error in summarize_stats: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()