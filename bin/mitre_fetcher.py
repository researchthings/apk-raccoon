#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 1.0
# Script to fetch or use cached MITRE mobile-attack JSON
# Why: Provides up-to-date attack patterns for enrichment; ETag for efficient updates without full redownload.

import sys, os, requests
import traceback

def main():
    try:
        offline = "--offline" in sys.argv
        out_json = sys.argv[-2] if len(sys.argv) > 2 else "../data/mobile-attack.json"
        etag_file = sys.argv[-1] if len(sys.argv) > 1 else "../data/mitre_etag.txt"
        url = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
        # url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/mobile-attack/mobile-attack.json"
        if offline and os.path.isfile(out_json):
            print("Offline: Using cached MITRE JSON.")
            return
        headers = {}
        if os.path.isfile(etag_file):
            with open(etag_file, "r") as f:
                etag = f.read().strip()
            headers["If-None-Match"] = etag
        resp = requests.get(url, headers=headers)
        if resp.status_code == 304:
            print("MITRE unchanged; using cache.")
            return
        resp.raise_for_status()
        with open(out_json, "w", encoding="utf-8") as f:
            f.write(resp.text)
        if "ETag" in resp.headers:
            with open(etag_file, "w") as f:
                f.write(resp.headers["ETag"])
        print(f"Fetched and wrote {out_json}")
    except Exception as e:
        print(f"[!] Error in fetch_mitre_data: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()