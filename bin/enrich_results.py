#!/usr/bin/env python3
"""Enrich findings with OWASP and MITRE ATT&CK mappings.

Adds contextual information (why relevant, how to resolve) to findings
by looking up rule IDs in OWASP YAML and searching MITRE ATT&CK JSON
for related techniques.

Author: Randy Grant
Date: 11-07-2025
Version: 1.0
"""

import json
import os
import re
import sys
import traceback

import pandas as pd
import yaml


def load_mitre(mitre_json: str) -> list:
    """Load attack-patterns from MITRE ATT&CK JSON.

    Args:
        mitre_json: Path to MITRE ATT&CK JSON file.

    Returns:
        List of technique dicts with id, name, desc fields.
    """
    if mitre_json and os.path.isfile(mitre_json):
        try:
            j = json.load(open(mitre_json,"r",encoding="utf-8"))
            objs = j.get("objects", [])
            tech = []
            for o in objs:
                if o.get("type") == "attack-pattern":
                    name = o.get("name","")
                    desc = o.get("description", "")
                    tid = None
                    for ext in o.get("external_references", []):
                        if ext.get("source_name") in ("mitre-attack","mitre-mobile-attack","mitre-ics-attack"):
                            tid = ext.get("external_id")
                            break
                    if tid:
                        tech.append({"id":tid, "name":name, "desc":desc})
            return tech
        except Exception as e:
            print(f"Warning: Failed to load MITRE: {str(e)}")
            return []
    print("Warning: MITRE JSON not found; skipping MITRE mappings.")
    return []

def match_mitre(tech_list: list, keywords: list) -> list:
    """Match MITRE techniques by keywords from OWASP YAML.

    Args:
        tech_list: List of technique dicts from load_mitre().
        keywords: Keywords to search for in technique names/descriptions.

    Returns:
        List of matching technique strings (max 5 to avoid CSV bloat).
    """
    hits = []
    if not tech_list or not keywords: return hits
    for kw in keywords:
        rx = re.compile(re.escape(kw), re.I)
        for t in tech_list:
            if t["id"] and (rx.search(t["name"] or "") or rx.search(t["desc"] or "")):
                hits.append(f'{t["id"]} {t["name"]}')
    out = list(dict.fromkeys(hits))  # dedupe
    return out[:5]

def main() -> None:
    """Enrich findings CSV and write to stdout.

    Command line args:
        sys.argv[1]: Path to findings CSV
        sys.argv[2]: Path to OWASP YAML mappings
        sys.argv[3]: Optional path to MITRE ATT&CK JSON

    Raises:
        SystemExit: If required arguments missing or enrichment fails.
    """
    try:
        if len(sys.argv) < 3:
            raise ValueError("Usage: enrich_results.py <findings.csv> <owasp_yaml> [mitre_json]")
        fcsv, oyaml = sys.argv[1], sys.argv[2]
        mjson = sys.argv[3] if len(sys.argv) > 3 else None

        df = pd.read_csv(fcsv)
        if os.path.isfile(oyaml):
            try:
                owasp = yaml.safe_load(open(oyaml,"r",encoding="utf-8")) or {"rules": {}}
            except Exception as e:
                print(f"Warning: Failed to load OWASP YAML: {str(e)}. Using empty mappings.")
                owasp = {"rules": {}}
        else:
            print("Warning: OWASP YAML not found; using empty mappings.")
            owasp = {"rules": {}}

        mitre_tech = load_mitre(mjson)

        # Prepare new columns
        # Why: These columns provide why (risk) and how (fix), fulfilling project purpose for remediation.
        df["OWASP"] = ""
        df["MITRE"] = ""
        df["WhyRelevant"] = ""
        df["HowResolve"] = ""

        for i, row in df.iterrows():
            rid = str(row.get("RuleID",""))
            meta = owasp.get("rules", {}).get(rid, {})
            df.at[i,"OWASP"] = "; ".join(meta.get("owasp", []))
            kws = meta.get("mitre_keywords", [])
            df.at[i,"MITRE"] = "; ".join(match_mitre(mitre_tech, kws))
            df.at[i,"WhyRelevant"] = meta.get("why", "Risk to confidentiality/integrity/availability.")
            df.at[i,"HowResolve"] = meta.get("how", "Research needed for fix.")

        df.to_csv(sys.stdout, index=False)
    except Exception as e:
        print(f"[!] Error in enrich_results: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()