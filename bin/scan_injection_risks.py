#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 1.0
# Script to scan for input/output validation issues (e.g., injection risks) in Android code
# Why: Addresses OWASP M4; lack of validation leads to SQLi, XSS, etc. Flags patterns for adding sanitization in remediation.

import sys, os, re, csv, zipfile
import traceback

INJ_PATTERNS = [
  ("INJ_SQL", r'(?i)execute\s*\(\s*["\'].*\+|rawQuery\s*\(\s*["\'].*\+', "High"),  # Dynamic SQL
  ("INJ_COMMAND", r'Runtime\.getRuntime\(\)\.exec\s*\(\s*["\'].*\+', "High"),  # Command inj
  ("INJ_XSS", r'(?i)webview\.loadDataWithBaseURL|loadUrl\s*\(\s*["\'].*\+', "Medium"),  # Potential XSS in WebView
  ("INJ_PATH_TRAVERSAL", r'File\s*\(\s*["\'].*\+.*getExternalStorage', "Medium"),  # Path traversal
  ("INJ_NO_VALIDATION", r'(?i)getParameter|getIntentExtra\s*\).*?(?!validate|sanitize)', "Low"),  # Input without validation heuristic
]

def iter_text(src_dir, apk_path):
    # Why: Standard iterator for decompiled or raw files.
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        yield p, f.read()
                except Exception as e:
                    print(f"Warning: Failed to read {p}: {str(e)}")
                    continue
    elif apk_path and os.path.isfile(apk_path):
        with zipfile.ZipFile(apk_path, 'r') as z:
            for zi in z.infolist():
                if zi.file_size > 0 and not zi.is_dir():
                    try:
                        yield zi.filename, z.read(zi.filename).decode("utf-8", errors="ignore")
                    except Exception as e:
                        print(f"Warning: Failed to read ZIP entry {zi.filename}: {str(e)}")
                        continue

def main():
    try:
        if len(sys.argv) < 3:
            raise ValueError("Usage: scan_injection_risks.py <src_dir> <out.csv> [apk_path]")
        src_dir, out = sys.argv[1], sys.argv[2]
        apk_path = sys.argv[3] if len(sys.argv) > 3 else None
        rows = []
        for path, text in iter_text(src_dir, apk_path):
            for rid, rx, sev in INJ_PATTERNS:
                for m in re.finditer(rx, text):
                    snippet = text[max(0, m.start()-40):m.end()+40].replace("\n"," ")
                    rows.append(dict(Source="injection", RuleID=rid, Title="Injection risk", Location=str(path),
                                     Evidence=snippet[:200], Severity=sev, HowFound="Regex scan"))
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source","RuleID","Title","Location","Evidence","Severity","HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(f"Wrote {out} ({len(rows)} rows)")
    except Exception as e:
        print(f"[!] Error in scan_injection_risks: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()