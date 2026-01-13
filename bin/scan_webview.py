#!/usr/bin/env python3
"""Scan for WebView security misconfigurations.

Detects insecure WebView settings including SSL error bypass, JavaScript
enablement, and file access permissions that could lead to MiTM or XSS attacks.

OWASP MASTG Coverage:
    - MASTG-TEST-0024: WebView SSL validation
    - MASTG-TEST-0025: WebView JavaScript security
    - MASTG-TEST-0026: WebView file access

Author: Randy Grant
Date: 11-07-2025
Version: 1.0
"""

import csv
import os
import re
import sys
import traceback
import zipfile

WEBVIEW_PATTERNS = [
  ("WEBVIEW_IGNORE_SSL", r'onReceivedSslError.*proceed\(\)', "High"),  # Why: Ignores cert errors.
  ("WEBVIEW_JS_ENABLED", r'setJavaScriptEnabled\(true\)', "Medium"),  # Why: JS risks XSS if not needed.
  ("WEBVIEW_FILE_ACCESS", r'setAllowFileAccess\(true\)', "Medium"),  # Why: Allows file scheme access.
]

def iter_text(src_dir: str, apk_path: str):
    """Iterate over code files yielding (path, content) tuples.

    Args:
        src_dir: Path to decompiled source directory.
        apk_path: Optional path to APK file for direct scanning.

    Yields:
        Tuple of (file_path, file_content) for each readable file.
    """
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

def main() -> None:
    """Scan files for WebView issues and write findings to CSV.

    Command line args:
        sys.argv[1]: Path to decompiled source directory
        sys.argv[2]: Output CSV path
        sys.argv[3]: Optional path to APK file

    Raises:
        SystemExit: If arguments missing or scanning fails.
    """
    try:
        if len(sys.argv) < 3:
            raise ValueError("Usage: check_webview_security.py <src_dir> <out.csv> [apk_path]")
        src_dir, out = sys.argv[1], sys.argv[2]
        apk_path = sys.argv[3] if len(sys.argv) > 3 else None
        rows = []
        for path, text in iter_text(src_dir, apk_path):
            for rid, rx, sev in WEBVIEW_PATTERNS:
                for m in re.finditer(rx, text):
                    snippet = text[max(0, m.start()-40):m.end()+40].replace("\n"," ")
                    rows.append(dict(Source="webview", RuleID=rid, Title="WebView security issue", Location=str(path),
                                     Evidence=snippet[:200], Severity=sev, HowFound="Regex scan"))
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source","RuleID","Title","Location","Evidence","Severity","HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(f"Wrote {out} ({len(rows)} rows)")
    except Exception as e:
        print(f"[!] Error in check_webview_security: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()