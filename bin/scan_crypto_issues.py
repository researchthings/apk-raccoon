#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 1.0
# Script to scan for crypto-related issues in Android source code or APKs
# Why: Weak crypto (e.g., ECB, MD5) leads to data breaches; flags with locations for upgrading algorithms.

import sys, os, re, csv, zipfile
import traceback

CRYPTO = [
  ("CRYPTO_ECB_MODE", r'Cipher\.getInstance\(\s*["\']AES/ECB', "High"),  # Why: ECB is insecure for patterns.
  ("CRYPTO_DES", r'Cipher\.getInstance\(\s*["\']DES', "High"),  # Why: DES is broken; use AES.
  ("CRYPTO_RC2", r'Cipher\.getInstance\(\s*["\']RC2', "High"),  # Why: RC2 weak; deprecated.
  ("CRYPTO_NPADDING", r'Cipher\.getInstance\(\s*["\'][^"\']+/NoPadding', "Medium"),  # Why: No padding risks.
  ("CRYPTO_MD5", r'(MessageDigest\.getInstance\(\s*["\']MD5)|\bMD5\b', "Medium"),  # Why: MD5 collision-prone.
  ("CRYPTO_SHA1", r'(MessageDigest\.getInstance\(\s*["\']SHA-?1)|\bSHA1\b', "Medium"),  # Why: SHA1 weak.
  ("CRYPTO_STATIC_IV", r'IvParameterSpec\(\s*new byte\[\]\s*{', "Medium"),  # Why: Static IV reduces security.
]

def iter_text(src_dir, apk_path):
    # Why: Iterates over decompiled or raw ZIP text; handles both for fallback robustness.
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
            raise ValueError("Usage: scan_crypto_issues.py <src_dir> <out.csv> [apk_path]")
        src_dir, out = sys.argv[1], sys.argv[2]
        apk_path = sys.argv[3] if len(sys.argv) > 3 else None
        rows = []
        for path, text in iter_text(src_dir, apk_path):
            for rid, rx, sev in CRYPTO:
                for m in re.finditer(rx, text):
                    snippet = text[max(0, m.start()-40):m.end()+40].replace("\n"," ")
                    rows.append(dict(Source="crypto", RuleID=rid, Title="Crypto misuse", Location=str(path),
                                     Evidence=snippet[:200], Severity=sev, HowFound="Regex scan"))
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source","RuleID","Title","Location","Evidence","Severity","HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(f"Wrote {out} ({len(rows)} rows)")
    except Exception as e:
        print(f"[!] Error in scan_crypto_issues: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()