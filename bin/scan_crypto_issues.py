#!/usr/bin/env python3
"""Scan for cryptographic weaknesses in Android source code.

Detects insecure algorithms (ECB, DES, MD5, SHA1), weak key management
practices, hardcoded keys, insufficient PBKDF2 iterations, and static IVs/salts.

OWASP MASTG Coverage:
    - MASTG-TEST-0013: Weak crypto algorithm detection
    - MASTG-TEST-0014: Key management issues
    - MASTG-TEST-0307-0312: Key derivation and storage

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

# =============================================================================
# Crypto Algorithm Issues
# =============================================================================

CRYPTO = [
  ("CRYPTO_ECB_MODE", r'Cipher\.getInstance\(\s*["\']AES/ECB', "High"),  # Why: ECB is insecure for patterns.
  ("CRYPTO_DES", r'Cipher\.getInstance\(\s*["\']DES', "High"),  # Why: DES is broken; use AES.
  ("CRYPTO_RC2", r'Cipher\.getInstance\(\s*["\']RC2', "High"),  # Why: RC2 weak; deprecated.
  ("CRYPTO_NPADDING", r'Cipher\.getInstance\(\s*["\'][^"\']+/NoPadding', "Medium"),  # Why: No padding risks.
  ("CRYPTO_MD5", r'(MessageDigest\.getInstance\(\s*["\']MD5)|\bMD5\b', "Medium"),  # Why: MD5 collision-prone.
  ("CRYPTO_SHA1", r'(MessageDigest\.getInstance\(\s*["\']SHA-?1)|\bSHA1\b', "Medium"),  # Why: SHA1 weak.
  ("CRYPTO_STATIC_IV", r'IvParameterSpec\(\s*new byte\[\]\s*{', "Medium"),  # Why: Static IV reduces security.
]

# =============================================================================
# Key Management Issues (MASTG-TEST-0307-0312)
# =============================================================================

KEY_MANAGEMENT = [
  # Hardcoded keys
  ("CRYPTO_HARDCODED_KEY", r'new\s+SecretKeySpec\s*\(\s*["\'][A-Za-z0-9+/=]{16,}["\']', "Critical"),
  # SecretKeySpec with literal bytes
  ("CRYPTO_HARDCODED_KEY", r'new\s+SecretKeySpec\s*\(\s*new\s+byte\[\]\s*\{[^}]+\}', "Critical"),
  # Hardcoded base64 key patterns
  ("CRYPTO_HARDCODED_KEY", r'(?i)(?:private[_-]?key|secret[_-]?key|api[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9+/=]{32,}["\']', "Critical"),
  # Hardcoded hex keys
  ("CRYPTO_HARDCODED_KEY", r'(?i)(?:private|secret|key)\s*[:=]\s*0x[A-Fa-f0-9]{32,}', "Critical"),

  # Weak PBKDF2 iterations (should be 100000+)
  ("CRYPTO_WEAK_PBKDF2", r'PBEKeySpec\s*\([^,]*,[^,]*,\s*(?:1000|2000|5000|10000)\s*[,\)]', "High"),
  # Very low iterations
  ("CRYPTO_WEAK_PBKDF2", r'PBEKeySpec\s*\([^,]*,[^,]*,\s*(?:100|500)\s*[,\)]', "Critical"),
  # Iterations less than 10000 in general
  ("CRYPTO_WEAK_PBKDF2", r'(?i)iterations?\s*[:=]\s*(?:100|500|1000|5000)\b', "High"),

  # Static/weak salt
  ("CRYPTO_STATIC_SALT", r'PBEKeySpec\s*\([^,]*,\s*new\s+byte\[\]\s*\{[^}]{1,16}\}', "High"),
  # Salt from hardcoded string
  ("CRYPTO_STATIC_SALT", r'PBEKeySpec\s*\([^,]*,\s*["\'][^"\']{1,16}["\']\.getBytes', "High"),
  # Common weak salts
  ("CRYPTO_STATIC_SALT", r'(?i)(?:salt|SALT)\s*[:=]\s*["\'](?:salt|0123456789|password|default)["\']', "High"),

  # Key material stored in String (memory exposure - should use char[] or byte[])
  ("CRYPTO_KEY_IN_STRING", r'String\s+(?:password|secret|key|passphrase)\s*[:=]', "Medium"),
  ("CRYPTO_KEY_IN_STRING", r'(?i)String\.valueOf\s*\([^)]*(?:password|secret|key)[^)]*\)', "Medium"),

  # Random without secure random
  ("CRYPTO_WEAK_RANDOM", r'\bnew\s+Random\s*\(\s*\)', "Medium"),
  ("CRYPTO_WEAK_RANDOM", r'Math\.random\s*\(\s*\)', "Medium"),

  # Key size issues (weak key lengths)
  ("CRYPTO_WEAK_KEY_SIZE", r'KeyGenerator\.getInstance\([^)]+\)\.init\(\s*(?:56|64|128)\s*\)', "Medium"),
  ("CRYPTO_WEAK_KEY_SIZE", r'RSAKeyGenParameterSpec\s*\(\s*(?:512|1024)\s*,', "High"),

  # Predictable key derivation
  ("CRYPTO_PREDICTABLE_KEY", r'(?i)getBytes\s*\(\s*\)\s*\)\s*//.*(?:key|secret|password)', "Low"),
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
    """Scan files for crypto issues and write findings to CSV.

    Command line args:
        sys.argv[1]: Path to decompiled source directory
        sys.argv[2]: Output CSV path
        sys.argv[3]: Optional path to APK file

    Raises:
        SystemExit: If arguments missing or scanning fails.
    """
    try:
        if len(sys.argv) < 3:
            raise ValueError("Usage: scan_crypto_issues.py <src_dir> <out.csv> [apk_path]")
        src_dir, out = sys.argv[1], sys.argv[2]
        apk_path = sys.argv[3] if len(sys.argv) > 3 else None
        rows = []
        for path, text in iter_text(src_dir, apk_path):
            # Check crypto algorithm issues
            for rid, rx, sev in CRYPTO:
                for m in re.finditer(rx, text):
                    snippet = text[max(0, m.start()-40):m.end()+40].replace("\n"," ")
                    rows.append(dict(Source="crypto", RuleID=rid, Title="Crypto misuse", Location=str(path),
                                     Evidence=snippet[:200], Severity=sev, HowFound="Regex scan"))

            # Check key management issues (MASTG-TEST-0307-0312)
            for rid, rx, sev in KEY_MANAGEMENT:
                for m in re.finditer(rx, text):
                    snippet = text[max(0, m.start()-40):m.end()+40].replace("\n"," ")
                    rows.append(dict(Source="crypto", RuleID=rid, Title="Key management issue", Location=str(path),
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