#!/usr/bin/env python3

# Author: Randy Grant
# Date: 01-09-2026
# Version: 1.0
# Script to scan for content provider security issues
# Why: Content providers are major attack surface; misconfigurations leak data.
#
# Checks:
# - Exported providers without permissions
# - SQL injection in content providers
# - Path traversal vulnerabilities
# - Grant URI permissions abuse
# - Missing signature-level protection

import sys
import os
import re
import csv
import zipfile
import traceback
from lxml import etree

# =============================================================================
# Content Provider vulnerability patterns
# =============================================================================

# SQL injection patterns in content providers
SQL_INJECTION_PATTERNS = [
    (
        "CP_SQL_INJECTION_CONCAT",
        r'(?i)(?:rawQuery|execSQL)\s*\(\s*["\'][^"\']*["\']\s*\+\s*(?:selection|projection|sortOrder|\w+)',
        "Critical",
        "SQL query with string concatenation (potential SQL injection)"
    ),
    (
        "CP_SQL_INJECTION_FORMAT",
        r'(?i)(?:rawQuery|execSQL)\s*\(\s*String\.format\s*\(',
        "Critical",
        "SQL query with String.format (potential SQL injection)"
    ),
    (
        "CP_SQL_INJECTION_INTERPOLATE",
        r'(?i)(?:rawQuery|execSQL)\s*\(\s*["`][^`"]*\$\{',
        "Critical",
        "SQL query with string interpolation (potential SQL injection)"
    ),
    (
        "CP_RAW_QUERY_NO_ARGS",
        r'rawQuery\s*\(\s*["\'][^"\']+(?:WHERE|AND|OR)[^"\']+["\'],\s*null\s*\)',
        "High",
        "rawQuery with WHERE clause and null selection args"
    ),
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    (
        "CP_PATH_TRAVERSAL_OPENFILE",
        r'openFile\s*\([^)]*\)\s*\{[^}]*new\s+File\s*\(\s*[^,)]+,\s*uri\.(?:getPath|getLastPathSegment)',
        "Critical",
        "openFile() constructs path from URI without validation"
    ),
    (
        "CP_PATH_NO_CANONICALIZE",
        r'(?:getPath|getLastPathSegment)\s*\(\s*\)[^;]*(?:new\s+File|FileInputStream|FileOutputStream)',
        "High",
        "File path from URI without canonicalization"
    ),
    (
        "CP_MISSING_PATH_CHECK",
        r'openFile\s*\([^)]*\)\s*\{(?:(?!getCanonicalPath|startsWith|contains\s*\(\s*["\']\.\.)[^}])*\}',
        "Medium",
        "openFile() may lack path traversal protection"
    ),
]

# Permission and export patterns
PERMISSION_PATTERNS = [
    (
        "CP_WORLD_READABLE",
        r'(?:MODE_WORLD_READABLE|openFileOutput\s*\([^)]*,\s*0)',
        "High",
        "World-readable file mode"
    ),
    (
        "CP_WORLD_WRITEABLE",
        r'(?:MODE_WORLD_WRITEABLE)',
        "High",
        "World-writeable file mode"
    ),
]

# Grant URI permission patterns
GRANT_URI_PATTERNS = [
    (
        "CP_GRANT_URI_WRITE",
        r'grantUriPermission\s*\([^)]*FLAG_GRANT_WRITE_URI_PERMISSION',
        "Medium",
        "Grant URI write permission (verify recipient is trusted)"
    ),
    (
        "CP_GRANT_URI_PERSISTABLE",
        r'grantUriPermission\s*\([^)]*FLAG_GRANT_PERSISTABLE_URI_PERMISSION',
        "Medium",
        "Grant persistable URI permission (long-term access)"
    ),
    (
        "CP_GRANT_URI_PREFIX",
        r'grantUriPermission\s*\([^)]*FLAG_GRANT_PREFIX_URI_PERMISSION',
        "High",
        "Grant prefix URI permission (broad access pattern)"
    ),
]


def parse_manifest_providers(mani_path):
    """Parse manifest for content provider declarations."""
    findings = []
    providers = []

    try:
        tree = etree.parse(mani_path)
        ns = '{http://schemas.android.com/apk/res/android}'

        for provider in tree.xpath('//provider'):
            prov_info = {
                "name": provider.get(f'{ns}name', 'unknown'),
                "authorities": provider.get(f'{ns}authorities', ''),
                "exported": provider.get(f'{ns}exported', 'false'),
                "permission": provider.get(f'{ns}permission', ''),
                "readPermission": provider.get(f'{ns}readPermission', ''),
                "writePermission": provider.get(f'{ns}writePermission', ''),
                "grantUriPermissions": provider.get(f'{ns}grantUriPermissions', 'false'),
            }
            providers.append(prov_info)

            # Check for exported without permissions
            is_exported = prov_info["exported"].lower() == "true"
            has_permission = bool(prov_info["permission"] or prov_info["readPermission"] or prov_info["writePermission"])

            # In Android 12+, default export behavior changed
            # If targetSdk >= 31 and exported not explicitly set, it's an error
            if is_exported and not has_permission:
                findings.append({
                    "RuleID": "CP_EXPORTED_NO_PERMISSION",
                    "Title": f"Exported provider without permission: {prov_info['name']}",
                    "Evidence": f"authorities={prov_info['authorities']}, exported=true, no permission set",
                    "Severity": "Critical"
                })

            # Check for grantUriPermissions=true on exported provider
            if is_exported and prov_info["grantUriPermissions"].lower() == "true":
                findings.append({
                    "RuleID": "CP_EXPORTED_GRANT_URI",
                    "Title": f"Exported provider with grantUriPermissions: {prov_info['name']}",
                    "Evidence": f"authorities={prov_info['authorities']}, grantUriPermissions=true",
                    "Severity": "High"
                })

            # Check path-permission elements
            path_perms = provider.xpath('.//path-permission')
            for pp in path_perms:
                path = pp.get(f'{ns}path', pp.get(f'{ns}pathPrefix', pp.get(f'{ns}pathPattern', '')))
                pp_perm = pp.get(f'{ns}permission', pp.get(f'{ns}readPermission', pp.get(f'{ns}writePermission', '')))
                if not pp_perm:
                    findings.append({
                        "RuleID": "CP_PATH_NO_PERMISSION",
                        "Title": f"path-permission without permission: {path}",
                        "Evidence": f"Provider {prov_info['name']} has path-permission without protection",
                        "Severity": "High"
                    })

            # Check for signature-level protection (best practice)
            all_perms = [prov_info["permission"], prov_info["readPermission"], prov_info["writePermission"]]
            has_signature_perm = any("signature" in str(p).lower() for p in all_perms if p)

            if is_exported and has_permission and not has_signature_perm:
                findings.append({
                    "RuleID": "CP_NO_SIGNATURE_PERM",
                    "Title": f"Exported provider without signature permission: {prov_info['name']}",
                    "Evidence": f"Consider using signature-level permission for sensitive providers",
                    "Severity": "Low"
                })

    except Exception as e:
        print(f"Warning: Manifest parse failed: {str(e)}", file=sys.stderr)

    return findings, providers


def iter_text(src_dir, apk_path=None):
    """Iterate over source files."""
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
                if not fn.endswith(('.java', '.kt', '.smali')):
                    continue
                p = os.path.join(root, fn)
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        yield p, f.read()
                except Exception as e:
                    print(f"Warning: Failed to read {p}: {str(e)}", file=sys.stderr)
                    continue

    elif apk_path and os.path.isfile(apk_path):
        with zipfile.ZipFile(apk_path, 'r') as z:
            for zi in z.infolist():
                if zi.file_size > 0 and not zi.is_dir():
                    try:
                        yield zi.filename, z.read(zi.filename).decode("utf-8", errors="ignore")
                    except Exception as e:
                        print(f"Warning: Failed to read ZIP entry {zi.filename}: {str(e)}", file=sys.stderr)
                        continue


def is_content_provider_file(text):
    """Check if file likely contains a ContentProvider implementation."""
    indicators = [
        r'extends\s+ContentProvider',
        r'implements\s+.*ContentProvider',
        r'class\s+\w+Provider\s+extends',
        r'override\s+fun\s+(?:query|insert|update|delete|openFile)\s*\(',
        r'@Override\s+.*(?:query|insert|update|delete|openFile)\s*\(',
    ]
    return any(re.search(pattern, text) for pattern in indicators)


def main():
    try:
        if len(sys.argv) < 4:
            print("Usage: scan_content_providers.py <src_dir> <manifest.xml> <out.csv> [apk_path]", file=sys.stderr)
            sys.exit(1)

        src_dir, mani_path, out = sys.argv[1], sys.argv[2], sys.argv[3]
        apk_path = sys.argv[4] if len(sys.argv) > 4 else None

        rows = []
        files_scanned = 0
        provider_files = 0

        # Parse manifest for provider declarations
        if mani_path and os.path.isfile(mani_path):
            manifest_findings, providers = parse_manifest_providers(mani_path)
            for finding in manifest_findings:
                rows.append({
                    "Source": "content_provider",
                    "RuleID": finding["RuleID"],
                    "Title": finding["Title"],
                    "Location": mani_path,
                    "Evidence": finding["Evidence"],
                    "Severity": finding["Severity"],
                    "HowFound": "XML parse"
                })

        # Scan source files
        for path, text in iter_text(src_dir, apk_path):
            files_scanned += 1

            # Focus on files that look like ContentProvider implementations
            is_provider = is_content_provider_file(text)
            if is_provider:
                provider_files += 1

            # Check SQL injection patterns (especially in provider files)
            for rid, rx, sev, desc in SQL_INJECTION_PATTERNS:
                for m in re.finditer(rx, text, re.DOTALL):
                    # Higher severity if in provider file
                    actual_sev = sev if is_provider else ("Medium" if sev == "Critical" else "Low")
                    snippet = text[max(0, m.start() - 30):m.end() + 50].replace("\n", " ")
                    rows.append({
                        "Source": "content_provider",
                        "RuleID": rid,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": actual_sev,
                        "HowFound": "Regex scan"
                    })

            # Check path traversal patterns (especially in provider files)
            if is_provider:
                for rid, rx, sev, desc in PATH_TRAVERSAL_PATTERNS:
                    for m in re.finditer(rx, text, re.DOTALL):
                        snippet = text[max(0, m.start() - 30):m.end() + 50].replace("\n", " ")
                        rows.append({
                            "Source": "content_provider",
                            "RuleID": rid,
                            "Title": desc,
                            "Location": str(path),
                            "Evidence": snippet[:200],
                            "Severity": sev,
                            "HowFound": "Regex scan"
                        })

            # Check permission patterns
            for rid, rx, sev, desc in PERMISSION_PATTERNS:
                for m in re.finditer(rx, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "content_provider",
                        "RuleID": rid,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": sev,
                        "HowFound": "Regex scan"
                    })

            # Check grant URI permission patterns
            for rid, rx, sev, desc in GRANT_URI_PATTERNS:
                for m in re.finditer(rx, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 50].replace("\n", " ")
                    rows.append({
                        "Source": "content_provider",
                        "RuleID": rid,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": sev,
                        "HowFound": "Regex scan"
                    })

        # Write output
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        print(f"Wrote {out} ({len(rows)} findings, {files_scanned} files scanned, {provider_files} provider files)")

    except Exception as e:
        print(f"[!] Error in scan_content_providers: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
