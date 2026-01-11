#!/usr/bin/env bash

# =====================================================================
#    _    ____  _  __  ____
#   / \  |  _ \| |/ / |  _ \ __ _  ___ ___ ___   ___  _ __
#  / _ \ | |_) | ' /  | |_) / _` |/ __/ __/ _ \ / _ \| '_ \
# / ___ \|  __/| . \  |  _ < (_| | (_| (_| (_) | (_) | | | |
#/_/   \_\_|   |_|\_\ |_| \_\__,_|\___\___\___/ \___/|_| |_|
#
# The trash panda that digs through your APK garbage
# to find security vulnerabilities
# =====================================================================

# Author: Randy Grant
# Date: 01-10-2026
# Version: 1.0.0
# APK Raccoon
# Orchestrates Android APK security audit aligned to OWASP MASVS/MSTG.
# Purpose: Automates decompilation, static/dynamic scans, SBOM/CVE, aggregation, and enrichment with remediation advice.
# Why: Provides hands-off vulnerability detection with fix guidance for security pros.

# ---------------- Why this script? ----------------
# This is the entrypoint to run all scans in sequence. It creates timestamped audit dirs for organization,
# handles fallbacks (e.g., jadx to apktool), and ensures portability for Docker by using env vars and checks.

set -euo pipefail

# ---------------- Tunables ----------------
# Why: These flags allow users to skip steps for faster runs or debugging, e.g., --no-dynamic if no device.
DO_SETUP=1            # install tools (but in Docker, this is handled in build)
DO_DECOMPILE=1        # try jadx (fallback apktool)
DO_STATIC=1           # run Python scanners
DO_SBOM=1             # run syft+grype
DO_DYNAMIC=1          # adb dynamic probe
OFFLINE=0             # if 1, skip MITRE fetch (use cached if present)
STRICT_MODE=0         # if 1, fail on any scanner failure (for CI)
DO_HTML=0             # if 1, generate HTML report
DO_SARIF=0            # if 1, generate SARIF report

usage() {
  cat <<USAGE

APK Raccoon v1.0.0
The trash panda that digs through your APK garbage to find vulnerabilities

Usage: $(basename "$0") [options] <app.apk>

Options:
  --no-setup        Skip tool bootstrap (assumes Docker has them)
  --no-decompile    Skip jadx/apktool decompile
  --no-static       Skip Python static scanners (30 scanners)
  --no-sbom         Skip SBOM + CVE step (syft/grype)
  --no-dynamic      Skip ADB dynamic probe
  --offline         Do not fetch MITRE (use cache if exists)
  --strict          Fail on any scanner failure (for CI/CD)
  --html            Generate HTML report (findings.html)
  --sarif           Generate SARIF report for CI/CD (findings.sarif)
  -h, --help        Show help

Scanners (30 total):
  Core: Manifest, Secrets, Crypto, WebView, Storage/Logging, Network,
        Auth, Injection, Binary Protections, Privacy, Cert Pinning,
        Content Providers, PendingIntents
  Extended: Firebase, Task Hijacking, Deep Links, Tapjacking,
            Broadcasts, Native Libraries, Dynamic Loading
  Advanced: Zip Slip, Serialization, Fragment Injection, XXE,
            Implicit Intents, Clipboard, Keyboard Cache, Random,
            APK Signature, Deprecated APIs

Output Formats:
  CSV (default), HTML (--html), SARIF (--sarif)

USAGE
  exit 0
}

APK=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-setup) DO_SETUP=0; shift;;
    --no-decompile) DO_DECOMPILE=0; shift;;
    --no-static) DO_STATIC=0; shift;;
    --no-sbom) DO_SBOM=0; shift;;
    --no-dynamic) DO_DYNAMIC=0; shift;;
    --offline) OFFLINE=1; shift;;
    --strict) STRICT_MODE=1; shift;;
    --html) DO_HTML=1; shift;;
    --sarif) DO_SARIF=1; shift;;
    -h|--help) usage;;
    *) APK="$1"; shift;;
  esac
done

if [[ -z "${APK:-}" || ! -f "$APK" ]]; then
  echo "[!] Error: Provide a valid APK path - File not found or empty." >&2
  usage
  exit 1
fi

# ---------------- Pre-flight validation ----------------
# Why: Fail fast with clear errors instead of cryptic failures later
preflight_check() {
  local errors=0

  # Check required data files
  local required_files=(
    "data/owasp_rule_mappings.yaml"
    # Core scanners
    "bin/scan_manifest.py"
    "bin/scan_secrets.py"
    "bin/scan_crypto_issues.py"
    "bin/scan_webview.py"
    "bin/scan_storage_logging.py"
    "bin/scan_network_security.py"
    "bin/scan_auth_issues.py"
    "bin/scan_injection_risks.py"
    "bin/scan_binary_protections.py"
    "bin/scan_privacy_issues.py"
    "bin/scan_cert_pinning.py"
    "bin/scan_content_providers.py"
    "bin/scan_pending_intents.py"
    # Extended scanners
    "bin/scan_firebase.py"
    "bin/scan_task_hijacking.py"
    "bin/scan_deep_links.py"
    "bin/scan_tapjacking.py"
    "bin/scan_broadcasts.py"
    "bin/scan_native_libs.py"
    "bin/scan_dynamic_loading.py"
    # Advanced scanners
    "bin/scan_zip_slip.py"
    "bin/scan_serialization.py"
    "bin/scan_fragment_injection.py"
    "bin/scan_xxe.py"
    "bin/scan_implicit_intents.py"
    "bin/scan_clipboard.py"
    "bin/scan_keyboard_cache.py"
    "bin/scan_random.py"
    "bin/scan_apk_signature.py"
    "bin/scan_deprecated_apis.py"
    # Output generators
    "bin/generate_html_report.py"
    "bin/generate_sarif.py"
    # Utilities
    "bin/aggregate_results.py"
    "bin/enrich_results.py"
    "bin/stats_summarizer.py"
  )

  for f in "${required_files[@]}"; do
    if [[ ! -f "$f" ]]; then
      echo "[!] Pre-flight: Missing required file: $f" >&2
      ((errors++))
    fi
  done

  # Check Python is available
  if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Pre-flight: python3 not found" >&2
    ((errors++))
  fi

  if [[ $errors -gt 0 ]]; then
    echo "[!] Pre-flight check failed with $errors error(s). Aborting." >&2
    exit 1
  fi

  echo "[+] Pre-flight check passed"
}

preflight_check

# ---------------- Paths ----------------
# Why: Named audit dir keeps runs isolated and identifiable. Use absolute paths for Docker consistency.
TS=$(date +"%Y%m%d_%H%M%S")
APK_BASENAME=$(basename "$APK" .apk | sed 's/[^a-zA-Z0-9._-]/_/g')  # Sanitize filename for directory name
if [[ -z "${AUDIT_DIR:-}" ]]; then
  # No AUDIT_DIR set: create in current directory with APK name
  AUDIT_DIR="${APK_BASENAME}_${TS}"
else
  # AUDIT_DIR set (e.g., Docker /output): create subdirectory with APK name
  AUDIT_DIR="${AUDIT_DIR}/${APK_BASENAME}_${TS}"
fi
mkdir -p "$AUDIT_DIR/00_meta" "$AUDIT_DIR/10_manifest" "$AUDIT_DIR/20_decompile" "$AUDIT_DIR/30_scans" "$AUDIT_DIR/40_sbom" "$AUDIT_DIR/60_dynamic" || {
  echo "[!] Error: Failed to create audit directories. Check permissions." >&2
  exit 1
}
cp "$APK" "$AUDIT_DIR/00_meta/app.apk" || { echo "Error: Failed to copy APK to $AUDIT_DIR/00_meta/app.apk - Check permissions." >&2; exit 1; }

ABS_AUDIT_DIR="$(cd "$AUDIT_DIR" && pwd)"
DECOMPILE_OUT="$ABS_AUDIT_DIR/20_decompile"
SCANS="$ABS_AUDIT_DIR/30_scans"
SBOM="$ABS_AUDIT_DIR/40_sbom"
DYN="$ABS_AUDIT_DIR/60_dynamic"
MANI="$ABS_AUDIT_DIR/10_manifest"
APK_LOCAL="$ABS_AUDIT_DIR/00_meta/app.apk"

# ---------------- Scanner failure tracking ----------------
# Why: Track failures to detect degraded scans; fail in strict mode or if too many failures
SCANNER_FAILURES=0
DECOMPILE_METHOD="none"

run_scanner() {
  local scanner_name="$1"
  shift
  if ! python3 "$@"; then
    echo "[!] Warning: $scanner_name failed." >&2
    ((SCANNER_FAILURES++))
    if [[ $STRICT_MODE -eq 1 ]]; then
      echo "[!] Strict mode: Aborting due to scanner failure." >&2
      exit 1
    fi
    return 1
  fi
  return 0
}

# ---------------- Setup ----------------
# Why: In Docker, tools are pre-installed. This section is for host runs or verification, but skipped by default in container.
if [[ $DO_SETUP -eq 1 ]]; then
  echo "[*] Verifying required tools (assumed installed in Docker)..."
  for tool in unzip zip jadx apktool syft grype apkanalyzer adb python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "[!] Error: Missing tool $tool - Install via package manager or Dockerfile." >&2
      exit 2
    fi
  done
  # Python deps handled in Docker via UV
fi

# ---------------- Decompile: try jadx, fallback apktool ----------------
# Why: Decompilation to source improves scan accuracy (e.g., for regex on Java code). Jadx is preferred for better output; apktool for smali if jadx fails.
SRC_DIR=""
JADX_SUCCESS=0

if [[ $DO_DECOMPILE -eq 1 ]]; then
  export JAVA_OPTS="-Xmx2048m"  # Why: Prevent OOM in decompile; 2GB is reasonable for most APKs.

  # Try jadx first
  if command -v jadx >/dev/null 2>&1; then
    echo "[*] Decompiling with jadx (this can take a while)..."
    if jadx --no-inline-anonymous --deobf --escape-unicode -r --show-bad-code -d "$DECOMPILE_OUT" "$APK_LOCAL"; then
      # Verify jadx actually produced Java sources
      if [[ -d "$DECOMPILE_OUT/sources" ]] && [[ -n "$(find "$DECOMPILE_OUT/sources" -name '*.java' 2>/dev/null | head -1)" ]]; then
        JADX_SUCCESS=1
        DECOMPILE_METHOD="jadx"
        echo "[+] jadx decompilation successful (Java sources available)"
      else
        echo "[!] Warning: jadx completed but produced no Java sources."
      fi
    else
      echo "[!] Warning: jadx reported errors."
    fi
  fi

  # Only fall back to apktool if jadx didn't produce valid sources
  if [[ $JADX_SUCCESS -eq 0 ]]; then
    if command -v apktool >/dev/null 2>&1; then
      echo "[*] Falling back to apktool (smali/decode)..."
      tmpout="$ABS_AUDIT_DIR/20_apktool_decode"
      rm -rf "$tmpout"
      if apktool d -f -o "$tmpout" "$APK_LOCAL"; then
        # Only replace decompile output if apktool succeeded and we don't have valid jadx output
        if [[ -d "$tmpout/smali" ]]; then
          rm -rf "$DECOMPILE_OUT"
          mv "$tmpout" "$DECOMPILE_OUT"
          DECOMPILE_METHOD="apktool"
          echo "[+] apktool decompilation successful (smali available)"
        else
          echo "[!] Warning: apktool completed but produced no smali output."
          rm -rf "$tmpout"
        fi
      else
        echo "[!] Error: apktool failed."
        rm -rf "$tmpout"
      fi
    else
      echo "[!] Warning: apktool missing."
    fi
  fi
fi

# Choose source dir for scanners (best effort)
# Why: Fall back to raw APK if decompile fails, ensuring scans always run but with reduced accuracy.
if [[ -d "$DECOMPILE_OUT/sources" ]]; then
  SRC_DIR="$DECOMPILE_OUT/sources"
elif [[ -d "$DECOMPILE_OUT/smali" ]]; then
  SRC_DIR="$DECOMPILE_OUT"
else
  SRC_DIR="$ABS_AUDIT_DIR/00_meta" # raw fallback (scanners handle zip)
  DECOMPILE_METHOD="raw_apk"
  echo ""
  echo "============================================================"
  echo "[!] WARNING: Using raw APK - scan accuracy significantly reduced!"
  echo "[!] Decompilation failed. Scanners will attempt to parse raw APK"
  echo "[!] contents but pattern matching will be limited."
  echo "============================================================"
  echo ""
fi

echo "[*] Decompilation method: $DECOMPILE_METHOD"
echo "[*] Source directory: $SRC_DIR"

# ---------------- Manifest extraction ----------------
# Why: Manifest is key for permissions, components; extract reliably with fallbacks for completeness.
MANIFEST_METHOD="none"
echo "[*] Extracting manifest..."

if command -v apkanalyzer >/dev/null 2>&1; then
  if apkanalyzer manifest print "$APK_LOCAL" > "$MANI/AndroidManifest.xml" 2>/dev/null && [[ -s "$MANI/AndroidManifest.xml" ]]; then
    MANIFEST_METHOD="apkanalyzer"
    echo "[+] Manifest extracted via apkanalyzer"
  fi
fi

if [[ ! -s "$MANI/AndroidManifest.xml" ]]; then
  # Fallback with androguard
  if python3 -m androguard axml "$APK_LOCAL" -o "$MANI/AndroidManifest.xml" 2>/dev/null && [[ -s "$MANI/AndroidManifest.xml" ]]; then
    MANIFEST_METHOD="androguard"
    echo "[+] Manifest extracted via androguard"
  fi
fi

if [[ ! -s "$MANI/AndroidManifest.xml" && -f "$DECOMPILE_OUT/AndroidManifest.xml" ]]; then
  if cp "$DECOMPILE_OUT/AndroidManifest.xml" "$MANI/AndroidManifest.xml" 2>/dev/null && [[ -s "$MANI/AndroidManifest.xml" ]]; then
    MANIFEST_METHOD="decompile_copy"
    echo "[+] Manifest copied from decompile output"
  fi
fi

if [[ ! -s "$MANI/AndroidManifest.xml" ]]; then
  echo "[!] Warning: Manifest decode failed; some checks will be limited."
  MANIFEST_METHOD="failed"
fi

# ---------------- Static scanners ----------------
# Why: Static analysis covers code-based vulns without runtime; parallelizable for speed.
# Expanded to 30 scanners for comprehensive OWASP MASVS/MSTG coverage.
if [[ $DO_STATIC -eq 1 ]]; then
  echo "[*] Running static analyzers (30 scanners)..."
  echo ""

  # Core scanners (original)
  echo "    [1/30] Manifest analysis..."
  run_scanner "Manifest scan"        bin/scan_manifest.py           "$MANI/AndroidManifest.xml" "$SCANS/manifest.csv"
  echo "    [2/30] Secret detection..."
  run_scanner "Secrets scan"         bin/scan_secrets.py            "$SRC_DIR"                   "$SCANS/secrets.csv"         "$APK_LOCAL"
  echo "    [3/30] Cryptography issues..."
  run_scanner "Crypto scan"          bin/scan_crypto_issues.py      "$SRC_DIR"                   "$SCANS/crypto.csv"          "$APK_LOCAL"
  echo "    [4/30] WebView security..."
  run_scanner "WebView scan"         bin/scan_webview.py            "$SRC_DIR"                   "$SCANS/webview.csv"         "$APK_LOCAL"
  echo "    [5/30] Storage and logging..."
  run_scanner "Storage/logging scan" bin/scan_storage_logging.py "$SRC_DIR"                   "$SCANS/logging_storage.csv" "$APK_LOCAL"
  echo "    [6/30] Network security..."
  run_scanner "Network scan"         bin/scan_network_security.py "$SRC_DIR" "$MANI/AndroidManifest.xml" "$SCANS/network.csv" "$APK_LOCAL"
  echo "    [7/30] Authentication issues..."
  run_scanner "Auth scan"            bin/scan_auth_issues.py "$SRC_DIR" "$MANI/AndroidManifest.xml" "$SCANS/auth.csv" "$APK_LOCAL"
  echo "    [8/30] Injection risks..."
  run_scanner "Injection scan"       bin/scan_injection_risks.py "$SRC_DIR" "$SCANS/injection.csv" "$APK_LOCAL"
  echo "    [9/30] Binary protections..."
  run_scanner "Binary protections scan" bin/scan_binary_protections.py "$SRC_DIR" "$APK_LOCAL" "$SCANS/binary_protections.csv"
  echo "    [10/30] Privacy issues..."
  run_scanner "Privacy scan"         bin/scan_privacy_issues.py "$SRC_DIR" "$SCANS/privacy.csv" "$APK_LOCAL" "$MANI/AndroidManifest.xml"
  echo "    [11/30] Certificate pinning..."
  run_scanner "Cert pinning scan"    bin/scan_cert_pinning.py "$SRC_DIR" "$SCANS/cert_pinning.csv" "$APK_LOCAL"
  echo "    [12/30] Content providers..."
  run_scanner "Content provider scan" bin/scan_content_providers.py "$SRC_DIR" "$MANI/AndroidManifest.xml" "$SCANS/content_providers.csv" "$APK_LOCAL"
  echo "    [13/30] PendingIntent security..."
  run_scanner "PendingIntent scan"   bin/scan_pending_intents.py "$SRC_DIR" "$SCANS/pending_intents.csv" "$APK_LOCAL" "$MANI/AndroidManifest.xml"

  # Extended scanners
  echo ""
  echo "    [14/30] Firebase misconfiguration..."
  run_scanner "Firebase scan"        bin/scan_firebase.py "$SRC_DIR" "$SCANS/firebase.csv" "$APK_LOCAL"
  echo "    [15/30] Task hijacking (StrandHogg)..."
  run_scanner "Task hijacking scan"  bin/scan_task_hijacking.py "$MANI/AndroidManifest.xml" "$SCANS/task_hijacking.csv" "$SRC_DIR"
  echo "    [16/30] Deep link security..."
  run_scanner "Deep links scan"      bin/scan_deep_links.py "$MANI/AndroidManifest.xml" "$SCANS/deep_links.csv" "$SRC_DIR"
  echo "    [17/30] Tapjacking/overlay attacks..."
  run_scanner "Tapjacking scan"      bin/scan_tapjacking.py "$MANI/AndroidManifest.xml" "$SCANS/tapjacking.csv" "$SRC_DIR"
  echo "    [18/30] Broadcast receiver security..."
  run_scanner "Broadcasts scan"      bin/scan_broadcasts.py "$MANI/AndroidManifest.xml" "$SCANS/broadcasts.csv" "$SRC_DIR"
  echo "    [19/30] Native library security..."
  run_scanner "Native libs scan"     bin/scan_native_libs.py "$SCANS/native_libs.csv" "$APK_LOCAL" "$SRC_DIR"
  echo "    [20/30] Dynamic code loading..."
  run_scanner "Dynamic loading scan" bin/scan_dynamic_loading.py "$SRC_DIR" "$SCANS/dynamic_loading.csv"

  # Advanced scanners
  echo ""
  echo "    [21/30] Zip slip (path traversal)..."
  run_scanner "Zip slip scan"        bin/scan_zip_slip.py "$SRC_DIR" "$SCANS/zip_slip.csv"
  echo "    [22/30] Unsafe deserialization..."
  run_scanner "Serialization scan"   bin/scan_serialization.py "$SRC_DIR" "$SCANS/serialization.csv"
  echo "    [23/30] Fragment injection..."
  run_scanner "Fragment injection scan" bin/scan_fragment_injection.py "$SRC_DIR" "$SCANS/fragment_injection.csv" "$MANI/AndroidManifest.xml"
  echo "    [24/30] XXE injection..."
  run_scanner "XXE scan"             bin/scan_xxe.py "$SRC_DIR" "$SCANS/xxe.csv"
  echo "    [25/30] Implicit intent leakage..."
  run_scanner "Implicit intents scan" bin/scan_implicit_intents.py "$SRC_DIR" "$SCANS/implicit_intents.csv"
  echo "    [26/30] Clipboard data exposure..."
  run_scanner "Clipboard scan"       bin/scan_clipboard.py "$SRC_DIR" "$SCANS/clipboard.csv"
  echo "    [27/30] Keyboard cache issues..."
  run_scanner "Keyboard cache scan"  bin/scan_keyboard_cache.py "$SRC_DIR" "$SCANS/keyboard_cache.csv"
  echo "    [28/30] Insecure random..."
  run_scanner "Random scan"          bin/scan_random.py "$SRC_DIR" "$SCANS/random.csv"
  echo "    [29/30] APK signature analysis..."
  run_scanner "APK signature scan"   bin/scan_apk_signature.py "$SCANS/apk_signature.csv" "$APK_LOCAL" "$SRC_DIR"
  echo "    [30/30] Deprecated API usage..."
  run_scanner "Deprecated APIs scan" bin/scan_deprecated_apis.py "$SRC_DIR" "$SCANS/deprecated_apis.csv"

  echo ""
  echo "[+] Static analysis complete (30 scanners)"
fi

# ---------------- SBOM + CVEs ----------------
# Why: SBOM detects library vulns; critical for supply chain risks, with remediation from CVEs.
if [[ $DO_SBOM -eq 1 ]]; then
  if command -v syft >/dev/null 2>&1 && command -v grype >/dev/null 2>&1; then
    echo "[*] Building SBOM & matching CVEs..."
    UNZ="$SBOM/unzipped"
    rm -rf "$UNZ"; mkdir -p "$UNZ"
    (cd "$UNZ" && unzip -oq "$APK_LOCAL") || echo "[!] Warning: Unzip failed."
    syft scan "dir:$UNZ" -o json > "$SBOM/syft.json" || echo "[!] Warning: syft failed."
    grype sbom:"$SBOM/syft.json" -o json > "$SBOM/grype.json" || echo "[!] Warning: grype failed."
    run_scanner "SBOM convert" bin/sbom_converter.py "$SBOM/grype.json" "$SBOM/grype.csv"
  else
    echo "[!] Warning: syft or grype not found; skipping SBOM/CVE."
  fi
fi

# ---------------- Dynamic probe ----------------
# Why: Dynamic checks IPC exposure which static can't fully cover; optional for no-device scenarios.
if [[ $DO_DYNAMIC -eq 1 ]]; then
  if command -v adb >/dev/null 2>&1; then
    echo "[*] Running dynamic IPC probe (if device is available)..."
    run_scanner "Dynamic IPC scan" bin/dynamic_ipc_scan.py "$APK_LOCAL" "$MANI/AndroidManifest.xml" "$DYN/dynamic.csv"
  else
    echo "[!] Warning: adb not found; skipping dynamic probe."
    python3 - <<PY "$DYN/dynamic.csv"
import sys, pandas as pd, os
out = sys.argv[1]
os.makedirs(os.path.dirname(out), exist_ok=True)
df = pd.DataFrame([{
  "Source":"dynamic","RuleID":"DYNAMIC_NO_DEVICE","Title":"No device detected",
  "Location":"","Evidence":"","Severity":"Info","HowFound":"adb not available"
}])
df.to_csv(out, index=False)
print(f"Wrote {out} (no device)")
PY
  fi
fi

# ---------------- Taxonomies (MITRE) + Enrichment ----------------
# Why: Fetch MITRE for dynamic mapping to techniques; offline mode avoids network if cached, for air-gapped use.
if [[ $OFFLINE -eq 1 ]]; then
  echo "[*] Offline mode: will NOT fetch MITRE; using cache if present."
  OFFLINE_FLAG="--offline"
else
  OFFLINE_FLAG=""
fi
python3 bin/mitre_fetcher.py $OFFLINE_FLAG "data/mitre_mobile_attack.json" "data/mitre_etag.txt" || echo "[!] Warning: MITRE fetch failed - Using cache if available."

# ---------------- Aggregate + enrich + print stats ----------------
# Why: Aggregation centralizes findings for easy review; enrichment adds why/fix for actionable output.
echo "[*] Aggregating findings -> findings.csv"
if ! python3 bin/aggregate_results.py "$ABS_AUDIT_DIR" > "$ABS_AUDIT_DIR/findings.csv"; then
  echo "[!] Error: Aggregation failed." >&2
  ((SCANNER_FAILURES++))
fi

# Validate findings.csv before enrichment
if [[ ! -s "$ABS_AUDIT_DIR/findings.csv" ]]; then
  echo "[!] Warning: findings.csv is empty or missing. Enrichment may fail."
fi

echo "[*] Enriching -> findings_enriched.csv (OWASP, MITRE, WhyRelevant, HowResolve)"
if ! python3 bin/enrich_results.py "$ABS_AUDIT_DIR/findings.csv" "data/owasp_rule_mappings.yaml" "data/mitre_mobile_attack.json" > "$ABS_AUDIT_DIR/findings_enriched.csv"; then
  echo "[!] Error: Enrichment failed." >&2
  ((SCANNER_FAILURES++))
fi

echo "[*] Summary:"
python3 bin/stats_summarizer.py "$ABS_AUDIT_DIR/stats.json" || echo "[!] Warning: Stats print failed."

# ---------------- Output generation ----------------
# Why: HTML and SARIF outputs enable integration with CI/CD and human-readable dashboards.
if [[ $DO_HTML -eq 1 ]]; then
  echo "[*] Generating HTML report..."
  if python3 bin/generate_html_report.py "$ABS_AUDIT_DIR/findings_enriched.csv" "$ABS_AUDIT_DIR/findings.html" --title "APK Security Report - $(basename "$APK")"; then
    echo "[+] HTML report generated: $ABS_AUDIT_DIR/findings.html"
  else
    echo "[!] Warning: HTML report generation failed."
    ((SCANNER_FAILURES++))
  fi
fi

if [[ $DO_SARIF -eq 1 ]]; then
  echo "[*] Generating SARIF report..."
  if python3 bin/generate_sarif.py "$ABS_AUDIT_DIR/findings_enriched.csv" "$ABS_AUDIT_DIR/findings.sarif" --tool-version "1.0.0"; then
    echo "[+] SARIF report generated: $ABS_AUDIT_DIR/findings.sarif"
  else
    echo "[!] Warning: SARIF report generation failed."
    ((SCANNER_FAILURES++))
  fi
fi

# ---------------- Final status ----------------
echo ""
echo "============================================================"
echo "    APK Raccoon - Scan Complete"
echo "============================================================"
echo ""
echo "[i] Decompilation method: $DECOMPILE_METHOD"
echo "[i] Manifest extraction: $MANIFEST_METHOD"
echo "[i] Scanner failures: $SCANNER_FAILURES"
echo ""
echo "[i] Output artifacts:"
echo "    Manifest:     $MANI"
echo "    Decompiled:   $DECOMPILE_OUT"
echo "    Scan Results: $SCANS"
echo "    SBOM/CVE:     $SBOM"
echo "    Dynamic:      $DYN"
echo ""
echo "[i] Final reports:"
echo "    Summary:      $ABS_AUDIT_DIR/stats.json"
echo "    All findings: $ABS_AUDIT_DIR/findings.csv"
echo "    Enriched:     $ABS_AUDIT_DIR/findings_enriched.csv"
if [[ $DO_HTML -eq 1 && -f "$ABS_AUDIT_DIR/findings.html" ]]; then
  echo "    HTML Report:  $ABS_AUDIT_DIR/findings.html"
fi
if [[ $DO_SARIF -eq 1 && -f "$ABS_AUDIT_DIR/findings.sarif" ]]; then
  echo "    SARIF Report: $ABS_AUDIT_DIR/findings.sarif"
fi
echo ""

# Exit with error if too many scanner failures (threshold: 3)
if [[ $SCANNER_FAILURES -gt 3 ]]; then
  echo "[!] ERROR: Too many scanner failures ($SCANNER_FAILURES). Results may be incomplete." >&2
  exit 1
fi

if [[ $SCANNER_FAILURES -gt 0 ]]; then
  echo "[!] WARNING: $SCANNER_FAILURES scanner(s) failed. Review warnings above." >&2
fi

exit 0
