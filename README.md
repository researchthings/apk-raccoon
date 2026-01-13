# APK Raccoon

```
    _    ____  _  __  ____
   / \  |  _ \| |/ / |  _ \ __ _  ___ ___ ___   ___  _ __
  / _ \ | |_) | ' /  | |_) / _` |/ __/ __/ _ \ / _ \| '_ \
 / ___ \|  __/| . \  |  _ < (_| | (_| (_| (_) | (_) | | | |
/_/   \_\_|   |_|\_\ |_| \_\__,_|\___\___\___/ \___/|_| |_|

Digging through your APK garbage like a pro to find 
security vulnerabilities. It's probably buggy so parental 
descretion is advised.
```

**APK Raccoon v1.0.0** is a comprehensive Android APK security scanner with **OWASP MASTG coverage**. It performs deep static analysis across **31 security scanners**, generates SBOM with CVE matching, and produces reports in **CSV, HTML, and SARIF** formats with actionable remediation guidance.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP MASVS](https://img.shields.io/badge/OWASP-MASVS%202.0-orange.svg)](https://mas.owasp.org/)
[![Tests](https://img.shields.io/badge/tests-163%20passed-brightgreen.svg)]()

---

## Features

| Category | Description |
| ---------- | ------------- |
| **31 Security Scanners** | 100% coverage of **static** analyzable Android MASTG tests (97): secrets, crypto, auth, network, storage, WebView, content providers, Firebase, StrandHogg, deep links, tapjacking, broadcasts, native libs, dynamic loading, zip slip, deserialization, XXE, fragment injection, screenshot protection, and more |
| **SBOM + CVE Analysis** | Software composition analysis with Syft/Grype for supply chain security |
| **200+ Detection Rules** | Modern patterns covering OWASP Top 10 Mobile, CWE Mobile, and MITRE ATT&CK Mobile |
| **Multiple Output Formats** | CSV (default), HTML dashboard with charts, SARIF for CI/CD integration |
| **Enriched Reports** | OWASP MASVS/MSTG mappings with "Why it matters" and "How to fix" guidance |
| **Docker-First** | Single command, reproducible results, CI/CD ready |
| **Offline Mode** | Works air gapped (except MITRE fetch) |

---

## OWASP MASTG Coverage

APK Raccoon provides **100% coverage of static analyzable Android MASTG tests**:

| Category | Total Tests | Static-Analyzable | Covered | Coverage |
| ---------- | ------------- | ------------------- | --------- | ---------- |
| STORAGE | 20 | 16 | 16 | 100% |
| CRYPTO | 15 | 15 | 15 | 100% |
| NETWORK | 20 | 20 | 20 | 100% |
| PLATFORM | 25 | 25 | 25 | 100% |
| CODE | 14 | 14 | 14 | 100% |
| PRIVACY | 7 | 7 | 7 | 100% |
| AUTH | 2 | 0 | 0 | N/A |
| RESILIENCE | 21 | 0 | 0 | N/A |
| **Total** | **124** | **97** | **97** | **100%** |

### What About the Other 27 Tests?

27 Android MASTG tests require **dynamic/runtime analysis** that static scanning cannot perform:

- **AUTH (2 tests)**: Biometric and credential testing requires device interaction
- **RESILIENCE (21 tests)**: Root detection, anti-debugging, emulator detection require runtime verification
- **STORAGE (4 tests)**: Memory analysis and backup behavior require device testing

These tests are out of scope for static analysis tools. For full MASTG compliance, complement APK Raccoon with dynamic testing tools like [Frida](https://frida.re/) or [MobSF](https://mobsf.github.io/Mobile-Security-Framework-MobSF/).

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Running Scans](#running-scans)
- [Testing](#testing)
- [Security Scanners](#security-scanners-31-total)
- [Output Formats](#output-formats)
- [CI/CD Integration](#cicd-integration)
- [Extending APK Raccoon](#extending-apk-raccoon)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Docker (Recommended)

```bash
# Step 1: Build the image (required first time only)
docker build -t apk-raccoon .
```

```bash
# Step 2: Run a scan (choose one option below)

# --- Option 1: Mount current directory for APK input AND output ---
# Place your APK in current directory. Mount it and set AUDIT_DIR so results are saved.
#   -v "$PWD:/work"       mounts current directory to /work inside container
#   -e AUDIT_DIR=/work    tells raccoon to write results to /work (the mounted dir)
#   /work/app.apk         path to APK INSIDE the container
cp /path/to/your/app.apk ./app.apk
docker run --rm \
  -v "$PWD:/work" \
  -e AUDIT_DIR=/work \
  apk-raccoon --html --sarif /work/app.apk

# Results appear in: ./<apk-name>_YYYYMMDD_HHMMSS/

# --- Option 2: Separate input and output directories ---
# Mount APK from one location, write results to another
docker run --rm \
  -v /path/to/apks:/input:ro \
  -v /path/to/results:/output \
  -e AUDIT_DIR=/output \
  apk-raccoon --html --sarif /input/app.apk

# Results appear in: /path/to/results/<apk-name>_YYYYMMDD_HHMMSS/

# --- Option 3: Build APK into image (for CI/CD pipelines) ---
# Create a Dockerfile.scan:
#   FROM apk-raccoon
#   COPY myapp.apk /input/target.apk
#   ENV AUDIT_DIR=/output
#   CMD ["--html", "--sarif", "/input/target.apk"]
# Build and run:
#   docker build -f Dockerfile.scan -t my-scan .
#   docker run --rm -v "$PWD/results:/output" my-scan
```

### Docker: Multiple Scans

For scanning multiple APKs, mount input and output directories:

```bash
# Mount APK directory (read-only) and output directory
docker run --rm \
  -v /path/to/apks:/input:ro \
  -v /path/to/results:/output \
  -e AUDIT_DIR=/output \
  apk-raccoon /input/first_app.apk

# Run another scan with same setup
docker run --rm \
  -v /path/to/apks:/input:ro \
  -v /path/to/results:/output \
  -e AUDIT_DIR=/output \
  apk-raccoon /input/second_app.apk

# Results in: /path/to/results/first_app_YYYYMMDD_HHMMSS/
#             /path/to/results/second_app_YYYYMMDD_HHMMSS/
```

Or use docker-compose for easier multi-scan workflows:

```bash
# With docker-compose.yml in the repo
docker-compose run raccoon /input/app.apk
```

### Local with uv (Fastest)

```bash
# Clone and enter directory
git clone https://github.com/researchthings/apk-raccoon.git
cd apk-raccoon

# Create venv and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv sync

# Run scan
./raccoon.sh --html /path/to/app.apk
```

### Local with conda

```bash
# Create conda environment
conda env create -f environment.yml
conda activate apk-raccoon

# Run scan
./raccoon.sh --html --sarif /path/to/app.apk
```

### Local with pip

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run scan
./raccoon.sh /path/to/app.apk
```

---

## Installation

### Prerequisites

| Tool | Purpose | Required |
| ------ | --------- | ---------- |
| Python 3.10+ | Scanner runtime | Yes |
| jadx | Java decompilation (preferred) | Yes* |
| apktool | Smali decompilation (fallback) | Yes* |
| syft | SBOM generation | Recommended |
| grype | CVE matching | Recommended |
| adb | Dynamic IPC probing | Optional |
| readelf | Native library analysis | Optional |

*At least one decompiler required

### Installing External Tools

**macOS (Homebrew):**

```bash
brew install jadx apktool
brew install anchore/grype/syft anchore/grype/grype
brew install android-platform-tools  # for adb
```

**Ubuntu/Debian:**

```bash
# jadx
wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d /opt/jadx
ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

# apktool
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar
mv apktool_2.9.3.jar /usr/local/bin/apktool.jar
chmod +x /usr/local/bin/apktool

# syft & grype
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# adb
apt install android-tools-adb
```

### Environment Setup

#### Option 1: uv (Recommended - Fastest)

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create environment and install
uv venv
source .venv/bin/activate
uv sync

# Install dev dependencies for testing
uv sync --dev
```

#### Option 2: conda

```bash
# Create environment from file
conda env create -f environment.yml
conda activate apk-raccoon

# For development, install dev deps via pip
pip install pytest pytest-cov ruff mypy
```

#### Option 3: pip + venv

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install runtime dependencies
pip install -r requirements.txt

# For development/testing
pip install -r requirements-dev.txt
```

---

## Running Scans

### Basic Usage

```bash
./raccoon.sh [options] <app.apk>
```

### Command Line Options

| Option | Description |
| -------- | ------------- |
| `--no-setup` | Skip tool verification (Docker has them pre-installed) |
| `--no-decompile` | Skip jadx/apktool decompilation |
| `--no-static` | Skip all 31 Python static scanners |
| `--no-sbom` | Skip SBOM + CVE analysis (syft/grype) |
| `--dynamic` | Enable ADB dynamic IPC probe (disabled by default) |
| `--offline` | Do not fetch MITRE data (use cache) |
| `--strict` | Exit non-zero on any scanner failure (for CI/CD) |
| `--html` | Generate interactive HTML dashboard |
| `--sarif` | Generate SARIF 2.1.0 report for CI/CD |
| `-h, --help` | Show help |

### Examples

```bash
# Full scan with all output formats
./raccoon.sh --html --sarif /path/to/app.apk

# Quick scan (skip SBOM and dynamic)
./raccoon.sh --no-sbom --no-dynamic /path/to/app.apk

# CI/CD mode (strict, no dynamic, with SARIF for GitHub Security)
./raccoon.sh --strict --no-dynamic --sarif /path/to/app.apk

# Offline mode (air-gapped environment)
./raccoon.sh --offline --no-sbom --no-dynamic /path/to/app.apk
```

### Output Directory Structure

Each scan creates a directory named after the APK: `<apk-name>_YYYYMMDD_HHMMSS/`

```
myapp_20260110_143022/
├── 00_meta/
│   └── app.apk              # Copy of scanned APK
├── 10_manifest/
│   └── AndroidManifest.xml  # Extracted manifest
├── 20_decompile/
│   └── sources/             # Decompiled Java/Kotlin (jadx)
│   └── smali/               # Smali bytecode (apktool fallback)
├── 30_scans/
│   ├── manifest.csv         # 31 individual scan results
│   ├── secrets.csv
│   ├── crypto.csv
│   ├── zip_slip.csv
│   ├── serialization.csv
│   └── ... (31 scan files)
├── 40_sbom/
│   ├── syft.json            # Software Bill of Materials
│   ├── grype.json           # CVE matches
│   └── grype.csv            # CVE findings
├── 60_dynamic/
│   └── dynamic.csv          # IPC probe results
├── findings.csv             # All findings aggregated
├── findings_enriched.csv    # With OWASP/MITRE/remediation
├── findings.html            # Interactive HTML dashboard (--html)
├── findings.sarif           # SARIF 2.1.0 report (--sarif)
└── stats.json               # Summary statistics
```

---

## Testing

### Running the Test Suite

```bash
# Activate your environment first
source .venv/bin/activate  # or: conda activate apk-raccoon

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_advanced_scanners.py -v

# Run specific test class
pytest tests/test_advanced_scanners.py::TestZipSlipPatterns -v

# Run with coverage report
pytest --cov=bin --cov-report=html
open htmlcov/index.html  # View coverage report

# Run only pattern tests (fast)
pytest tests/test_patterns.py tests/test_advanced_scanners.py -v
```

### Test Structure

```
tests/
├── test_patterns.py           # Core pattern matching tests (secrets, crypto)
├── test_new_scanners.py       # Extended scanner tests (Firebase, StrandHogg, etc.)
├── test_advanced_scanners.py  # Advanced scanner tests (ZipSlip, XXE, etc.)
├── test_scanner_utils.py      # Utility function tests
└── conftest.py                # Pytest fixtures
```

### Test Categories

| Test File | Tests | Coverage |
| ----------- | ------- | ---------- |
| `test_patterns.py` | 45 | Core secret/crypto patterns |
| `test_new_scanners.py` | 50 | Extended scanners |
| `test_advanced_scanners.py` | 41 | Advanced scanners |
| `test_scanner_utils.py` | 27 | CSV output, file iteration |
| **Total** | **163** | All pattern matching |

### Testing Individual Scanners

```bash
# Test a scanner directly on sample code
python bin/scan_zip_slip.py tests/fixtures/sample_src tests/output/zip_slip.csv

# Test SARIF generator
python bin/generate_sarif.py tests/fixtures/sample_findings.csv /tmp/test.sarif

# Test HTML generator
python bin/generate_html_report.py tests/fixtures/sample_findings.csv /tmp/test.html
```

### Creating Test Fixtures

```bash
# Create sample vulnerable code for testing
mkdir -p tests/fixtures/sample_src

# Add vulnerable Java file
cat > tests/fixtures/sample_src/VulnerableActivity.java << 'EOF'
package com.example;

import java.util.zip.*;
import java.io.*;

public class VulnerableActivity {
    // Zip Slip vulnerable
    public void extractZip(ZipInputStream zis) {
        for (ZipEntry entry : entries) {
            File file = new File(targetDir, entry.getName());  // Vulnerable!
            // ...
        }
    }

    // Insecure random
    public int getRandomToken() {
        return new Random().nextInt();  // Vulnerable!
    }
}
EOF

# Run scanner on fixture
python bin/scan_zip_slip.py tests/fixtures/sample_src /tmp/test.csv
python bin/scan_random.py tests/fixtures/sample_src /tmp/test.csv
```

### Continuous Testing During Development

```bash
# Watch mode with pytest-watch (install: pip install pytest-watch)
ptw tests/ -- -v

# Or use entr (install: brew install entr)
find bin tests -name "*.py" | entr -c pytest -v
```

---

## Security Scanners (31 Total)

### Core Scanners (1-13)

| # | Scanner | What It Detects |
| --- | --------- | ----------------- |
| 1 | `scan_manifest.py` | Debuggable, exported components, dangerous permissions, backup settings |
| 2 | `scan_secrets.py` | AWS keys, API tokens, private keys, hardcoded passwords |
| 3 | `scan_crypto_issues.py` | ECB mode, DES/RC2, weak hashes, static IVs |
| 4 | `scan_webview.py` | JavaScript enabled, file access, SSL bypass |
| 5 | `scan_storage_logging.py` | World-readable prefs, external storage, sensitive logging |
| 6 | `scan_network_security.py` | Cleartext traffic, HTTP URLs, trust-all certificates |
| 7 | `scan_auth_issues.py` | Weak passwords, client-side auth, token exposure |
| 8 | `scan_injection_risks.py` | SQL injection, command injection, XSS |
| 9 | `scan_binary_protections.py` | Root detection, anti-debug, obfuscation |
| 10 | `scan_privacy_issues.py` | PII in code, excess permissions |
| 11 | `scan_cert_pinning.py` | Pinning implementation, bypass patterns |
| 12 | `scan_content_providers.py` | Exported providers, SQL injection |
| 13 | `scan_pending_intents.py` | Empty intents, mutable flags |

### Extended Scanners (14-20)

| # | Scanner | What It Detects |
| --- |--------- | ----------------- |
| 14 | `scan_firebase.py` | Exposed database URLs, FCM server keys |
| 15 | `scan_task_hijacking.py` | StrandHogg 1.0/2.0, taskAffinity issues |
| 16 | `scan_deep_links.py` | Missing autoVerify, scheme hijacking |
| 17 | `scan_tapjacking.py` | Overlay attacks, missing filterTouchesWhenObscured |
| 18 | `scan_broadcasts.py` | Exported receivers, sticky broadcasts |
| 19 | `scan_native_libs.py` | NX/RELRO/canary flags, known CVEs |
| 20 | `scan_dynamic_loading.py` | DexClassLoader abuse, remote code download |

### Advanced Scanners (21-31)

| # | Scanner | What It Detects | CWE |
| --- | --------- | ----------------- | ----- |
| 21 | `scan_zip_slip.py` | Path traversal in ZIP extraction | CWE-22 |
| 22 | `scan_serialization.py` | Unsafe ObjectInputStream/XMLDecoder | CWE-502 |
| 23 | `scan_fragment_injection.py` | PreferenceActivity fragment bypass | CWE-470 |
| 24 | `scan_xxe.py` | XML External Entity injection | CWE-611 |
| 25 | `scan_implicit_intents.py` | Broadcast/Service intent leakage | CWE-927 |
| 26 | `scan_clipboard.py` | Sensitive data in clipboard | CWE-200 |
| 27 | `scan_keyboard_cache.py` | Keyboard autocomplete on passwords | CWE-524 |
| 28 | `scan_random.py` | java.util.Random vs SecureRandom | CWE-338 |
| 29 | `scan_apk_signature.py` | APK signature scheme analysis | CWE-347 |
| 30 | `scan_deprecated_apis.py` | Obsolete/insecure API usage | CWE-477 |
| 31 | `scan_screenshot_protection.py` | FLAG_SECURE, sensitive screen protection | CWE-200 |

---

## Output Formats

### CSV (Default)

Standard CSV with all findings:

```csv
Source,RuleID,Title,Location,Evidence,Severity,HowFound
secrets,SECRET_AWS_ACCESS_KEY,AWS Access Key,MainActivity.java:42,AKIA...,Critical,Pattern match
```

### HTML Dashboard (`--html`)

Interactive HTML5 dashboard with:

- Severity distribution chart (Chart.js)
- Searchable/sortable findings table (DataTables)
- Dark/light mode toggle
- OWASP and MITRE enrichment display
- Export capabilities

```bash
./raccoon.sh --html app.apk
open audit_*/findings.html
```

### SARIF (`--sarif`)

SARIF 2.1.0 format for CI/CD integration:

- GitHub Security tab compatible
- GitLab SAST compatible
- Azure DevOps compatible
- CWE and OWASP taxonomy relationships

```bash
./raccoon.sh --sarif app.apk
# Upload to GitHub Security:
# gh api repos/{owner}/{repo}/code-scanning/sarifs -f sarif=@audit_*/findings.sarif
```

---

## Severity Definitions

All findings are classified using a 5-level severity scale:

| Severity | Description | Examples | Action |
|---------- | ------------- | ---------- | -------- |
| **Critical** | Immediate exploitation risk | Hardcoded secrets, disabled cert validation, SQL injection | Fix immediately |
| **High** | Significant weakness with clear attack vector | Weak crypto (DES/ECB), cleartext traffic, exported sensitive components | Fix before release |
| **Medium** | Moderate risk requiring review | Debug flags, missing protections, static IV | Address before release |
| **Low** | Best practice violations | Verbose logging, unstripped symbols, missing cert pinning | Consider fixing |
| **Info** | Informational/positive observations | FLAG_SECURE detected, root detection present | No action needed |

**Key distinction**: Critical/High/Medium/Low indicate problems found. Info indicates protection mechanisms detected or neutral observations.

See [data/severity_definitions.yaml](data/severity_definitions.yaml) for the complete definition with examples.

---

## CI/CD Integration

### GitHub Actions

```yaml
name: APK Raccoon Scan

on:
  push:
    paths:
      - '**.apk'
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build APK Raccoon
        run: docker build -t apk-raccoon .

      - name: Run Security Scan
        run: |
          docker run --rm -v "$PWD:/work" apk-raccoon \
            --no-dynamic --strict --sarif /work/app.apk

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: audit_*/findings.sarif

      - name: Check for Critical Findings
        run: |
          CRITICAL=$(jq '.by_severity.Critical // 0' audit_*/stats.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "FAIL: $CRITICAL critical vulnerabilities found!"
            exit 1
          fi

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: audit_*/
```

### GitLab CI

```yaml
apk-raccoon-scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t apk-raccoon .
    - docker run --rm -v "$PWD:/work" apk-raccoon --no-dynamic --strict --sarif /work/app.apk
    - |
      CRITICAL=$(jq '.by_severity.Critical // 0' audit_*/stats.json)
      if [ "$CRITICAL" -gt 0 ]; then exit 1; fi
  artifacts:
    paths:
      - audit_*/
    reports:
      sast: audit_*/findings.sarif
    expire_in: 30 days
```

---

## Extending APK Raccoon

### Adding Custom Secret Patterns

Edit `bin/scan_secrets.py`:

```python
SECRET_PATTERNS = [
    # ... existing patterns ...

    # Custom: My Company API Key
    (
        r"MYCO_[A-Za-z0-9]{32}",
        "SECRET_MYCOMPANY_KEY",
        "High",
        "MyCompany API Key",
        "Internal API key detected - rotate immediately",
    ),
]
```

### Adding OWASP Mappings

Edit `data/owasp_rule_mappings.yaml`:

```yaml
MY_CUSTOM_RULE:
  owasp: [MASVS-STORAGE-1, MSTG-STORAGE-2]
  mitre_keywords: [credential, hardcoded]
  why: Explanation of why this matters
  how: How to fix the issue
```

### Creating a New Scanner

See `bin/scan_zip_slip.py` as a template. Key components:

1. Pattern definitions with severity
2. `scan()` function returning findings list
3. CSV output with standard fieldnames
4. Main entry point

---

## Troubleshooting

### "jadx failed" or "apktool failed"

- **Cause**: APK may be heavily obfuscated or use anti-tampering
- **Solution**: Scanner continues with raw APK analysis (reduced accuracy)

### "No findings generated"

- **Cause**: Decompilation may have failed completely
- **Check**: Look for `20_decompile/sources/` or `20_decompile/smali/`

### Tests failing

```bash
# Ensure you're in the right environment
source .venv/bin/activate

# Check Python version (needs 3.10+)
python --version

# Reinstall dependencies
pip install -r requirements-dev.txt

# Run tests with verbose output
pytest -v --tb=long
```

### Scanner failures in strict mode

- **Cause**: Individual scanner hit an error
- **Solution**: Check stderr output, run without `--strict` for partial results

---

## Requirements

### Docker Build

- Docker 20.10+
- ~2GB disk space for image

### Local Installation

- Python 3.10+
- jadx 1.5.0+ (preferred) or apktool 2.9+
- (Recommended) syft, grype for SBOM/CVE
- (Optional) readelf for native lib analysis

---

## Security Considerations

- APK Raccoon is for **authorized apk vulnerability testing only**
- Findings should be reviewed by qualified security professionals as there could be a lot of stuff
- Some patterns will produce false positives - manual verification recommended
- Do not use on APKs you don't have permission to analyze

---

## License

MIT License - See [LICENSE](LICENSE) file

---

## Author

**Randy Grant** - <rgrant.research@gmail.com>

---

## Acknowledgments

- [OWASP MASVS/MASTG](https://mas.owasp.org/) - Mobile security standards
- [jadx](https://github.com/skylot/jadx) - APK decompiler
- [Androguard](https://github.com/androguard/androguard) - Android analysis
- [Syft](https://github.com/anchore/syft) / [Grype](https://github.com/anchore/grype) - SBOM/CVE tools

---

## Changelog

### v1.0.0 (2026-01-10)

- Initial release
- 31 security scanners with 100% coverage of static-analyzable Android MASTG tests (97)
- HTML dashboard output with Chart.js
- SARIF 2.1.0 output for CI/CD integration
- SBOM/CVE analysis with Syft/Grype
- MITRE ATT&CK Mobile mapping
- Docker support
- 163 unit tests

---

*All findings should be reviewed by qualified cybersecurity professionals. This tool is for authorized security testing only.*
