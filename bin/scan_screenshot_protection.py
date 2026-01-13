#!/usr/bin/env python3
"""Scan for Screenshot Protection implementation.

Detects whether sensitive screens properly implement FLAG_SECURE to prevent
screenshots and screen recording by malicious apps or screen capture.

Checks:
    - FLAG_SECURE usage on activities
    - SurfaceView.setSecure() usage
    - Sensitive activities without protection
    - Screen recording detection capabilities

OWASP MASTG Coverage:
    - MASTG-TEST-0010: Testing for FLAG_SECURE
    - MASTG-TEST-0291-0294: Screenshot Prevention APIs

Author: Randy Grant
Date: 01-12-2026
Version: 1.0
"""

import csv
import os
import re
import sys
import traceback
import zipfile

# =============================================================================
# Screenshot Protection Detection Patterns
# =============================================================================

# Positive patterns - indicators that protection IS present
PROTECTION_PRESENT_PATTERNS = [
    # FLAG_SECURE usage
    (r'(?i)(?:getWindow|window)\s*\(\s*\)\.setFlags\s*\([^)]*FLAG_SECURE', "SCREEN_FLAG_SECURE", "Info", "Activity protected with FLAG_SECURE"),
    (r'(?i)(?:getWindow|window)\s*\(\s*\)\.addFlags\s*\([^)]*FLAG_SECURE', "SCREEN_FLAG_SECURE", "Info", "Activity protected with FLAG_SECURE (addFlags)"),
    (r'(?i)WindowManager\.LayoutParams\.FLAG_SECURE', "SCREEN_FLAG_SECURE", "Info", "FLAG_SECURE constant referenced"),

    # SurfaceView setSecure
    (r'(?i)surfaceView\s*\.setSecure\s*\(\s*true\s*\)', "SCREEN_SURFACE_SECURE", "Info", "SurfaceView protected with setSecure()"),
    (r'(?i)setSecure\s*\(\s*true\s*\)', "SCREEN_SURFACE_SECURE", "Info", "setSecure(true) called"),

    # Compose SecureOn/SecureEventDispatcherPolicy
    (r'(?i)SecureEventDispatcherPolicy', "SCREEN_COMPOSE_SECURE", "Info", "Compose secure event policy"),
    (r'(?i)setRecentsScreenshotEnabled\s*\(\s*false\s*\)', "SCREEN_RECENTS_DISABLED", "Info", "Recent screenshots disabled"),

    # Jetpack Security
    (r'(?i)ScreenCaptureCallback', "SCREEN_CAPTURE_CALLBACK", "Info", "Screen capture callback detected"),
]

# Negative patterns - indicators that protection may be MISSING on sensitive screens
SENSITIVE_ACTIVITY_PATTERNS = [
    # Login/Authentication activities
    (r'class\s+\w*(?:Login|SignIn|Auth)\w*\s+(?:extends|:)\s+(?:Activity|AppCompatActivity|FragmentActivity)', "SCREEN_SENSITIVE_LOGIN", "Medium", "Login activity - verify FLAG_SECURE protection"),
    # Payment activities
    (r'class\s+\w*(?:Payment|Checkout|Billing|Card)\w*\s+(?:extends|:)\s+(?:Activity|AppCompatActivity|FragmentActivity)', "SCREEN_SENSITIVE_PAYMENT", "High", "Payment activity - verify FLAG_SECURE protection"),
    # OTP/Verification activities
    (r'class\s+\w*(?:OTP|Otp|Verification|Verify|TwoFactor|2FA)\w*\s+(?:extends|:)\s+(?:Activity|AppCompatActivity|FragmentActivity)', "SCREEN_SENSITIVE_OTP", "High", "OTP/Verification activity - verify FLAG_SECURE protection"),
    # PIN/Password activities
    (r'class\s+\w*(?:PIN|Pin|Password|Passcode|Lock)\w*\s+(?:extends|:)\s+(?:Activity|AppCompatActivity|FragmentActivity)', "SCREEN_SENSITIVE_PIN", "High", "PIN/Password activity - verify FLAG_SECURE protection"),
    # Account/Profile activities with sensitive data
    (r'class\s+\w*(?:Account|Profile|Personal|Settings)\w*\s+(?:extends|:)\s+(?:Activity|AppCompatActivity|FragmentActivity)', "SCREEN_SENSITIVE_ACCOUNT", "Low", "Account/Profile activity - consider FLAG_SECURE protection"),
]

# Screen recording prevention check
SCREEN_RECORDING_PATTERNS = [
    # MediaProjection callback (for detecting screen recording)
    (r'MediaProjectionManager', "SCREEN_PROJECTION_DETECT", "Info", "MediaProjection detection capability"),
    # Display listener for screen mirroring
    (r'DisplayManager\s*\.\s*registerDisplayListener', "SCREEN_DISPLAY_LISTENER", "Info", "Display listener for mirroring detection"),
]


def iter_text(src_dir, apk_path=None):
    """Iterate over source files, yielding path and content.

    Args:
        src_dir: Directory containing source files to scan.
        apk_path: Optional path to APK file to scan.

    Yields:
        Tuples of (file_path, file_content) for each matching file.
    """
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
                # Only scan code files
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


def check_has_protection(text):
    """Check if the file has any screenshot protection.

    Args:
        text: Source code content to check.

    Returns:
        True if any screenshot protection pattern is found.
    """
    for pattern, _, _, _ in PROTECTION_PRESENT_PATTERNS:
        if re.search(pattern, text):
            return True
    return False


def main():
    """Scan for screenshot protection and write findings to CSV.

    Command line args:
        sys.argv[1]: Path to source directory
        sys.argv[2]: Output CSV path
        sys.argv[3]: Optional path to APK file

    Raises:
        SystemExit: If required arguments are missing or an error occurs.
    """
    try:
        if len(sys.argv) < 3:
            print("Usage: scan_screenshot_protection.py <src_dir> <out.csv> [apk_path]", file=sys.stderr)
            sys.exit(1)

        src_dir, out = sys.argv[1], sys.argv[2]
        apk_path = sys.argv[3] if len(sys.argv) > 3 else None

        rows = []
        files_scanned = 0
        protection_found = False
        sensitive_activities = []

        for path, text in iter_text(src_dir, apk_path):
            files_scanned += 1

            # Check for protection patterns (positive indicators)
            for pattern, rule_id, severity, desc in PROTECTION_PRESENT_PATTERNS:
                for m in re.finditer(pattern, text):
                    protection_found = True
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "screenshot",
                        "RuleID": rule_id,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": severity,
                        "HowFound": "Regex scan"
                    })

            # Check for sensitive activities (potential missing protection)
            for pattern, rule_id, severity, desc in SENSITIVE_ACTIVITY_PATTERNS:
                for m in re.finditer(pattern, text):
                    # Check if this file has protection
                    has_protection = check_has_protection(text)
                    if not has_protection:
                        snippet = text[max(0, m.start() - 30):m.end() + 50].replace("\n", " ")
                        sensitive_activities.append({
                            "Source": "screenshot",
                            "RuleID": rule_id,
                            "Title": desc,
                            "Location": str(path),
                            "Evidence": snippet[:200],
                            "Severity": severity,
                            "HowFound": "Heuristic (no FLAG_SECURE found in sensitive activity)"
                        })

            # Check for screen recording detection patterns
            for pattern, rule_id, severity, desc in SCREEN_RECORDING_PATTERNS:
                for m in re.finditer(pattern, text):
                    snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                    rows.append({
                        "Source": "screenshot",
                        "RuleID": rule_id,
                        "Title": desc,
                        "Location": str(path),
                        "Evidence": snippet[:200],
                        "Severity": severity,
                        "HowFound": "Regex scan"
                    })

        # Add sensitive activity findings (limit to avoid noise)
        for finding in sensitive_activities[:10]:
            rows.append(finding)

        if len(sensitive_activities) > 10:
            rows.append({
                "Source": "screenshot",
                "RuleID": "SCREEN_SENSITIVE_SUMMARY",
                "Title": f"Sensitive activities without FLAG_SECURE ({len(sensitive_activities) - 10} more)",
                "Location": "Multiple files",
                "Evidence": f"Found {len(sensitive_activities)} sensitive activities without screenshot protection",
                "Severity": "Medium",
                "HowFound": "Heuristic (summary)"
            })

        # If no protection found at all, report
        if not protection_found and files_scanned > 0:
            rows.append({
                "Source": "screenshot",
                "RuleID": "SCREEN_NO_PROTECTION",
                "Title": "No screenshot protection detected in app",
                "Location": f"Entire codebase ({files_scanned} files)",
                "Evidence": "No FLAG_SECURE or setSecure() usage found",
                "Severity": "Medium",
                "HowFound": "Absence detection"
            })

        # Write output
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        print(f"Wrote {out} ({len(rows)} findings, {files_scanned} files scanned)")

    except Exception as e:
        print(f"[!] Error in scan_screenshot_protection: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
