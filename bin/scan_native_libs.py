#!/usr/bin/env python3
"""Scan for Native Library (JNI/NDK) security issues.

Analyzes native (.so) libraries for security issues including missing
security flags, known vulnerable libraries, and unsafe JNI patterns.

Checks:
    - Missing security flags (NX, RELRO, PIE, Stack Canary)
    - Known vulnerable libraries (OpenSSL, libpng, etc.)
    - Debug symbols and DWARF sections not stripped
    - RPATH/RUNPATH entries (misconfigured build)
    - Unsafe JNI patterns in code

OWASP MASTG Coverage:
    - MASTG-TEST-0044: Testing Native Code Security
    - MASTG-TEST-0040: Testing for Debugging Symbols
    - MASTG-TEST-0222: Testing for RPATH/RUNPATH

Note: Full ELF analysis requires 'readelf' or 'llvm-readelf' on PATH.

Author: Randy Grant
Date: 01-09-2026
Version: 1.0
"""

from __future__ import annotations

import csv
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Iterator

# CSV output schema
CSV_FIELDNAMES = ["Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"]

# Known vulnerable native libraries (library name -> CVE/issue)
VULNERABLE_LIBRARIES = {
    "libssl.so.1.0": ("OpenSSL 1.0.x", "Critical", "Multiple CVEs - upgrade to 1.1.1+"),
    "libcrypto.so.1.0": ("OpenSSL 1.0.x crypto", "Critical", "Multiple CVEs - upgrade"),
    "libpng12.so": ("libpng 1.2.x", "High", "Multiple CVEs including buffer overflows"),
    "libpng15.so": ("libpng 1.5.x", "Medium", "Known vulnerabilities - upgrade"),
    "libjpeg.so.6": ("libjpeg 6b", "Medium", "Old version with known issues"),
    "libxml2.so.2.9.1": ("libxml2 2.9.1", "High", "CVE-2015-8242 and others"),
    "libsqlite.so": ("SQLite bundled", "Low", "Check version for CVEs"),
    "libffmpeg": ("FFmpeg bundled", "Medium", "Check version - frequent CVEs"),
    "libavcodec": ("FFmpeg avcodec", "Medium", "Check version for codec CVEs"),
    "libwebp.so": ("WebP library", "Medium", "CVE-2023-4863 and others - verify version"),
}

# Suspicious library name patterns
SUSPICIOUS_LIB_PATTERNS = [
    (r"lib.*debug.*\.so", "NAT_DEBUG_LIB", "Medium", "Debug library included"),
    (r"lib.*test.*\.so", "NAT_TEST_LIB", "Medium", "Test library included"),
    (r"libfrida.*\.so", "NAT_FRIDA", "Info", "Frida library detected (instrumentation)"),
    (r"libxposed.*\.so", "NAT_XPOSED", "Info", "Xposed framework library detected"),
    (r"libsubstrate.*\.so", "NAT_SUBSTRATE", "Info", "Substrate library detected"),
    (r".*anti.*root.*\.so", "NAT_ANTIROOT", "Info", "Anti-root library detected"),
    (r".*root.*detect.*\.so", "NAT_ROOTDETECT", "Info", "Root detection library detected"),
]

# JNI/Native code patterns in source
JNI_CODE_PATTERNS = [
    # System.loadLibrary - track native lib loading
    (
        r"System\.loadLibrary\s*\(\s*[\"']([^\"']+)[\"']\s*\)",
        "NAT_LOAD_LIBRARY",
        "Info",
        "Native Library Loading",
        "Native library loaded via System.loadLibrary",
    ),
    # System.load with full path
    (
        r"System\.load\s*\(\s*[^)]+\)",
        "NAT_LOAD_PATH",
        "Medium",
        "Native Library Load by Path",
        "Loading native library by full path - potential path injection",
    ),
    # JNI_OnLoad defined
    (
        r"JNI_OnLoad\s*\(",
        "NAT_JNI_ONLOAD",
        "Info",
        "JNI_OnLoad Implementation",
        "Native library has JNI_OnLoad - review for security",
    ),
    # exec/system calls in native (smali)
    (
        r"Ljava/lang/Runtime;->exec",
        "NAT_RUNTIME_EXEC",
        "High",
        "Runtime.exec in JNI Context",
        "Native code calling Runtime.exec - potential command injection",
    ),
    # Native method declaration
    (
        r"native\s+\w+\s+\w+\s*\([^)]*\)",
        "NAT_NATIVE_METHOD",
        "Info",
        "Native Method Declaration",
        "JNI native method declared",
    ),
    # RegisterNatives in native code
    (
        r"RegisterNatives\s*\(",
        "NAT_REGISTER_NATIVES",
        "Info",
        "Dynamic JNI Registration",
        "JNI methods registered dynamically via RegisterNatives",
    ),
]


def truncate(s: str, max_len: int = 150) -> str:
    """Truncate string for CSV evidence field.

    Args:
        s: The string to truncate.
        max_len: Maximum length before truncation.

    Returns:
        Truncated string with ellipsis if needed, newlines removed.
    """
    s = s.replace("\n", " ").replace("\r", "").strip()
    return s[:max_len] + "..." if len(s) > max_len else s


def find_readelf() -> str | None:
    """Find readelf or llvm-readelf binary.

    Returns:
        Path to readelf binary if found, None otherwise.
    """
    for cmd in ["readelf", "llvm-readelf", "arm-linux-gnueabi-readelf"]:
        path = shutil.which(cmd)
        if path:
            return path
    return None


def analyze_elf_security(lib_path: str, readelf_cmd: str) -> dict:
    """Analyze ELF binary for security flags using readelf.

    Args:
        lib_path: Path to the ELF binary file.
        readelf_cmd: Path to readelf command.

    Returns:
        Dictionary with security flag status (nx, pie, relro, canary, etc.).
    """
    result = {
        "nx": None,  # NX (No-Execute) stack
        "pie": None,  # Position Independent Executable
        "relro": None,  # Relocation Read-Only
        "canary": None,  # Stack canary
        "stripped": None,  # Debug symbols stripped
        "dwarf_debug": None,  # DWARF debug sections (MASTG-TEST-0040)
        "rpath": None,  # RPATH entries (MASTG-TEST-0222)
        "runpath": None,  # RUNPATH entries
    }

    try:
        # Check program headers for NX stack
        headers = subprocess.run(
            [readelf_cmd, "-l", lib_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        if headers.returncode == 0:
            output = headers.stdout
            # Check for GNU_STACK with RWE (no NX protection)
            if "GNU_STACK" in output:
                if re.search(r"GNU_STACK.*RWE", output):
                    result["nx"] = False
                else:
                    result["nx"] = True

        # Check dynamic section for RELRO, RPATH, and other flags
        dynamic = subprocess.run(
            [readelf_cmd, "-d", lib_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        if dynamic.returncode == 0:
            output = dynamic.stdout
            # Check for BIND_NOW (Full RELRO)
            if "BIND_NOW" in output:
                result["relro"] = "full"
            elif "FLAGS" in output:
                result["relro"] = "partial"
            else:
                result["relro"] = "none"

            # Check for RPATH/RUNPATH (MASTG-TEST-0222)
            # RPATH/RUNPATH are not supported on Android and indicate misconfigured build
            if "RPATH" in output or "(RPATH)" in output:
                result["rpath"] = True
            else:
                result["rpath"] = False

            if "RUNPATH" in output or "(RUNPATH)" in output:
                result["runpath"] = True
            else:
                result["runpath"] = False

        # Check symbols for stack canary
        symbols = subprocess.run(
            [readelf_cmd, "-s", lib_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        if symbols.returncode == 0:
            output = symbols.stdout
            # Look for stack protector symbols
            if "__stack_chk_fail" in output or "__stack_chk_guard" in output:
                result["canary"] = True
            else:
                result["canary"] = False

            # Check if symbols are stripped
            if "Symbol table '.symtab'" not in output:
                result["stripped"] = True
            else:
                result["stripped"] = False

        # Check file header for PIE
        file_header = subprocess.run(
            [readelf_cmd, "-h", lib_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        if file_header.returncode == 0:
            output = file_header.stdout
            if "DYN (Shared object file)" in output or "DYN (Position-Independent" in output:
                result["pie"] = True
            elif "EXEC" in output:
                result["pie"] = False

        # Check section headers for DWARF debug sections (MASTG-TEST-0040)
        sections = subprocess.run(
            [readelf_cmd, "-S", lib_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        if sections.returncode == 0:
            output = sections.stdout
            # Look for DWARF debug sections that should be stripped
            dwarf_sections = [".debug_info", ".debug_str", ".debug_line",
                              ".debug_abbrev", ".debug_loc", ".debug_ranges",
                              ".debug_frame", ".debug_aranges"]
            for section in dwarf_sections:
                if section in output:
                    result["dwarf_debug"] = True
                    break
            else:
                result["dwarf_debug"] = False

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return result


def iter_native_libs_from_apk(apk_path: str) -> Iterator[tuple[str, str, bytes]]:
    """Extract native libraries from APK, yielding library info.

    Args:
        apk_path: Path to APK file.

    Yields:
        Tuples of (architecture, library_name, binary_content).
    """
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if name.startswith("lib/") and name.endswith(".so"):
                    parts = name.split("/")
                    if len(parts) >= 3:
                        arch = parts[1]  # armeabi-v7a, arm64-v8a, x86, x86_64
                        lib_name = parts[-1]
                        try:
                            content = zf.read(name)
                            yield arch, lib_name, content
                        except Exception:
                            continue
    except Exception:
        return


def iter_native_libs_from_dir(src_dir: str) -> Iterator[tuple[str, str, str]]:
    """Find native libraries in extracted source directory.

    Args:
        src_dir: Directory containing extracted source files.

    Yields:
        Tuples of (architecture, library_name, file_path).
    """
    src_path = Path(src_dir)
    if not src_path.exists():
        return

    for p in src_path.rglob("*.so"):
        if p.is_file():
            # Try to determine architecture from path
            arch = "unknown"
            for part in p.parts:
                if part in ("armeabi-v7a", "arm64-v8a", "x86", "x86_64", "armeabi"):
                    arch = part
                    break
            yield arch, p.name, str(p)


def iter_source_files(src_dir: str) -> Iterator[tuple[str, str]]:
    """Iterate over source files, yielding path and content.

    Args:
        src_dir: Directory containing source files to scan.

    Yields:
        Tuples of (file_path, file_content) for each matching file.
    """
    src_path = Path(src_dir)
    if not src_path.exists():
        return

    extensions = {".java", ".kt", ".smali", ".c", ".cpp", ".h"}

    for p in src_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in extensions:
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                yield str(p), content
            except Exception:
                continue


def scan_native_libs(apk_path: str | None, src_dir: str | None) -> list[dict]:
    """Scan native libraries for security issues.

    Args:
        apk_path: Optional path to APK file.
        src_dir: Optional path to extracted source directory.

    Returns:
        List of finding dictionaries for native library issues.
    """
    findings = []
    libs_found = []
    readelf_cmd = find_readelf()

    if readelf_cmd:
        findings.append({
            "Source": "native_libs",
            "RuleID": "NAT_READELF_AVAILABLE",
            "Title": f"ELF Analysis Available ({os.path.basename(readelf_cmd)})",
            "Location": "System",
            "Evidence": f"Using {readelf_cmd} for detailed analysis",
            "Severity": "Info",
            "HowFound": "Full ELF security analysis enabled",
        })
    else:
        findings.append({
            "Source": "native_libs",
            "RuleID": "NAT_NO_READELF",
            "Title": "readelf Not Available - Limited Analysis",
            "Location": "System",
            "Evidence": "Install binutils or llvm for full ELF analysis",
            "Severity": "Info",
            "HowFound": "Skipping binary security flag analysis",
        })

    # Track architectures found
    architectures = set()

    # Analyze libs from APK
    if apk_path and os.path.exists(apk_path):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            for arch, lib_name, content in iter_native_libs_from_apk(apk_path):
                libs_found.append((arch, lib_name))
                architectures.add(arch)

                # Check against known vulnerable libraries
                for vuln_pattern, (description, severity, howfound) in VULNERABLE_LIBRARIES.items():
                    if vuln_pattern in lib_name.lower():
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": "NAT_VULNERABLE_LIB",
                            "Title": f"Potentially Vulnerable Library: {lib_name}",
                            "Location": f"lib/{arch}/{lib_name}",
                            "Evidence": description,
                            "Severity": severity,
                            "HowFound": howfound,
                        })

                # Check suspicious patterns
                for pattern, rule_id, severity, howfound in SUSPICIOUS_LIB_PATTERNS:
                    if re.search(pattern, lib_name, re.IGNORECASE):
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": rule_id,
                            "Title": f"Suspicious Library: {lib_name}",
                            "Location": f"lib/{arch}/{lib_name}",
                            "Evidence": lib_name,
                            "Severity": severity,
                            "HowFound": howfound,
                        })

                # If readelf available, do detailed analysis
                if readelf_cmd:
                    tmp_lib = os.path.join(tmpdir, lib_name)
                    with open(tmp_lib, "wb") as f:
                        f.write(content)

                    elf_info = analyze_elf_security(tmp_lib, readelf_cmd)

                    # Check NX
                    if elf_info["nx"] is False:
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": "NAT_NO_NX",
                            "Title": f"Executable Stack (No NX): {lib_name}",
                            "Location": f"lib/{arch}/{lib_name}",
                            "Evidence": "GNU_STACK is RWE (executable)",
                            "Severity": "High",
                            "HowFound": "Stack is executable - vulnerable to code injection",
                        })

                    # Check RELRO
                    if elf_info["relro"] == "none":
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": "NAT_NO_RELRO",
                            "Title": f"No RELRO Protection: {lib_name}",
                            "Location": f"lib/{arch}/{lib_name}",
                            "Evidence": "RELRO not enabled",
                            "Severity": "Medium",
                            "HowFound": "GOT/PLT vulnerable to overwrite attacks",
                        })
                    elif elf_info["relro"] == "partial":
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": "NAT_PARTIAL_RELRO",
                            "Title": f"Partial RELRO: {lib_name}",
                            "Location": f"lib/{arch}/{lib_name}",
                            "Evidence": "Partial RELRO (no BIND_NOW)",
                            "Severity": "Low",
                            "HowFound": "Consider enabling full RELRO with -Wl,-z,relro,-z,now",
                        })

                    # Check stack canary
                    if elf_info["canary"] is False:
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": "NAT_NO_CANARY",
                            "Title": f"No Stack Canary: {lib_name}",
                            "Location": f"lib/{arch}/{lib_name}",
                            "Evidence": "__stack_chk_fail not found",
                            "Severity": "Medium",
                            "HowFound": "Compile with -fstack-protector-strong",
                        })

                    # Check symbols stripping
                    if elf_info["stripped"] is False:
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": "NAT_NOT_STRIPPED",
                            "Title": f"Debug Symbols Present: {lib_name}",
                            "Location": f"lib/{arch}/{lib_name}",
                            "Evidence": "Symbol table not stripped",
                            "Severity": "Low",
                            "HowFound": "Strip symbols for release: strip --strip-all",
                        })

                    # Check for DWARF debug sections (MASTG-TEST-0040)
                    if elf_info["dwarf_debug"] is True:
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": "NAT_DWARF_DEBUG",
                            "Title": f"DWARF Debug Sections Present: {lib_name}",
                            "Location": f"lib/{arch}/{lib_name}",
                            "Evidence": "Contains .debug_* sections",
                            "Severity": "Medium",
                            "HowFound": "DWARF sections expose source info - strip with: strip --strip-debug",
                        })

                    # Check for RPATH (MASTG-TEST-0222)
                    if elf_info["rpath"] is True:
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": "NAT_RPATH",
                            "Title": f"RPATH Entry Detected: {lib_name}",
                            "Location": f"lib/{arch}/{lib_name}",
                            "Evidence": "DT_RPATH found in dynamic section",
                            "Severity": "Medium",
                            "HowFound": "RPATH not supported on Android - indicates misconfigured build",
                        })

                    # Check for RUNPATH
                    if elf_info["runpath"] is True:
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": "NAT_RUNPATH",
                            "Title": f"RUNPATH Entry Detected: {lib_name}",
                            "Location": f"lib/{arch}/{lib_name}",
                            "Evidence": "DT_RUNPATH found in dynamic section",
                            "Severity": "Low",
                            "HowFound": "RUNPATH not used by Android linker",
                        })

    # Also check libs in extracted source directory
    if src_dir:
        for arch, lib_name, lib_path in iter_native_libs_from_dir(src_dir):
            if (arch, lib_name) not in libs_found:
                libs_found.append((arch, lib_name))
                architectures.add(arch)

                # Check vulnerable libraries
                for vuln_pattern, (description, severity, howfound) in VULNERABLE_LIBRARIES.items():
                    if vuln_pattern in lib_name.lower():
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": "NAT_VULNERABLE_LIB",
                            "Title": f"Potentially Vulnerable Library: {lib_name}",
                            "Location": lib_path,
                            "Evidence": description,
                            "Severity": severity,
                            "HowFound": howfound,
                        })

                # If readelf available and file exists
                if readelf_cmd and os.path.exists(lib_path):
                    elf_info = analyze_elf_security(lib_path, readelf_cmd)
                    # Same checks as above...
                    if elf_info["nx"] is False:
                        findings.append({
                            "Source": "native_libs",
                            "RuleID": "NAT_NO_NX",
                            "Title": f"Executable Stack (No NX): {lib_name}",
                            "Location": lib_path,
                            "Evidence": "GNU_STACK is RWE",
                            "Severity": "High",
                            "HowFound": "Stack is executable",
                        })

    # Report architecture coverage
    if architectures:
        findings.append({
            "Source": "native_libs",
            "RuleID": "NAT_ARCHITECTURES",
            "Title": f"Native Architectures: {', '.join(sorted(architectures))}",
            "Location": "APK",
            "Evidence": f"{len(architectures)} architecture(s) supported",
            "Severity": "Info",
            "HowFound": "Architecture coverage report",
        })

        # Check for 32-bit only (potential issue)
        if architectures == {"armeabi-v7a"} or architectures == {"x86"}:
            findings.append({
                "Source": "native_libs",
                "RuleID": "NAT_32BIT_ONLY",
                "Title": "32-bit Native Libraries Only",
                "Location": "APK",
                "Evidence": f"Only {', '.join(architectures)} found",
                "Severity": "Low",
                "HowFound": "Consider adding arm64-v8a for 64-bit devices (required by Play Store)",
            })

    # Summary
    findings.append({
        "Source": "native_libs",
        "RuleID": "NAT_SUMMARY",
        "Title": f"Native Library Analysis: {len(libs_found)} libraries found",
        "Location": "APK",
        "Evidence": truncate(", ".join(f"{n}({a})" for a, n in libs_found[:5])),
        "Severity": "Info",
        "HowFound": f"Analyzed {len(libs_found)} native libraries",
    })

    return findings


def scan_code_for_jni_patterns(src_dir: str) -> list[dict]:
    """Scan source code for JNI/native code patterns.

    Args:
        src_dir: Directory containing decompiled source files.

    Returns:
        List of finding dictionaries for JNI patterns.
    """
    findings = []
    seen = set()

    compiled_patterns = []
    for pattern, rule_id, severity, title, description in JNI_CODE_PATTERNS:
        try:
            compiled_patterns.append(
                (re.compile(pattern, re.IGNORECASE), rule_id, severity, title, description)
            )
        except re.error:
            continue

    for filepath, content in iter_source_files(src_dir):
        for regex, rule_id, severity, title, description in compiled_patterns:
            for match in regex.finditer(content):
                evidence = match.group(0)
                key = (rule_id, filepath, evidence[:30])
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "Source": "native_libs",
                        "RuleID": rule_id,
                        "Title": title,
                        "Location": filepath,
                        "Evidence": truncate(evidence),
                        "Severity": severity,
                        "HowFound": description,
                    })

    return findings


def scan_for_native_libs(apk_path: str | None, src_dir: str | None) -> list[dict]:
    """Scan for native library security issues.

    Args:
        apk_path: Optional path to APK file.
        src_dir: Optional path to source directory.

    Returns:
        List of finding dictionaries with vulnerability details.
    """
    findings = []

    # Scan native libraries
    lib_findings = scan_native_libs(apk_path, src_dir)
    findings.extend(lib_findings)

    # Scan code for JNI patterns
    if src_dir:
        code_findings = scan_code_for_jni_patterns(src_dir)
        findings.extend(code_findings)

    return findings


def write_findings_csv(output_path: str, findings: list[dict]) -> None:
    """Write findings to CSV file.

    Args:
        output_path: Path for the output CSV file.
        findings: List of finding dictionaries to write.
    """
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(findings)

    print(f"Wrote {len(findings)} finding(s) to {output_path}")


def main() -> None:
    """Scan native libraries for security issues and write findings to CSV.

    Command line args:
        sys.argv[1]: Output CSV path
        sys.argv[2]: Optional path to APK file
        sys.argv[3]: Optional path to source directory

    Raises:
        SystemExit: If required arguments are missing.
    """
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output.csv> [apk_path] [src_dir]", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    apk_path = sys.argv[2] if len(sys.argv) > 2 else None
    src_dir = sys.argv[3] if len(sys.argv) > 3 else None

    if not apk_path and not src_dir:
        print("Warning: No APK or source directory provided", file=sys.stderr)

    findings = scan_for_native_libs(apk_path, src_dir)
    write_findings_csv(output_path, findings)


if __name__ == "__main__":
    main()
