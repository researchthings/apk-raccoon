#!/usr/bin/env python3
"""
Shared utilities for Android APK security scanners.

This module provides common functionality used across all scanner modules:
- File iteration (source directories and APK archives)
- CSV output handling
- Pattern matching utilities
- Logging configuration
- Finding data structures

Author: Randy Grant
Date: 01-09-2026
Version: 1.0
"""

from __future__ import annotations

import csv
import logging
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional, Callable, Pattern


# =============================================================================
# Severity Levels
# =============================================================================

class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    def __str__(self) -> str:
        return self.value


# =============================================================================
# Finding Data Structure
# =============================================================================

@dataclass
class Finding:
    """Represents a security finding from a scanner."""
    source: str
    rule_id: str
    title: str
    location: str
    evidence: str
    severity: Severity | str
    how_found: str

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary for CSV output."""
        return {
            "Source": self.source,
            "RuleID": self.rule_id,
            "Title": self.title,
            "Location": self.location,
            "Evidence": str(self.evidence)[:200],  # Truncate evidence
            "Severity": str(self.severity),
            "HowFound": self.how_found
        }


# =============================================================================
# File Extensions
# =============================================================================

# Code file extensions to scan
CODE_EXTENSIONS: frozenset[str] = frozenset({
    '.java', '.kt', '.smali', '.xml', '.json', '.properties'
})

# Binary/media files to skip
SKIP_EXTENSIONS: frozenset[str] = frozenset({
    # Images
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
    # Media
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv',
    # Fonts
    '.ttf', '.otf', '.woff', '.woff2', '.eot',
    # Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    # Archives
    '.zip', '.tar', '.gz', '.rar', '.7z',
    # Native libraries
    '.so', '.dll', '.dylib', '.a',
    # Android specific
    '.dex', '.arsc',
})


# =============================================================================
# Logging Configuration
# =============================================================================

def setup_logging(
    name: str,
    level: int = logging.INFO,
    format_string: str | None = None
) -> logging.Logger:
    """
    Configure logging for a scanner module.

    Args:
        name: Logger name (typically __name__)
        level: Logging level (default INFO)
        format_string: Custom format string (optional)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(level)

        if format_string is None:
            format_string = "[%(levelname)s] %(name)s: %(message)s"

        formatter = logging.Formatter(format_string)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


# Default logger for this module
_logger = setup_logging(__name__)


# =============================================================================
# File Iteration
# =============================================================================

def should_skip_file(filename: str, extensions: frozenset[str] | None = None) -> bool:
    """
    Check if a file should be skipped based on extension.

    Args:
        filename: Name or path of the file
        extensions: Set of extensions to skip (default: SKIP_EXTENSIONS)

    Returns:
        True if the file should be skipped
    """
    if extensions is None:
        extensions = SKIP_EXTENSIONS
    ext = os.path.splitext(filename)[1].lower()
    return ext in extensions


def should_include_file(
    filename: str,
    include_extensions: frozenset[str] | None = None
) -> bool:
    """
    Check if a file should be included based on extension.

    Args:
        filename: Name or path of the file
        include_extensions: Set of extensions to include (default: CODE_EXTENSIONS)

    Returns:
        True if the file should be included
    """
    if include_extensions is None:
        include_extensions = CODE_EXTENSIONS
    ext = os.path.splitext(filename)[1].lower()
    return ext in include_extensions


def iter_source_files(
    src_dir: str | Path,
    apk_path: str | Path | None = None,
    include_extensions: frozenset[str] | None = None,
    skip_extensions: frozenset[str] | None = None
) -> Iterator[tuple[str, str]]:
    """
    Iterate over source files in a directory or APK archive.

    This is the primary file iteration function used by all scanners.
    It handles both decompiled source directories and raw APK files.

    Args:
        src_dir: Path to source directory (decompiled code)
        apk_path: Optional path to APK file for fallback scanning
        include_extensions: Extensions to include (default: CODE_EXTENSIONS)
        skip_extensions: Extensions to skip (default: SKIP_EXTENSIONS)

    Yields:
        Tuples of (file_path, file_content)

    Example:
        >>> for path, content in iter_source_files("/path/to/sources"):
        ...     if "password" in content.lower():
        ...         print(f"Found password reference in {path}")
    """
    src_dir = Path(src_dir) if isinstance(src_dir, str) else src_dir

    if include_extensions is None:
        include_extensions = CODE_EXTENSIONS
    if skip_extensions is None:
        skip_extensions = SKIP_EXTENSIONS

    # Scan source directory if it exists
    if src_dir.is_dir():
        for root, _, files in os.walk(src_dir):
            for filename in files:
                # Check extension filters
                if not should_include_file(filename, include_extensions):
                    continue
                if should_skip_file(filename, skip_extensions):
                    continue

                file_path = os.path.join(root, filename)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        yield file_path, f.read()
                except OSError as e:
                    _logger.warning(f"Failed to read {file_path}: {e}")
                    continue

    # Fall back to APK if provided and directory doesn't exist or is empty
    elif apk_path:
        apk_path = Path(apk_path) if isinstance(apk_path, str) else apk_path
        if apk_path.is_file():
            try:
                with zipfile.ZipFile(apk_path, 'r') as z:
                    for zi in z.infolist():
                        if zi.file_size == 0 or zi.is_dir():
                            continue
                        if should_skip_file(zi.filename, skip_extensions):
                            continue

                        try:
                            content = z.read(zi.filename).decode("utf-8", errors="ignore")
                            yield zi.filename, content
                        except Exception as e:
                            _logger.warning(f"Failed to read ZIP entry {zi.filename}: {e}")
                            continue
            except zipfile.BadZipFile as e:
                _logger.error(f"Invalid ZIP/APK file {apk_path}: {e}")


def iter_code_files(
    src_dir: str | Path,
    apk_path: str | Path | None = None
) -> Iterator[tuple[str, str]]:
    """
    Iterate over code files only (.java, .kt, .smali).

    Convenience wrapper for iter_source_files with code-specific extensions.

    Args:
        src_dir: Path to source directory
        apk_path: Optional path to APK file

    Yields:
        Tuples of (file_path, file_content)
    """
    code_only = frozenset({'.java', '.kt', '.smali'})
    yield from iter_source_files(
        src_dir,
        apk_path,
        include_extensions=code_only
    )


# =============================================================================
# CSV Output
# =============================================================================

# Standard CSV field names for all scanners
CSV_FIELDNAMES: list[str] = [
    "Source", "RuleID", "Title", "Location", "Evidence", "Severity", "HowFound"
]


def write_findings_csv(
    output_path: str | Path,
    findings: list[Finding] | list[dict[str, str]],
    fieldnames: list[str] | None = None
) -> int:
    """
    Write findings to a CSV file.

    Args:
        output_path: Path to output CSV file
        findings: List of Finding objects or dicts
        fieldnames: CSV field names (default: CSV_FIELDNAMES)

    Returns:
        Number of findings written
    """
    if fieldnames is None:
        fieldnames = CSV_FIELDNAMES

    output_path = Path(output_path) if isinstance(output_path, str) else output_path

    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            if isinstance(finding, Finding):
                writer.writerow(finding.to_dict())
            else:
                writer.writerow(finding)

    return len(findings)


# =============================================================================
# Pattern Matching Utilities
# =============================================================================

def extract_snippet(
    text: str,
    match_start: int,
    match_end: int,
    context_before: int = 30,
    context_after: int = 30,
    max_length: int = 200
) -> str:
    """
    Extract a snippet of text around a match for evidence.

    Args:
        text: Full text content
        match_start: Start position of the match
        match_end: End position of the match
        context_before: Characters to include before match
        context_after: Characters to include after match
        max_length: Maximum snippet length

    Returns:
        Snippet with newlines replaced by spaces, truncated to max_length
    """
    start = max(0, match_start - context_before)
    end = min(len(text), match_end + context_after)
    snippet = text[start:end].replace("\n", " ").replace("\r", "")
    return snippet[:max_length]


def get_line_context(text: str, position: int) -> tuple[str, int]:
    """
    Get the line containing a position and the line number.

    Args:
        text: Full text content
        position: Character position in text

    Returns:
        Tuple of (line_content, line_number)
    """
    # Find line start
    line_start = text.rfind('\n', 0, position) + 1
    # Find line end
    line_end = text.find('\n', position)
    if line_end == -1:
        line_end = len(text)

    # Count line number
    line_number = text[:position].count('\n') + 1

    return text[line_start:line_end], line_number


def is_in_comment(text: str, position: int) -> bool:
    """
    Check if a position appears to be inside a comment.

    Handles Java/Kotlin single-line (//) and XML (<!--) comments.

    Args:
        text: Full text content
        position: Character position to check

    Returns:
        True if position appears to be in a comment
    """
    line, _ = get_line_context(text, position)

    comment_patterns = [
        r'^\s*//',      # Java/Kotlin single-line
        r'^\s*\*',      # Java multi-line continuation
        r'^\s*#',       # Properties file
        r'<!--',        # XML comment (anywhere in line)
    ]

    for pattern in comment_patterns:
        if re.match(pattern, line):
            return True

    return False


def compile_patterns(
    patterns: list[tuple[str, str, str, str]]
) -> list[tuple[str, Pattern[str], str, str]]:
    """
    Pre-compile regex patterns for efficiency.

    Args:
        patterns: List of (rule_id, pattern_string, severity, description)

    Returns:
        List of (rule_id, compiled_pattern, severity, description)
    """
    compiled = []
    for rule_id, pattern_str, severity, description in patterns:
        try:
            compiled_pattern = re.compile(pattern_str, re.IGNORECASE | re.DOTALL)
            compiled.append((rule_id, compiled_pattern, severity, description))
        except re.error as e:
            _logger.error(f"Invalid regex pattern for {rule_id}: {e}")
    return compiled


# =============================================================================
# Context Analysis
# =============================================================================

def check_encryption_context(
    text: str,
    position: int,
    context_range: int = 300
) -> bool:
    """
    Check if encryption is used in the context around a position.

    Args:
        text: Full text content
        position: Character position to check around
        context_range: Characters to check before and after

    Returns:
        True if encryption indicators are found nearby
    """
    start = max(0, position - context_range)
    end = min(len(text), position + context_range)
    context = text[start:end].lower()

    encryption_indicators = [
        'encrypt', 'cipher', 'aes', 'rsa', 'keystore',
        'encryptedsharedpreferences', 'securepreferences',
        'masterkey', 'crypto', 'securely'
    ]

    return any(indicator in context for indicator in encryption_indicators)


# =============================================================================
# Scanner Base Class (Optional)
# =============================================================================

class ScannerBase:
    """
    Optional base class for scanners providing common functionality.

    Scanners can inherit from this or use the utility functions directly.
    """

    def __init__(
        self,
        source_name: str,
        src_dir: str | Path,
        output_path: str | Path,
        apk_path: str | Path | None = None
    ):
        self.source_name = source_name
        self.src_dir = Path(src_dir)
        self.output_path = Path(output_path)
        self.apk_path = Path(apk_path) if apk_path else None
        self.findings: list[Finding] = []
        self.files_scanned = 0
        self.logger = setup_logging(self.__class__.__name__)

    def add_finding(
        self,
        rule_id: str,
        title: str,
        location: str,
        evidence: str,
        severity: Severity | str,
        how_found: str = "Regex scan"
    ) -> None:
        """Add a finding to the results."""
        self.findings.append(Finding(
            source=self.source_name,
            rule_id=rule_id,
            title=title,
            location=location,
            evidence=evidence,
            severity=severity,
            how_found=how_found
        ))

    def iter_files(self) -> Iterator[tuple[str, str]]:
        """Iterate over source files."""
        for path, content in iter_source_files(self.src_dir, self.apk_path):
            self.files_scanned += 1
            yield path, content

    def write_results(self) -> None:
        """Write findings to CSV."""
        count = write_findings_csv(self.output_path, self.findings)
        print(f"Wrote {self.output_path} ({count} findings, {self.files_scanned} files scanned)")

    def run(self) -> int:
        """
        Run the scanner. Override scan() in subclasses.

        Returns:
            Exit code (0 for success, 1 for failure)
        """
        try:
            self.scan()
            self.write_results()
            return 0
        except Exception as e:
            self.logger.error(f"Scanner failed: {e}")
            import traceback
            traceback.print_exc()
            return 1

    def scan(self) -> None:
        """Override this method to implement scanning logic."""
        raise NotImplementedError("Subclasses must implement scan()")


# =============================================================================
# Manifest Parsing Utilities
# =============================================================================

def parse_android_namespace(element) -> str:
    """Get the Android namespace prefix from an element."""
    return '{http://schemas.android.com/apk/res/android}'


def get_android_attribute(element, attr_name: str, ns: str | None = None) -> str | None:
    """
    Get an Android-namespaced attribute from an XML element.

    Args:
        element: lxml Element
        attr_name: Attribute name without namespace
        ns: Namespace string (default: Android namespace)

    Returns:
        Attribute value or None
    """
    if ns is None:
        ns = '{http://schemas.android.com/apk/res/android}'
    return element.get(f'{ns}{attr_name}')
