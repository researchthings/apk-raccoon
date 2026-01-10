#!/usr/bin/env python3
"""
Unit tests for scanner_utils module.

Run with: python -m pytest tests/test_scanner_utils.py -v
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add bin directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "bin"))

from scanner_utils import (
    Severity,
    Finding,
    should_skip_file,
    should_include_file,
    extract_snippet,
    get_line_context,
    is_in_comment,
    check_encryption_context,
    write_findings_csv,
    iter_source_files,
    compile_patterns,
    CSV_FIELDNAMES,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        assert str(Severity.CRITICAL) == "Critical"
        assert str(Severity.HIGH) == "High"
        assert str(Severity.MEDIUM) == "Medium"
        assert str(Severity.LOW) == "Low"
        assert str(Severity.INFO) == "Info"

    def test_severity_comparison(self):
        assert Severity.CRITICAL == "Critical"
        assert Severity.HIGH == "High"


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        finding = Finding(
            source="test",
            rule_id="TEST_001",
            title="Test Finding",
            location="/path/to/file.java",
            evidence="password = 'secret'",
            severity=Severity.HIGH,
            how_found="Regex scan"
        )
        assert finding.source == "test"
        assert finding.rule_id == "TEST_001"
        assert finding.severity == Severity.HIGH

    def test_finding_to_dict(self):
        finding = Finding(
            source="test",
            rule_id="TEST_001",
            title="Test Finding",
            location="/path/to/file.java",
            evidence="password = 'secret'",
            severity=Severity.HIGH,
            how_found="Regex scan"
        )
        d = finding.to_dict()
        assert d["Source"] == "test"
        assert d["RuleID"] == "TEST_001"
        assert d["Severity"] == "High"

    def test_finding_evidence_truncation(self):
        long_evidence = "x" * 300
        finding = Finding(
            source="test",
            rule_id="TEST_001",
            title="Test",
            location="/path",
            evidence=long_evidence,
            severity=Severity.LOW,
            how_found="Test"
        )
        d = finding.to_dict()
        assert len(d["Evidence"]) == 200


class TestFileFilters:
    """Tests for file extension filtering."""

    def test_should_skip_binary_files(self):
        assert should_skip_file("image.png") is True
        assert should_skip_file("video.mp4") is True
        assert should_skip_file("library.so") is True
        assert should_skip_file("classes.dex") is True

    def test_should_not_skip_code_files(self):
        assert should_skip_file("Main.java") is False
        assert should_skip_file("Utils.kt") is False
        assert should_skip_file("layout.xml") is False

    def test_should_include_code_files(self):
        assert should_include_file("Main.java") is True
        assert should_include_file("Utils.kt") is True
        assert should_include_file("config.xml") is True

    def test_should_not_include_binary_files(self):
        assert should_include_file("image.png") is False
        assert should_include_file("classes.dex") is False


class TestSnippetExtraction:
    """Tests for extract_snippet function."""

    def test_basic_snippet(self):
        text = "before match after"
        snippet = extract_snippet(text, 7, 12, context_before=3, context_after=3)
        assert "re " in snippet
        assert "match" in snippet
        assert " af" in snippet

    def test_snippet_at_start(self):
        text = "match after"
        snippet = extract_snippet(text, 0, 5, context_before=10, context_after=3)
        assert snippet.startswith("match")

    def test_snippet_at_end(self):
        text = "before match"
        snippet = extract_snippet(text, 7, 12, context_before=3, context_after=10)
        assert snippet.endswith("match")

    def test_snippet_truncation(self):
        text = "x" * 500
        snippet = extract_snippet(text, 100, 200, max_length=50)
        assert len(snippet) == 50

    def test_snippet_newline_replacement(self):
        text = "line1\nmatch\nline3"
        snippet = extract_snippet(text, 6, 11, context_before=5, context_after=5)
        assert "\n" not in snippet


class TestLineContext:
    """Tests for get_line_context function."""

    def test_get_line_content(self):
        text = "line1\nline2 match\nline3"
        line, num = get_line_context(text, 10)  # position in "line2 match"
        assert "line2" in line
        assert "match" in line
        assert num == 2

    def test_first_line(self):
        text = "first line\nsecond line"
        line, num = get_line_context(text, 5)
        assert "first" in line
        assert num == 1

    def test_last_line_no_newline(self):
        text = "line1\nlast line"
        line, num = get_line_context(text, 10)
        assert "last" in line
        assert num == 2


class TestCommentDetection:
    """Tests for is_in_comment function."""

    def test_java_single_line_comment(self):
        text = "// this is a comment\nreal code"
        assert is_in_comment(text, 5) is True  # inside comment
        assert is_in_comment(text, 25) is False  # in real code

    def test_java_multiline_comment_continuation(self):
        text = "/*\n * continuation\n */"
        assert is_in_comment(text, 6) is True  # at *

    def test_xml_comment(self):
        text = "<!-- this is commented -->\n<element/>"
        assert is_in_comment(text, 10) is True

    def test_properties_comment(self):
        text = "# comment line\nkey=value"
        assert is_in_comment(text, 5) is True
        assert is_in_comment(text, 18) is False

    def test_not_in_comment(self):
        text = 'String password = "secret";'
        assert is_in_comment(text, 10) is False


class TestEncryptionContext:
    """Tests for check_encryption_context function."""

    def test_encryption_nearby(self):
        text = "Cipher cipher = Cipher.getInstance('AES'); data = encrypt(password);"
        assert check_encryption_context(text, 50, context_range=100) is True

    def test_keystore_nearby(self):
        text = "KeyStore keystore = KeyStore.getInstance(); store(password);"
        assert check_encryption_context(text, 50, context_range=100) is True

    def test_encrypted_shared_prefs(self):
        text = "EncryptedSharedPreferences.create(); prefs.putString('password', value);"
        assert check_encryption_context(text, 50, context_range=100) is True

    def test_no_encryption(self):
        text = "SharedPreferences prefs = getPrefs(); prefs.putString('password', value);"
        assert check_encryption_context(text, 50, context_range=100) is False


class TestPatternCompilation:
    """Tests for compile_patterns function."""

    def test_valid_patterns(self):
        patterns = [
            ("TEST_001", r"password\s*=", "High", "Password assignment"),
            ("TEST_002", r"secret\s*:", "Medium", "Secret value"),
        ]
        compiled = compile_patterns(patterns)
        assert len(compiled) == 2
        assert compiled[0][0] == "TEST_001"
        assert compiled[0][1].pattern == r"password\s*="

    def test_invalid_pattern_skipped(self):
        patterns = [
            ("VALID", r"password", "High", "Valid"),
            ("INVALID", r"[invalid(", "High", "Invalid regex"),
        ]
        compiled = compile_patterns(patterns)
        assert len(compiled) == 1
        assert compiled[0][0] == "VALID"


class TestCSVOutput:
    """Tests for CSV writing functions."""

    def test_write_findings_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "findings.csv"
            findings = [
                Finding(
                    source="test",
                    rule_id="TEST_001",
                    title="Test Finding",
                    location="/path/file.java",
                    evidence="evidence here",
                    severity=Severity.HIGH,
                    how_found="Test"
                )
            ]
            count = write_findings_csv(output_path, findings)
            assert count == 1
            assert output_path.exists()

            # Read and verify
            with open(output_path) as f:
                content = f.read()
            assert "TEST_001" in content
            assert "Test Finding" in content

    def test_write_dict_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "findings.csv"
            findings = [
                {
                    "Source": "test",
                    "RuleID": "TEST_001",
                    "Title": "Test",
                    "Location": "/path",
                    "Evidence": "evidence",
                    "Severity": "High",
                    "HowFound": "Test"
                }
            ]
            count = write_findings_csv(output_path, findings)
            assert count == 1

    def test_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "subdir" / "findings.csv"
            write_findings_csv(output_path, [])
            assert output_path.exists()


class TestFileIteration:
    """Tests for file iteration functions."""

    def test_iter_source_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            java_file = Path(tmpdir) / "Test.java"
            java_file.write_text("public class Test {}")

            kt_file = Path(tmpdir) / "Utils.kt"
            kt_file.write_text("object Utils {}")

            png_file = Path(tmpdir) / "image.png"
            png_file.write_bytes(b"\x89PNG")

            # Iterate
            files = list(iter_source_files(tmpdir))

            # Should find Java and Kotlin, not PNG
            paths = [p for p, _ in files]
            assert any("Test.java" in p for p in paths)
            assert any("Utils.kt" in p for p in paths)
            assert not any("image.png" in p for p in paths)

    def test_iter_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            files = list(iter_source_files(tmpdir))
            assert files == []

    def test_iter_nonexistent_directory(self):
        files = list(iter_source_files("/nonexistent/path"))
        assert files == []


class TestCSVFieldnames:
    """Tests for CSV field name consistency."""

    def test_fieldnames_match_finding_dict(self):
        finding = Finding(
            source="test",
            rule_id="TEST",
            title="Title",
            location="/path",
            evidence="evidence",
            severity=Severity.HIGH,
            how_found="Test"
        )
        d = finding.to_dict()
        assert set(d.keys()) == set(CSV_FIELDNAMES)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
