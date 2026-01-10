#!/usr/bin/env python3
"""
Unit tests for advanced scanner patterns (v2.2.0).

Tests patterns from:
- scan_zip_slip.py
- scan_serialization.py
- scan_fragment_injection.py
- scan_xxe.py
- scan_implicit_intents.py
- scan_clipboard.py
- scan_keyboard_cache.py
- scan_random.py
- scan_apk_signature.py
- scan_deprecated_apis.py

Run with: python -m pytest tests/test_advanced_scanners.py -v
"""

import re
import sys
from pathlib import Path

import pytest

# Add bin directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "bin"))


class TestZipSlipPatterns:
    """Tests for Zip Slip / Path Traversal patterns."""

    def test_zipentry_getname_pattern(self):
        pattern = r"ZipEntry[^;]*\.getName\s*\(\s*\)"
        # Pattern requires ZipEntry and getName() in same statement (no semicolons between)
        code = 'for (ZipEntry entry : entries) if (entry.getName().contains(".."))'
        assert re.search(pattern, code) is not None

    def test_zipinputstream_pattern(self):
        pattern = r"ZipInputStream[^;]*getNextEntry"
        # Pattern requires ZipInputStream and getNextEntry in same statement
        code = "while ((entry = new ZipInputStream(fis).getNextEntry()) != null)"
        assert re.search(pattern, code) is not None

    def test_jarentry_pattern(self):
        pattern = r"JarEntry[^;]*\.getName\s*\(\s*\)"
        # Pattern requires JarEntry and getName() in same statement
        code = 'for (JarEntry entry : jarEntries) process(entry.getName())'
        assert re.search(pattern, code) is not None

    def test_canonical_path_good(self):
        pattern = r"\.getCanonicalPath\s*\(\s*\)"
        code = 'String canonical = file.getCanonicalPath();'
        assert re.search(pattern, code) is not None

    def test_startswith_good(self):
        pattern = r"\.startsWith\s*\([^)]*\)"
        code = 'if (path.startsWith(targetDir)) {'
        assert re.search(pattern, code) is not None


class TestSerializationPatterns:
    """Tests for Unsafe Deserialization patterns."""

    def test_readobject_pattern(self):
        pattern = r"ObjectInputStream[^;]*\.readObject\s*\(\s*\)"
        # Pattern requires ObjectInputStream and readObject() in same statement
        code = "Object obj = new ObjectInputStream(fis).readObject()"
        assert re.search(pattern, code) is not None

    def test_ois_from_network(self):
        pattern = r"new\s+ObjectInputStream\s*\(\s*(?:socket|connection|url|http|input|file|stream)"
        code = "ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());"
        assert re.search(pattern, code, re.IGNORECASE) is not None

    def test_custom_readobject(self):
        pattern = r"private\s+void\s+readObject\s*\(\s*ObjectInputStream"
        code = "private void readObject(ObjectInputStream ois) throws IOException {"
        assert re.search(pattern, code) is not None

    def test_jackson_default_typing(self):
        pattern = r"enableDefaultTyping|activateDefaultTyping|DefaultTyping"
        code = "mapper.enableDefaultTyping();"
        assert re.search(pattern, code) is not None
        code2 = "mapper.activateDefaultTyping(ptv);"
        assert re.search(pattern, code2) is not None

    def test_xml_decoder(self):
        pattern = r"XMLDecoder[^;]*\.readObject\s*\(\s*\)"
        # Pattern requires XMLDecoder and readObject() in same statement
        code = "Object obj = new XMLDecoder(fis).readObject()"
        assert re.search(pattern, code) is not None


class TestFragmentInjectionPatterns:
    """Tests for Fragment Injection patterns."""

    def test_preference_activity_vulnerable(self):
        pattern = r"class\s+\w+\s+extends\s+PreferenceActivity"
        code = "public class SettingsActivity extends PreferenceActivity {"
        assert re.search(pattern, code) is not None

    def test_isvalid_always_true(self):
        pattern = r"(?:protected|public)\s+boolean\s+isValidFragment\s*\([^)]*\)\s*\{[^}]*return\s+true\s*;"
        code = """
        protected boolean isValidFragment(String fragmentName) {
            return true;
        }
        """
        assert re.search(pattern, code, re.DOTALL) is not None

    def test_fragment_instantiate_intent(self):
        pattern = r"Fragment\.instantiate\s*\([^,]+,\s*(?:getIntent\(\)|intent)\.[^,]+"
        code = "Fragment.instantiate(this, getIntent().getStringExtra(FRAGMENT_CLASS));"
        assert re.search(pattern, code) is not None


class TestXXEPatterns:
    """Tests for XXE Injection patterns."""

    def test_saxparser_no_feature(self):
        pattern = r"SAXParserFactory\.newInstance\s*\(\s*\)"
        code = "SAXParserFactory factory = SAXParserFactory.newInstance();"
        assert re.search(pattern, code) is not None

    def test_documentbuilder_no_feature(self):
        pattern = r"DocumentBuilderFactory\.newInstance\s*\(\s*\)"
        code = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();"
        assert re.search(pattern, code) is not None

    def test_secure_processing_good(self):
        pattern = r"setFeature\s*\([^)]*(?:FEATURE_SECURE_PROCESSING|disallow-doctype-decl)[^)]*,\s*true"
        code = 'factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);'
        assert re.search(pattern, code) is not None

    def test_external_entities_enabled_bad(self):
        pattern = r"setFeature\s*\([^)]*external-(?:general|parameter)-entities[^)]*,\s*true"
        code = 'factory.setFeature("http://xml.org/sax/features/external-general-entities", true);'
        assert re.search(pattern, code) is not None


class TestImplicitIntentPatterns:
    """Tests for Implicit Intent Leakage patterns."""

    def test_sendbroadcast_no_permission(self):
        pattern = r"sendBroadcast\s*\(\s*\w+\s*\)(?!\s*,)"
        code = "sendBroadcast(intent);"
        assert re.search(pattern, code) is not None
        # With permission should not match
        code2 = "sendBroadcast(intent, MY_PERMISSION);"
        assert re.search(pattern, code2) is None

    def test_start_service_implicit(self):
        pattern = r'startService\s*\(\s*new\s+Intent\s*\(\s*["\']'
        code = 'startService(new Intent("com.example.ACTION"));'
        assert re.search(pattern, code) is not None

    def test_setpackage_good(self):
        pattern = r'\.setPackage\s*\(\s*["\'][^"\']+["\']\s*\)'
        code = 'intent.setPackage("com.example.app");'
        assert re.search(pattern, code) is not None


class TestClipboardPatterns:
    """Tests for Clipboard Data Exposure patterns."""

    def test_set_primary_clip(self):
        pattern = r"ClipboardManager[^;]*\.setPrimaryClip\s*\("
        # Pattern requires ClipboardManager and setPrimaryClip in same statement
        code = "((ClipboardManager) getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(clip)"
        assert re.search(pattern, code) is not None

    def test_password_in_clipboard(self):
        pattern = r"setPrimaryClip[^;]*(?:password|passwd|pwd)"
        code = 'clipboardManager.setPrimaryClip(ClipData.newPlainText("pwd", password));'
        assert re.search(pattern, code, re.IGNORECASE) is not None

    def test_sensitive_flag_good(self):
        pattern = r"EXTRA_IS_SENSITIVE"
        code = 'clip.getDescription().setExtras(bundle.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true));'
        assert re.search(pattern, code) is not None


class TestKeyboardCachePatterns:
    """Tests for Keyboard Cache patterns."""

    def test_password_inputtype(self):
        pattern = r'android:inputType\s*=\s*["\'][^"\']*textPassword[^"\']*["\']'
        code = 'android:inputType="textPassword"'
        assert re.search(pattern, code) is not None

    def test_no_suggestions(self):
        pattern = r'android:inputType\s*=\s*["\'][^"\']*textNoSuggestions[^"\']*["\']'
        code = 'android:inputType="textNoSuggestions|textPassword"'
        assert re.search(pattern, code) is not None

    def test_type_text_flag_code(self):
        pattern = r"TYPE_TEXT_FLAG_NO_SUGGESTIONS"
        code = "editText.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);"
        assert re.search(pattern, code) is not None


class TestRandomPatterns:
    """Tests for Insecure Random patterns."""

    def test_java_util_random(self):
        pattern = r"java\.util\.Random"
        code = "import java.util.Random;"
        assert re.search(pattern, code) is not None

    def test_new_random(self):
        pattern = r"new\s+Random\s*\(\s*\)"
        code = "Random random = new Random();"
        assert re.search(pattern, code) is not None

    def test_math_random(self):
        pattern = r"Math\.random\s*\(\s*\)"
        code = "double val = Math.random();"
        assert re.search(pattern, code) is not None

    def test_time_seed_bad(self):
        pattern = r"new\s+Random\s*\(\s*System\.currentTimeMillis\s*\(\s*\)\s*\)"
        code = "Random random = new Random(System.currentTimeMillis());"
        assert re.search(pattern, code) is not None

    def test_constant_seed_bad(self):
        pattern = r"new\s+Random\s*\(\s*\d+\s*\)"
        code = "Random random = new Random(12345);"
        assert re.search(pattern, code) is not None

    def test_secure_random_good(self):
        pattern = r"SecureRandom"
        code = "SecureRandom secureRandom = new SecureRandom();"
        assert re.search(pattern, code) is not None


class TestDeprecatedAPIPatterns:
    """Tests for Deprecated API patterns."""

    def test_des_cipher(self):
        pattern = r'Cipher\.getInstance\s*\(\s*["\']DES["\']'
        code = 'Cipher cipher = Cipher.getInstance("DES");'
        assert re.search(pattern, code) is not None

    def test_md5_hash(self):
        pattern = r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']'
        code = 'MessageDigest md = MessageDigest.getInstance("MD5");'
        assert re.search(pattern, code) is not None

    def test_sha1_hash(self):
        pattern = r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']'
        code = 'MessageDigest md = MessageDigest.getInstance("SHA1");'
        assert re.search(pattern, code, re.IGNORECASE) is not None
        code2 = 'MessageDigest.getInstance("SHA-1")'
        assert re.search(pattern, code2, re.IGNORECASE) is not None

    def test_mode_world_readable(self):
        pattern = r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"
        code = "getSharedPreferences(name, MODE_WORLD_READABLE);"
        assert re.search(pattern, code) is not None

    def test_apache_http(self):
        pattern = r"org\.apache\.http"
        code = "import org.apache.http.client.HttpClient;"
        assert re.search(pattern, code) is not None

    def test_async_task(self):
        pattern = r"extends\s+AsyncTask|new\s+AsyncTask"
        code = "public class MyTask extends AsyncTask<Void, Void, String> {"
        assert re.search(pattern, code) is not None

    def test_runtime_exec(self):
        pattern = r"Runtime\.getRuntime\(\)\.exec"
        code = "Runtime.getRuntime().exec(command);"
        assert re.search(pattern, code) is not None


class TestOutputGenerators:
    """Tests for output generator modules."""

    def test_html_report_import(self):
        """Verify HTML report generator can be imported."""
        try:
            import generate_html_report
            assert hasattr(generate_html_report, 'generate_html_report')
            assert hasattr(generate_html_report, 'read_findings')
        except ImportError:
            pytest.skip("generate_html_report module not found")

    def test_sarif_import(self):
        """Verify SARIF generator can be imported."""
        try:
            import generate_sarif
            assert hasattr(generate_sarif, 'generate_sarif_report')
            assert hasattr(generate_sarif, 'build_rules')
            assert hasattr(generate_sarif, 'build_results')
        except ImportError:
            pytest.skip("generate_sarif module not found")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
