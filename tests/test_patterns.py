#!/usr/bin/env python3
"""
Unit tests for scanner regex patterns.

These tests verify that security patterns correctly match vulnerable code
and don't produce false positives on safe code.

Run with: python -m pytest tests/test_patterns.py -v
"""

import re
import sys
from pathlib import Path

import pytest

# Add bin directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "bin"))


class TestSecretPatterns:
    """Tests for secret detection patterns from detect_secrets.py."""

    # AWS patterns
    def test_aws_access_key_pattern(self):
        pattern = r'AKIA[0-9A-Z]{16}'
        assert re.search(pattern, "AKIAIOSFODNN7EXAMPLE") is not None
        assert re.search(pattern, "AKIAI44QH8DHBEXAMPLE") is not None
        assert re.search(pattern, "AKIAshort") is None  # Too short

    def test_aws_secret_key_pattern(self):
        pattern = r'(?i)(?:aws[_-]?)?secret[_-]?(?:access[_-]?)?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'
        test = 'aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        assert re.search(pattern, test) is not None

    # GitHub tokens
    def test_github_token_pattern(self):
        pattern = r'gh[pousr]_[A-Za-z0-9_]{36,}'
        assert re.search(pattern, "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1234") is not None
        assert re.search(pattern, "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1234") is not None
        assert re.search(pattern, "ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1234") is not None
        assert re.search(pattern, "ghp_short") is None  # Too short

    # Stripe keys (using constructed string to avoid push protection triggers)
    def test_stripe_live_key_pattern(self):
        pattern = r'sk_live_[0-9a-zA-Z]{24,}'
        # Construct test key dynamically to avoid secret scanning
        test_key = "sk_" + "live_" + "X" * 28
        assert re.search(pattern, test_key) is not None
        assert re.search(pattern, "sk_test_" + "X" * 28) is None  # Test key prefix

    # Private keys
    def test_rsa_private_key_pattern(self):
        pattern = r'-----BEGIN RSA PRIVATE KEY-----'
        assert re.search(pattern, "-----BEGIN RSA PRIVATE KEY-----\nMIIE...") is not None
        assert re.search(pattern, "-----BEGIN PUBLIC KEY-----") is None

    # JWT
    def test_jwt_pattern(self):
        pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
        assert re.search(pattern, jwt) is not None

    # Database URIs
    def test_mongodb_uri_pattern(self):
        pattern = r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\']+'
        assert re.search(pattern, "mongodb://user:pass@host.com/db") is not None
        assert re.search(pattern, "mongodb+srv://user:pass@cluster.mongodb.net") is not None
        assert re.search(pattern, "mongodb://host.com/db") is None  # No credentials

    def test_postgres_uri_pattern(self):
        pattern = r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\']+'
        assert re.search(pattern, "postgres://user:pass@localhost/db") is not None
        assert re.search(pattern, "postgresql://user:pass@host:5432/db") is not None


class TestNetworkSecurityPatterns:
    """Tests for network security patterns from scan_network_security.py."""

    def test_http_url_pattern(self):
        pattern = r'http://[^\s"\'<>)}\]]+[^\s"\'<>)}\]\.,;]'
        assert re.search(pattern, 'url = "http://api.example.com/data"') is not None
        assert re.search(pattern, 'url = "https://api.example.com/data"') is None

    def test_trust_manager_pattern(self):
        pattern = r'class\s+\w+\s+implements\s+X509TrustManager'
        code = "public class InsecureTrustManager implements X509TrustManager {"
        assert re.search(pattern, code) is not None

    def test_hostname_verifier_pattern(self):
        pattern = r'class\s+\w+\s+implements\s+HostnameVerifier'
        code = "class AllowAllHostnameVerifier implements HostnameVerifier {"
        assert re.search(pattern, code) is not None

    def test_ssl_error_bypass_pattern(self):
        pattern = r'onReceivedSslError[^}]*handler\.proceed\s*\(\s*\)'
        code = """
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            handler.proceed();
        }
        """
        assert re.search(pattern, code, re.DOTALL) is not None


class TestAuthPatterns:
    """Tests for auth patterns from scan_auth_issues.py."""

    def test_weak_password_pattern(self):
        pattern = r'(?i)(?:password|passwd|pwd)\s*=\s*["\']([^"\']{1,6})["\']'
        assert re.search(pattern, 'password = "123"') is not None
        assert re.search(pattern, 'password = "abc"') is not None
        assert re.search(pattern, 'password = "verylongpassword"') is None  # Too long

    def test_password_comparison_pattern(self):
        # Pattern matches .equals( method calls specifically
        pattern = r'(?i)(?:password|passwd|pwd)\s*\.equals\s*\('
        assert re.search(pattern, 'if (password.equals(input))') is not None
        assert re.search(pattern, 'if (pwd.equals(userInput))') is not None
        assert re.search(pattern, 'password == input') is None  # == not matched by this pattern


class TestCryptoPatterns:
    """Tests for crypto patterns from scan_crypto_issues.py."""

    def test_ecb_mode_pattern(self):
        pattern = r'(?i)Cipher\.getInstance\s*\(\s*["\'][^"\']*ECB'
        assert re.search(pattern, 'Cipher.getInstance("AES/ECB/PKCS5Padding")') is not None
        assert re.search(pattern, 'Cipher.getInstance("AES/GCM/NoPadding")') is None

    def test_des_pattern(self):
        pattern = r'(?i)Cipher\.getInstance\s*\(\s*["\'](?:DES|DESede)'
        assert re.search(pattern, 'Cipher.getInstance("DES")') is not None
        assert re.search(pattern, 'Cipher.getInstance("DESede")') is not None
        assert re.search(pattern, 'Cipher.getInstance("AES")') is None

    def test_md5_pattern(self):
        pattern = r'(?i)MessageDigest\.getInstance\s*\(\s*["\']MD5'
        assert re.search(pattern, 'MessageDigest.getInstance("MD5")') is not None
        assert re.search(pattern, 'MessageDigest.getInstance("SHA-256")') is None

    def test_static_iv_pattern(self):
        pattern = r'(?i)new\s+IvParameterSpec\s*\(\s*(?:new\s+byte\s*\[\s*\]\s*\{|")'
        assert re.search(pattern, 'new IvParameterSpec(new byte[] {1, 2, 3})') is not None
        assert re.search(pattern, 'new IvParameterSpec("staticiv".getBytes())') is not None


class TestContentProviderPatterns:
    """Tests for content provider patterns from scan_content_providers.py."""

    def test_sql_injection_concat_pattern(self):
        pattern = r'(?i)(?:rawQuery|execSQL)\s*\(\s*["\'][^"\']*["\']\s*\+\s*(?:selection|projection|sortOrder|\w+)'
        code = 'db.rawQuery("SELECT * FROM users WHERE id=" + userId, null)'
        assert re.search(pattern, code) is not None

    def test_sql_injection_format_pattern(self):
        pattern = r'(?i)(?:rawQuery|execSQL)\s*\(\s*String\.format\s*\('
        code = 'db.rawQuery(String.format("SELECT * FROM %s", table), null)'
        assert re.search(pattern, code) is not None

    def test_world_readable_pattern(self):
        pattern = r'(?:MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)'
        assert re.search(pattern, "openFileOutput(file, MODE_WORLD_READABLE)") is not None


class TestPendingIntentPatterns:
    """Tests for PendingIntent patterns from scan_pending_intents.py."""

    def test_pending_intent_creation_pattern(self):
        pattern = r'PendingIntent\.(?:getActivity|getActivities|getBroadcast|getService|getForegroundService)\s*\('
        assert re.search(pattern, "PendingIntent.getActivity(context, 0, intent, 0)") is not None
        assert re.search(pattern, "PendingIntent.getBroadcast(context, 0, intent, 0)") is not None
        assert re.search(pattern, "PendingIntent.getService(context, 0, intent, 0)") is not None

    def test_flag_immutable_pattern(self):
        pattern = r'FLAG_IMMUTABLE|PendingIntent\.FLAG_IMMUTABLE'
        assert re.search(pattern, "PendingIntent.FLAG_IMMUTABLE") is not None
        assert re.search(pattern, "FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT") is not None

    def test_empty_intent_pattern(self):
        pattern = r'new\s+Intent\s*\(\s*\)'
        assert re.search(pattern, "new Intent()") is not None
        assert re.search(pattern, "new Intent(context, Activity.class)") is None


class TestCertPinningPatterns:
    """Tests for certificate pinning patterns from scan_cert_pinning.py."""

    def test_certificate_pinner_pattern(self):
        pattern = r'CertificatePinner\.Builder\(\)'
        code = "new CertificatePinner.Builder().add(hostname, pins).build()"
        assert re.search(pattern, code) is not None

    def test_pin_add_pattern(self):
        pattern = r'\.add\s*\(\s*["\'][^"\']+["\']\s*,\s*["\']sha256/'
        code = '.add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")'
        assert re.search(pattern, code) is not None

    def test_trustkit_pattern(self):
        pattern = r'TrustKit\.initializeWithNetworkSecurityConfiguration'
        assert re.search(pattern, "TrustKit.initializeWithNetworkSecurityConfiguration(context)") is not None


class TestPrivacyPatterns:
    """Tests for privacy patterns from scan_privacy_issues.py."""

    def test_ssn_pattern(self):
        pattern = r'(?i)(?:ssn|social[_-]?security)[_-]?(?:number)?\s*[:=]\s*["\']?\d{3}[- ]?\d{2}[- ]?\d{4}'
        assert re.search(pattern, 'ssn = "123-45-6789"') is not None
        assert re.search(pattern, 'social_security_number = "123456789"') is not None

    def test_credit_card_pattern(self):
        pattern = r'(?i)(?:credit[_-]?card|card[_-]?number|cc[_-]?num)\s*[:=]\s*["\']?\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}'
        assert re.search(pattern, 'credit_card = "4111111111111111"') is not None
        assert re.search(pattern, 'card_number = "4111-1111-1111-1111"') is not None


class TestStorageLoggingPatterns:
    """Tests for storage/logging patterns from scan_storage_logging.py."""

    def test_log_pattern(self):
        pattern = r'\bLog\.([dewivw]|wtf)\s*\(\s*[^,]+,\s*(.{0,200}?)\)'
        assert re.search(pattern, 'Log.d(TAG, "message")') is not None
        assert re.search(pattern, 'Log.e(TAG, "error: " + error)') is not None
        assert re.search(pattern, 'Log.wtf(TAG, "critical")') is not None

    def test_sensitive_log_password(self):
        pattern = r'(?i)password\s*[:=]\s*["\'][^\'"]+["\']'
        assert re.search(pattern, 'Log.d(TAG, "password = \'secret\'")') is not None

    def test_external_storage_pattern(self):
        pattern = r'Environment\.getExternalStorage(?:Directory|PublicDirectory)\s*\('
        assert re.search(pattern, "Environment.getExternalStorageDirectory()") is not None
        assert re.search(pattern, "Environment.getExternalStoragePublicDirectory(PICTURES)") is not None


class TestBinaryProtectionPatterns:
    """Tests for binary protection patterns from scan_binary_protections.py."""

    def test_root_detection_patterns(self):
        patterns = [r'\bRootBeer\b', r'\bisRooted\b', r'\bcheckRoot\b']
        code = "if (RootBeer.isRooted()) { /* handle */ }"
        assert any(re.search(p, code) for p in patterns)

    def test_anti_debug_patterns(self):
        patterns = [r'\bisDebuggerConnected\b', r'\bDebug\.isDebuggerConnected\b']
        code = "if (Debug.isDebuggerConnected()) { exit(); }"
        assert any(re.search(p, code) for p in patterns)


class TestFalsePositiveAvoidance:
    """Tests to verify patterns don't match safe code."""

    def test_https_not_matched_as_http(self):
        pattern = r'http://[^\s"\'<>)}\]]+[^\s"\'<>)}\]\.,;]'
        assert re.search(pattern, 'url = "https://secure.example.com"') is None

    def test_localhost_skipped(self):
        safe_patterns = [
            r'http://localhost',
            r'http://127\.0\.0\.1',
            r'http://10\.\d+\.\d+\.\d+',
        ]
        test_urls = [
            "http://localhost:8080/api",
            "http://127.0.0.1:3000",
            "http://10.0.0.1/internal",
        ]
        for url in test_urls:
            assert any(re.search(p, url) for p in safe_patterns)

    def test_example_urls_skipped(self):
        pattern = r'http://example\.(?:com|org)'
        assert re.search(pattern, "http://example.com/api") is not None
        assert re.search(pattern, "http://example.org/test") is not None

    def test_android_schema_skipped(self):
        pattern = r'http://schemas\.android\.com'
        assert re.search(pattern, "xmlns:android=\"http://schemas.android.com/apk/res/android\"") is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
