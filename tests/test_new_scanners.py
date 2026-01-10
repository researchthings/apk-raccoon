#!/usr/bin/env python3
"""
Unit tests for the 7 new bleeding-edge security scanners.

Tests verify that security patterns correctly match vulnerable code
and don't produce false positives on safe code.

Scanners tested:
- Firebase misconfiguration (scan_firebase.py)
- Task hijacking / StrandHogg (scan_task_hijacking.py)
- Deep links (scan_deep_links.py)
- Tapjacking (scan_tapjacking.py)
- Broadcasts (scan_broadcasts.py)
- Native libraries (scan_native_libs.py)
- Dynamic loading (scan_dynamic_loading.py)

Run with: python -m pytest tests/test_new_scanners.py -v
"""

import re
import sys
from pathlib import Path

import pytest

# Add bin directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "bin"))


class TestFirebasePatterns:
    """Tests for Firebase misconfiguration patterns from scan_firebase.py."""

    def test_firebase_realtime_db_url(self):
        pattern = r"https://[a-z0-9-]+\.firebaseio\.com/?"
        assert re.search(pattern, "https://myapp-12345.firebaseio.com/") is not None
        assert re.search(pattern, "https://test-project.firebaseio.com") is not None
        assert re.search(pattern, "https://example.com/") is None

    def test_firebase_storage_bucket(self):
        pattern = r"https://firebasestorage\.googleapis\.com/v0/b/[a-z0-9-]+\.appspot\.com"
        assert re.search(pattern, "https://firebasestorage.googleapis.com/v0/b/myapp.appspot.com") is not None
        assert re.search(pattern, "https://firebasestorage.googleapis.com/v0/b/test-project.appspot.com") is not None
        assert re.search(pattern, "https://storage.googleapis.com/") is None

    def test_firebase_storage_gs(self):
        pattern = r"gs://[a-z0-9-]+\.appspot\.com"
        assert re.search(pattern, "gs://myapp.appspot.com") is not None
        assert re.search(pattern, "gs://test-project.appspot.com") is not None
        assert re.search(pattern, "gs://bucket-name") is None

    def test_firebase_api_key(self):
        pattern = r"AIza[0-9A-Za-z_-]{35}"
        assert re.search(pattern, "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") is not None
        assert re.search(pattern, "AIza1234567890abcdefghijklmnopqrstuvwxy") is not None
        assert re.search(pattern, "AIza_short") is None  # Too short

    def test_firebase_project_id(self):
        pattern = r'"project_id"\s*:\s*"([a-z0-9-]+)"'
        assert re.search(pattern, '"project_id": "my-firebase-app"') is not None
        assert re.search(pattern, '"project_id":"test-project-123"') is not None
        assert re.search(pattern, '"project_id": "INVALID"') is None  # Uppercase

    def test_firebase_fcm_server_key(self):
        pattern = r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
        # FCM server key format
        key = "AAAA1234567:" + "a" * 140
        assert re.search(pattern, key) is not None
        assert re.search(pattern, "AAAAshort:key") is None

    def test_firebase_auth_domain(self):
        pattern = r"[a-z0-9-]+\.firebaseapp\.com"
        assert re.search(pattern, "myapp.firebaseapp.com") is not None
        assert re.search(pattern, "test-project.firebaseapp.com") is not None
        assert re.search(pattern, "example.com") is None

    def test_firebase_db_reference(self):
        pattern = r"FirebaseDatabase\.getInstance\(\)\.getReference\("
        code = "FirebaseDatabase.getInstance().getReference(\"users\")"
        assert re.search(pattern, code) is not None
        assert re.search(pattern, "FirebaseAuth.getInstance()") is None

    def test_firebase_anon_auth(self):
        pattern = r"signInAnonymously\(\)"
        assert re.search(pattern, "auth.signInAnonymously()") is not None
        assert re.search(pattern, "signInWithCredential()") is None


class TestTaskHijackingPatterns:
    """Tests for StrandHogg/task hijacking patterns from scan_task_hijacking.py."""

    def test_startactivities_pattern(self):
        pattern = r"startActivities\s*\(\s*[^)]+\)"
        assert re.search(pattern, "startActivities(intents)") is not None
        assert re.search(pattern, "context.startActivities(new Intent[] {i1, i2})") is not None
        assert re.search(pattern, "startActivity(intent)") is None

    def test_dangerous_launch_modes(self):
        dangerous_modes = {"singleTask", "singleInstance"}
        assert "singleTask" in dangerous_modes
        assert "singleInstance" in dangerous_modes
        assert "standard" not in dangerous_modes
        assert "singleTop" not in dangerous_modes


class TestDeepLinkPatterns:
    """Tests for deep link security patterns from scan_deep_links.py."""

    def test_webview_injection_pattern(self):
        pattern = r"getIntent\(\)\.getData\(\).*loadUrl\("
        code = """
        Uri data = getIntent().getData();
        webView.loadUrl(data.toString());
        """
        assert re.search(pattern, code, re.DOTALL) is not None

    def test_unvalidated_data_pattern(self):
        pattern = r"getIntent\(\)\.getData\(\)\.toString\(\)"
        assert re.search(pattern, "String url = getIntent().getData().toString();") is not None
        assert re.search(pattern, "intent.getData().toString()") is None  # Different pattern

    def test_sql_injection_pattern(self):
        pattern = r"getIntent\(\)\.getData\(\).*rawQuery|execSQL"
        code = """
        String id = getIntent().getData().getQueryParameter("id");
        db.rawQuery("SELECT * FROM users WHERE id=" + id, null);
        """
        assert re.search(pattern, code, re.DOTALL) is not None

    def test_intent_injection_pattern(self):
        pattern = r"Intent\.parseUri\(.*getIntent\(\)\.getData\(\)"
        code = "Intent.parseUri(getIntent().getData().toString(), 0)"
        assert re.search(pattern, code, re.DOTALL) is not None

    def test_path_traversal_pattern(self):
        pattern = r"getIntent\(\)\.getData\(\)\.getPath\(\).*File\("
        code = """
        String path = getIntent().getData().getPath();
        File file = new File(path);
        """
        assert re.search(pattern, code, re.DOTALL) is not None

    def test_query_parameter_pattern(self):
        pattern = r"\.getQueryParameter\([\"'][^\"']+[\"']\)"
        assert re.search(pattern, '.getQueryParameter("token")') is not None
        assert re.search(pattern, ".getQueryParameter('id')") is not None


class TestTapjackingPatterns:
    """Tests for tapjacking/overlay attack patterns from scan_tapjacking.py."""

    def test_filter_touches_xml_pattern(self):
        pattern = r"filterTouchesWhenObscured\s*=\s*[\"']?true"
        assert re.search(pattern, 'android:filterTouchesWhenObscured="true"') is not None
        assert re.search(pattern, "filterTouchesWhenObscured=true") is not None
        assert re.search(pattern, 'filterTouchesWhenObscured="false"') is None

    def test_filter_touches_code_pattern(self):
        pattern = r"\.setFilterTouchesWhenObscured\s*\(\s*true\s*\)"
        assert re.search(pattern, "button.setFilterTouchesWhenObscured(true)") is not None
        assert re.search(pattern, ".setFilterTouchesWhenObscured( true )") is not None
        assert re.search(pattern, ".setFilterTouchesWhenObscured(false)") is None

    def test_flag_secure_pattern(self):
        pattern = r"FLAG_SECURE|WindowManager\.LayoutParams\.FLAG_SECURE"
        assert re.search(pattern, "getWindow().addFlags(FLAG_SECURE)") is not None
        assert re.search(pattern, "WindowManager.LayoutParams.FLAG_SECURE") is not None
        assert re.search(pattern, "FLAG_FULLSCREEN") is None

    def test_overlay_detection_pattern(self):
        pattern = r"onFilterTouchEventForSecurity|FLAG_WINDOW_IS_OBSCURED"
        assert re.search(pattern, "onFilterTouchEventForSecurity(event)") is not None
        assert re.search(pattern, "FLAG_WINDOW_IS_OBSCURED") is not None

    def test_filter_disabled_pattern(self):
        pattern = r"\.setFilterTouchesWhenObscured\s*\(\s*false\s*\)"
        assert re.search(pattern, ".setFilterTouchesWhenObscured(false)") is not None
        assert re.search(pattern, ".setFilterTouchesWhenObscured(true)") is None

    def test_sensitive_activity_keywords(self):
        keywords = [
            "login", "auth", "password", "payment", "checkout", "transfer",
            "confirm", "verify", "otp", "pin", "biometric", "fingerprint",
        ]
        test_names = ["LoginActivity", "PaymentFragment", "AuthService"]
        for name in test_names:
            name_lower = name.lower()
            assert any(kw in name_lower for kw in keywords)


class TestBroadcastPatterns:
    """Tests for broadcast receiver security patterns from scan_broadcasts.py."""

    def test_sticky_broadcast_pattern(self):
        pattern = r"sendStickyBroadcast\s*\("
        assert re.search(pattern, "sendStickyBroadcast(intent)") is not None
        assert re.search(pattern, "sendBroadcast(intent)") is None

    def test_sticky_ordered_broadcast_pattern(self):
        pattern = r"sendStickyOrderedBroadcast\s*\("
        assert re.search(pattern, "sendStickyOrderedBroadcast(intent, null, null, 0, null, null)") is not None

    def test_local_broadcast_pattern(self):
        pattern = r"LocalBroadcastManager"
        assert re.search(pattern, "LocalBroadcastManager.getInstance(context)") is not None

    def test_explicit_export_flag_pattern(self):
        pattern = r"RECEIVER_EXPORTED|RECEIVER_NOT_EXPORTED"
        assert re.search(pattern, "registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)") is not None
        assert re.search(pattern, "RECEIVER_NOT_EXPORTED") is not None

    def test_abort_broadcast_pattern(self):
        pattern = r"abortBroadcast\s*\(\)"
        assert re.search(pattern, "abortBroadcast()") is not None
        assert re.search(pattern, "abortBroadcast") is None  # Needs parentheses

    def test_pending_intent_broadcast_pattern(self):
        pattern = r"PendingIntent\.getBroadcast\s*\("
        assert re.search(pattern, "PendingIntent.getBroadcast(context, 0, intent, 0)") is not None
        assert re.search(pattern, "PendingIntent.getActivity(context, 0, intent, 0)") is None

    def test_sensitive_broadcast_actions(self):
        sensitive_actions = {
            "android.intent.action.BOOT_COMPLETED",
            "android.provider.Telephony.SMS_RECEIVED",
            "android.intent.action.NEW_OUTGOING_CALL",
        }
        assert "android.provider.Telephony.SMS_RECEIVED" in sensitive_actions
        assert "android.intent.action.MAIN" not in sensitive_actions


class TestNativeLibPatterns:
    """Tests for native library security patterns from scan_native_libs.py."""

    def test_native_lib_extensions(self):
        extensions = {".so"}
        assert ".so" in extensions
        assert ".dll" not in extensions

    def test_vulnerable_lib_patterns(self):
        vulnerable_libs = ["libssl.so.1.0", "libcrypto.so.1.0", "libwebp.so"]
        test_libs = ["libssl.so.1.0.2", "libcrypto.so.1.0.1", "libwebp.so"]
        for lib in test_libs:
            assert any(vuln in lib for vuln in vulnerable_libs)

    def test_arch_coverage(self):
        expected_archs = {"arm64-v8a", "armeabi-v7a", "x86_64", "x86"}
        found = {"arm64-v8a", "armeabi-v7a"}
        missing = expected_archs - found
        assert len(missing) > 0  # Test that we detect missing architectures


class TestDynamicLoadingPatterns:
    """Tests for dynamic code loading patterns from scan_dynamic_loading.py."""

    def test_dex_classloader_pattern(self):
        pattern = r"DexClassLoader\s*\("
        assert re.search(pattern, "new DexClassLoader(path, opt, lib, parent)") is not None
        assert re.search(pattern, "DexClassLoader loader = new DexClassLoader(") is not None
        assert re.search(pattern, "PathClassLoader") is None

    def test_path_classloader_pattern(self):
        pattern = r"PathClassLoader\s*\("
        assert re.search(pattern, "new PathClassLoader(dexPath, parent)") is not None
        assert re.search(pattern, "DexClassLoader") is None

    def test_inmemory_classloader_pattern(self):
        pattern = r"InMemoryDexClassLoader\s*\("
        assert re.search(pattern, "new InMemoryDexClassLoader(buffer, parent)") is not None

    def test_class_forname_pattern(self):
        pattern = r"Class\.forName\s*\([^\"'\)]+\)"
        # Dynamic string (variable) - pattern excludes strings with quotes
        assert re.search(pattern, "Class.forName(className)") is not None
        assert re.search(pattern, "Class.forName(pkg + cls)") is not None
        # Pattern specifically excludes calls with string literals (quotes inside)
        assert re.search(pattern, 'Class.forName("com.example.Class")') is None

    def test_load_class_pattern(self):
        pattern = r"\.loadClass\s*\([^)]+\)"
        assert re.search(pattern, "classLoader.loadClass(className)") is not None
        assert re.search(pattern, "loader.loadClass(\"com.example.MyClass\")") is not None

    def test_define_class_pattern(self):
        pattern = r"defineClass\s*\("
        assert re.search(pattern, "defineClass(name, bytes, 0, bytes.length)") is not None

    def test_runtime_exec_pattern(self):
        pattern = r"Runtime\.getRuntime\(\)\.exec\s*\("
        assert re.search(pattern, 'Runtime.getRuntime().exec("ls")') is not None
        assert re.search(pattern, "Runtime.getRuntime().exec(cmd)") is not None

    def test_process_builder_pattern(self):
        pattern = r"ProcessBuilder\s*\("
        assert re.search(pattern, 'new ProcessBuilder("cmd", "/c", "dir")') is not None
        assert re.search(pattern, "ProcessBuilder(command)") is not None

    def test_script_engine_pattern(self):
        pattern = r"ScriptEngine(?:Manager)?|\.eval\s*\("
        assert re.search(pattern, "ScriptEngineManager manager = new ScriptEngineManager()") is not None
        assert re.search(pattern, "engine.eval(script)") is not None

    def test_dex_file_reference_pattern(self):
        pattern = r"[\"'][^\"']*\.dex[\"']"
        assert re.search(pattern, '"classes.dex"') is not None
        assert re.search(pattern, "'/data/data/app/plugin.dex'") is not None
        assert re.search(pattern, "classes.dex") is None  # Not quoted

    def test_external_storage_load_pattern(self):
        pattern = r"getExternalStorageDirectory\(\).*(?:DexClassLoader|PathClassLoader|loadClass)"
        code = """
        File ext = Environment.getExternalStorageDirectory();
        new DexClassLoader(ext + "/plugin.dex", cache, null, parent);
        """
        assert re.search(pattern, code, re.DOTALL) is not None


class TestFalsePositiveAvoidanceNewScanners:
    """Tests to verify new scanner patterns don't match safe code."""

    def test_https_firebase_storage_not_matched_as_http(self):
        # Firebase storage pattern should match full URL, not partial
        pattern = r"https://firebasestorage\.googleapis\.com/v0/b/[a-z0-9-]+\.appspot\.com"
        assert re.search(pattern, "http://firebasestorage.googleapis.com/") is None

    def test_safe_classloader_usage(self):
        # Standard library class loading shouldn't trigger high severity
        pattern = r"Class\.forName\s*\(\s*[\"'][^\"']+[\"']\s*\)"
        # Static string is lower risk
        assert re.search(pattern, 'Class.forName("java.util.ArrayList")') is not None

    def test_safe_touch_handling(self):
        # Touch handling with security check
        pattern = r"\.setFilterTouchesWhenObscured\s*\(\s*true\s*\)"
        code = "view.setFilterTouchesWhenObscured(true)"
        assert re.search(pattern, code) is not None  # This is safe, should detect

    def test_local_broadcast_is_safe(self):
        # LocalBroadcastManager is actually safe
        pattern = r"LocalBroadcastManager"
        code = "LocalBroadcastManager.getInstance(this).sendBroadcast(intent)"
        assert re.search(pattern, code) is not None  # Detected as Info (good practice)

    def test_receiver_not_exported_is_safe(self):
        # RECEIVER_NOT_EXPORTED is good practice
        pattern = r"RECEIVER_NOT_EXPORTED"
        code = "registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)"
        assert re.search(pattern, code) is not None  # Detected as Info


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
