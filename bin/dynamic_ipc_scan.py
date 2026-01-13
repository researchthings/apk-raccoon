#!/usr/bin/env python3

# Author: Randy Grant
# Date: 11-07-2025
# Version: 1.0
# Script to probe IPC dynamically via ADB
# Why: Detects exposed components at runtime; complements static manifest analysis for real-world risks.

import logging
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

import pandas as pd

# Suppress androguard's verbose debug logging
logging.getLogger("androguard").setLevel(logging.WARNING)

try:
    from androguard.core.apk import APK  # androguard 4.x
except ImportError:
    from androguard.core.bytecodes.apk import APK  # androguard 3.x
import time
import traceback


def get_package_name(manifest_path):
    # Why: Extract package to install/uninstall via ADB.
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    return root.attrib.get("package", "unknown")

def wait_for_device(timeout=60):
    # Why: Wait for emulator/device to be fully online, as boot can take time.
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            output = subprocess.run(["adb", "devices"], capture_output=True, text=True, check=True).stdout
            if "device" in output.lower():
                print("Device detected.")
                return True
            time.sleep(5)
            print("Waiting for device...")
        except:
            pass
    return False

def is_split_apk(apk_path):
    # Why: Check if the APK is a base split requiring additional splits, to avoid install failure.
    try:
        a = APK(apk_path)
        manifest_xml = a.get_android_manifest_axml().get_xml()
        if 'isSplitRequired="true"' in manifest_xml:
            return True
        return False
    except Exception as e:
        print(f"Warning: Could not check if APK is split: {str(e)}")
        return False

def main():
    try:
        if len(sys.argv) < 4:
            raise ValueError("Usage: dynamic_ipc_scan.py <apk_path> <manifest.xml> <out.csv>")
        apk_path, manifest_path, out = sys.argv[1:]
        package = get_package_name(manifest_path)
        # Check if APK is split base
        if is_split_apk(apk_path):
            print("Warning: APK is a split base; dynamic probe skipped as full bundle needed.")
            df = pd.DataFrame([{"Source":"dynamic","RuleID":"DYNAMIC_SPLIT_APK","Title":"Split APK detected; installation requires full bundle","Location":"","Evidence":"","Severity":"Info","HowFound":"manifest check"}])
            df.to_csv(out, index=False)
            print(f"Wrote {out} ({len(df)} rows)")
            return
        # Restart ADB server to fix common 'no devices' issues
        print("Restarting ADB server...")
        subprocess.run(["adb", "kill-server"], capture_output=True)
        subprocess.run(["adb", "start-server"], capture_output=True)
        # Check for devices and wait if needed
        if not wait_for_device():
            print("Warning: No devices found after timeout.")
            df = pd.DataFrame([{"Source":"dynamic","RuleID":"DYNAMIC_NO_DEVICE","Title":"No device detected after wait","Location":"","Evidence":"","Severity":"Info","HowFound":"adb check timed out"}])
            df.to_csv(out, index=False)
            print(f"Wrote {out} ({len(df)} rows)")
            return
        # Install APK
        subprocess.run(["adb", "install", "-r", apk_path], check=True, capture_output=True)
        # Probe activities, services, etc. (example: dumpsys for exposed)
        dumpsys_out = subprocess.run(["adb", "shell", "dumpsys", "package", package], capture_output=True, text=True).stdout
        # Heuristic parse for exposed IPC (expand as needed)
        rows = []
        if "exported=true" in dumpsys_out:
            rows.append(dict(Source="dynamic", RuleID="IPC_EXPORTED", Title="Exported component found", Location=package,
                             Evidence="dumpsys shows exported=true", Severity="High", HowFound="ADB probe"))
        df = pd.DataFrame(rows)
        df.to_csv(out, index=False)
        print(f"Wrote {out} ({len(df)} rows)")
        # Uninstall
        subprocess.run(["adb", "uninstall", package], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Warning: ADB command failed: {e.stderr}")
        df = pd.DataFrame([{"Source":"dynamic","RuleID":"DYNAMIC_ADB_ERROR","Title":"ADB probe failed","Location":"","Evidence":str(e),"Severity":"Info","HowFound":"Runtime error"}])
        df.to_csv(out, index=False)
        print(f"Wrote {out} ({len(df)} rows)")
    except Exception as e:
        print(f"[!] Error in dynamic_ipc_scan: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()