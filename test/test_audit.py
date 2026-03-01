"""
test_audit.py - Audit test: simulate a native crash caused by sandbox restrictions.

This script simulates a realistic scenario where a native library crashes
because a code path that handles sandbox denials wasn't properly implemented.

Scenario:
  1. Application tries to create a working directory for its cache database.
  2. Sandbox denies write access to the user profile.
  3. The code falls through to a native path with a null pointer.
  4. The process crashes with STATUS_ACCESS_VIOLATION (0xC0000005).

Run inside the sandbox with audit:
  sandy.exe -c test_audit_config.toml -a audit.log -x <python.exe> test_audit.py
"""

import os
import sys
import ctypes

print("=== Audit Crash Test ===")
print(f"PID: {os.getpid()}")
print(f"CWD: {os.getcwd()}")
print()

# --- Phase 1: Attempt to set up a working directory ---
# A well-behaved app would try to create a cache/data directory.
# Inside the sandbox, this should be denied.

user = os.environ.get("USERPROFILE", "C:/Users/unknown")
work_dir = os.path.join(user, "app_cache")
db_path = None

print(f"[1] Creating working directory: {work_dir}")
try:
    os.makedirs(work_dir, exist_ok=True)
    db_path = os.path.join(work_dir, "cache.db")
    print(f"    OK: db_path = {db_path}")
except PermissionError as e:
    print(f"    DENIED: {e}")
except OSError as e:
    print(f"    ERROR: {e}")

# --- Phase 2: Attempt to access temp directory ---
# Some apps fall back to %TEMP% if the primary path fails.

if db_path is None:
    # Note: %TEMP% in AppContainer is remapped to a private writable dir.
    # A real app might try the actual system temp or another fixed path.
    fallback = os.path.join("C:/Users", os.environ.get("USERNAME", "H"), "AppData/Local/Temp/app_cache")
    print(f"[2] Fallback to user temp: {fallback}")
    try:
        os.makedirs(fallback, exist_ok=True)
        db_path = os.path.join(fallback, "cache.db")
        print(f"    OK: db_path = {db_path}")
    except (PermissionError, OSError) as e:
        print(f"    DENIED: {e}")

# --- Phase 3: Attempt network connectivity check ---
print("[3] Checking network connectivity...")
try:
    import urllib.request
    urllib.request.urlopen("http://example.com", timeout=3)
    print("    OK: network available")
except Exception as e:
    print(f"    BLOCKED: {e}")

# --- Phase 4: Attempt to read app config from registry ---
print("[4] Reading application config from registry...")
try:
    import winreg
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\TestApp\Config")
    winreg.CloseKey(key)
    print("    OK: config key found")
except FileNotFoundError:
    print("    NOT FOUND: config key doesn't exist (normal)")
except PermissionError as e:
    print(f"    DENIED: {e}")
except OSError as e:
    print(f"    ERROR: {e}")

# --- Phase 5: Native code path that crashes ---
# Simulate a C library that receives a null path and doesn't handle it.
# This is a realistic bug: native code assumes the path is always valid.

print("[5] Initializing native cache layer...")
print("    db_path =", repr(db_path))

if db_path is None:
    print("    ERROR: No writable path available!")
    print("    BUG: Native code will crash due to unhandled error...")
    sys.stdout.flush()

    # Simulate: native library hits an unrecoverable error because the
    # database path is unavailable.  Calls abort() which produces a
    # genuine native crash that Python cannot intercept.
    os.abort()  # CRASH: C runtime abort
else:
    print("    Cache initialized successfully at:", db_path)
    print("    (No crash — sandbox allowed the path)")
    sys.exit(0)
