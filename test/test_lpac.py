"""
test_lpac.py — LPAC (Less Privileged AppContainer) isolation tests.

Run inside the sandbox:
    sandy.exe -c test_lpac_config.toml -x <python.exe> test_lpac.py

Tests verify the core LPAC invariant: the process is NOT a member of
ALL APPLICATION PACKAGES (App. Packages). System32 is explicitly granted
(execute only — required for DLL loading), but everything else that
normally relies on App. Packages access is blocked.

Test matrix:
  SHOULD BE BLOCKED:
    1. Read arbitrary System32 file content     (execute-only grant, no read)
    2. Write to System32                        (execute-only grant, no write)
    3. List C:\Program Files                    (App. Packages only, not granted)
    4. List C:\Windows\Temp                     (always blocked)
    5. Read user profile (Desktop)              (no grant)
    6. Outbound network (network = false)
    7. Write to explicitly read-only granted folder
    8. Read folder with no grant (sibling of workspace)

  SHOULD SUCCEED:
    9. Read explicitly granted scripts folder
   10. Execute Python itself (execute grant on Python dir)
   11. Write to workspace (all grant)
   12. Create file in workspace
   13. Delete file in workspace
   14. Stat test root dir ([allow.this] stat grant)
   15. List workspace subdirectory
   16. Import standard library (DLLs from System32 via execute grant)

  LPAC-SPECIFIC:
   17. Registry isolation (AppContainer private hive)
"""

import os
import sys

print("=== LPAC Token Isolation Tests ===")
print(f"Token:  LPAC (Restricted App. Packages)")
print(f"PID:    {os.getpid()}")
print(f"Python: {sys.executable}")
print(f"CWD:    {os.getcwd()}")
print()

passed = failed = skipped = 0


def expect_blocked(label, fn):
    """Expect fn() to raise PermissionError or OSError."""
    global passed, failed
    try:
        result = fn()
        print(f"  [FAIL] {label}: succeeded (got {result!r}) — should be blocked!")
        failed += 1
    except (PermissionError, OSError) as e:
        err = e.args[0] if e.args else ''
        print(f"  [PASS] {label}: blocked -> {type(e).__name__}: {err}")
        passed += 1
    except Exception as e:
        print(f"  [PASS] {label}: blocked -> {type(e).__name__}")
        passed += 1


def expect_ok(label, fn):
    """Expect fn() to succeed."""
    global passed, failed
    try:
        result = fn()
        print(f"  [PASS] {label}: {result}")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] {label}: {type(e).__name__}: {e}")
        failed += 1


ROOT = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\H"), "test_lpac")
WORKSPACE = os.path.join(ROOT, "workspace")
SCRIPTS = os.path.join(ROOT, "scripts")


# ===================================================================
#  PART 1: SHOULD BE BLOCKED
# ===================================================================
print("--- PART 1: Access that LPAC should block ---")
print()

# 1. Read System32 file content — we have execute-only, not read
print("  [1] System32 file read (execute-only grant, no read)")
expect_blocked("Read kernel32.dll content",
    lambda: (open(r"C:\Windows\System32\kernel32.dll", "rb").read(16), "read OK")[1])

# 2. Write to System32 — execute-only grant, no write
print("  [2] Write to System32 (execute-only grant)")
expect_blocked("Write to System32",
    lambda: (open(r"C:\Windows\System32\lpac_probe.txt", "w").write("probe"), "wrote")[1])

# 3. List Program Files — App. Packages only, not explicitly granted
print("  [3] Program Files listing (App. Packages only, not granted)")
expect_blocked("List C:\\Program Files",
    lambda: f"listed {len(os.listdir(r'C:\Program Files'))} entries")

# 4. Windows\Temp — always blocked
print("  [4] Windows\\Temp (always blocked)")
expect_blocked("List C:\\Windows\\Temp",
    lambda: f"listed {len(os.listdir(r'C:\Windows\Temp'))} entries")

# 5. User profile — no grant
print("  [5] User profile (no grant)")
desktop = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\H"), "Desktop")
expect_blocked("List user Desktop",
    lambda: f"listed {len(os.listdir(desktop))} entries")

# 6. Network — explicitly disabled
print("  [6] Outbound network (network = false)")
try:
    import urllib.request
    expect_blocked("HTTP GET example.com",
        lambda: f"HTTP {urllib.request.urlopen('http://example.com', timeout=5).getcode()}")
except ImportError:
    print("  [SKIP] urllib not available")
    skipped += 1

# 7. Write to read-only granted folder (scripts has read only)
print("  [7] Write to read-only folder (scripts/)")
expect_blocked("Write scripts/probe.txt",
    lambda: (open(os.path.join(SCRIPTS, "probe.txt"), "w").write("probe"), "wrote")[1])

# 8. Read sibling folder with no grant
print("  [8] Read un-granted sibling folder")
no_grant_dir = os.path.join(ROOT, "no_grant_zone")
expect_blocked("List no_grant_zone/",
    lambda: f"listed {len(os.listdir(no_grant_dir))} entries")

print()

# ===================================================================
#  PART 2: SHOULD SUCCEED (explicit grants)
# ===================================================================
print("--- PART 2: Access via explicit grants ---")
print()

# 9. Read scripts folder (explicit read grant)
print("  [9] Read granted scripts folder")
expect_ok("List scripts/",
    lambda: f"listed {len(os.listdir(SCRIPTS))} entries")

# 10. Execute Python (execute grant on Python dir)
print("  [10] Execute Python (execute grant)")
expect_ok("Import sys module",
    lambda: f"sys.version = {sys.version.split()[0]}")

# 11. Write to workspace (all grant)
print("  [11] Write to workspace (all grant)")
probe_file = os.path.join(WORKSPACE, "lpac_probe.txt")
expect_ok("Write workspace/lpac_probe.txt",
    lambda: (open(probe_file, "w").write("lpac writes work"), f"wrote {os.path.getsize(probe_file)} bytes")[1])

# 12. Create new file in workspace
print("  [12] Create file in workspace")
expect_ok("Create workspace/new_file.txt",
    lambda: (open(os.path.join(WORKSPACE, "new_file.txt"), "w").write("new"), "created")[1])

# 13. Delete file in workspace
print("  [13] Delete file in workspace")
delete_target = os.path.join(WORKSPACE, "to_delete.txt")
with open(delete_target, "w") as f:
    f.write("delete me")
expect_ok("Delete workspace/to_delete.txt",
    lambda: (os.remove(delete_target), "deleted")[1])

# 14. Stat test root dir (allow.this stat grant)
print("  [14] Stat root dir (allow.this stat)")
expect_ok("Stat test_lpac/",
    lambda: f"isdir={os.path.isdir(ROOT)}")

# 15. List workspace subdirectory
print("  [15] List workspace subdir")
subdir = os.path.join(WORKSPACE, "subdir")
os.makedirs(subdir, exist_ok=True)
expect_ok("List workspace/subdir/",
    lambda: f"listed {len(os.listdir(subdir))} entries")

# 16. Standard library imports (DLLs load from System32 via execute grant)
print("  [16] Standard library imports (DLL loading)")
expect_ok("Import json + hashlib",
    lambda: (__import__('json'), __import__('hashlib'), "imports OK")[2])

print()

# ===================================================================
#  PART 3: LPAC-SPECIFIC INVARIANTS
# ===================================================================
print("--- PART 3: LPAC-specific invariants ---")
print()

# 17. Registry — AppContainer uses private hive; HKCU access should be blocked
print("  [17] Registry isolation")
try:
    import winreg
    expect_blocked("Read HKCU\\Software\\Microsoft",
        lambda: (winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft"), "opened")[1])
except ImportError:
    print("  [SKIP] winreg not available")
    skipped += 1

print()

# ===================================================================
# SUMMARY
# ===================================================================
total = passed + failed
print(f"=== Results: {passed} passed, {failed} failed, {skipped} skipped (of {total + skipped}) ===")

if failed > 0:
    print("LPAC TESTS FAILED — isolation breach detected!")
    sys.exit(1)
else:
    print("All LPAC isolation tests passed.")
    sys.exit(0)
