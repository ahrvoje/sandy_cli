"""
test_sandy.py - Comprehensive sandbox permission tests for Sandy.

Run inside the sandbox:
    sandy.exe -c test_sandy_config.toml -x <python.exe> test_sandy.py

Tests cover:
  1. App folder (read-only by default)
  2. System directory reads (allowed by AppContainer)
  3. System directory writes (must be blocked)
  4. User profile access (must be blocked)
  5. Working directory changes
  6. Network access (must be blocked)
  7. Permission-specific folders:
     - %USERPROFILE%\test_R   -> [read]      read ok, write blocked
     - %USERPROFILE%\test_W   -> [write]     write ok, read blocked
     - %USERPROFILE%\test_RW  -> [readwrite] both ok
"""

import os
import sys

print("=== Sandy Sandbox Tests ===")
print(f"Working dir: {os.getcwd()}")
print(f"Python:      {sys.executable}")
print()

passed = failed = 0


def expect_ok(label, fn):
    global passed, failed
    try:
        result = fn()
        print(f"  [PASS] {label}: {result}")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] {label}: {e}")
        failed += 1


def expect_blocked(label, fn):
    global passed, failed
    try:
        fn()
        print(f"  [FAIL] {label}: should have been blocked!")
        failed += 1
    except Exception as e:
        print(f"  [PASS] {label}: blocked -> {type(e).__name__}")
        passed += 1


# ---------------------------------------------------------------------------
# 1. APP FOLDER (read-only by default)
# ---------------------------------------------------------------------------
print("--- App folder (read-only) ---")
expect_ok("List app folder",
    lambda: f"{len(os.listdir('.'))} items")
expect_blocked("Create file in app folder",
    lambda: open("test.txt", "w").write("hello"))
expect_blocked("Create subfolder in app folder",
    lambda: os.makedirs("test_sub"))
print()

# ---------------------------------------------------------------------------
# 2. READING SYSTEM DIRS (AppContainer generally allows reading these)
# ---------------------------------------------------------------------------
print("--- System dir reads (allowed by AppContainer) ---")
expect_ok("Read C:\\Windows",
    lambda: f"{len(os.listdir('C:/Windows'))} items")
expect_ok("Read Program Files",
    lambda: f"{len(os.listdir('C:/Program Files'))} items")
expect_ok("Read C:\\Windows\\System32",
    lambda: f"{len(os.listdir('C:/Windows/System32'))} items")
print()

# ---------------------------------------------------------------------------
# 3. WRITING TO SYSTEM DIRS (must be blocked)
# ---------------------------------------------------------------------------
print("--- System dir writes (must be blocked) ---")
expect_blocked("Write to C:\\Windows",
    lambda: open("C:/Windows/hack.txt", "w").write("x"))
expect_blocked("Write to C:\\",
    lambda: open("C:/hack.txt", "w").write("x"))
expect_blocked("Write to System32",
    lambda: open("C:/Windows/System32/hack.txt", "w").write("x"))
expect_blocked("Write to Program Files",
    lambda: open("C:/Program Files/hack.txt", "w").write("x"))
expect_blocked("Create dir in C:\\",
    lambda: os.mkdir("C:/sandy_escape"))
print()

# ---------------------------------------------------------------------------
# 4. USER PROFILE ACCESS (blocked)
# ---------------------------------------------------------------------------
print("--- User profile (blocked) ---")
user = os.environ.get("USERPROFILE", "C:/Users/unknown")
expect_blocked("Read user Desktop",
    lambda: os.listdir(f"{user}/Desktop"))
expect_blocked("Read user Documents",
    lambda: os.listdir(f"{user}/Documents"))
expect_blocked("Write to user home",
    lambda: open(f"{user}/hack.txt", "w").write("x"))
print()

# ---------------------------------------------------------------------------
# 5. WORKING DIRECTORY CHANGES
# ---------------------------------------------------------------------------
print("--- Working directory ---")
cwd = os.getcwd()
expect_blocked("Write file after chdir to C:\\Windows",
    lambda: (os.chdir("C:/Windows"), open("hack.txt", "w").write("x")))
os.chdir(cwd)
print()

# ---------------------------------------------------------------------------
# 6. NETWORK ACCESS (blocked by AppContainer)
# ---------------------------------------------------------------------------
print("--- Network access (blocked) ---")
try:
    import urllib.request
    expect_blocked("HTTP request",
        lambda: urllib.request.urlopen("http://example.com", timeout=3).read())
except ImportError:
    print("  [SKIP] urllib not available in embedded Python")
print()

# ---------------------------------------------------------------------------
# 7. PERMISSION-SPECIFIC FOLDER TESTS
#    These folders must be configured in the TOML config:
#      [read]
#      "%USERPROFILE%\test_R"
#
#      [write]
#      "%USERPROFILE%\test_W"
#
#      [readwrite]
#      "%USERPROFILE%\test_RW"
# ---------------------------------------------------------------------------
print("--- Permission folder tests ---")

test_R  = os.path.join(user, "test_R")
test_W  = os.path.join(user, "test_W")
test_RW = os.path.join(user, "test_RW")

# Verify readable test folders exist (can't check test_W — it's write-only)
for folder in [test_R, test_RW]:
    if not os.path.isdir(folder):
        print(f"  [SKIP] Folder missing: {folder} (create it before testing)")
        print()
        break
else:
    # -- Read-only folder --
    print("--- [Read-only] ---")
    print(f"  test_R = {test_R}")
    seed_file = os.path.join(test_R, "seed.txt")
    expect_ok("test_R: list dir",
        lambda: f"{len(os.listdir(test_R))} items")
    if os.path.isfile(seed_file):
        expect_ok("test_R: read seed.txt",
            lambda: open(seed_file).read())
    else:
        print(f"  [SKIP] test_R: no seed.txt to read (create one before testing)")
    expect_blocked("test_R: create file (should fail)",
        lambda: open(os.path.join(test_R, "hack.txt"), "w").write("x"))
    expect_blocked("test_R: delete seed.txt (should fail)",
        lambda: os.remove(seed_file))
    print()

    # -- Write-only folder --
    print("--- [Write-only] ---")
    print(f"  test_W = {test_W}")
    expect_ok("test_W: create file",
        lambda: open(os.path.join(test_W, "written.txt"), "w").write("hello") or "written")
    expect_blocked("test_W: list dir (should fail)",
        lambda: os.listdir(test_W))
    expect_blocked("test_W: read file (should fail)",
        lambda: open(os.path.join(test_W, "written.txt")).read())
    print()

    # -- Read & Write folder --
    print("--- [Read & Write] ---")
    print(f"  test_RW = {test_RW}")
    expect_ok("test_RW: create file",
        lambda: open(os.path.join(test_RW, "rw_test.txt"), "w").write("hello") or "written")
    expect_ok("test_RW: read file",
        lambda: open(os.path.join(test_RW, "rw_test.txt")).read())
    expect_ok("test_RW: list dir",
        lambda: f"{len(os.listdir(test_RW))} items")
    expect_ok("test_RW: delete file",
        lambda: os.remove(os.path.join(test_RW, "rw_test.txt")) or "deleted")
    print()

# ---------------------------------------------------------------------------
# 8. FILE-LEVEL ACCESS TESTS
#    Individual files (not folders) can also be granted specific permissions.
#    test_file_R.txt  -> read only
#    test_file_W.txt  -> write only
#    test_file_RW.txt -> read + write
# ---------------------------------------------------------------------------
print("--- File-level access tests ---")

file_R = os.path.join(user, "test_file_R.txt")
file_W = os.path.join(user, "test_file_W.txt")
file_RW = os.path.join(user, "test_file_RW.txt")
file_none = os.path.join(user, "test_file_NONE.txt")

# -- Read-only file --
print(f"  file_R = {file_R}")
expect_ok("file_R: read content",
    lambda: open(file_R).read().strip())
expect_blocked("file_R: write (should fail)",
    lambda: open(file_R, "w").write("x"))

# -- Write-only file --
print(f"  file_W = {file_W}")
expect_ok("file_W: write content",
    lambda: open(file_W, "w").write("hello") or "written")
expect_blocked("file_W: read (should fail)",
    lambda: open(file_W).read())

# -- Read+Write file --
print(f"  file_RW = {file_RW}")
expect_ok("file_RW: write content",
    lambda: open(file_RW, "w").write("hello") or "written")
expect_ok("file_RW: read content",
    lambda: open(file_RW).read())

# -- File not in config (no access) --
expect_blocked("file_NONE: read (should fail)",
    lambda: open(file_none).read())
expect_blocked("file_NONE: write (should fail)",
    lambda: open(file_none, "w").write("x"))
print()

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
print(f"=== Results: {passed} passed, {failed} failed ===")
sys.exit(1 if failed > 0 else 0)
