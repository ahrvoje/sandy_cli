"""
test_sandy.py - Comprehensive sandbox permission tests for Sandy.

Run inside the sandbox via test_sandy.bat which creates:
  %USERPROFILE%\test_sandy\
    scripts/      [read]  — this script
    R/            [read]  — read-only folder with seed.txt
    W/            [write] — write-only folder
    RW/           [all]   — read+write folder
    file_R.txt    [read]  — read-only file
    file_W.txt    [write] — write-only file
    file_RW.txt   [all]   — read+write file
"""

import os
import sys

ROOT = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\unknown"), "test_sandy")

print("=== Sandy Sandbox Tests ===")
print(f"Working dir: {os.getcwd()}")
print(f"Python:      {sys.executable}")
print(f"Test root:   {ROOT}")
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
# 1. APP FOLDER (no implicit grant — blocked since auto-grant was removed)
# ---------------------------------------------------------------------------
print("--- App folder (read-only) ---")
expect_blocked("List app folder",
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
try:
    os.chdir(cwd)
except OSError:
    pass  # workdir may be read-only (no traverse)
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
# ---------------------------------------------------------------------------
print("--- Permission folder tests ---")

test_R  = os.path.join(ROOT, "R")
test_W  = os.path.join(ROOT, "W")
test_RW = os.path.join(ROOT, "RW")

# -- Read-only folder --
print("--- [Read-only] ---")
print(f"  test_R = {test_R}")
seed_file = os.path.join(test_R, "seed.txt")
expect_ok("test_R: list dir",
    lambda: f"{len(os.listdir(test_R))} items")
expect_ok("test_R: read seed.txt",
    lambda: open(seed_file).read().strip())
expect_blocked("test_R: create file (should fail)",
    lambda: open(os.path.join(test_R, "hack.txt"), "w").write("x"))
expect_blocked("test_R: delete seed.txt (should fail)",
    lambda: os.remove(seed_file))
print()

# -- Write-only folder --
print("--- [Write-only] ---")
print(f"  test_W = {test_W}")
expect_ok("test_W: create file",
    lambda: open(os.path.join(test_W, "written.txt"), "w").write("hello"))
expect_blocked("test_W: list dir (should fail)",
    lambda: os.listdir(test_W))
expect_blocked("test_W: read file (should fail)",
    lambda: open(os.path.join(test_W, "written.txt")).read())
print()

# -- Read & Write folder --
print("--- [Read & Write] ---")
print(f"  test_RW = {test_RW}")
expect_ok("test_RW: create file",
    lambda: open(os.path.join(test_RW, "rw_test.txt"), "w").write("hello"))
expect_ok("test_RW: read file",
    lambda: open(os.path.join(test_RW, "rw_test.txt")).read())
expect_ok("test_RW: list dir",
    lambda: f"{len(os.listdir(test_RW))} items")
expect_ok("test_RW: delete file",
    lambda: os.remove(os.path.join(test_RW, "rw_test.txt")) or "deleted")
print()

# ---------------------------------------------------------------------------
# 8. FILE-LEVEL ACCESS TESTS
# ---------------------------------------------------------------------------
print("--- File-level access tests ---")

file_R = os.path.join(ROOT, "file_R.txt")
file_W = os.path.join(ROOT, "file_W.txt")
file_RW = os.path.join(ROOT, "file_RW.txt")
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
    lambda: open(file_W, "w").write("hello"))
expect_blocked("file_W: read (should fail)",
    lambda: open(file_W).read())

# -- Read+Write file --
print(f"  file_RW = {file_RW}")
expect_ok("file_RW: write content",
    lambda: open(file_RW, "w").write("hello"))
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
