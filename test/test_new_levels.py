"""
test_new_levels.py — Verify new access levels: run, stat, touch, create

Tests the simplest cases for each new grant type.
Expects to run inside Sandy sandbox with the test_new_levels TOML config.
"""

import os
import sys
import time
import ctypes

PASS = 0
FAIL = 0

def test(name, condition):
    global PASS, FAIL
    if condition:
        print(f"  [PASS] {name}")
        PASS += 1
    else:
        print(f"  [FAIL] {name}")
        FAIL += 1

ROOT = os.path.join(os.environ["USERPROFILE"], "test_new_levels")

# ---- run_dir tests (execute only, no read) ----
print("\n--- run_dir: execute only ---")
run_dir = os.path.join(ROOT, "run_dir")
run_file = os.path.join(run_dir, "hello.bat")

# Can stat the dir (run includes FILE_READ_ATTRIBUTES)
try:
    os.stat(run_dir)
    test("run: can stat run_dir", True)
except:
    test("run: can stat run_dir", False)

# Cannot read file content (no FILE_GENERIC_READ)
try:
    with open(run_file, "r") as f:
        f.read()
    test("run: cannot read file content", False)
except PermissionError:
    test("run: cannot read file content", True)
except OSError:
    test("run: cannot read file content (OSError)", True)

# Cannot write to file
try:
    with open(run_file, "w") as f:
        f.write("overwrite")
    test("run: cannot write file", False)
except (PermissionError, OSError):
    test("run: cannot write file", True)

# ---- stat_dir tests (read attributes only, non-recursive) ----
print("\n--- stat_dir: attributes only ---")
stat_dir = os.path.join(ROOT, "stat_dir")
stat_file = os.path.join(stat_dir, "file.txt")

# Can stat the directory
try:
    r = os.stat(stat_dir)
    test("stat: can stat directory", r is not None)
except:
    test("stat: can stat directory", False)

# Cannot read file content
try:
    with open(stat_file, "r") as f:
        f.read()
    test("stat: cannot read file content", False)
except (PermissionError, OSError):
    test("stat: cannot read file content", True)

# Cannot list directory contents (no FILE_LIST_DIRECTORY)
try:
    entries = os.listdir(stat_dir)
    test("stat: cannot list directory", False)
except (PermissionError, OSError):
    test("stat: cannot list directory", True)

# Cannot write to file
try:
    with open(stat_file, "w") as f:
        f.write("data")
    test("stat: cannot write file", False)
except (PermissionError, OSError):
    test("stat: cannot write file", True)

# ---- touch_dir tests (modify attributes only, non-recursive) ----
print("\n--- touch_dir: modify attributes only ---")
touch_dir = os.path.join(ROOT, "touch_dir")
touch_file = os.path.join(touch_dir, "file.txt")

# Can stat the directory (touch includes FILE_READ_ATTRIBUTES)
try:
    os.stat(touch_dir)
    test("touch: can stat directory", True)
except:
    test("touch: can stat directory", False)

# Can modify directory timestamps via utime (FILE_WRITE_ATTRIBUTES)
try:
    now = time.time()
    os.utime(touch_dir, (now, now))
    test("touch: can modify directory timestamps", True)
except (PermissionError, OSError):
    test("touch: can modify directory timestamps", False)

# Cannot read file content
try:
    with open(touch_file, "r") as f:
        f.read()
    test("touch: cannot read file content", False)
except (PermissionError, OSError):
    test("touch: cannot read file content", True)

# Cannot write to file
try:
    with open(touch_file, "w") as f:
        f.write("data")
    test("touch: cannot write file", False)
except (PermissionError, OSError):
    test("touch: cannot write file", True)

# ---- create_dir tests (create new files, no overwrite) ----
print("\n--- create_dir: create only ---")
create_dir = os.path.join(ROOT, "create_dir")
existing_file = os.path.join(create_dir, "existing.txt")
new_file = os.path.join(create_dir, "new_file.txt")

# Can create a new file (FILE_ADD_FILE)
try:
    # Use low-level open to create without needing write-data
    fd = os.open(new_file, os.O_CREAT | os.O_WRONLY, 0o644)
    os.close(fd)
    test("create: can create new file", True)
except (PermissionError, OSError) as e:
    test(f"create: can create new file ({e})", False)

# Can create a new subdirectory (FILE_ADD_SUBDIRECTORY)
new_subdir = os.path.join(create_dir, "new_subdir")
try:
    os.mkdir(new_subdir)
    test("create: can create subdirectory", True)
except (PermissionError, OSError) as e:
    test(f"create: can create subdirectory ({e})", False)

# Cannot read existing file content
try:
    with open(existing_file, "r") as f:
        f.read()
    test("create: cannot read existing file", False)
except (PermissionError, OSError):
    test("create: cannot read existing file", True)

# ---- Summary ----
print(f"\n=== Results: {PASS} passed, {FAIL} failed ===")
sys.exit(1 if FAIL > 0 else 0)
