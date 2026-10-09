"""
test_new_levels.py — Verify access levels: run, stat, touch, create

Tests the simplest cases for each grant type, and in Restricted Token
mode the deny rule of each level.
Expects to run inside Sandy sandbox with the test_new_levels TOML config.
TEST_MODE = AC | RT selects the mode-specific part (set by the .bat).
"""

import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes

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

def denied(fn):
    """True only when fn fails with an access error (not with any other error)."""
    try:
        fn()
        return False
    except PermissionError:
        return True
    except OSError as e:
        return e.winerror == 5

def works(fn):
    try:
        fn()
        return True
    except OSError as e:
        print(f"         ({e})")
        return False

def raw_overwrite(path):
    """Open an EXISTING file with FILE_WRITE_DATA only, as a hostile program would."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    h = k32.CreateFileW(path, 0x0002, 7, None, 3, 0, None)   # FILE_WRITE_DATA, OPEN_EXISTING
    if h in (None, wintypes.HANDLE(-1).value):
        raise ctypes.WinError(ctypes.get_last_error())
    k32.CloseHandle(wintypes.HANDLE(h))

MODE = os.environ.get("TEST_MODE", "AC")
ROOT = os.path.join(os.environ["USERPROFILE"], "test_new_levels")
TAG = f"{MODE}_{os.getpid()}"   # both modes run on the same tree: keep created names apart

# ---- run_dir tests (execute only, no read) ----
print("\n--- run_dir: execute only ---")
run_dir = os.path.join(ROOT, "run_dir")
run_file = os.path.join(run_dir, "hello.bat")

# Can stat the dir (run includes FILE_READ_ATTRIBUTES)
test("run: can stat run_dir", works(lambda: os.stat(run_dir)))
# Cannot read file content (no FILE_GENERIC_READ)
test("run: cannot read file content", denied(lambda: open(run_file, "r").read()))
test("run: cannot write file", denied(lambda: open(run_file, "w").write("overwrite")))

# ---- stat_dir tests (read attributes only) ----
print("\n--- stat_dir: attributes only ---")
stat_dir = os.path.join(ROOT, "stat_dir")
stat_file = os.path.join(stat_dir, "file.txt")

test("stat: can stat directory", works(lambda: os.stat(stat_dir)))
test("stat: cannot read file content", denied(lambda: open(stat_file, "r").read()))
# Cannot list directory contents (no FILE_LIST_DIRECTORY)
test("stat: cannot list directory", denied(lambda: os.listdir(stat_dir)))
test("stat: cannot write file", denied(lambda: open(stat_file, "w").write("data")))

# ---- touch_dir tests (modify attributes only) ----
print("\n--- touch_dir: modify attributes only ---")
touch_dir = os.path.join(ROOT, "touch_dir")
touch_file = os.path.join(touch_dir, "file.txt")

# Can stat the directory (touch includes FILE_READ_ATTRIBUTES)
test("touch: can stat directory", works(lambda: os.stat(touch_dir)))
# Can modify directory timestamps via utime (FILE_WRITE_ATTRIBUTES)
now = time.time()
test("touch: can modify directory timestamps", works(lambda: os.utime(touch_dir, (now, now))))
test("touch: cannot read file content", denied(lambda: open(touch_file, "r").read()))
test("touch: cannot write file", denied(lambda: open(touch_file, "w").write("data")))

# ---- create_dir tests (create new files, no overwrite) ----
print("\n--- create_dir: create only ---")
create_dir = os.path.join(ROOT, "create_dir")
existing_file = os.path.join(create_dir, "existing.txt")

# Can create a new file (FILE_ADD_FILE)
# Use low-level open to create without needing write-data
test("create: can create new file",
     works(lambda: os.close(os.open(os.path.join(create_dir, f"new_file_{TAG}.txt"),
                                    os.O_CREAT | os.O_WRONLY, 0o644))))
# Can create a new subdirectory (FILE_ADD_SUBDIRECTORY)
test("create: can create subdirectory",
     works(lambda: os.mkdir(os.path.join(create_dir, f"new_subdir_{TAG}"))))
test("create: cannot read existing file", denied(lambda: open(existing_file, "r").read()))
# FILE_ADD_FILE has the bit value of FILE_WRITE_DATA: the rule must not reach files
test("create: cannot overwrite existing file (raw FILE_WRITE_DATA open)",
     denied(lambda: raw_overwrite(existing_file)))

# ---- deny rules, one per level (Restricted Token only) ----
if MODE == "RT":
    base = os.path.join(ROOT, "denied")       # [allow.deep] all

    print("\n--- denied/no_run: deny.run blocks execution only ---")
    test("no_run: control — the same program runs from denied/",
         works(lambda: subprocess.run([os.path.join(base, "tool.exe")], capture_output=True, timeout=20)))
    test("no_run: cannot run the program",
         denied(lambda: subprocess.run([os.path.join(base, "no_run", "tool.exe")], capture_output=True, timeout=20)))
    test("no_run: can still read a file",
         works(lambda: open(os.path.join(base, "no_run", "blocked.bat"), "r").read()))

    print("\n--- denied/no_touch: deny.touch blocks attribute changes only ---")
    f = os.path.join(base, "no_touch", "file.txt")
    test("no_touch: cannot modify timestamps", denied(lambda: os.utime(f, (now, now))))
    test("no_touch: can still read the file", works(lambda: open(f, "r").read()))

    print("\n--- denied/no_create: deny.create blocks new files and folders only ---")
    d = os.path.join(base, "no_create")
    test("no_create: cannot create a file", denied(lambda: open(os.path.join(d, "new.txt"), "w").write("x")))
    test("no_create: cannot create a folder", denied(lambda: os.mkdir(os.path.join(d, "sub"))))
    test("no_create: can still read the existing file",
         works(lambda: open(os.path.join(d, "existing.txt"), "r").read()))
    test("no_create: can still overwrite the existing file",
         works(lambda: open(os.path.join(d, "existing.txt"), "r+").write("changed")))

    # deny.stat: Windows also gives FILE_READ_ATTRIBUTES through the list
    # right of the parent folder, so the rule cannot hide attributes here.
    # It must not block anything else.
    print("\n--- denied/no_stat: deny.stat blocks nothing else ---")
    test("no_stat: can still read the file",
         works(lambda: open(os.path.join(base, "no_stat", "file.txt"), "r").read()))

# ---- Summary ----
print(f"\n=== Results [{MODE}]: {PASS} passed, {FAIL} failed ===")
sys.exit(1 if FAIL > 0 else 0)
