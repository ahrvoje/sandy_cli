"""Test grant scope enforcement after profile registry round-trip.

Tries to create files inside deep-granted and this-granted directories
plus their children.  Prints machine-readable PASS/FAIL lines for the
calling batch script to verify.

IMPORTANT: Uses only write (create file + write data).  Does NOT call
os.remove() because the 'write' grant does not include DELETE permission.
Probe files are left behind for the batch script to clean up.

Expected results:
  deep_dir       -> WRITE OK   (deep grant covers this object)
  deep_dir/sub   -> WRITE OK   (deep grant inherits to children)
  this_dir       -> WRITE OK   (this grant covers this object)
  this_dir/sub   -> WRITE FAIL (this grant does NOT inherit)
"""
import os, sys

root = sys.argv[1]  # e.g. C:\Users\H\test_sandy_profile\scope

tests = [
    ("deep_dir",                       True),
    (os.path.join("deep_dir", "sub"),  True),
    ("this_dir",                       True),
    (os.path.join("this_dir", "sub"),  False),
]

for relpath, expect_ok in tests:
    target = os.path.join(root, relpath, "probe.txt")
    try:
        with open(target, "w") as f:
            f.write("probe")
        # Do NOT os.remove — 'write' grant lacks DELETE permission
        ok = True
    except PermissionError:
        ok = False
    except OSError:
        ok = False

    tag = "PASS" if (ok == expect_ok) else "FAIL"
    detail = "write_ok" if ok else "write_denied"
    print(f"SCOPE_{tag}: {relpath} -> {detail} (expected {'ok' if expect_ok else 'denied'})")
