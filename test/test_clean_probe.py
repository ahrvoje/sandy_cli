"""
test_clean_probe.py — Sandboxed runaway-deletion probe.

Runs inside an AppContainer with:
  - read-only access to the arena root (can list, cannot delete)
  - full (all) access to arena/sub1 and arena/sub2 (can delete recursively)

Simulates a script that accidentally calls shutil.rmtree on the entire tree,
including the protected root. Verifies that children are deleted but the root
survives due to Sandy's kernel-enforced ACL containment.

Usage: python test_clean_probe.py <arena_root>

Exit 0  = root survived AND children gone (expected clean result)
Exit 1  = unexpected result (root deleted, or children survived)
"""

import sys
import shutil
import pathlib

if len(sys.argv) < 2:
    print("PROBE_ERROR: missing arena path argument")
    sys.exit(2)

root = pathlib.Path(sys.argv[1])

if not root.exists():
    print("PROBE_ERROR: arena root does not exist: " + str(root))
    sys.exit(2)

# ── Collect items before deletion ───────────────────────────────────────
before = sorted(str(p) for p in root.rglob("*"))
print("BEFORE:" + str(len(before)) + " items under arena")

# ── Attempt full recursive delete (the "accidental" call) ───────────────
blocked = []

def on_error(func, path, exc_info):
    blocked.append(str(path))
    # Do NOT raise — let shutil continue past errors

shutil.rmtree(str(root), onerror=on_error)

# ── Verify outcome ───────────────────────────────────────────────────────
root_exists  = root.exists()
sub1_exists  = (root / "sub1").exists()
sub2_exists  = (root / "sub2").exists()
# Exclude the probe script itself from the after-count: it lives in the
# protected root (read grant, no delete) so its survival is expected.
this_script  = root / "test_clean_probe.py"
after        = [p for p in root.rglob("*") if p != this_script] if root_exists else []

print("ROOT_EXISTS:"  + str(int(root_exists)))
print("SUB1_EXISTS:"  + str(int(sub1_exists)))
print("SUB2_EXISTS:"  + str(int(sub2_exists)))
print("AFTER_COUNT:"  + str(len(after)))
print("BLOCKED_COUNT:" + str(len(blocked)))
for b in blocked:
    print("  BLOCKED: " + b)

# ── Exit code decision ───────────────────────────────────────────────────
ok = root_exists and not sub1_exists and not sub2_exists and len(after) == 0
sys.exit(0 if ok else 1)
