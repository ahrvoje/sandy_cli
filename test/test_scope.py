import os, sys, pathlib

ROOT = pathlib.Path(os.environ.get("TEST_ROOT", os.path.expanduser("~\\test_scope")))
MODE = os.environ.get("TEST_MODE", "AC")  # AC or RT

pass_count = 0
fail_count = 0

def test(name, condition, detail=""):
    global pass_count, fail_count
    if condition:
        print(f"  [PASS] {name}")
        pass_count += 1
    else:
        msg = f"  [FAIL] {name}"
        if detail:
            msg += f" -- {detail}"
        print(msg)
        fail_count += 1

def can_read(path):
    try:
        with open(path, "r") as f: f.read()
        return True
    except: return False

def can_write(path):
    try:
        with open(path, "w") as f: f.write("test")
        return True
    except: return False

def can_listdir(path):
    try:
        os.listdir(path)
        return True
    except: return False

# =====================================================================
# ALLOW.DEEP tests — grants should propagate to children
# =====================================================================
print(f"=== [{MODE}] ALLOW.DEEP: multilevel propagation ===")

deep_root = ROOT / "deep"
deep_child = ROOT / "deep" / "child"

# Deep all — read + write at both levels
test("allow.deep all: parent read",  can_read(deep_root / "file.txt"))
test("allow.deep all: child read",   can_read(deep_child / "file.txt"))
test("allow.deep all: parent write", can_write(deep_root / "write_test.txt"))
test("allow.deep all: child write",  can_write(deep_child / "write_test.txt"))

# Deep all via separate dir
all_root = ROOT / "deep_all"
all_child = ROOT / "deep_all" / "child"
test("allow.deep all2: parent read",  can_read(all_root / "file.txt"))
test("allow.deep all2: child read",   can_read(all_child / "file.txt"))
test("allow.deep all2: parent write", can_write(all_root / "w.txt"))
test("allow.deep all2: child write",  can_write(all_child / "w.txt"))

print()

# =====================================================================
# ALLOW.THIS tests — grants should NOT propagate to children
#
# Windows semantics: "this" scope (no OI|CI) on a directory means:
#   - The ACE applies to the directory OBJECT only
#   - listdir works (directory itself)
#   - write to files in the dir works (FILE_ADD_FILE on the dir)
#   - Files INSIDE do not inherit the ACE
#
# In AC mode (zero baseline), child dir is fully blocked.
# In RT mode, BUILTIN\Users gives read access so child reads work
# regardless. We only test write non-propagation in RT.
# =====================================================================
print(f"=== [{MODE}] ALLOW.THIS: non-recursive (single object) ===")

this_root = ROOT / "this"
this_child = ROOT / "this" / "child"

# This all — parent dir operations should work
test("allow.this all: parent write",   can_write(this_root / "write_test.txt"))
test("allow.this all: parent listdir", can_listdir(this_root))

# This all — child should NOT inherit
test("allow.this all: child write DENIED",   not can_write(this_child / "write_test.txt"),
     "child should NOT inherit this-scope grant")

if MODE == "AC":
    # AC starts from zero — no baseline access, so child is fully blocked
    test("allow.this all: child read DENIED (AC)",    not can_read(this_child / "file.txt"),
         "AC child should NOT inherit this-scope grant")
    test("allow.this all: child listdir DENIED (AC)", not can_listdir(this_child),
         "AC child should NOT inherit this-scope grant")

print()

# =====================================================================
# RT-only: DENY.DEEP and DENY.THIS tests
#
# deny.deep 'all' on a path: real DENY_ACCESS ACE with OI|CI.
# Blocks read+write at parent AND all children.
# Even BUILTIN\Users read is overridden because kernel evaluates
# deny-before-allow for the RT SID.
#
# deny.this 'all' on a path: DENY_ACCESS with no inheritance.
# Blocks at the directory object only. Children keep their
# inherited or baseline access.
# =====================================================================
if MODE == "RT":
    print("=== [RT] DENY.DEEP: multilevel deny ===")

    dd_root = ROOT / "deny_deep"
    dd_child = ROOT / "deny_deep" / "child"

    # deny.deep all — should block write at parent AND child
    test("deny.deep all: parent write DENIED", not can_write(dd_root / "blocked.txt"),
         "deny.deep should block parent write")
    test("deny.deep all: child write DENIED",  not can_write(dd_child / "blocked.txt"),
         "deny.deep should block child write")
    # deny.deep all — should block read at parent AND child
    test("deny.deep all: parent read DENIED",  not can_read(dd_root / "file.txt"),
         "deny.deep should block parent read")
    test("deny.deep all: child read DENIED",   not can_read(dd_child / "file.txt"),
         "deny.deep should block child read")

    print()
    print("=== [RT] DENY.THIS: single-object deny ===")

    dt_root = ROOT / "deny_this"
    dt_child = ROOT / "deny_this" / "child"

    # deny.this all — should block write at parent
    test("deny.this all: parent write DENIED", not can_write(dt_root / "blocked.txt"),
         "deny.this should block parent write")
    # deny.this should NOT propagate to child — child reads and writes should work
    # via BUILTIN\Users baseline (reads) and owner access (writes)
    test("deny.this all: child read ALLOWED",  can_read(dt_child / "file.txt"),
         "deny.this should NOT propagate to child")

    print()

# =====================================================================
# Summary
# =====================================================================
total = pass_count + fail_count
print(f"Results: {pass_count}/{total} passed, {fail_count} failed")
sys.exit(0 if fail_count == 0 else 1)
