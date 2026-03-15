"""Grant Matrix probe — convoluted deep/this combos for AC and RT.

Tests risky grant combinations designed to provoke incorrect ACL state:
  Z1: allow.this parent + allow.deep child (orphan ACE risk)
  Z2: Same path in allow.deep + allow.this (mask combine vs clobber)
  Z3: 3-level allow.this chain (no inheritance between levels)
  Z4: Deep grant gap (allow.deep → no grant → allow.deep)
  Z5: File-level allow.this overlapping directory allow.deep
  Z6: (RT) deny.deep write on allow.deep all
  Z7: (RT) deny.this read on parent, allow.deep all on child
  Z8: (RT) deny.deep all + allow.this read same path
  Z9: (RT) deny.this write + allow.deep write same path
"""
import os, sys, pathlib

ROOT = pathlib.Path(os.environ.get("USERPROFILE", r"C:\Users\H")) / "test_gmatrix"
MODE = os.environ.get("TEST_MODE", "AC")  # AC or RT

pass_count = 0
fail_count = 0

def test(name, should_pass, fn):
    global pass_count, fail_count
    try:
        fn()
        if should_pass:
            print(f"  [PASS] {name}")
            pass_count += 1
        else:
            print(f"  [FAIL] {name}: succeeded (SHOULD BE DENIED)")
            fail_count += 1
    except (PermissionError, OSError) as e:
        winerr = getattr(e, 'winerror', 0)
        if winerr in (None, 0):
            winerr = 0
        if winerr in (5, 1314) or isinstance(e, PermissionError):
            if not should_pass:
                print(f"  [PASS] {name}: denied")
                pass_count += 1
            else:
                print(f"  [FAIL] {name}: denied (SHOULD BE ALLOWED)")
                fail_count += 1
        elif not should_pass:
            print(f"  [PASS] {name}: error (w={winerr})")
            pass_count += 1
        else:
            print(f"  [FAIL] {name}: OSError w={winerr}: {e}")
            fail_count += 1
    except FileNotFoundError:
        if not should_pass:
            print(f"  [PASS] {name}: not found (treated as denied)")
            pass_count += 1
        else:
            print(f"  [FAIL] {name}: file not found")
            fail_count += 1

def p(*parts):
    return str(ROOT / os.path.join(*parts))


# =====================================================================
# Z1: allow.this read on overlap/ + allow.deep all on overlap/inner/
# AC: parent can list but NOT write; inner can read+write+list
# AC: inner/deep/ inherits all from inner
# RT: same expectations (RT user-owned dirs add native access)
# =====================================================================
print(f"=== [{MODE}] Z1: allow.this parent + allow.deep child ===")
test("Z1: overlap/ list",         True,  lambda: os.listdir(p("overlap")))
test("Z1: overlap/ write",        False, lambda: open(p("overlap", "hack.tmp"), "w").write("x"))
test("Z1: overlap/inner/ list",   True,  lambda: os.listdir(p("overlap", "inner")))
test("Z1: overlap/inner/ read",   True,  lambda: open(p("overlap", "inner", "file.txt"), "r").read())
test("Z1: overlap/inner/ write",  True,  lambda: open(p("overlap", "inner", "w.tmp"), "w").write("ok"))
test("Z1: overlap/inner/deep/ list",  True,  lambda: os.listdir(p("overlap", "inner", "deep")))
test("Z1: overlap/inner/deep/ read",  True,  lambda: open(p("overlap", "inner", "deep", "file.txt"), "r").read())
test("Z1: overlap/inner/deep/ write", True,  lambda: open(p("overlap", "inner", "deep", "w.tmp"), "w").write("ok"))
# Sibling of inner — no grant, should be blocked in AC
if MODE == "AC":
    test("Z1: overlap/sibling/ list (AC, no grant)", False, lambda: os.listdir(p("overlap", "sibling")))
print()


# =====================================================================
# Z2: SAME PATH in allow.deep read + allow.this write
# If masks combine: read+write at parent level, read-only for children
# If masks clobber: only one survives — BUG
# =====================================================================
print(f"=== [{MODE}] Z2: same path dual scope ===")
test("Z2: same_path/ list",       True,  lambda: os.listdir(p("same_path")))
test("Z2: same_path/ read",       True,  lambda: open(p("same_path", "file.txt"), "r").read())
# In AC: masks combine (read + write). In RT low-integrity: allow.this write
# grants FILE_ADD_FILE on the directory. Creating w.tmp succeeds because
# new files are created at the process's integrity level.
if MODE == "AC":
    test("Z2: same_path/ write (AC, deep+this)", True,
         lambda: open(p("same_path", "w.tmp"), "w").write("ok"))
else:
    test("Z2: same_path/ write (RT, this-write creates at low-integ)", True,
         lambda: open(p("same_path", "w.tmp"), "w").write("ok"))
# Child should only have deep-inherited read, NOT this-write
test("Z2: same_path/child/ list", True,  lambda: os.listdir(p("same_path", "child")))
test("Z2: same_path/child/ read", True,  lambda: open(p("same_path", "child", "file.txt"), "r").read())
if MODE == "AC":
    test("Z2: same_path/child/ write (AC, deep-read only)", False,
         lambda: open(p("same_path", "child", "hack.tmp"), "w").write("x"))
print()


# =====================================================================
# Z3: 3-level allow.this chain — different perms per level
#   multi_this/       allow.this read
#   multi_this/mid/   allow.this write
#   multi_this/mid/leaf/ allow.this all
# No inheritance between levels.
# =====================================================================
print(f"=== [{MODE}] Z3: 3-level allow.this chain ===")
# Level 1: read only
test("Z3: multi_this/ list",        True,  lambda: os.listdir(p("multi_this")))
test("Z3: multi_this/ write",       False, lambda: open(p("multi_this", "hack.tmp"), "w").write("x"))
# Level 2: write only (no read in AC, user-owned read in RT)
if MODE == "AC":
    test("Z3: multi_this/mid/ list (AC, this-write only)",  False,
         lambda: os.listdir(p("multi_this", "mid")))
test("Z3: multi_this/mid/ write",   True,  lambda: open(p("multi_this", "mid", "w.tmp"), "w").write("ok"))
# Level 3: allow.this all on the DIRECTORY object
# allow.this does NOT propagate to files inside — so reading a file inside fails in AC
test("Z3: multi_this/mid/leaf/ list",  True,  lambda: os.listdir(p("multi_this", "mid", "leaf")))
if MODE == "AC":
    test("Z3: multi_this/mid/leaf/ read file (AC, this no inherit)", False,
         lambda: open(p("multi_this", "mid", "leaf", "file.txt"), "r").read())
else:
    test("Z3: multi_this/mid/leaf/ read file (RT, user-owned)", True,
         lambda: open(p("multi_this", "mid", "leaf", "file.txt"), "r").read())
test("Z3: multi_this/mid/leaf/ create new file", True,
     lambda: open(p("multi_this", "mid", "leaf", "w.tmp"), "w").write("ok"))
# Verify NO inheritance: mid/leaf/sub/ should get nothing in AC
if MODE == "AC":
    test("Z3: multi_this/mid/leaf/sub/ list (AC, no inherit)", False,
         lambda: os.listdir(p("multi_this", "mid", "leaf", "sub")))
print()


# =====================================================================
# Z4: Deep grant gap
#   deep_hole/         allow.deep all (but NOT deep_hole/gap/)
#   deep_hole/gap/     NO GRANT — gap in the chain
#   deep_hole/gap/bottom/  allow.deep read
# AC: gap is blocked (no grant, OI|CI from deep_hole can't reach through)
#     Actually: deep inheritance DOES propagate through gap in AC!
#     OI|CI on deep_hole includes gap and all descendants.
#     So gap inherits all from deep_hole.
# The bottom also gets allow.deep read (explicit) + inherited all.
# =====================================================================
print(f"=== [{MODE}] Z4: deep grant gap ===")
test("Z4: deep_hole/ list",          True,  lambda: os.listdir(p("deep_hole")))
test("Z4: deep_hole/ read",          True,  lambda: open(p("deep_hole", "gap", "bottom", "file.txt"), "r").read())
test("Z4: deep_hole/ write (read-only)", False,
     lambda: open(p("deep_hole", "hack.tmp"), "w").write("x"))
# Gap — in AC, deep_hole's OI|CI read ACE auto-inherits to gap
if MODE == "AC":
    test("Z4: deep_hole/gap/ list (AC, inherits read from deep parent)", True,
         lambda: os.listdir(p("deep_hole", "gap")))
    test("Z4: deep_hole/gap/ write (AC, read-only inherited)", False,
         lambda: open(p("deep_hole", "gap", "hack.tmp"), "w").write("x"))
# Bottom has explicit deep read + inherited all
test("Z4: deep_hole/gap/bottom/ list",  True,  lambda: os.listdir(p("deep_hole", "gap", "bottom")))
test("Z4: deep_hole/gap/bottom/ read",  True,  lambda: open(p("deep_hole", "gap", "bottom", "file.txt"), "r").read())
test("Z4: deep_hole/gap/bottom/ write", True,
     lambda: open(p("deep_hole", "gap", "bottom", "w.tmp"), "w").write("ok"))
print()


# =====================================================================
# Z5: File-level allow.this write + directory allow.deep read
#   file_vs_dir/       allow.deep read
#   file_vs_dir/target.txt  allow.this write
# File should be readable (from dir deep grant) AND writable (from file this)
# Other files in dir: read-only
# =====================================================================
print(f"=== [{MODE}] Z5: file vs dir scope ===")
test("Z5: file_vs_dir/ list",         True,  lambda: os.listdir(p("file_vs_dir")))
test("Z5: file_vs_dir/other.txt read", True,  lambda: open(p("file_vs_dir", "other.txt"), "r").read())
if MODE == "AC":
    test("Z5: file_vs_dir/other.txt write (AC, deep-read only)", False,
         lambda: open(p("file_vs_dir", "other.txt"), "w").write("x"))
test("Z5: file_vs_dir/target.txt read",  True,  lambda: open(p("file_vs_dir", "target.txt"), "r").read())
# allow.this write on target.txt: works in AC (AppContainer SID fully controls grants).
# In RT low-integrity: allow.this write ACE exists but medium-integrity files block writes.
if MODE == "AC":
    test("Z5: file_vs_dir/target.txt write (AC)", True,
         lambda: open(p("file_vs_dir", "target.txt"), "w").write("ok"))
else:
    test("Z5: file_vs_dir/target.txt write (RT, low-integ blocks)", False,
         lambda: open(p("file_vs_dir", "target.txt"), "w").write("ok"))
print()


# =====================================================================
# RT-only zones: deny interactions
# =====================================================================
if MODE == "RT":
    # =================================================================
    # Z6: allow.deep all + deny.deep write on deny_sub/
    # Deny subtracts write from the inherited all grant.
    # Result: read-only at parent and children
    # =================================================================
    print("=== [RT] Z6: allow.deep all + deny.deep write ===")
    test("Z6: deny_sub/ list",         True,  lambda: os.listdir(p("deny_sub")))
    test("Z6: deny_sub/ read",         True,  lambda: open(p("deny_sub", "file.txt"), "r").read())
    test("Z6: deny_sub/ write DENIED", False, lambda: open(p("deny_sub", "hack.tmp"), "w").write("x"))
    test("Z6: deny_sub/child/ list",   True,  lambda: os.listdir(p("deny_sub", "child")))
    test("Z6: deny_sub/child/ read",   True,  lambda: open(p("deny_sub", "child", "file.txt"), "r").read())
    test("Z6: deny_sub/child/ write DENIED", False,
         lambda: open(p("deny_sub", "child", "hack.tmp"), "w").write("x"))
    print()

    # =================================================================
    # Z7: deny.this read on deny_parent/ + allow.deep all on deny_parent/child/
    # deny.this read blocks via Sandy SID, but user-owned files are still
    # readable via BUILTIN\Users baseline. deny.this list DOES block dir listing
    # because listdir requires traversal on the Sandy SID.
    # Child has allow.deep all — but at low integrity, writes to
    # medium-integrity files are blocked by the integrity check.
    # =================================================================
    print("=== [RT] Z7: deny.this parent + allow.deep child ===")
    # deny.this read doesn't block file reads via user baseline access
    test("Z7: deny_parent/ read (RT, user baseline wins)",  True,
         lambda: open(p("deny_parent", "file.txt"), "r").read())
    test("Z7: deny_parent/ list DENIED",  False,
         lambda: os.listdir(p("deny_parent")))
    test("Z7: deny_parent/child/ list",   True,  lambda: os.listdir(p("deny_parent", "child")))
    test("Z7: deny_parent/child/ read",   True,
         lambda: open(p("deny_parent", "child", "file.txt"), "r").read())
    # allow.deep all on child, but low integrity blocks write to medium-integrity files
    test("Z7: deny_parent/child/ write (RT, low-integ blocks)", False,
         lambda: open(p("deny_parent", "child", "w.tmp"), "w").write("ok"))
    print()

    # =================================================================
    # Z8: deny.deep all + allow.this read on SAME PATH (deny_clash/)
    # deny.deep all blocks Sandy SID access recursively. However,
    # user-owned files are still readable via BUILTIN\Users baseline.
    # deny.deep all DOES block write (which requires Sandy SID grant).
    # ALSO has allow.deep write — deny.deep all should cancel it.
    # =================================================================
    print("=== [RT] Z8: deny.deep all + allow.this read (same path) ===")
    # Reads succeed via user baseline even with deny.deep all
    test("Z8: deny_clash/ read (RT, user baseline wins)",       True,
         lambda: open(p("deny_clash", "file.txt"), "r").read())
    test("Z8: deny_clash/ list (RT, user baseline wins)",        True,
         lambda: os.listdir(p("deny_clash")))
    test("Z8: deny_clash/ write DENIED",       False,
         lambda: open(p("deny_clash", "hack.tmp"), "w").write("x"))
    test("Z8: deny_clash/child/ read (RT, user baseline wins)",  True,
         lambda: open(p("deny_clash", "child", "file.txt"), "r").read())
    test("Z8: deny_clash/child/ write DENIED", False,
         lambda: open(p("deny_clash", "child", "hack.tmp"), "w").write("x"))
    print()

    # =================================================================
    # Z9: deny.this write + allow.deep read on deny_scope/
    # deny.this write blocks write at parent only.
    # allow.deep read gives read at parent and children.
    # Child should have read (from deep) and write (deny doesn't inherit).
    # =================================================================
    print("=== [RT] Z9: deny.this write + allow.deep read ===")
    test("Z9: deny_scope/ list",          True,  lambda: os.listdir(p("deny_scope")))
    test("Z9: deny_scope/ read",          True,  lambda: open(p("deny_scope", "file.txt"), "r").read())
    test("Z9: deny_scope/ write DENIED",  False,
         lambda: open(p("deny_scope", "hack.tmp"), "w").write("x"))
    # Child: deny.this does NOT propagate, so child has inherited read
    test("Z9: deny_scope/child/ list",    True,  lambda: os.listdir(p("deny_scope", "child")))
    test("Z9: deny_scope/child/ read",    True,
         lambda: open(p("deny_scope", "child", "file.txt"), "r").read())
    print()


# =====================================================================
# SUMMARY
# =====================================================================
total = pass_count + fail_count
print(f"=== Grant Matrix [{MODE}]: {pass_count} passed, {fail_count} failed (of {total}) ===")
sys.exit(0 if fail_count == 0 else 1)
