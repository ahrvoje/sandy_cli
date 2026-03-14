"""Expert adversarial test suite — targets Sandy's IMPLEMENTATION assumptions.

Categories:
  A. Grant pipeline & deny math (SDDL poisoning, double-grant, overflow, stacking)
  B. Containment boundary (auto-grant pivot, CWD escape, env injection)
  C. Cleanup pipeline (runtime file orphans, deep nested deny barrier)

Run inside AppContainer via test_expert.bat.
"""
import os, sys, ctypes, ctypes.wintypes

ROOT = os.path.join(os.environ.get('USERPROFILE', r'C:\Users\H'), 'test_expert')
ARENA = os.path.join(ROOT, 'arena')
results = []

def test(name, should_pass, fn):
    try:
        result = fn()
        if should_pass:
            print(f"  [PASS] {name}")
            results.append(('PASS', name))
        else:
            print(f"  [FAIL] {name}: succeeded (SHOULD BE BLOCKED)")
            results.append(('FAIL', name))
    except PermissionError:
        if not should_pass:
            print(f"  [PASS] {name}: blocked")
            results.append(('PASS', name))
        else:
            print(f"  [FAIL] {name}: blocked (SHOULD WORK)")
            results.append(('FAIL', name))
    except OSError as e:
        if e.winerror in (5, 1314, 21, 6, 145):
            if not should_pass:
                print(f"  [PASS] {name}: blocked (w={e.winerror})")
                results.append(('PASS', name))
            else:
                print(f"  [FAIL] {name}: blocked (SHOULD WORK, w={e.winerror})")
                results.append(('FAIL', name))
        else:
            print(f"  [ERR]  {name}: OSError {e.winerror}: {e}")
            results.append(('ERR', name))
    except Exception as e:
        if not should_pass:
            print(f"  [PASS] {name}: blocked ({type(e).__name__})")
            results.append(('PASS', name))
        else:
            print(f"  [ERR]  {name}: {type(e).__name__}: {e}")
            results.append(('ERR', name))

def p(*parts):
    return os.path.join(ARENA, *parts)


# ===========================================================================
# BASELINE — verify arena access and deny zones are working
# ===========================================================================
print("=== BASELINE ===")
test("arena: write+read", True, lambda: (
    open(p('playground', 'baseline.tmp'), 'w').write('ok'),
    open(p('playground', 'baseline.tmp'), 'r').read(),
    os.remove(p('playground', 'baseline.tmp'))
))
test("denied_zone: list", False, lambda: os.listdir(p('denied_zone')))
test("readonly_zone: read report.txt", True,
     lambda: open(p('readonly_zone', 'report.txt'), 'r').read())
test("readonly_zone: write", False,
     lambda: open(p('readonly_zone', 'hack.tmp'), 'w').write('x'))


# ===========================================================================
# A3: Deny Math Overflow — deny.all on read-only folder (via arena grant)
# ===========================================================================
print("\n=== A3: Deny math — deny.all on arena child ===")
# denied_zone has allow.all (inherited from arena) + deny.all
# After subtraction, reducedMask should be just sharedBits
# The folder should be completely inaccessible
test("denied_zone: stat", False,
     lambda: os.listdir(p('denied_zone')))
test("denied_zone: create file", False,
     lambda: open(p('denied_zone', 'test.tmp'), 'w').write('x'))
test("denied_zone: rmdir", False,
     lambda: os.rmdir(p('denied_zone')))

# Verify DELETE and FILE_DELETE_CHILD are both blocked
test("denied_zone: delete via parent", False,
     lambda: os.rmdir(p('denied_zone')))


# ===========================================================================
# A4: Stacked Denies — deny.write + deny.read on same path
# ===========================================================================
print("\n=== A4: Stacked denies (write + read on double_deny/) ===")
# double_deny/ has allow.all (arena) + deny.write + deny.read
# Both denies should compound — the second reads the first's reduced DACL
test("double_deny: list dir", False,
     lambda: os.listdir(p('double_deny')))
test("double_deny: read data.txt", False,
     lambda: open(p('double_deny', 'data.txt'), 'r').read())
test("double_deny: write", False,
     lambda: open(p('double_deny', 'hack.tmp'), 'w').write('x'))
test("double_deny: create subdir", False,
     lambda: os.mkdir(p('double_deny', 'sub')))
# DELETE is now also blocked (no grant at all in AC mode, not just deny)
test("double_deny: delete blocked (no grant)", False,
     lambda: os.remove(p('double_deny', 'data.txt')))


# ===========================================================================
# B1: Auto-Grant Pivot — read secret file next to exe
# ===========================================================================
print("\n=== B1: Auto-grant pivot (exe folder read) ===")
# Sandy auto-grants read to the exe folder (Python dir)
# Verify we CAN read files there (expected — it's the exe folder)
exe_folder = os.path.dirname(sys.executable)
test("exe folder: list", True, lambda: os.listdir(exe_folder))
test("exe folder: read python.exe", True,
     lambda: open(sys.executable, 'rb').read(4))
# Verify we CANNOT write to the exe folder
test("exe folder: write (should block)", False,
     lambda: open(os.path.join(exe_folder, 'hack.tmp'), 'w').write('x'))


# ===========================================================================
# B2: Working Directory Independence — CWD doesn't bypass grants
# ===========================================================================
print("\n=== B2: Working directory vs grants ===")
try:
    # Save original CWD
    orig_cwd = os.getcwd()
    # Create a subdir in arena, chdir into it
    test_dir = p('playground', 'cwd_test')
    os.makedirs(test_dir, exist_ok=True)
    os.chdir(test_dir)
    # Write using relative path (should work — we're in arena)
    test("cwd in arena: relative write", True,
         lambda: open('rel_test.tmp', 'w').write('ok'))
    os.remove('rel_test.tmp')
    # Try chdir to denied zone (should fail)
    try:
        os.chdir(p('denied_zone'))
        print("  [FAIL] chdir to denied_zone succeeded!")
        results.append(('FAIL', 'cwd: chdir to denied'))
    except (PermissionError, OSError):
        print("  [PASS] chdir to denied_zone blocked")
        results.append(('PASS', 'cwd: chdir to denied blocked'))
    # chdir to Windows — write should fail
    try:
        os.chdir(r'C:\Windows')
        test("cwd=Windows: relative write", False,
             lambda: open('rel_hack.tmp', 'w').write('x'))
    except (PermissionError, OSError):
        print("  [PASS] cwd=Windows: chdir blocked")
        results.append(('PASS', 'cwd: chdir to Windows blocked'))
    # chdir back to arena for cleanup
    try:
        os.chdir(ARENA)
    except (PermissionError, OSError):
        pass
    try:
        os.rmdir(test_dir)
    except (PermissionError, OSError):
        pass
except Exception as e:
    print(f"  [ERR] cwd test: {e}")
    results.append(('ERR', f'cwd: {e}'))


# ===========================================================================
# B4: Environment Variable Filtering
# ===========================================================================
print("\n=== B4: Environment variable filtering ===")
# With envInherit=false, verify sensitive vars
path_var = os.environ.get('PATH', '')
if path_var:
    # PATH should NOT be passed with envInherit=false
    print(f"  [FAIL] PATH is set ({len(path_var)} chars) — should be filtered")
    results.append(('FAIL', 'env: PATH leaked'))
else:
    print("  [PASS] PATH is not set (properly filtered)")
    results.append(('PASS', 'env: PATH filtered'))

# Essential vars SHOULD be present
for var in ['SYSTEMROOT', 'SYSTEMDRIVE', 'WINDIR', 'TEMP', 'COMSPEC']:
    val = os.environ.get(var, '')
    if val:
        print(f"  [PASS] {var} present (essential)")
        results.append(('PASS', f'env: {var} present'))
    else:
        print(f"  [FAIL] {var} missing (essential var should be passed)")
        results.append(('FAIL', f'env: {var} missing'))

# Sensitive vars that should NOT be passed
for var in ['USERNAME', 'COMPUTERNAME', 'LOGONSERVER', 'SESSIONNAME']:
    val = os.environ.get(var, '')
    if val:
        print(f"  [INFO] {var} present: {val}")
        results.append(('INFO', f'env: {var} present'))
    else:
        print(f"  [PASS] {var} filtered")
        results.append(('PASS', f'env: {var} filtered'))


# ===========================================================================
# C1: Runtime File Cleanup — create many files and dirs, verify cleanup
# ===========================================================================
print("\n=== C1: Runtime file storm (50 files + 10 dirs) ===")
runtime_base = p('playground', 'runtime_storm')
os.makedirs(runtime_base, exist_ok=True)

# Create 10 subdirs with 5 files each
created_paths = []
for i in range(10):
    d = os.path.join(runtime_base, f'dir_{i:02d}')
    os.makedirs(d, exist_ok=True)
    created_paths.append(d)
    for j in range(5):
        f = os.path.join(d, f'file_{j:02d}.txt')
        with open(f, 'w') as fh:
            fh.write(f'storm_{i}_{j}')
        created_paths.append(f)

total = len(created_paths)
print(f"  [INFO] Created {total} runtime objects (10 dirs + 50 files)")
results.append(('INFO', f'runtime: created {total} objects'))

# Verify we can read them back
sample = os.path.join(runtime_base, 'dir_05', 'file_03.txt')
test("runtime: read sample file", True,
     lambda: open(sample, 'r').read())

# Leave them for cleanup verification (batch will check post-exit)


# ===========================================================================
# C2: Deep Nested Deny — 5 levels down
# ===========================================================================
print("\n=== C2: Deep nested access (5 levels) ===")
deep_child = p('deep', 'a', 'b', 'c', 'd')
# Peek chain: deep → a → b, then all on c (inherits to d)
test("deep/a: list", True, lambda: os.listdir(p('deep', 'a')))
test("deep/a/b: list", True, lambda: os.listdir(p('deep', 'a', 'b')))
test("deep/a/b/c: list", True, lambda: os.listdir(p('deep', 'a', 'b', 'c')))
# 'd' inherits all from c (AC has no deny to block it)
test("deep/a/b/c/d: list (inherits all)", True, lambda: os.listdir(deep_child))
test("deep/a/b/c/d: read secret.txt", True,
     lambda: open(os.path.join(deep_child, 'secret.txt'), 'r').read())
test("deep/a/b/c/d: write (inherits all)", True,
     lambda: (open(os.path.join(deep_child, 'hack.tmp'), 'w').write('x'),
              os.remove(os.path.join(deep_child, 'hack.tmp'))))

# Write in 'c' should also WORK
test("deep/a/b/c: write", True,
     lambda: (open(p('deep', 'a', 'b', 'c', 'test.tmp'), 'w').write('ok'),
              os.remove(p('deep', 'a', 'b', 'c', 'test.tmp'))))


# ===========================================================================
# ACL PROBING: WRITE_DAC / WRITE_OWNER / FILE_DELETE_CHILD on all zones
# ===========================================================================
print("\n=== ACL bit probing (WRITE_DAC, WRITE_OWNER, FILE_DELETE_CHILD) ===")

WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
FILE_DELETE_CHILD = 0x0040

for folder_name in ['', 'denied_zone', 'readonly_zone', 'playground', 'deep']:
    folder_path = p(folder_name) if folder_name else ARENA
    label = folder_name or 'arena'

    for access_name, access_mask in [('WRITE_DAC', WRITE_DAC),
                                       ('WRITE_OWNER', WRITE_OWNER),
                                       ('FILE_DELETE_CHILD', FILE_DELETE_CHILD)]:
        h = ctypes.windll.kernel32.CreateFileW(
            folder_path, access_mask, 0x7, None, 3, 0x02000000, None)
        if h != ctypes.wintypes.HANDLE(-1).value and h != -1:
            print(f"  [FAIL] {label}: {access_name} SUCCEEDED!")
            results.append(('FAIL', f'{label}: {access_name}'))
            ctypes.windll.kernel32.CloseHandle(h)
        else:
            err = ctypes.windll.kernel32.GetLastError()
            print(f"  [PASS] {label}: {access_name} blocked (err={err})")
            results.append(('PASS', f'{label}: {access_name} blocked'))


# ===========================================================================
# SUMMARY
# ===========================================================================
passed = sum(1 for r in results if r[0] == 'PASS')
failed = sum(1 for r in results if r[0] == 'FAIL')
errors = sum(1 for r in results if r[0] == 'ERR')
skipped = sum(1 for r in results if r[0] == 'SKIP')
info = sum(1 for r in results if r[0] == 'INFO')

print(f"\n{'=' * 70}")
print(f"  EXPERT TEST: {passed} passed, {failed} FAILED, {errors} errors, {skipped} skipped, {info} info")
print(f"  (of {len(results)} total)")
if failed > 0:
    print(f"\n  SANDY WAS BROKEN:")
    for status, name in results:
        if status == 'FAIL':
            print(f"    !! {name}")
print(f"{'=' * 70}")

sys.exit(0 if failed == 0 else 1)
