"""Diabolical test suite -- targets Sandy's IMPLEMENTATION, not Windows kernel.

Attack vectors:
  1. Delete-recreate bypass (parent FILE_DELETE_CHILD vs child deny)
  2. OID stripping + rename (defeats OID-based cleanup tracking)
  3. Registry poisoning attempt (HKCU\Software\Sandy from AppContainer)
  4. User profile leak (%TEMP%, %APPDATA%, %LOCALAPPDATA%)
  5. Self-DACL escalation (WRITE_DAC from ALL grant)
  6. Env var leak audit (sensitive vars exposed via inherit=true)
  7. Deny partial bypass (deny.write on folder, test granularity)
  8. DACL round-trip fidelity (tested from batch via SDDL compare)

Run inside AppContainer via test_diabolical.bat.
"""
import os, sys, ctypes, ctypes.wintypes, winreg

ROOT = os.path.join(os.environ.get('USERPROFILE', r'C:\Users\H'), 'test_diabolical')
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
        if e.winerror in (5, 1314, 21, 6):
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
# BASELINE
# ===========================================================================
print("=== BASELINE ===")
test("arena: write+read", True, lambda: (
    open(p('playground', 'baseline.tmp'), 'w').write('ok'),
    open(p('playground', 'baseline.tmp'), 'r').read(),
    os.remove(p('playground', 'baseline.tmp'))
))
test("killzone: list denied", False, lambda: os.listdir(p('killzone')))
test("fortress: list denied", False, lambda: os.listdir(p('fortress')))


# ===========================================================================
# ATTACK 1: Delete-Recreate Deny Bypass
#
# killzone/ is EMPTY and has [deny all]. Parent arena/ has [allow all]
# which includes FILE_DELETE_CHILD. We should be able to:
#   1. os.rmdir(killzone)  -- parent's FILE_DELETE_CHILD
#   2. os.mkdir(killzone)  -- parent's FILE_ADD_SUBDIRECTORY
#   3. The NEW killzone/ inherits arena/'s ALL grant, NO deny applied
#   4. Write files into it freely
#
# If this works, it's a REAL Sandy bypass.
# ===========================================================================
print("\n=== ATTACK 1: Delete-recreate deny bypass ===")
killzone = p('killzone')
try:
    # Step 1: Delete the empty denied folder
    os.rmdir(killzone)
    print("  [INFO] rmdir(killzone) SUCCEEDED -- deny bypass step 1")

    # Step 2: Recreate it (inherits parent's ALL, no deny)
    os.mkdir(killzone)
    print("  [INFO] mkdir(killzone) SUCCEEDED -- deny bypass step 2")

    # Step 3: Write into the recreated folder
    test_file = os.path.join(killzone, 'pwned.txt')
    try:
        with open(test_file, 'w') as f:
            f.write('DENY BYPASSED')
        content = open(test_file, 'r').read()
        if content == 'DENY BYPASSED':
            print("  [FAIL] DELETE-RECREATE BYPASS: wrote and read from formerly denied folder!")
            results.append(('FAIL', 'delete-recreate: FULL BYPASS'))
        else:
            print(f"  [ERR]  unexpected content: {content}")
            results.append(('ERR', 'delete-recreate: unexpected'))
    except PermissionError:
        print("  [PASS] delete-recreate: recreated folder still denied")
        results.append(('PASS', 'delete-recreate: still denied'))

except PermissionError:
    print("  [PASS] delete-recreate: rmdir denied (parent DELETE_CHILD blocked)")
    results.append(('PASS', 'delete-recreate: rmdir blocked'))
except OSError as e:
    if e.winerror == 5:
        print("  [PASS] delete-recreate: rmdir denied (access denied)")
        results.append(('PASS', 'delete-recreate: rmdir blocked'))
    elif e.winerror == 145:  # dir not empty
        print("  [PASS] delete-recreate: rmdir failed (not empty)")
        results.append(('PASS', 'delete-recreate: not empty'))
    else:
        print(f"  [ERR]  delete-recreate: {e}")
        results.append(('ERR', f'delete-recreate: {e.winerror}'))


# ===========================================================================
# ATTACK 2: OID Stripping + Rename
#
# Strip the NTFS Object ID from a denied folder, then rename it.
# Sandy's cleanup can't find it by path (renamed) or OID (stripped).
# This should leave orphaned ACLs.
# ===========================================================================
print("\n=== ATTACK 2: OID stripping + rename ===")
fortress = p('fortress')
FSCTL_DELETE_OBJECT_ID = 0x900A0

try:
    # Step 1: Try to strip the Object ID
    hFile = ctypes.windll.kernel32.CreateFileW(
        fortress, 0x40000000,  # GENERIC_WRITE
        0x7,  # FILE_SHARE_ALL
        None, 3,  # OPEN_EXISTING
        0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
        None
    )
    if hFile != ctypes.wintypes.HANDLE(-1).value and hFile != -1:
        bytesReturned = ctypes.wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            hFile, FSCTL_DELETE_OBJECT_ID,
            None, 0, None, 0, ctypes.byref(bytesReturned), None
        )
        ctypes.windll.kernel32.CloseHandle(hFile)
        if ok:
            print("  [INFO] OID stripped from fortress/")
        else:
            err = ctypes.windll.kernel32.GetLastError()
            print(f"  [INFO] OID strip failed (error={err})")
    else:
        err = ctypes.windll.kernel32.GetLastError()
        print(f"  [INFO] Cannot open fortress for write (err={err}) -- deny blocks GENERIC_WRITE")

    # Step 2: Rename (we know this works from test_evil)
    renamed = p('fortress_escaped')
    os.rename(fortress, renamed)
    print("  [INFO] fortress renamed to fortress_escaped")
    # Signal to batch: cleanup should fail to restore this folder's DACL
    with open(p('_oid_attack_done'), 'w') as f:
        f.write(renamed)
    # DON'T rename back -- we want cleanup to struggle

except PermissionError:
    print("  [PASS] OID attack: blocked (cannot open or rename)")
    results.append(('PASS', 'oid-strip: blocked'))
except OSError as e:
    print(f"  [INFO] OID attack partial: {e}")
    results.append(('ERR', f'oid-strip: {e.winerror}'))


# ===========================================================================
# ATTACK 3: Registry Poisoning
#
# Try to read/write HKCU\Software\Sandy\Grants from inside AppContainer.
# If accessible, the child can delete grant tracking or poison cleanup.
# ===========================================================================
print("\n=== ATTACK 3: Registry poisoning ===")
try:
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Sandy\Grants", 0, winreg.KEY_READ)
    # If we got here, we can READ the grants registry
    try:
        count = winreg.QueryInfoKey(key)[0]  # number of subkeys
        print(f"  [FAIL] registry READ: opened Grants key, {count} subkeys visible!")
        results.append(('FAIL', 'registry: read access'))
    finally:
        winreg.CloseKey(key)
except PermissionError:
    print("  [PASS] registry: read blocked")
    results.append(('PASS', 'registry: read blocked'))
except FileNotFoundError:
    print("  [PASS] registry: key not found (may be empty)")
    results.append(('PASS', 'registry: key not found'))
except OSError as e:
    if e.winerror == 5:
        print("  [PASS] registry: access denied")
        results.append(('PASS', 'registry: access denied'))
    else:
        print(f"  [ERR]  registry: {e}")
        results.append(('ERR', f'registry: {e.winerror}'))

# Try writing a fake entry
try:
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Sandy\Test\Grants\FAKE_POISON")
    winreg.SetValueEx(key, "poison", 0, winreg.REG_SZ, "owned")
    winreg.CloseKey(key)
    print("  [FAIL] registry WRITE: created poisoned key!")
    results.append(('FAIL', 'registry: write access'))
except PermissionError:
    print("  [PASS] registry: write blocked")
    results.append(('PASS', 'registry: write blocked'))
except OSError as e:
    if e.winerror == 5:
        print("  [PASS] registry: write denied")
        results.append(('PASS', 'registry: write denied'))
    else:
        print(f"  [ERR]  registry write: {e}")
        results.append(('ERR', f'registry write: {e.winerror}'))


# ===========================================================================
# ATTACK 4: User Profile Leak
#
# %TEMP%, %APPDATA%, %LOCALAPPDATA% are in user profile which is NOT
# explicitly granted. AppContainer should block access.
# ===========================================================================
print("\n=== ATTACK 4: User profile leak ===")
for var, label in [('TEMP', '%TEMP%'), ('APPDATA', '%APPDATA%'), ('LOCALAPPDATA', '%LOCALAPPDATA%')]:
    folder = os.environ.get(var, '')
    if folder and os.path.isdir(folder):
        # AppContainer has implicit access to local AppData (by Windows design)
        # These are INFO-level findings, not failures
        try:
            os.listdir(folder)
            print(f"  [INFO] {label}: accessible (AppContainer implicit access)")
            results.append(('INFO', f'{label}: accessible'))
        except PermissionError:
            print(f"  [PASS] {label}: blocked")
            results.append(('PASS', f'{label}: blocked'))
    else:
        print(f"  [SKIP] {label} not set or not a directory")
        results.append(('SKIP', f'{label}: not set'))


# ===========================================================================
# ATTACK 5: Self-DACL Escalation
#
# Child has ALL on arena/ -> this includes WRITE_DAC. Can the child
# modify the DACL on arena/fortress to RE-ADD full access?
# Note: fortress has deny.all (reduced ALLOW ACE), but the denied
# folder's DACL is what was set by Sandy.
# ===========================================================================
print("\n=== ATTACK 5: Self-DACL escalation ===")
# Try to modify fortress DACL to grant us full access
try:
    import ctypes.wintypes

    # First check: can we call GetNamedSecurityInfo on fortress?
    fortress_path = p('fortress')
    if not os.path.exists(fortress_path):
        fortress_path = p('fortress_escaped')

    if os.path.exists(fortress_path):
        # Try to open with WRITE_DAC
        WRITE_DAC = 0x00040000
        hFile = ctypes.windll.kernel32.CreateFileW(
            fortress_path, WRITE_DAC,
            0x7, None, 3, 0x02000000, None
        )
        if hFile != ctypes.wintypes.HANDLE(-1).value and hFile != -1:
            print("  [FAIL] self-dacl: opened fortress with WRITE_DAC!")
            results.append(('FAIL', 'self-dacl: WRITE_DAC obtained'))
            ctypes.windll.kernel32.CloseHandle(hFile)
        else:
            err = ctypes.windll.kernel32.GetLastError()
            print(f"  [PASS] self-dacl: WRITE_DAC blocked on fortress (err={err})")
            results.append(('PASS', 'self-dacl: WRITE_DAC blocked'))
    else:
        print("  [SKIP] fortress not found (may have been renamed)")
        results.append(('SKIP', 'self-dacl: fortress gone'))

    # Also try WRITE_DAC on a folder we DON'T have access to
    userprofile = os.environ.get('USERPROFILE', '')
    if userprofile:
        hFile = ctypes.windll.kernel32.CreateFileW(
            userprofile, WRITE_DAC,
            0x7, None, 3, 0x02000000, None
        )
        if hFile != ctypes.wintypes.HANDLE(-1).value and hFile != -1:
            print("  [FAIL] self-dacl: WRITE_DAC on USERPROFILE!")
            results.append(('FAIL', 'self-dacl: USERPROFILE WRITE_DAC'))
            ctypes.windll.kernel32.CloseHandle(hFile)
        else:
            print("  [PASS] self-dacl: WRITE_DAC blocked on USERPROFILE")
            results.append(('PASS', 'self-dacl: USERPROFILE blocked'))

except Exception as e:
    print(f"  [ERR]  self-dacl: {e}")
    results.append(('ERR', f'self-dacl: {e}'))


# ===========================================================================
# ATTACK 6: Env Var Leak Audit
#
# With inherit=true, check what environment info is exposed.
# This isn't a sandbox escape, but reveals sensitive info.
# ===========================================================================
print("\n=== ATTACK 6: Env var leak audit ===")
sensitive_vars = ['USERPROFILE', 'HOMEPATH', 'USERNAME', 'COMPUTERNAME',
                  'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP',
                  'SESSIONNAME', 'LOGONSERVER']
leaked = []
for var in sensitive_vars:
    val = os.environ.get(var, '')
    if val:
        leaked.append(f"{var}={val}")

if leaked:
    print(f"  [INFO] {len(leaked)} sensitive env vars exposed:")
    for lk in leaked[:5]:
        print(f"    {lk}")
    if len(leaked) > 5:
        print(f"    ... and {len(leaked)-5} more")
    # This is informational, not a FAIL
    results.append(('INFO', f'env leak: {len(leaked)} vars'))
else:
    print("  [PASS] no sensitive env vars found")
    results.append(('PASS', 'env leak: clean'))


# ===========================================================================
# ATTACK 7: Deny Granularity — deny.write should still allow read
#
# readonly_zone/ has [deny write]. Can we still read from it?
# And is write truly blocked at every sub-level?
# ===========================================================================
print("\n=== ATTACK 7: Deny granularity (deny.write) ===")
test("readonly_zone: read report.txt", True,
     lambda: open(p('readonly_zone', 'report.txt'), 'r').read())
test("readonly_zone: list dir", True,
     lambda: os.listdir(p('readonly_zone')))
test("readonly_zone: write file", False,
     lambda: open(p('readonly_zone', 'hack.tmp'), 'w').write('x'))
test("readonly_zone: create subdir", False,
     lambda: os.mkdir(p('readonly_zone', 'subdir')))
# With read-only grant (no deny), DELETE is blocked (no DELETE permission in read mask)
test("readonly_zone: delete blocked (read-only grant)", False,
     lambda: os.remove(p('readonly_zone', 'report.txt')))
# Try appending (FILE_APPEND_DATA is a write-class bit)
test("readonly_zone: append to file", False,
     lambda: open(p('readonly_zone', 'report.txt'), 'a').write('appended'))


# ===========================================================================
# ATTACK 8: DACL Escalation — re-add FILE_DELETE_CHILD via WRITE_DAC
#
# The precise exploit path that stripping WRITE_DAC prevents:
#   1. Open arena/ with WRITE_DAC (we have ALL on it)
#   2. Read current DACL with READ_CONTROL
#   3. Add FILE_DELETE_CHILD to our ACE
#   4. Delete denied children (killzone/)
#   5. Recreate without deny — full bypass
#
# If WRITE_DAC is properly stripped, step 1 fails.
# ===========================================================================
print("\n=== ATTACK 8: DACL escalation (WRITE_DAC re-add FILE_DELETE_CHILD) ===")

WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000

# Step 1: Try WRITE_DAC on arena/ (the [allow all] parent)
hArena = ctypes.windll.kernel32.CreateFileW(
    ARENA, WRITE_DAC,
    0x7, None, 3, 0x02000000, None
)
if hArena != ctypes.wintypes.HANDLE(-1).value and hArena != -1:
    print("  [FAIL] WRITE_DAC on arena/ SUCCEEDED — can modify parent DACL!")
    results.append(('FAIL', 'dacl-escalation: WRITE_DAC on arena'))
    ctypes.windll.kernel32.CloseHandle(hArena)

    # If we got here, try the full exploit chain
    try:
        os.rmdir(p('killzone'))
        os.mkdir(p('killzone'))
        with open(os.path.join(p('killzone'), 'escalated.txt'), 'w') as f:
            f.write('DACL ESCALATION')
        print("  [FAIL] FULL DACL ESCALATION: wrote to formerly denied folder!")
        results.append(('FAIL', 'dacl-escalation: FULL BYPASS'))
    except PermissionError:
        print("  [INFO] WRITE_DAC obtained but exploit chain blocked")
        results.append(('INFO', 'dacl-escalation: partial'))
else:
    err = ctypes.windll.kernel32.GetLastError()
    print(f"  [PASS] WRITE_DAC blocked on arena/ (err={err})")
    results.append(('PASS', 'dacl-escalation: WRITE_DAC blocked'))

# Also verify WRITE_OWNER is blocked
hArena2 = ctypes.windll.kernel32.CreateFileW(
    ARENA, WRITE_OWNER,
    0x7, None, 3, 0x02000000, None
)
if hArena2 != ctypes.wintypes.HANDLE(-1).value and hArena2 != -1:
    print("  [FAIL] WRITE_OWNER on arena/ SUCCEEDED!")
    results.append(('FAIL', 'dacl-escalation: WRITE_OWNER on arena'))
    ctypes.windll.kernel32.CloseHandle(hArena2)
else:
    err = ctypes.windll.kernel32.GetLastError()
    print(f"  [PASS] WRITE_OWNER blocked on arena/ (err={err})")
    results.append(('PASS', 'dacl-escalation: WRITE_OWNER blocked'))

# Verify WRITE_DAC blocked on playground/ (inherits from arena)
hPlay = ctypes.windll.kernel32.CreateFileW(
    p('playground'), WRITE_DAC,
    0x7, None, 3, 0x02000000, None
)
if hPlay != ctypes.wintypes.HANDLE(-1).value and hPlay != -1:
    print("  [FAIL] WRITE_DAC on playground/ (child) SUCCEEDED!")
    results.append(('FAIL', 'dacl-escalation: WRITE_DAC inherited'))
    ctypes.windll.kernel32.CloseHandle(hPlay)
else:
    err = ctypes.windll.kernel32.GetLastError()
    print(f"  [PASS] WRITE_DAC blocked on playground/ (child, err={err})")
    results.append(('PASS', 'dacl-escalation: WRITE_DAC inheritance blocked'))


# ===========================================================================
passed = sum(1 for r in results if r[0] == 'PASS')
failed = sum(1 for r in results if r[0] == 'FAIL')
errors = sum(1 for r in results if r[0] == 'ERR')
skipped = sum(1 for r in results if r[0] == 'SKIP')
info = sum(1 for r in results if r[0] == 'INFO')

print(f"\n{'=' * 70}")
print(f"  DIABOLICAL TEST: {passed} passed, {failed} FAILED, {errors} errors, {skipped} skipped, {info} info")
print(f"  (of {len(results)} total)")
if failed > 0:
    print(f"\n  SANDY WAS BROKEN:")
    for status, name in results:
        if status == 'FAIL':
            print(f"    !! {name}")
print(f"{'=' * 70}")

sys.exit(0 if failed == 0 else 1)
