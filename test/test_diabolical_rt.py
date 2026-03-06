r"""RT version of diabolical test — expectations adjusted for Restricted Token.

Key RT differences:
  - Registry: medium integrity CAN access HKCU (expected, not a failure)
  - WRITE_DAC on USERPROFILE: succeeds (owner privilege, expected)
  - deny.write readonly_zone: read blocked (PROTECTED_DACL)
  - DACL escalation: WRITE_DAC/WRITE_OWNER succeed on user-owned (expected)
  - User profile paths: accessible (no AC capability isolation)
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
    open(p('baseline.tmp'), 'w').write('ok'),
    open(p('baseline.tmp'), 'r').read(),
    os.remove(p('baseline.tmp'))
))
test("killzone: list denied", False, lambda: os.listdir(p('killzone')))
test("fortress: list denied", False, lambda: os.listdir(p('fortress')))


# ===========================================================================
# ATTACK 1: Delete-Recreate Deny Bypass
# ===========================================================================
print("\n=== ATTACK 1: Delete-recreate deny bypass ===")
killzone = p('killzone')
try:
    os.rmdir(killzone)
    print("  [INFO] rmdir(killzone) SUCCEEDED -- deny bypass step 1")
    os.mkdir(killzone)
    print("  [INFO] mkdir(killzone) SUCCEEDED -- deny bypass step 2")
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
    elif e.winerror == 145:
        print("  [PASS] delete-recreate: rmdir failed (not empty)")
        results.append(('PASS', 'delete-recreate: not empty'))
    else:
        print(f"  [ERR]  delete-recreate: {e}")
        results.append(('ERR', f'delete-recreate: {e.winerror}'))


# ===========================================================================
# ATTACK 2: OID Stripping + Rename
# ===========================================================================
print("\n=== ATTACK 2: OID stripping + rename ===")
fortress = p('fortress')
FSCTL_DELETE_OBJECT_ID = 0x900A0

try:
    hFile = ctypes.windll.kernel32.CreateFileW(
        fortress, 0x40000000, 0x7, None, 3, 0x02000000, None)
    if hFile != ctypes.wintypes.HANDLE(-1).value and hFile != -1:
        bytesReturned = ctypes.wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            hFile, FSCTL_DELETE_OBJECT_ID,
            None, 0, None, 0, ctypes.byref(bytesReturned), None)
        ctypes.windll.kernel32.CloseHandle(hFile)
        if ok:
            print("  [INFO] OID stripped from fortress/")
        else:
            err = ctypes.windll.kernel32.GetLastError()
            print(f"  [INFO] OID strip failed (error={err})")
    else:
        err = ctypes.windll.kernel32.GetLastError()
        print(f"  [INFO] Cannot open fortress for write (err={err}) -- deny blocks GENERIC_WRITE")

    renamed = p('fortress_escaped')
    os.rename(fortress, renamed)
    print("  [INFO] fortress renamed to fortress_escaped")
    with open(p('_oid_attack_done'), 'w') as f:
        f.write(renamed)
except PermissionError:
    print("  [PASS] OID attack: blocked (cannot open or rename)")
    results.append(('PASS', 'oid-strip: blocked'))
except OSError as e:
    print(f"  [INFO] OID attack partial: {e}")
    results.append(('ERR', f'oid-strip: {e.winerror}'))


# ===========================================================================
# ATTACK 3: Registry Access (RT: medium integrity → HKCU accessible)
#   This is EXPECTED for RT — medium integrity has HKCU access.
#   We mark as INFO, not FAIL.
# ===========================================================================
print("\n=== ATTACK 3: Registry access (RT: expected accessible) ===")
try:
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Sandy\Grants", 0, winreg.KEY_READ)
    try:
        count = winreg.QueryInfoKey(key)[0]
        print(f"  [INFO] registry READ: Grants key accessible, {count} subkeys (expected for RT)")
        results.append(('INFO', 'registry: read accessible (expected for RT)'))
    finally:
        winreg.CloseKey(key)
except PermissionError:
    print("  [PASS] registry: read blocked (unexpected for RT)")
    results.append(('PASS', 'registry: read blocked'))
except FileNotFoundError:
    print("  [INFO] registry: key not found (may be empty)")
    results.append(('INFO', 'registry: key not found'))
except OSError as e:
    print(f"  [INFO] registry: {e}")
    results.append(('INFO', f'registry: {e.winerror}'))

# Try writing — also expected accessible at medium integrity
try:
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Sandy\Grants\FAKE_POISON_RT")
    winreg.SetValueEx(key, "poison", 0, winreg.REG_SZ, "rt_test")
    winreg.CloseKey(key)
    print("  [INFO] registry WRITE: created test key (expected for RT)")
    results.append(('INFO', 'registry: write accessible (expected for RT)'))
    # Clean up our test key
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\Sandy\Grants\FAKE_POISON_RT")
        print("  [INFO] cleaned up test registry key")
    except Exception:
        pass
except PermissionError:
    print("  [PASS] registry: write blocked (unexpected for RT)")
    results.append(('PASS', 'registry: write blocked'))
except OSError as e:
    print(f"  [INFO] registry write: {e}")
    results.append(('INFO', f'registry write: {e.winerror}'))


# ===========================================================================
# ATTACK 4: User Profile Leak
#   RT: medium integrity has access to user profile (expected)
# ===========================================================================
print("\n=== ATTACK 4: User profile access (RT: expected accessible) ===")
for var, label in [('TEMP', '%TEMP%'), ('APPDATA', '%APPDATA%'), ('LOCALAPPDATA', '%LOCALAPPDATA%')]:
    folder = os.environ.get(var, '')
    if folder and os.path.isdir(folder):
        try:
            os.listdir(folder)
            print(f"  [INFO] {label}: accessible (expected for RT)")
            results.append(('INFO', f'{label}: accessible'))
        except PermissionError:
            print(f"  [INFO] {label}: blocked (unusual for RT)")
            results.append(('INFO', f'{label}: blocked'))
    else:
        print(f"  [SKIP] {label} not set or not a directory")
        results.append(('SKIP', f'{label}: not set'))


# ===========================================================================
# ATTACK 5: Self-DACL escalation
#   RT: WRITE_DAC on fortress should be blocked (deny.all)
#   But WRITE_DAC on USERPROFILE succeeds (user is owner)
# ===========================================================================
print("\n=== ATTACK 5: Self-DACL escalation ===")
try:
    WRITE_DAC = 0x00040000
    fortress_path = p('fortress')
    if not os.path.exists(fortress_path):
        fortress_path = p('fortress_escaped')

    if os.path.exists(fortress_path):
        hFile = ctypes.windll.kernel32.CreateFileW(
            fortress_path, WRITE_DAC, 0x7, None, 3, 0x02000000, None)
        if hFile != ctypes.wintypes.HANDLE(-1).value and hFile != -1:
            print("  [FAIL] self-dacl: WRITE_DAC on fortress succeeded (should be blocked by deny)")
            results.append(('FAIL', 'self-dacl: fortress WRITE_DAC'))
            ctypes.windll.kernel32.CloseHandle(hFile)
        else:
            err = ctypes.windll.kernel32.GetLastError()
            print(f"  [PASS] self-dacl: WRITE_DAC blocked on fortress (err={err})")
            results.append(('PASS', 'self-dacl: WRITE_DAC blocked'))
    else:
        print("  [SKIP] fortress not found (may have been renamed)")
        results.append(('SKIP', 'self-dacl: fortress gone'))

    userprofile = os.environ.get('USERPROFILE', '')
    if userprofile:
        hFile = ctypes.windll.kernel32.CreateFileW(
            userprofile, WRITE_DAC, 0x7, None, 3, 0x02000000, None)
        if hFile != ctypes.wintypes.HANDLE(-1).value and hFile != -1:
            # RT: user is owner → WRITE_DAC succeeds (expected)
            print("  [INFO] self-dacl: WRITE_DAC on USERPROFILE (user is owner, expected)")
            results.append(('INFO', 'self-dacl: USERPROFILE owner'))
            ctypes.windll.kernel32.CloseHandle(hFile)
        else:
            print("  [PASS] self-dacl: WRITE_DAC blocked on USERPROFILE")
            results.append(('PASS', 'self-dacl: USERPROFILE blocked'))

except Exception as e:
    print(f"  [ERR]  self-dacl: {e}")
    results.append(('ERR', f'self-dacl: {e}'))


# ===========================================================================
# ATTACK 6: Env Var Leak (informational only)
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
    results.append(('INFO', f'env leak: {len(leaked)} vars'))
else:
    print("  [PASS] no sensitive env vars found")
    results.append(('PASS', 'env leak: clean'))


# ===========================================================================
# ATTACK 7: Deny Granularity (deny.write)
#   RT: PROTECTED_DACL strips inherited user ACEs → read also blocked
# ===========================================================================
print("\n=== ATTACK 7: Deny granularity (deny.write) ===")
# RT: read blocked because PROTECTED_DACL removes inherited user read ACE
test("readonly_zone: read report.txt (RT: blocked by PROTECTED_DACL)", False,
     lambda: open(p('readonly_zone', 'report.txt'), 'r').read())
test("readonly_zone: list dir (RT: blocked by PROTECTED_DACL)", False,
     lambda: os.listdir(p('readonly_zone')))
test("readonly_zone: write file", False,
     lambda: open(p('readonly_zone', 'hack.tmp'), 'w').write('x'))
test("readonly_zone: create subdir", False,
     lambda: os.mkdir(p('readonly_zone', 'subdir')))
try:
    os.remove(p('readonly_zone', 'report.txt'))
    print("  [INFO] readonly_zone: delete succeeded (deny.write != deny.delete, documented)")
    results.append(('INFO', 'readonly_zone: delete (expected, documented)'))
except PermissionError:
    print("  [PASS] readonly_zone: delete blocked")
    results.append(('PASS', 'readonly_zone: delete blocked'))
test("readonly_zone: append to file", False,
     lambda: open(p('readonly_zone', 'report.txt'), 'a').write('appended'))


# ===========================================================================
# ATTACK 8: DACL Escalation
#   RT: WRITE_DAC/WRITE_OWNER succeed on user-owned paths (expected)
# ===========================================================================
print("\n=== ATTACK 8: DACL escalation ===")

WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000

# RT: user owns arena → WRITE_DAC succeeds (expected)
hArena = ctypes.windll.kernel32.CreateFileW(
    ARENA, WRITE_DAC, 0x7, None, 3, 0x02000000, None)
if hArena != ctypes.wintypes.HANDLE(-1).value and hArena != -1:
    print("  [INFO] WRITE_DAC on arena/ (user is owner, expected for RT)")
    results.append(('INFO', 'dacl-escalation: WRITE_DAC owner'))
    ctypes.windll.kernel32.CloseHandle(hArena)

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

hArena2 = ctypes.windll.kernel32.CreateFileW(
    ARENA, WRITE_OWNER, 0x7, None, 3, 0x02000000, None)
if hArena2 != ctypes.wintypes.HANDLE(-1).value and hArena2 != -1:
    print("  [INFO] WRITE_OWNER on arena/ (user is owner, expected for RT)")
    results.append(('INFO', 'dacl-escalation: WRITE_OWNER owner'))
    ctypes.windll.kernel32.CloseHandle(hArena2)
else:
    err = ctypes.windll.kernel32.GetLastError()
    print(f"  [PASS] WRITE_OWNER blocked on arena/ (err={err})")
    results.append(('PASS', 'dacl-escalation: WRITE_OWNER blocked'))

hPlay = ctypes.windll.kernel32.CreateFileW(
    p('playground'), WRITE_DAC, 0x7, None, 3, 0x02000000, None)
if hPlay != ctypes.wintypes.HANDLE(-1).value and hPlay != -1:
    print("  [INFO] WRITE_DAC on playground/ (inherited owner access, expected for RT)")
    results.append(('INFO', 'dacl-escalation: WRITE_DAC playground'))
    ctypes.windll.kernel32.CloseHandle(hPlay)
else:
    err = ctypes.windll.kernel32.GetLastError()
    print(f"  [PASS] WRITE_DAC blocked on playground/ (err={err})")
    results.append(('PASS', 'dacl-escalation: WRITE_DAC blocked'))


# ===========================================================================
passed = sum(1 for r in results if r[0] == 'PASS')
failed = sum(1 for r in results if r[0] == 'FAIL')
errors = sum(1 for r in results if r[0] == 'ERR')
skipped = sum(1 for r in results if r[0] == 'SKIP')
info = sum(1 for r in results if r[0] == 'INFO')

print(f"\n{'=' * 70}")
print(f"  DIABOLICAL TEST (RT): {passed} passed, {failed} FAILED, {errors} errors, {skipped} skipped, {info} info")
print(f"  (of {len(results)} total)")
if failed > 0:
    print(f"\n  FAILURES:")
    for status, name in results:
        if status == 'FAIL':
            print(f"    !! {name}")
print(f"{'=' * 70}")

sys.exit(0 if failed == 0 else 1)
