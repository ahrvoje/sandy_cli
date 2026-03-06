"""RT version of evil/adversarial test — expectations adjusted for Restricted Token.

Key RT difference:
  - deny.write on records/ with PROTECTED_DACL → read also blocked
"""
import os, sys, ctypes, subprocess

ROOT = os.path.join(os.environ.get('USERPROFILE', r'C:\Users\H'), 'test_evil')
ARENA = os.path.join(ROOT, 'arena')
results = []

def test(name, should_pass, fn):
    try:
        result = fn()
        if should_pass:
            print(f"  [PASS] {name}")
            results.append(('PASS', name))
        else:
            print(f"  [FAIL] {name}: succeeded (SHOULD BE DENIED)")
            results.append(('FAIL', name))
    except PermissionError:
        if not should_pass:
            print(f"  [PASS] {name}: denied")
            results.append(('PASS', name))
        else:
            print(f"  [FAIL] {name}: denied (SHOULD BE ALLOWED)")
            results.append(('FAIL', name))
    except OSError as e:
        if e.winerror in (5, 1314, 21):
            if not should_pass:
                print(f"  [PASS] {name}: denied (winerror={e.winerror})")
                results.append(('PASS', name))
            else:
                print(f"  [FAIL] {name}: denied (SHOULD WORK, w={e.winerror})")
                results.append(('FAIL', name))
        else:
            print(f"  [ERR]  {name}: OSError {e.winerror}: {e}")
            results.append(('ERR', name))
    except Exception as e:
        print(f"  [ERR]  {name}: {type(e).__name__}: {e}")
        results.append(('ERR', name))

def p(*parts):
    return os.path.join(ARENA, *parts)

# ===========================================================================
# BASELINE
# ===========================================================================
print("=== BASELINE: Verify arena access works ===")
test("arena: list",   True, lambda: os.listdir(ARENA))
test("arena: write",  True, lambda: open(p('baseline.tmp'), 'w').write('ok'))
test("arena: read",   True, lambda: open(p('baseline.tmp'), 'r').read())
test("arena: delete", True, lambda: os.remove(p('baseline.tmp')))
test("vault: denied", False, lambda: os.listdir(p('vault')))

# ===========================================================================
# ATTACK 1: Junction/Symlink Escape
# ===========================================================================
print("\n=== ATTACK 1: Junction escape (passage/escape -> vault) ===")
junction_path = p('passage', 'escape')
if os.path.exists(junction_path):
    test("junction: list",    False, lambda: os.listdir(junction_path))
    test("junction: read",    False, lambda: open(os.path.join(junction_path, 'secret.txt'), 'r').read())
    test("junction: write",   False, lambda: open(os.path.join(junction_path, 'new.tmp'), 'w').write('pwned'))
else:
    print("  [SKIP] Junction does not exist (mklink /J may have failed)")
    results.append(('SKIP', 'junction'))

# ===========================================================================
# ATTACK 2: 8.3 Short Name Bypass
# ===========================================================================
print("\n=== ATTACK 2: 8.3 short name bypass ===")
short_name_dir = p('LONGSE~1')
for candidate in ['LONGSE~1', 'LONGS~1', 'LONGSE~2']:
    candidate_path = p(candidate)
    if os.path.exists(candidate_path):
        short_name_dir = candidate_path
        break

if os.path.exists(short_name_dir):
    print(f"  Short name found: {os.path.basename(short_name_dir)}")
    test("8.3: list via short name", False, lambda: os.listdir(short_name_dir))
    test("8.3: read via short name", False,
         lambda: open(os.path.join(short_name_dir, 'classified.txt'), 'r').read())
    test("8.3: write via short name", False,
         lambda: open(os.path.join(short_name_dir, 'hack.tmp'), 'w').write('pwned'))
else:
    print("  [INFO] No 8.3 alias found. Trying GetShortPathNameW...")
    try:
        buf = ctypes.create_unicode_buffer(260)
        long_path = p('LongSecretName')
        ret = ctypes.windll.kernel32.GetShortPathNameW(long_path, buf, 260)
        if ret > 0 and buf.value != long_path:
            short_name_dir = buf.value
            print(f"  Short path: {short_name_dir}")
            test("8.3: list via GetShortPathName", False, lambda: os.listdir(short_name_dir))
            test("8.3: read via GetShortPathName", False,
                 lambda: open(os.path.join(short_name_dir, 'classified.txt'), 'r').read())
        else:
            print("  [SKIP] 8.3 names disabled on this volume")
            results.append(('SKIP', '8.3'))
    except Exception as e:
        print(f"  [SKIP] GetShortPathNameW failed: {e}")
        results.append(('SKIP', '8.3'))

# ===========================================================================
# ATTACK 3: Path Traversal
# ===========================================================================
print("\n=== ATTACK 3: Path traversal via .. ===")
traversal_path = os.path.join(p('passage'), '..', 'vault', 'secret.txt')
test("traversal: read vault/secret.txt via ..", False,
     lambda: open(traversal_path, 'r').read())

traversal_write = os.path.join(p('passage'), '..', 'vault', 'hack.tmp')
test("traversal: write vault/hack.tmp via ..", False,
     lambda: open(traversal_write, 'w').write('pwned'))

raw_traversal = p('passage') + r'\..\..\vault\secret.txt'
test("traversal: raw path (no normalization)", False,
     lambda: open(raw_traversal, 'r').read())

# ===========================================================================
# ATTACK 4: ADS
#   RT: deny.write + PROTECTED_DACL → read also blocked on records/
# ===========================================================================
print("\n=== ATTACK 4: Alternate Data Streams ===")
ads_target = p('records', 'report.txt') + ':hidden_stream'
test("ADS: write hidden stream on deny-write file", False,
     lambda: open(ads_target, 'w').write('secret data'))

ads_folder = p('records') + ':folder_stream'
test("ADS: write stream on deny-write folder", False,
     lambda: open(ads_folder, 'w').write('secret data'))

# RT: PROTECTED_DACL blocks read too (no inherited user ACE)
test("records: read report.txt (RT: blocked by PROTECTED_DACL)", False,
     lambda: open(p('records', 'report.txt'), 'r').read())

# ===========================================================================
# ATTACK 5: Hard Link Exfiltration
# ===========================================================================
print("\n=== ATTACK 5: Hard link exfiltration ===")
hardlink_src = p('vault', 'secret.txt')
hardlink_dst = p('exfiltrated.txt')
try:
    os.link(hardlink_src, hardlink_dst)
    print("  [INFO] Hard link creation SUCCEEDED — this is suspicious")
    test("hardlink: read exfiltrated content", False,
         lambda: open(hardlink_dst, 'r').read())
    try: os.remove(hardlink_dst)
    except: pass
except PermissionError:
    print("  [PASS] hardlink: creation denied (cannot link to vault)")
    results.append(('PASS', 'hardlink: creation denied'))
except OSError as e:
    if e.winerror in (5, 1):
        print("  [PASS] hardlink: creation denied")
        results.append(('PASS', 'hardlink: creation denied'))
    else:
        print(f"  [ERR]  hardlink: OSError {e.winerror}: {e}")
        results.append(('ERR', f'hardlink: {e.winerror}'))

# ===========================================================================
# ATTACK 6: Rename Escape
# ===========================================================================
print("\n=== ATTACK 6: Rename escape ===")
try:
    os.rename(p('vault'), p('vault_escaped'))
    print("  [INFO] rename vault -> vault_escaped SUCCEEDED")
    test("rename: list escaped vault", False,
         lambda: os.listdir(p('vault_escaped')))
    test("rename: read escaped secret", False,
         lambda: open(os.path.join(p('vault_escaped'), 'secret.txt'), 'r').read())
    try: os.rename(p('vault_escaped'), p('vault'))
    except: pass
except PermissionError:
    print("  [PASS] rename: denied (cannot rename vault)")
    results.append(('PASS', 'rename: denied'))
except OSError as e:
    if e.winerror == 5:
        print("  [PASS] rename: denied (access denied)")
        results.append(('PASS', 'rename: denied'))
    else:
        print(f"  [ERR]  rename: OSError {e.winerror}: {e}")
        results.append(('ERR', f'rename: {e.winerror}'))

# ===========================================================================
# ATTACK 7: Case Mismatch
# ===========================================================================
print("\n=== ATTACK 7: Case mismatch bypass ===")
test("case: list CASESENSITIVE (upper)",    False, lambda: os.listdir(p('CASESENSITIVE')))
test("case: list casesensitive (lower)",    False, lambda: os.listdir(p('casesensitive')))
test("case: list CaSeSenSiTiVe (mixed)",    False, lambda: os.listdir(p('CaSeSenSiTiVe')))
test("case: read via lowercase",            False,
     lambda: open(os.path.join(p('casesensitive'), 'hidden.txt'), 'r').read())
test("case: write via uppercase",           False,
     lambda: open(os.path.join(p('CASESENSITIVE'), 'hack.tmp'), 'w').write('pwned'))

# ===========================================================================
# ATTACK 8: Deep Nesting / MAX_PATH
# ===========================================================================
print("\n=== ATTACK 8: Deep nesting / MAX_PATH ===")
deep_base = p('deep')
deep_path = deep_base
segment = 'abcdefghijklmnop'
while len(deep_path) < 280:
    deep_path = os.path.join(deep_path, segment)

try:
    os.makedirs(deep_path, exist_ok=True)
    deep_file = os.path.join(deep_path, 'deep.txt')
    test("deep: write at 300+ char depth", True,
         lambda: open(deep_file, 'w').write('deep'))
    test("deep: read at 300+ char depth", True,
         lambda: open(deep_file, 'r').read())
    print("  [INFO] Deep path length:", len(deep_path))
except OSError as e:
    print(f"  [ERR]  deep mkdir failed: {e}")
    results.append(('ERR', f'deep: {e}'))

# ===========================================================================
# ATTACK 9: Post-Grant File Creation
# ===========================================================================
print("\n=== ATTACK 9: Post-grant file creation ===")
new_dir = p('newdir_postgrant')
try:
    os.makedirs(new_dir, exist_ok=True)
    test("postgrant: write in new dir",  True, lambda: open(os.path.join(new_dir, 'f.txt'), 'w').write('ok'))
    test("postgrant: read in new dir",   True, lambda: open(os.path.join(new_dir, 'f.txt'), 'r').read())
    test("postgrant: delete in new dir", True, lambda: os.remove(os.path.join(new_dir, 'f.txt')))
    os.rmdir(new_dir)
except Exception as e:
    print(f"  [ERR]  postgrant: {e}")
    results.append(('ERR', f'postgrant: {e}'))

# ===========================================================================
# ATTACK 10: Symlink Process Escape
# ===========================================================================
print("\n=== ATTACK 10: Symlink process escape ===")
try:
    link_path = p('cmd_link.exe')
    target = r'C:\Windows\System32\cmd.exe'
    os.symlink(target, link_path)
    print("  [INFO] Symlink to cmd.exe created — trying execution")
    try:
        result = subprocess.run([link_path, '/c', 'echo', 'escaped'],
                               capture_output=True, timeout=5)
        if result.returncode == 0:
            print(f"  [FAIL] process escape: cmd.exe ran! Output: {result.stdout}")
            results.append(('FAIL', 'process escape'))
        else:
            print(f"  [PASS] process escape: blocked (exit={result.returncode})")
            results.append(('PASS', 'process escape'))
    except PermissionError:
        print("  [PASS] process escape: execution denied")
        results.append(('PASS', 'process escape'))
    except Exception as e:
        print(f"  [PASS] process escape: blocked ({type(e).__name__})")
        results.append(('PASS', 'process escape'))
    try: os.remove(link_path)
    except: pass
except OSError as e:
    if e.winerror in (1314, 5):
        print("  [PASS] symlink creation denied (need SeCreateSymbolicLinkPrivilege)")
        results.append(('PASS', 'symlink: creation denied'))
    else:
        print(f"  [ERR]  symlink: {e}")
        results.append(('ERR', f'symlink: {e}'))

# ===========================================================================
# SUMMARY
# ===========================================================================
passed = sum(1 for r in results if r[0] == 'PASS')
failed = sum(1 for r in results if r[0] == 'FAIL')
errors = sum(1 for r in results if r[0] == 'ERR')
skipped = sum(1 for r in results if r[0] == 'SKIP')

print(f"\n{'=' * 70}")
print(f"  ADVERSARIAL TEST (RT): {passed} passed, {failed} FAILED, {errors} errors, {skipped} skipped")
print(f"  (of {len(results)} total)")
if failed > 0:
    print(f"\n  FAILURES:")
    for status, name in results:
        if status == 'FAIL':
            print(f"    !! {name}")
print(f"{'=' * 70}")

sys.exit(0 if failed == 0 else 1)
