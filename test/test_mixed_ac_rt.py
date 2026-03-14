"""Mixed AC+RT probe — tests overlapping grants from two different sandbox modes.

Run inside either AppContainer or Restricted Token sandbox via test_mixed_ac_rt.bat.
Both instances run the same script against the same folder tree.

Folder tree:
  test_mixed/
    shared/              [allow all]
      workspace/         inherits all — full control expected
      protected/         [deny write] — AC: read OK, write blocked
                                        RT: all blocked (PROTECTED_DACL strips inherited user ACEs)
    scripts/             [allow read] — AC: read-only.  RT: user-owned, write OK
"""
import os, sys, ctypes

ROOT = os.path.join(os.environ.get('USERPROFILE', r'C:\Users\H'), 'test_mixed')
SHARED = os.path.join(ROOT, 'shared')
results = []

def test(name, should_pass, fn):
    """Run fn. should_pass=True = expect success, False = expect PermissionError."""
    try:
        fn()
        if should_pass:
            print(f"  [PASS] {name}")
            results.append(True)
        else:
            print(f"  [FAIL] {name}: succeeded (SHOULD BE DENIED)")
            results.append(False)
    except PermissionError:
        if not should_pass:
            print(f"  [PASS] {name}: denied")
            results.append(True)
        else:
            print(f"  [FAIL] {name}: denied (SHOULD BE ALLOWED)")
            results.append(False)
    except OSError as e:
        if e.winerror in (5, 1314):
            if not should_pass:
                print(f"  [PASS] {name}: denied (winerror={e.winerror})")
                results.append(True)
            else:
                print(f"  [FAIL] {name}: denied (SHOULD BE ALLOWED, winerror={e.winerror})")
                results.append(False)
        else:
            print(f"  [FAIL] {name}: OSError {e.winerror}: {e}")
            results.append(False)
    except Exception as e:
        print(f"  [FAIL] {name}: {type(e).__name__}: {e}")
        results.append(False)

def p(*parts):
    return os.path.join(SHARED, *parts)

# ================================================================
# Detect sandbox mode via behavior:
# Try listing a user-owned path NOT granted by Sandy.
# AC: blocked (no capability for ungranted paths)
# RT: succeeds (user's native SID has access)
# ================================================================
mode = "UNKNOWN"
try:
    user = os.environ.get('USERPROFILE', '')
    if user:
        os.listdir(user)
        mode = "RT"  # succeeded → user's native SID has access, must be RT
except (PermissionError, OSError):
    mode = "AC"  # blocked → capability isolation, must be AC

is_rt = (mode == "RT")

print(f"=== Mixed AC+RT Probe — Mode: {mode} ===")
print(f"PID: {os.getpid()}")
print()

# ================================================================
# GROUP 1: shared/workspace — inherits [allow] all → full control
# Same in both AC and RT
# ================================================================
print("--- shared/workspace (allow.all inherited) ---")
test("workspace: list dir",   True,  lambda: os.listdir(p('workspace')))
test("workspace: read file",  True,  lambda: open(p('workspace', 'seed.txt'), 'r').read())
test("workspace: write file", True,  lambda: open(p('workspace', 'seed.txt'), 'w').write('modified by ' + mode))
test("workspace: create file", True, lambda: open(p('workspace', f'created_by_{mode}.txt'), 'w').write(f'created by {mode}'))
test("workspace: delete file", True, lambda: os.remove(p('workspace', f'created_by_{mode}.txt')))

# ================================================================
# GROUP 2: shared/protected
#   AC: read OK, write blocked (explicit read grant, no write grant)
#   RT: read/list ALSO blocked (PROTECT_DACL strips inherited user ACEs)
# ================================================================
print("--- shared/protected (AC: allow.read, RT: deny.write) ---")
# AC: True (read grant), RT: False (PROTECTED_DACL strips inherited user ACEs)
test("protected: list dir",      not is_rt, lambda: os.listdir(p('protected')))
test("protected: read file",     not is_rt, lambda: open(p('protected', 'data.txt'), 'r').read())
test("protected: overwrite file", False,     lambda: open(p('protected', 'data.txt'), 'w').write('hack'))
test("protected: create file",   False,     lambda: open(p('protected', f'hack_{mode}.tmp'), 'w').write('x'))

# ================================================================
# GROUP 3: scripts — [allow] read
#   AC: read-only (no native user access, only Sandy's read ACE)
#   RT: user's native SID has full access → write succeeds too
# ================================================================
print("--- scripts (allow.read) ---")
test("scripts: list dir",  True,  lambda: os.listdir(os.path.join(ROOT, 'scripts')))
test("scripts: write file", is_rt, lambda: (
    open(os.path.join(ROOT, 'scripts', 'hack.tmp'), 'w').write('x'),
    os.remove(os.path.join(ROOT, 'scripts', 'hack.tmp'))))

# ================================================================
# GROUP 4: Ungranted paths
#   AC: blocked (no capability)
#   RT: user's native SID has access (no AC capability isolation)
# ================================================================
print("--- ungranted paths ---")
user = os.environ.get('USERPROFILE', 'C:/Users/unknown')
test("desktop: list",  is_rt, lambda: os.listdir(os.path.join(user, 'Desktop')))
test("desktop: write", is_rt, lambda: (
    open(os.path.join(user, 'Desktop', 'hack.txt'), 'w').write('x'),
    os.remove(os.path.join(user, 'Desktop', 'hack.txt'))))

# ================================================================
# Write mode marker for the orchestrator to verify both ran
# ================================================================
marker_file = p('workspace', f'marker_{mode}.txt')
try:
    with open(marker_file, 'w') as f:
        f.write(f"Mode: {mode}\nPID: {os.getpid()}\n")
    print(f"\n  [INFO] Wrote marker: {marker_file}")
except Exception as e:
    print(f"\n  [WARN] Could not write marker: {e}")

# ================================================================
# SUMMARY
# ================================================================
passed = sum(results)
failed = len(results) - passed
print(f"\n=== Mixed Probe ({mode}): {passed} passed, {failed} failed (of {len(results)}) ===")
sys.exit(0 if failed == 0 else 1)
