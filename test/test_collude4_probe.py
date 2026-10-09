"""Collusion4 — Unified probe for all 4 actors.

Usage: python test_collude4_probe.py <alpha|beta|gamma|delta>

Each actor is an AppContainer instance with ALL on hub/.  Each actor has one
home folder, and the actors exit one after the other:
  Alpha: home vault/      (exits 1st)
  Beta:  home logs/       (exits 2nd)
  Gamma: home drop/       (exits 3rd)
  Delta: home quarantine/ (exits 4th)

After each earlier actor has exited and its Sandy has removed its grant, the
remaining actors verify that their own access to every folder of hub/ is
intact — proving that one instance's cleanup does not touch another's grant.
"""
import ctypes, os, re, sys, time
from ctypes import wintypes

ACTOR = sys.argv[1] if len(sys.argv) > 1 else 'unknown'
ROOT = os.path.join(os.environ['USERPROFILE'], 'test_collude4')
HUB = os.path.join(ROOT, 'hub')
VAULT = os.path.join(HUB, 'vault')
LOGS = os.path.join(HUB, 'logs')
DROP = os.path.join(HUB, 'drop')
QUARANTINE = os.path.join(HUB, 'quarantine')
COMMON = os.path.join(HUB, 'common')
SIGNALS = os.path.join(HUB, 'signals')

# The home folder of each actor
HOME_MAP = {
    'alpha': VAULT,
    'beta': LOGS,
    'gamma': DROP,
    'delta': QUARANTINE,
}
# Ordered exit sequence
EXIT_ORDER = ['alpha', 'beta', 'gamma', 'delta']

results = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def signal(state):
    with open(os.path.join(SIGNALS, f'{ACTOR}_{state}'), 'w') as f:
        f.write(str(os.getpid()))

def wait_signal(name, state, timeout=60):
    path = os.path.join(SIGNALS, f'{name}_{state}')
    for _ in range(timeout * 2):
        if os.path.exists(path):
            return True
        time.sleep(0.5)
    return False

def wait_all_ready():
    for a in EXIT_ORDER:
        if not wait_signal(a, 'ready'):
            print(f"  [WARN] {a} never signaled ready")
            return False
    return True

def grants_on_hub():
    """Number of AppContainer instances that hold a grant on hub/ (one explicit ACE each)."""
    advapi32 = ctypes.WinDLL('advapi32')
    advapi32.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                               ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                               ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
    sd = ctypes.c_void_p()
    if advapi32.GetNamedSecurityInfoW(HUB, 1, 4, None, None, None, None, ctypes.byref(sd)):
        return None
    text = wintypes.LPWSTR()
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 4, ctypes.byref(text), None)
    count = len(set(re.findall(r'S-1-15-2-[0-9]+(?:-[0-9]+){6,}', text.value or '')))
    kernel32 = ctypes.WinDLL('kernel32')
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree(text)
    kernel32.LocalFree(sd)
    return count

def wait_for_cleanup(remaining, timeout=60):
    """Wait until only `remaining` instances hold a grant on hub/: the exited actor's Sandy is done."""
    for _ in range(timeout * 4):
        if grants_on_hub() == remaining:
            return True
        time.sleep(0.25)
    return False

def check_access(path, label):
    try:
        os.listdir(path)
        print(f"  [PASS] {label}: accessible")
        results.append(('PASS', label))
    except PermissionError:
        print(f"  [FAIL] {label}: denied (should be accessible!)")
        results.append(('FAIL', label))

def check_read(filepath, expected, label):
    try:
        content = open(filepath).read().strip()
        if expected in content:
            print(f"  [PASS] {label}")
            results.append(('PASS', label))
        else:
            print(f"  [FAIL] {label}: got '{content[:40]}'")
            results.append(('FAIL', label))
    except PermissionError:
        print(f"  [FAIL] {label}: denied")
        results.append(('FAIL', label))

def check_write(filepath, content, label):
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"  [PASS] {label}")
        results.append(('PASS', label))
    except PermissionError:
        print(f"  [FAIL] {label}: denied")
        results.append(('FAIL', label))

def folder_name(path):
    return os.path.basename(path)


# ---------------------------------------------------------------------------
# Main test logic
# ---------------------------------------------------------------------------
print(f"=== {ACTOR.upper()} START ===")

# Signal readiness and wait for all actors
signal('ready')
print(f"  [OK] {ACTOR} ready")
if wait_all_ready():
    print("  [OK] All 4 actors running concurrently")
else:
    print("  [WARN] Not all actors signaled ready")

my_home = HOME_MAP[ACTOR]
my_home_nested = None
# Find the nested dir inside our home folder
for child in ['inner', 'archive', 'inbox', 'locked']:
    candidate = os.path.join(my_home, child)
    if os.path.isdir(candidate):
        my_home_nested = candidate
        break

# -----------------------------------------------------------------------
# Phase 1: Verify access to the own home folder (root + nested)
# -----------------------------------------------------------------------
print(f"\n=== Phase 1: Verify access to home folder {folder_name(my_home)}/ ===")
check_access(my_home, f"access home {folder_name(my_home)}/")
if my_home_nested:
    check_access(my_home_nested, f"access home {folder_name(my_home)}/{os.path.basename(my_home_nested)}/")

# -----------------------------------------------------------------------
# Phase 2: Verify access to the shared folder and to the other homes
# -----------------------------------------------------------------------
print(f"\n=== Phase 2: Verify access to the other folders of hub/ ===")
check_access(COMMON, "access common/")
check_read(os.path.join(COMMON, 'shared.txt'), 'SHARED_DATA', "read common/shared.txt")
check_write(os.path.join(COMMON, f'{ACTOR}_was_here.txt'), f'{ACTOR.upper()}_DATA', f"write common/{ACTOR}_was_here.txt")

# Every actor has ALL on hub/, so the home folder of another actor is
# reachable too.  A grant of one instance never blocks another instance.
for other_actor, other_home in HOME_MAP.items():
    if other_actor != ACTOR:
        check_access(other_home, f"access {folder_name(other_home)}/ (home of {other_actor})")

# -----------------------------------------------------------------------
# Phase 3: Staggered exit — wait for predecessors and verify
# -----------------------------------------------------------------------
my_pos = EXIT_ORDER.index(ACTOR)
predecessors = EXIT_ORDER[:my_pos]

if predecessors:
    print(f"\n=== Phase 3: Verify own access survives predecessor cleanup ===")

for i, pred in enumerate(predecessors):
    print(f"\n--- Waiting for {pred} to exit ---")
    if wait_signal(pred, 'done'):
        remaining = len(EXIT_ORDER) - (i + 1)
        if wait_for_cleanup(remaining):
            print(f"  [OK] {pred} exited and its grant on hub/ is gone ({remaining} grants left)")
        else:
            print(f"  [WARN] {pred} exited, but its grant on hub/ is still there")
    else:
        print(f"  [WARN] {pred} never signaled done")

    # Core invariant: our own grant must survive the cleanup of another instance
    check_access(my_home, f"access home {folder_name(my_home)}/ (after {pred} cleanup)")
    if my_home_nested:
        check_access(my_home_nested,
                     f"access home {folder_name(my_home)}/{os.path.basename(my_home_nested)}/ (after {pred} cleanup)")
    check_write(os.path.join(my_home, f'{ACTOR}_after_{pred}.txt'), f'{ACTOR.upper()}_DATA',
                f"write home {folder_name(my_home)}/ (after {pred} cleanup)")
    check_access(COMMON, f"access common/ (after {pred} cleanup)")

    # The home folder of the exited actor: its grant is gone, ours is not.
    pred_home = HOME_MAP[pred]
    check_access(pred_home, f"access {folder_name(pred_home)}/ (home of {pred}, after {pred} cleanup)")

    # The home folders of the actors that are still running
    for future in EXIT_ORDER[i+1:]:
        if future != ACTOR:
            check_access(HOME_MAP[future],
                         f"access {folder_name(HOME_MAP[future])}/ (home of {future}, still running)")

# -----------------------------------------------------------------------
# Phase 4: Write final proof + signal done
# -----------------------------------------------------------------------
if not predecessors:
    print(f"\n=== Phase 3: {ACTOR} exits first (no predecessors) ===")

check_write(os.path.join(COMMON, f'{ACTOR}_final.txt'),
            f'{ACTOR.upper()}_COMPLETED', f"write final proof")

signal('done')

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
passed = sum(1 for r in results if r[0] == 'PASS')
failed = sum(1 for r in results if r[0] == 'FAIL')
print(f"\n  {ACTOR.upper()}: {passed} pass, {failed} fail")
sys.exit(0 if failed == 0 else 1)
