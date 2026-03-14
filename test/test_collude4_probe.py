"""Collusion4 — Unified probe for all 4 actors.

Usage: python test_collude4_probe.py <alpha|beta|gamma|delta>

Each actor has ALL on hub/ with one unique deny:
  Alpha: deny vault/   (exits 1st)
  Beta:  deny logs/    (exits 2nd)
  Gamma: deny drop/    (exits 3rd)
  Delta: deny quarantine/ (exits 4th)

After each predecessor exits, remaining actors verify their
own denies still hold — proving cleanup independence.
"""
import os, sys, time

ACTOR = sys.argv[1] if len(sys.argv) > 1 else 'unknown'
ROOT = os.path.join(os.environ.get('USERPROFILE', r'C:\Users\H'), 'test_collude4')
HUB = os.path.join(ROOT, 'hub')
VAULT = os.path.join(HUB, 'vault')
LOGS = os.path.join(HUB, 'logs')
DROP = os.path.join(HUB, 'drop')
QUARANTINE = os.path.join(HUB, 'quarantine')
COMMON = os.path.join(HUB, 'common')
SIGNALS = os.path.join(HUB, 'signals')

# Which directory each actor denies
DENY_MAP = {
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

def check_deny(path, label):
    try:
        os.listdir(path)
        print(f"  [FAIL] {label}: accessible (deny broken!)")
        results.append(('FAIL', label))
    except PermissionError:
        print(f"  [PASS] {label}: denied")
        results.append(('PASS', label))

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

def deny_name(path):
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

my_deny = DENY_MAP[ACTOR]
my_deny_nested = None
# Find nested dir inside our denied path
for child in ['inner', 'archive', 'inbox', 'locked']:
    candidate = os.path.join(my_deny, child)
    if os.path.isdir(candidate):
        my_deny_nested = candidate
        break

# -----------------------------------------------------------------------
# Phase 1: Verify own deny works (root + nested)
# -----------------------------------------------------------------------
print(f"\n=== Phase 1: Verify own deny on {deny_name(my_deny)}/ ===")
check_deny(my_deny, f"deny {deny_name(my_deny)}/")
if my_deny_nested:
    check_deny(my_deny_nested, f"deny {deny_name(my_deny)}/{os.path.basename(my_deny_nested)}/")

# -----------------------------------------------------------------------
# Phase 2: Verify access to non-denied directories
# -----------------------------------------------------------------------
print(f"\n=== Phase 2: Verify access to allowed directories ===")
check_access(COMMON, "access common/")
check_read(os.path.join(COMMON, 'shared.txt'), 'SHARED_DATA', "read common/shared.txt")
check_write(os.path.join(COMMON, f'{ACTOR}_was_here.txt'), f'{ACTOR.upper()}_DATA', f"write common/{ACTOR}_was_here.txt")

# Check access to other actors' denied dirs — may be blocked if that
# actor's deny already set PROTECTED_DACL (blocking our inherited ACE).
# This is expected behavior, not a bug. Phase 3 verifies access after
# the deny owner exits and re-enables inheritance.
for other_actor, other_deny in DENY_MAP.items():
    if other_actor != ACTOR:
        name = deny_name(other_deny)
        try:
            os.listdir(other_deny)
            print(f"  [PASS] access {name}/ (other's deny): accessible")
            results.append(('PASS', f'access {name}/ (other\'s deny)'))
        except PermissionError:
            print(f"  [INFO] access {name}/ blocked (PROTECTED_DACL from {other_actor}'s deny)")
            results.append(('INFO', f'access {name}/ blocked by {other_actor}'))

# -----------------------------------------------------------------------
# Phase 3: Staggered exit — wait for predecessors and verify
# -----------------------------------------------------------------------
my_pos = EXIT_ORDER.index(ACTOR)
predecessors = EXIT_ORDER[:my_pos]

if predecessors:
    print(f"\n=== Phase 3: Verify denies survive predecessor cleanup ===")

for i, pred in enumerate(predecessors):
    print(f"\n--- Waiting for {pred} to exit ---")
    if wait_signal(pred, 'done'):
        print(f"  [OK] {pred} exited, sleeping 5s for cleanup")
        time.sleep(5)
    else:
        print(f"  [WARN] {pred} never signaled done")

    # Core invariant: our own deny must survive
    check_deny(my_deny, f"deny {deny_name(my_deny)}/ (after {pred} cleanup)")
    if my_deny_nested:
        check_deny(my_deny_nested,
                    f"deny {deny_name(my_deny)}/{os.path.basename(my_deny_nested)}/ (after {pred} cleanup)")

    # Verify we still have access to allowed areas
    check_access(COMMON, f"access common/ (after {pred} cleanup)")

    # The predecessor's deny is now lifted — verify access restored.
    # NOTE: access may still be blocked if ANOTHER still-running actor
    # also denies this same path (not the case in this test, but guard).
    pred_deny = DENY_MAP[pred]
    check_access(pred_deny, f"access {deny_name(pred_deny)}/ (after {pred} cleanup, deny lifted)")

    # Verify other still-running actors' denied dirs — may be blocked
    # by their PROTECTED_DACL (expected, not a bug).
    for future in EXIT_ORDER[i+1:]:
        if future != ACTOR:
            name = deny_name(DENY_MAP[future])
            try:
                os.listdir(DENY_MAP[future])
                print(f"  [PASS] access {name}/ ({future} still running): accessible")
                results.append(('PASS', f'access {name}/ ({future} running)'))
            except PermissionError:
                print(f"  [INFO] access {name}/ blocked ({future}'s PROTECTED_DACL)")
                results.append(('INFO', f'access {name}/ blocked by {future}'))

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
