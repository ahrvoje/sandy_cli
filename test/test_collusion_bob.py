"""Collusion test — Bob probe (Instance B)

Bob grants [all] to shared/ with [deny all] on shared/locked/.
He relies on Alice to exfiltrate data from locked/.
Bob exits SECOND — his cleanup restores SDDL that includes Alice's SID.
"""
import os, sys, time

ROOT = os.path.join(os.environ.get('USERPROFILE', r'C:\Users\H'), 'test_collusion')
SHARED = os.path.join(ROOT, 'shared')
LOCKED = os.path.join(SHARED, 'locked')
RELAY = os.path.join(SHARED, 'relay')
SIGNALS = os.path.join(SHARED, 'signals')
results = []

def p(*parts):
    return os.path.join(SHARED, *parts)


print("=== BOB START ===")

# --- Signal readiness ---
os.makedirs(SIGNALS, exist_ok=True)
with open(os.path.join(SIGNALS, 'bob_ready'), 'w') as f:
    f.write(str(os.getpid()))
print("  [OK] Bob ready signal posted")

# --- Wait for Alice to be ready (max 30s) ---
alice_ready = os.path.join(SIGNALS, 'alice_ready')
for i in range(60):
    if os.path.exists(alice_ready):
        break
    time.sleep(0.5)
if os.path.exists(alice_ready):
    print("  [OK] Alice is ready — both instances running concurrently")
else:
    print("  [WARN] Alice never showed up (timeout)")


# ===========================================================================
# ATTACK 1: Verify Bob's deny works — locked/ is inaccessible
# ===========================================================================
print("\n=== BOB: Verify deny on locked/ ===")
try:
    os.listdir(LOCKED)
    print("  [FAIL] Bob can list locked/ (deny not working!)")
    results.append(('FAIL', 'bob-deny: list succeeded'))
except PermissionError:
    print("  [PASS] Bob cannot list locked/ (deny works)")
    results.append(('PASS', 'bob-deny: list blocked'))

try:
    open(os.path.join(LOCKED, 'secret.txt'), 'r').read()
    print("  [FAIL] Bob can read secret.txt (deny not working!)")
    results.append(('FAIL', 'bob-deny: read succeeded'))
except PermissionError:
    print("  [PASS] Bob cannot read secret.txt (deny works)")
    results.append(('PASS', 'bob-deny: read blocked'))


# ===========================================================================
# ATTACK 2: Read exfiltrated data from relay (Alice's heist)
# ===========================================================================
print("\n=== BOB: Read exfiltrated data ===")
exfil_file = os.path.join(RELAY, 'exfiltrated.txt')
# Wait for Alice to create the relay
for i in range(20):
    if os.path.exists(exfil_file):
        break
    time.sleep(0.5)

if os.path.exists(exfil_file):
    try:
        content = open(exfil_file, 'r').read()
        if 'EXFILTRATED' in content:
            print(f"  [INFO] Bob received exfiltrated data: {content.strip()}")
            print("         -> Two instances colluded to bypass deny!")
            results.append(('INFO', 'exfil: Bob got Alice relay'))
        else:
            print(f"  [ERR] Unexpected content: {content}")
            results.append(('ERR', 'exfil: bad content'))
    except PermissionError:
        print("  [INFO] Bob can't read relay (unexpected)")
        results.append(('INFO', 'exfil: blocked'))
else:
    print("  [INFO] No exfiltrated file (Alice didn't post yet)")
    results.append(('INFO', 'exfil: not available'))


# ===========================================================================
# ATTACK 3: Concurrent write to shared area
# ===========================================================================
print("\n=== BOB: Concurrent writes ===")
try:
    with open(p('bob_file.txt'), 'w') as f:
        f.write('BOB_WAS_HERE')
    content = open(p('bob_file.txt'), 'r').read()
    if content == 'BOB_WAS_HERE':
        print("  [PASS] Bob write+read in shared/")
        results.append(('PASS', 'concurrent: Bob write'))
except Exception as e:
    print(f"  [FAIL] Bob write: {e}")
    results.append(('FAIL', f'concurrent: {e}'))

# Can Bob read what Alice wrote to shared/?
try:
    alice_file = os.path.join(LOCKED, 'alice_was_here.txt')
    content = open(alice_file, 'r').read()
    print(f"  [FAIL] Bob read Alice's file in locked/: {content[:30]}")
    results.append(('FAIL', 'concurrent: Bob read locked'))
except PermissionError:
    print("  [PASS] Bob can't read Alice's file in locked/")
    results.append(('PASS', 'concurrent: locked still denied'))


# ===========================================================================
# Wait for Alice to exit FIRST, then delay before Bob exits
# ===========================================================================
print("\n=== BOB: Waiting for Alice to exit ===")
alice_done = os.path.join(SIGNALS, 'alice_done')
for i in range(60):
    if os.path.exists(alice_done):
        break
    time.sleep(0.5)

if os.path.exists(alice_done):
    print("  [OK] Alice exited — her Sandy is cleaning up")
    # Wait for Alice's Sandy to finish cleanup
    print("  [OK] Sleeping 8s to ensure Alice's Sandy fully cleaned up")
    time.sleep(8)
    print("  [OK] Alice's cleanup should be done. Bob exiting now.")
else:
    print("  [WARN] Alice never signaled done")


# ===========================================================================
# Verify shared/ is still accessible after Alice's cleanup
# ===========================================================================
print("\n=== BOB: Post-Alice-cleanup verification ===")
try:
    os.listdir(SHARED)
    print("  [PASS] shared/ still accessible after Alice cleanup")
    results.append(('PASS', 'post-alice: shared accessible'))
except PermissionError:
    print("  [FAIL] shared/ inaccessible after Alice cleanup!")
    results.append(('FAIL', 'post-alice: shared broken'))

try:
    os.listdir(LOCKED)
    print("  [FAIL] locked/ accessible after Alice cleanup (deny lost!)  ")
    results.append(('FAIL', 'post-alice: deny lost'))
except PermissionError:
    print("  [PASS] locked/ still denied after Alice cleanup")
    results.append(('PASS', 'post-alice: deny survives'))


# ===========================================================================
# SUMMARY
# ===========================================================================
passed = sum(1 for r in results if r[0] == 'PASS')
failed = sum(1 for r in results if r[0] == 'FAIL')
info = sum(1 for r in results if r[0] == 'INFO')

print(f"\n  BOB: {passed} pass, {failed} fail, {info} info")

sys.exit(0 if failed == 0 else 1)
