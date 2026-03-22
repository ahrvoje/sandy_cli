"""Collusion test — Bob probe (Instance B)

Bob grants [all] to shared/ (AppContainer mode, no deny support).
He exits SECOND — his cleanup must restore the true original DACLs
without leaving zombie AppContainer SIDs from Alice's prior run.
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
# CHECK 1: Verify Bob has access to shared/ (both instances granted)
# ===========================================================================
print("\n=== BOB: Verify access to shared/ ===")
try:
    os.listdir(SHARED)
    print("  [PASS] Bob can list shared/")
    results.append(('PASS', 'access: shared/ listed'))
except PermissionError:
    print("  [FAIL] Bob can't list shared/ (grant not applied)")
    results.append(('FAIL', 'access: shared/ blocked'))

try:
    os.listdir(LOCKED)
    print("  [PASS] Bob can list locked/ (AC, all grant inherited)")
    results.append(('PASS', 'access: locked/ listed'))
except PermissionError:
    print("  [FAIL] Bob can't list locked/ (unexpected)")
    results.append(('FAIL', 'access: locked/ blocked'))


# ===========================================================================
# CHECK 2: Read exfiltrated data from relay (Alice wrote it)
# ===========================================================================
print("\n=== BOB: Read relay data ===")
exfil_file = os.path.join(RELAY, 'exfiltrated.txt')
# Wait for Alice to create the relay
for i in range(20):
    if os.path.exists(exfil_file):
        break
    time.sleep(0.5)

if os.path.exists(exfil_file):
    try:
        content = open(exfil_file, 'r').read()
        print(f"  [PASS] Bob read relay data: {content.strip()}")
        results.append(('PASS', 'relay: Bob read Alice data'))
    except PermissionError:
        print("  [FAIL] Bob can't read relay (unexpected)")
        results.append(('FAIL', 'relay: blocked'))
else:
    print("  [INFO] No relay file (Alice didn't post yet)")
    results.append(('INFO', 'relay: not available'))


# ===========================================================================
# CHECK 3: Concurrent write to shared area
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
    with open(p('bob_final.txt'), 'w') as f:
        f.write('BOB_FINAL')
    print("  [PASS] Bob can still write after Alice cleanup")
    results.append(('PASS', 'post-alice: Bob write OK'))
except Exception as e:
    print(f"  [FAIL] Bob can't write after Alice cleanup: {e}")
    results.append(('FAIL', f'post-alice: write failed'))


# ===========================================================================
# SUMMARY
# ===========================================================================
passed = sum(1 for r in results if r[0] == 'PASS')
failed = sum(1 for r in results if r[0] == 'FAIL')
info = sum(1 for r in results if r[0] == 'INFO')

# Signal Bob is done (used by batch script for completion detection)
with open(os.path.join(SIGNALS, 'bob_done'), 'w') as f:
    f.write('exit')

print(f"\n  BOB: {passed} pass, {failed} fail, {info} info")

sys.exit(0 if failed == 0 else 1)
