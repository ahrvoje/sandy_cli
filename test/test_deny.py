"""Test deny enforcement: ALL access granted to folder, WRITE denied to folder.
With REVOKE_ACCESS approach, the SID's ACE is stripped entirely from the
denied path — so ALL access (read, write, execute, delete) should be blocked."""
import os, sys

folder = r'C:\Users\H\test_RW'
results = []

# Test 1: list dir should be BLOCKED (whole ACE revoked)
try:
    items = os.listdir(folder)
    print(f"[FAIL] List dir: {len(items)} items (should be blocked)")
    results.append(False)
except PermissionError:
    print(f"[PASS] List dir: blocked (ACE revoked)")
    results.append(True)

# Test 2: read file should be BLOCKED
seed = os.path.join(folder, 'seed.txt')
try:
    with open(seed, 'r') as f:
        f.read()
    print(f"[FAIL] Read file: succeeded (should be blocked)")
    results.append(False)
except PermissionError:
    print(f"[PASS] Read file: blocked (ACE revoked)")
    results.append(True)

# Test 3: write should be BLOCKED
try:
    with open(os.path.join(folder, 'test.txt'), 'w') as f:
        f.write('test')
    print(f"[FAIL] Write file: succeeded (should be blocked)")
    results.append(False)
except PermissionError:
    print(f"[PASS] Write file: blocked (ACE revoked)")
    results.append(True)

passed = sum(results)
failed = len(results) - passed
print(f"\n=== Deny Test: {passed} passed, {failed} failed ===")
sys.exit(0 if failed == 0 else 1)
