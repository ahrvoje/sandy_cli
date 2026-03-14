"""Test AC allow-only: READ-ONLY grant on folder.
Reads should succeed, writes and deletes should be blocked.
For actual deny testing, use the RT variant."""
import os, sys

folder = r'C:\Users\H\test_RW'
results = []

# Test 1: list dir should SUCCEED (only write is denied, read still allowed)
try:
    items = os.listdir(folder)
    print(f"[PASS] List dir: {len(items)} items (read allowed)")
    results.append(True)
except PermissionError:
    print(f"[FAIL] List dir: blocked (read should be allowed)")
    results.append(False)

# Test 2: read file should SUCCEED
seed = os.path.join(folder, 'seed.txt')
try:
    with open(seed, 'r') as f:
        content = f.read()
    print(f"[PASS] Read file: {len(content)} bytes (read allowed)")
    results.append(True)
except PermissionError:
    print(f"[FAIL] Read file: blocked (read should be allowed)")
    results.append(False)

# Test 3: write should be BLOCKED (DENY ACE)
try:
    with open(os.path.join(folder, 'test_deny_output.txt'), 'w') as f:
        f.write('test')
    print(f"[FAIL] Write file: succeeded (should be blocked by DENY ACE)")
    results.append(False)
    # Cleanup
    try: os.remove(os.path.join(folder, 'test_deny_output.txt'))
    except: pass
except PermissionError:
    print(f"[PASS] Write file: blocked (DENY ACE working)")
    results.append(True)

# Test 4: delete should FAIL (read-only grant has no DELETE permission)
try:
    os.remove(seed)
    print(f"[FAIL] Delete file: succeeded (should be blocked with read-only grant)")
    results.append(False)
except PermissionError:
    print(f"[PASS] Delete file: blocked (read-only grant, no DELETE)")
    results.append(True)

passed = sum(results)
failed = len(results) - passed
print(f"\n=== Deny Test: {passed} passed, {failed} failed ===")
sys.exit(0 if failed == 0 else 1)

