"""Test deny enforcement: ALL access granted to folder, WRITE denied to folder.
With DENY_ACCESS approach, reads should succeed but writes should be blocked.
DENY ACEs override ALLOW ACEs in Windows ACL evaluation."""
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

# Test 4: delete should SUCCEED (DELETE is separate from WRITE permission)
# If you want to deny delete, use deny.delete or deny.all
try:
    os.remove(seed)
    print(f"[PASS] Delete file: succeeded (DELETE is not part of WRITE mask)")
    results.append(True)
except PermissionError:
    print(f"[FAIL] Delete file: blocked (DELETE should not be blocked by deny.write)")
    results.append(False)

passed = sum(results)
failed = len(results) - passed
print(f"\n=== Deny Test: {passed} passed, {failed} failed ===")
sys.exit(0 if failed == 0 else 1)

