"""Collusion test — Alice probe (Instance A)

Alice grants [all] to shared/ (AppContainer mode).
She exits FIRST to trigger the cleanup race condition.

The key scenario:
  Alice's Sandy adds SID_A ACE to shared/.
  Bob starts AFTER Alice -> Bob also adds SID_B ACE.
  Alice exits: her cleanup removes SID_A ACEs.
  Bob exits: his cleanup removes SID_B ACEs.
  Without cleanup serialization, auto-inheritance interleaving
  can leave orphaned SIDs on the shared tree.
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


print("=== ALICE START ===")

# --- Signal readiness ---
os.makedirs(SIGNALS, exist_ok=True)
with open(os.path.join(SIGNALS, 'alice_ready'), 'w') as f:
    f.write(str(os.getpid()))
print("  [OK] Alice ready signal posted")

# --- Wait for Bob to be ready (max 30s) ---
bob_ready = os.path.join(SIGNALS, 'bob_ready')
for i in range(60):
    if os.path.exists(bob_ready):
        break
    time.sleep(0.5)
if os.path.exists(bob_ready):
    print("  [OK] Bob is ready — both instances running concurrently")
else:
    print("  [WARN] Bob never showed up (timeout)")


# ===========================================================================
# CHECK 1: Verify access — Alice has [all] on shared/
# ===========================================================================
print("\n=== ATTACK 1: Cross-instance access ===")
try:
    # Alice writes to locked/ — both instances have [all] on shared/
    with open(os.path.join(LOCKED, 'alice_was_here.txt'), 'w') as f:
        f.write('DATA_FROM_ALICE: Bob cannot read this directly')
    print("  [INFO] Alice wrote to shared/locked/")
    results.append(('INFO', 'access: Alice wrote to locked/'))
except PermissionError:
    print("  [FAIL] Alice blocked from locked/ (unexpected)")
    results.append(('FAIL', 'access: Alice blocked'))

# Alice can also read the seed secret
try:
    content = open(os.path.join(LOCKED, 'secret.txt'), 'r').read()
    print(f"  [INFO] Alice read secret: {content.strip()}")
    results.append(('INFO', f'access: secret={content.strip()}'))
except Exception as e:
    print(f"  [ERR] Alice can't read secret: {e}")
    results.append(('ERR', f'access: {e}'))


# ===========================================================================
# CHECK 2: Data relay — Alice copies data for Bob to read later
# ===========================================================================
print("\n=== ATTACK 2: Data relay ===")
os.makedirs(RELAY, exist_ok=True)
try:
    secret = open(os.path.join(LOCKED, 'secret.txt'), 'r').read()
    with open(os.path.join(RELAY, 'exfiltrated.txt'), 'w') as f:
        f.write(f'EXFILTRATED: {secret}')
    print("  [INFO] Alice relayed secret to shared/relay/")
    results.append(('INFO', 'relay: secret copied'))
except Exception as e:
    print(f"  [ERR] relay: {e}")
    results.append(('ERR', f'relay: {e}'))


# ===========================================================================
# CHECK 3: ACL accumulation — verify Alice can read shared/
# ===========================================================================
print("\n=== ATTACK 3: ACL accumulation probe ===")
try:
    import ctypes, ctypes.wintypes
    # Just check if we can query the DACL
    h = ctypes.windll.kernel32.CreateFileW(
        SHARED, 0x80000000, 0x7, None, 3, 0x02000000, None)  # GENERIC_READ
    if h != ctypes.wintypes.HANDLE(-1).value and h != -1:
        ctypes.windll.kernel32.CloseHandle(h)
        print("  [PASS] Alice can open shared/ for reading")
        results.append(('PASS', 'acl: Alice can read shared/'))
    else:
        print("  [FAIL] Alice can't open shared/")
        results.append(('FAIL', 'acl: Alice blocked'))
except ImportError as e:
    print(f"  [SKIP] ctypes not available in sandbox: {e}")
    results.append(('SKIP', f'acl: ctypes unavailable'))
except Exception as e:
    print(f"  [ERR] {e}")
    results.append(('ERR', f'acl: {e}'))


# ===========================================================================
# Signal Alice is done and exit FIRST
# ===========================================================================
print("\n=== ALICE EXITING FIRST ===")
with open(os.path.join(SIGNALS, 'alice_done'), 'w') as f:
    f.write('exit')

print(f"\n  ALICE: {sum(1 for r in results if r[0]=='PASS')} pass, "
      f"{sum(1 for r in results if r[0]=='FAIL')} fail, "
      f"{sum(1 for r in results if r[0]=='INFO')} info")

sys.exit(0)
