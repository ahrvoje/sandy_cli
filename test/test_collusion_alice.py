"""Collusion test — Alice probe (Instance A)

Alice grants [all] to shared/ with NO denies.
She exploits access to shared/locked/ (which Bob can't touch)
and relays data to Bob via shared/relay/.
Alice exits FIRST to trigger the cleanup race condition.

The key attack:
  Alice's Sandy saves SDDL_0 (true original) for shared/.
  Alice's Sandy adds SID_A ACE -> SDDL_1.
  Bob starts AFTER Alice -> Bob saves SDDL_1 as "original" (includes SID_A!).
  Bob's Sandy adds SID_B ACE -> SDDL_2.
  Alice exits: GetOtherInstancePaths sees Bob alive -> SKIPS shared/.
  Bob exits: restores SDDL_1 (with SID_A ACE baked in!) -> ORPHANED!
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
# ATTACK 1: Cross-deny breach — Alice writes to Bob's denied area
# ===========================================================================
print("\n=== ATTACK 1: Cross-deny breach ===")
try:
    # Alice has NO deny on locked/ — she can write!
    with open(os.path.join(LOCKED, 'alice_was_here.txt'), 'w') as f:
        f.write('DATA_FROM_ALICE: Bob cannot read this directly')
    print("  [INFO] Alice wrote to shared/locked/ (Bob's denied zone)")
    results.append(('INFO', 'cross-deny: Alice wrote to locked/'))
except PermissionError:
    print("  [FAIL] Alice blocked from locked/ (unexpected)")
    results.append(('FAIL', 'cross-deny: Alice blocked'))

# Alice can also read the seed secret
try:
    content = open(os.path.join(LOCKED, 'secret.txt'), 'r').read()
    print(f"  [INFO] Alice read secret: {content.strip()}")
    results.append(('INFO', f'cross-deny: secret={content.strip()}'))
except Exception as e:
    print(f"  [ERR] Alice can't read secret: {e}")
    results.append(('ERR', f'cross-deny: {e}'))


# ===========================================================================
# ATTACK 2: Data relay — Alice copies forbidden data for Bob
# ===========================================================================
print("\n=== ATTACK 2: Data relay ===")
os.makedirs(RELAY, exist_ok=True)
try:
    secret = open(os.path.join(LOCKED, 'secret.txt'), 'r').read()
    with open(os.path.join(RELAY, 'exfiltrated.txt'), 'w') as f:
        f.write(f'EXFILTRATED: {secret}')
    print("  [INFO] Alice relayed secret to shared/relay/")
    results.append(('INFO', 'relay: secret copied to non-denied area'))
except Exception as e:
    print(f"  [ERR] relay: {e}")
    results.append(('ERR', f'relay: {e}'))


# ===========================================================================
# ATTACK 3: ACL accumulation — verify both SIDs are on shared/
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
