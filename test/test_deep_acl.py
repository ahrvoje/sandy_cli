"""Deep ACL test (AppContainer): 4-level nesting, granular allows, 46 test cases.

AC mode has NO deny support.  Zones that were deny-restricted in the RT variant
are implemented by simply withholding grants (no grant = no access for AC).
Zones that relied on deny.write or deny.read to get partial access (e.g. write-
only, read-only within an allow.all parent) are restructured: the parent loses
its broad allow.all, and only the children that need access get explicit grants.

Zone map (12 zones — AC mode):
  app/src              L2  (no grant)     → blocked
  app/src/core         L3  read           → list+read, no write
  app/src/core/engine  L4  inherits read  → list+read, no write
  app/src/contrib      L3  (no grant)     → blocked
  app/src/contrib/plug L4  (no grant)     → blocked
  app/docs/public/gui  L4  all (inherit)  → full control
  app/docs/classified  L3  (no grant)     → blocked
  app/docs/class/memos L4  (no grant)     → blocked
  lib/stable/v1        L3  read (inherit) → read only
  lib/experimental/bet L3  (no grant)     → blocked
  scripts/common/utils L3  execute+read   → read+exec, no write
  scripts/restricted/* L3  (no grant)     → blocked
"""
import os, sys

ROOT = r'C:\Users\H\test_deep'
results = []

def test(name, should_pass, fn):
    try:
        result = fn()
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
                print(f"  [FAIL] {name}: denied (SHOULD BE ALLOWED, w={e.winerror})")
                results.append(False)
        else:
            print(f"  [FAIL] {name}: OSError {e.winerror}: {e}")
            results.append(False)
    except Exception as e:
        print(f"  [FAIL] {name}: {type(e).__name__}: {e}")
        results.append(False)

def p(*parts):
    return os.path.join(ROOT, *parts)

# ================================================================
# ZONE 1: app/src (L2) — no grant → all access blocked
# ================================================================
print("--- Z1: app/src (L2, no grant — blocked) ---")
test("src: list",   False, lambda: os.listdir(p('app','src')))
test("src: read (core/core.py — inside read zone)",
                    True,  lambda: open(p('app','src','core','core.py'),'r').read())
test("src: write",  False, lambda: open(p('app','src','marker.tmp'),'w').write('ok'))
test("src: create", False, lambda: open(p('app','src','new.tmp'),'w').write('new'))

# ================================================================
# ZONE 2: app/src/core (L3) — read grant → list+read, write blocked
# ================================================================
print("--- Z2: app/src/core (L3, allow.read) ---")
test("core: list",   True,  lambda: os.listdir(p('app','src','core')))
test("core: read",   True,  lambda: open(p('app','src','core','core.py'),'r').read())
test("core: write",  False, lambda: open(p('app','src','core','core.py'),'w').write('x'))
test("core: create", False, lambda: open(p('app','src','core','hack.tmp'),'w').write('x'))
test("core: delete", False, lambda: os.remove(p('app','src','core','core.py')))

# ================================================================
# ZONE 3: app/src/core/engine (L4) — inherits read from core
# ================================================================
print("--- Z3: app/src/core/engine (L4, read inherited) ---")
test("engine: list",   True,  lambda: os.listdir(p('app','src','core','engine')))
test("engine: read",   True,  lambda: open(p('app','src','core','engine','module.py'),'r').read())
test("engine: write",  False, lambda: open(p('app','src','core','engine','module.py'),'w').write('x'))
test("engine: create", False, lambda: open(p('app','src','core','engine','new.tmp'),'w').write('x'))
test("engine: delete", False, lambda: os.remove(p('app','src','core','engine','module.py')))

# ================================================================
# ZONE 4: app/src/contrib (L3) — no grant → blocked
# ================================================================
print("--- Z4: app/src/contrib (L3, no grant — blocked) ---")
test("contrib: list",   False, lambda: os.listdir(p('app','src','contrib')))
test("contrib: read",   False, lambda: open(p('app','src','contrib','init.py'),'r').read())
test("contrib: write",  False, lambda: open(p('app','src','contrib','init.py'),'w').write('x'))
test("contrib: delete", False, lambda: os.remove(p('app','src','contrib','init.py')))

# ================================================================
# ZONE 5: app/src/contrib/plugins (L4) — no grant → blocked
# ================================================================
print("--- Z5: app/src/contrib/plugins (L4, no grant — blocked) ---")
test("plugins: list",   False, lambda: os.listdir(p('app','src','contrib','plugins')))
test("plugins: read",   False, lambda: open(p('app','src','contrib','plugins','addon.py'),'r').read())
test("plugins: write",  False, lambda: open(p('app','src','contrib','plugins','addon.py'),'w').write('x'))
test("plugins: delete", False, lambda: os.remove(p('app','src','contrib','plugins','addon.py')))

# ================================================================
# ZONE 6: app/docs/public/guides (L4) — all (inherited from docs/public)
# ================================================================
print("--- Z6: app/docs/public/guides (L4, all access) ---")
test("guides: list",   True, lambda: os.listdir(p('app','docs','public','guides')))
test("guides: read",   True, lambda: open(p('app','docs','public','guides','tutorial.md'),'r').read())
test("guides: write",  True, lambda: open(p('app','docs','public','guides','tutorial.md'),'w').write('x'))
test("guides: delete", True, lambda: os.remove(p('app','docs','public','guides','tutorial.md')))

# ================================================================
# ZONE 7: app/docs/classified (L3) — no grant → fully blocked
#   (AC can't do write-only; no deny available)
# ================================================================
print("--- Z7: app/docs/classified (L3, no grant — blocked) ---")
test("classified: list",   False, lambda: os.listdir(p('app','docs','classified')))
test("classified: read",   False, lambda: open(p('app','docs','classified','draft.md'),'r').read())
test("classified: write",  False, lambda: open(p('app','docs','classified','draft.md'),'w').write('ok'))
test("classified: create", False, lambda: open(p('app','docs','classified','new.tmp'),'w').write('x'))

# ================================================================
# ZONE 8: app/docs/classified/memos (L4) — no grant → blocked
# ================================================================
print("--- Z8: app/docs/classified/memos (L4, no grant — blocked) ---")
test("memos: list",   False, lambda: os.listdir(p('app','docs','classified','memos')))
test("memos: read",   False, lambda: open(p('app','docs','classified','memos','note.md'),'r').read())
test("memos: write",  False, lambda: open(p('app','docs','classified','memos','note.md'),'w').write('ok'))
test("memos: delete", False, lambda: os.remove(p('app','docs','classified','memos','note.md')))

# ================================================================
# ZONE 9: library/stable/v1 (L3) — read (inherited) → read only
# ================================================================
print("--- Z9: library/stable/v1 (L3, allow.read) ---")
test("v1: list",  True,  lambda: os.listdir(p('library','stable','v1')))
test("v1: read",  True,  lambda: open(p('library','stable','v1','mod.py'),'r').read())
test("v1: write", False, lambda: open(p('library','stable','v1','mod.py'),'w').write('x'))

# ================================================================
# ZONE 10: library/experimental/beta (L3) — no grant → blocked
# ================================================================
print("--- Z10: library/experimental/beta (L3, no grant — blocked) ---")
test("beta: list", False, lambda: os.listdir(p('library','experimental','beta')))
test("beta: read", False, lambda: open(p('library','experimental','beta','beta.py'),'r').read())

# ================================================================
# ZONE 11: scripts/common/utils (L3) — execute+read → read+exec
# ================================================================
print("--- Z11: scripts/common/utils (L3, allow.execute + read) ---")
test("utils: list",  True,  lambda: os.listdir(p('scripts','common','utils')))
test("utils: read",  True,  lambda: open(p('scripts','common','utils','helper.bat'),'r').read())
test("utils: write", False, lambda: open(p('scripts','common','utils','helper.bat'),'w').write('x'))

# ================================================================
# ZONE 12: scripts/restricted/admin (L3) — no grant → blocked
# ================================================================
print("--- Z12: scripts/restricted/admin (L3, no grant — blocked) ---")
test("admin: list", False, lambda: os.listdir(p('scripts','restricted','admin')))
test("admin: read", False, lambda: open(p('scripts','restricted','admin','root.bat'),'r').read())

# ================================================================
# SUMMARY
# ================================================================
passed = sum(results)
failed = len(results) - passed
print(f"\n=== Deep ACL Test: {passed} passed, {failed} failed (of {len(results)}) ===")
sys.exit(0 if failed == 0 else 1)
