"""Deep ACL test: 4-level nesting, heterogeneous allow/deny, 46 test cases.

Tests deny-over-allow priority, deny inheritance to L4, and all access levels.

Zone map (12 zones):
  app/src              L2  all            → full control
  app/src/core         L3  all+deny.write → read OK, write blocked
  app/src/core/engine  L4  inherited deny → read OK, write blocked
  app/src/contrib      L3  all+deny.all   → everything blocked
  app/src/contrib/plug L4  inherited deny → everything blocked
  app/docs/public/gui  L4  all            → full control
  app/docs/classified  L3  all+deny.read  → write OK, read blocked
  app/docs/class/memos L4  inherited deny → write OK, read blocked
  lib/stable/v1        L3  read           → read only
  lib/experimental/bet L3  read+deny.read → fully blocked
  scripts/common/utils L3  execute        → read+exec, no write
  scripts/restricted/* L3  exec+deny.exec → fully blocked
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
# ZONE 1: app/src (L2) — inherits [allow] all → full control
# ================================================================
print("--- Z1: app/src (L2, allow.all inherited) ---")
test("src: list",   True,  lambda: os.listdir(p('app','src')))
test("src: read",   True,  lambda: open(p('app','src','core','core.py'),'r').read())
test("src: write",  True,  lambda: open(p('app','src','marker.tmp'),'w').write('ok'))
test("src: create", True,  lambda: open(p('app','src','new.tmp'),'w').write('new'))
test("src: delete", True,  lambda: os.remove(p('app','src','new.tmp')))

# ================================================================
# ZONE 2: app/src/core (L3) — [deny] write → read OK, write blocked
# ================================================================
print("--- Z2: app/src/core (L3, deny.write) ---")
test("core: list",   True,  lambda: os.listdir(p('app','src','core')))
test("core: read",   True,  lambda: open(p('app','src','core','core.py'),'r').read())
test("core: write",  False, lambda: open(p('app','src','core','core.py'),'w').write('x'))
test("core: create", False, lambda: open(p('app','src','core','hack.tmp'),'w').write('x'))
test("core: delete", True,  lambda: os.remove(p('app','src','core','core.py')))

# ================================================================
# ZONE 3: app/src/core/engine (L4) — inherited deny.write from L3
# ================================================================
print("--- Z3: app/src/core/engine (L4, deny.write inherited) ---")
test("engine: list",   True,  lambda: os.listdir(p('app','src','core','engine')))
test("engine: read",   True,  lambda: open(p('app','src','core','engine','module.py'),'r').read())
test("engine: write",  False, lambda: open(p('app','src','core','engine','module.py'),'w').write('x'))
test("engine: create", False, lambda: open(p('app','src','core','engine','new.tmp'),'w').write('x'))
test("engine: delete", True,  lambda: os.remove(p('app','src','core','engine','module.py')))

# ================================================================
# ZONE 4: app/src/contrib (L3) — [deny] all → everything blocked
# ================================================================
print("--- Z4: app/src/contrib (L3, deny.all) ---")
test("contrib: list",   False, lambda: os.listdir(p('app','src','contrib')))
test("contrib: read",   False, lambda: open(p('app','src','contrib','init.py'),'r').read())
test("contrib: write",  False, lambda: open(p('app','src','contrib','init.py'),'w').write('x'))
test("contrib: delete", False, lambda: os.remove(p('app','src','contrib','init.py')))

# ================================================================
# ZONE 5: app/src/contrib/plugins (L4) — inherited deny.all
# ================================================================
print("--- Z5: app/src/contrib/plugins (L4, deny.all inherited) ---")
test("plugins: list",   False, lambda: os.listdir(p('app','src','contrib','plugins')))
test("plugins: read",   False, lambda: open(p('app','src','contrib','plugins','addon.py'),'r').read())
test("plugins: write",  False, lambda: open(p('app','src','contrib','plugins','addon.py'),'w').write('x'))
test("plugins: delete", False, lambda: os.remove(p('app','src','contrib','plugins','addon.py')))

# ================================================================
# ZONE 6: app/docs/public/guides (L4) — full access from all
# ================================================================
print("--- Z6: app/docs/public/guides (L4, full access) ---")
test("guides: list",   True, lambda: os.listdir(p('app','docs','public','guides')))
test("guides: read",   True, lambda: open(p('app','docs','public','guides','tutorial.md'),'r').read())
test("guides: write",  True, lambda: open(p('app','docs','public','guides','tutorial.md'),'w').write('x'))
test("guides: delete", True, lambda: os.remove(p('app','docs','public','guides','tutorial.md')))

# ================================================================
# ZONE 7: app/docs/classified (L3) — [deny] read → write OK, read blocked
# ================================================================
print("--- Z7: app/docs/classified (L3, deny.read) ---")
test("classified: list",   False, lambda: os.listdir(p('app','docs','classified')))
test("classified: read",   False, lambda: open(p('app','docs','classified','draft.md'),'r').read())
test("classified: write",  True,  lambda: open(p('app','docs','classified','draft.md'),'w').write('ok'))
test("classified: create", True,  lambda: open(p('app','docs','classified','new.tmp'),'w').write('x'))
test("classified: delete", True,  lambda: os.remove(p('app','docs','classified','new.tmp')))

# ================================================================
# ZONE 8: app/docs/classified/memos (L4) — inherited deny.read
# ================================================================
print("--- Z8: app/docs/classified/memos (L4, deny.read inherited) ---")
test("memos: list",   False, lambda: os.listdir(p('app','docs','classified','memos')))
test("memos: read",   False, lambda: open(p('app','docs','classified','memos','note.md'),'r').read())
test("memos: write",  True,  lambda: open(p('app','docs','classified','memos','note.md'),'w').write('ok'))
test("memos: delete", True,  lambda: os.remove(p('app','docs','classified','memos','note.md')))

# ================================================================
# ZONE 9: library/stable/v1 (L3) — [allow] read → read only
# ================================================================
print("--- Z9: library/stable/v1 (L3, allow.read) ---")
test("v1: list",  True,  lambda: os.listdir(p('library','stable','v1')))
test("v1: read",  True,  lambda: open(p('library','stable','v1','mod.py'),'r').read())
test("v1: write", False, lambda: open(p('library','stable','v1','mod.py'),'w').write('x'))

# ================================================================
# ZONE 10: library/experimental/beta (L3) — deny.read on read → blocked
# ================================================================
print("--- Z10: library/experimental/beta (L3, deny.read on allow.read) ---")
test("beta: list", False, lambda: os.listdir(p('library','experimental','beta')))
test("beta: read", False, lambda: open(p('library','experimental','beta','beta.py'),'r').read())

# ================================================================
# ZONE 11: scripts/common/utils (L3) — [allow] execute → read+exec
# ================================================================
print("--- Z11: scripts/common/utils (L3, allow.execute) ---")
test("utils: list",  True,  lambda: os.listdir(p('scripts','common','utils')))
test("utils: read",  True,  lambda: open(p('scripts','common','utils','helper.bat'),'r').read())
test("utils: write", False, lambda: open(p('scripts','common','utils','helper.bat'),'w').write('x'))

# ================================================================
# ZONE 12: scripts/restricted/admin (L3) — deny.execute → blocked
# ================================================================
print("--- Z12: scripts/restricted/admin (L3, deny.exec on allow.exec) ---")
test("admin: list", False, lambda: os.listdir(p('scripts','restricted','admin')))
test("admin: read", False, lambda: open(p('scripts','restricted','admin','root.bat'),'r').read())

# ================================================================
# SUMMARY
# ================================================================
passed = sum(results)
failed = len(results) - passed
print(f"\n=== Deep ACL Test: {passed} passed, {failed} failed (of {len(results)}) ===")
sys.exit(0 if failed == 0 else 1)
