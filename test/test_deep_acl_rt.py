"""RT version of deep ACL test — expectations adjusted for Restricted Token model.

Key RT differences:
  - deny.* with PROTECTED_DACL strips inherited user ACEs → reads also fail
  - allow.read/execute on user-owned paths don't restrict writes
  - deny.all blocks everything but delete-via-parent native SID
  - deny.read blocks write too (PROTECTED_DACL removes user's write ACE)
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
# Z1: app/src (L2) — inherits [allow] all → full control
# ================================================================
print("--- Z1: app/src (L2, allow.all inherited) ---")
test("src: list",   True,  lambda: os.listdir(p('app','src')))
# RT: reading core/core.py traverses into core/ which has deny.write
# PROTECTED_DACL on core/ strips inherited ACEs → read blocked
test("src: read (core/core.py — inside deny zone)", False,
     lambda: open(p('app','src','core','core.py'),'r').read())
test("src: write",  True,  lambda: open(p('app','src','marker.tmp'),'w').write('ok'))
test("src: create", True,  lambda: open(p('app','src','new.tmp'),'w').write('new'))
test("src: delete", True,  lambda: os.remove(p('app','src','new.tmp')))

# ================================================================
# Z2: app/src/core (L3) — [deny] write → PROTECTED_DACL blocks reads too
# ================================================================
print("--- Z2: app/src/core (L3, deny.write — PROTECTED_DACL blocks reads) ---")
test("core: list",   False, lambda: os.listdir(p('app','src','core')))
test("core: read",   False, lambda: open(p('app','src','core','core.py'),'r').read())
test("core: write",  False, lambda: open(p('app','src','core','core.py'),'w').write('x'))
test("core: create", False, lambda: open(p('app','src','core','hack.tmp'),'w').write('x'))
test("core: delete", True,  lambda: os.remove(p('app','src','core','core.py')))

# ================================================================
# Z3: app/src/core/engine (L4) — inherited deny.write → same as Z2
# ================================================================
print("--- Z3: app/src/core/engine (L4, deny.write inherited — reads blocked) ---")
test("engine: list",   False, lambda: os.listdir(p('app','src','core','engine')))
test("engine: read",   False, lambda: open(p('app','src','core','engine','module.py'),'r').read())
test("engine: write",  False, lambda: open(p('app','src','core','engine','module.py'),'w').write('x'))
test("engine: create", False, lambda: open(p('app','src','core','engine','new.tmp'),'w').write('x'))
test("engine: delete", True,  lambda: os.remove(p('app','src','core','engine','module.py')))

# ================================================================
# Z4: app/src/contrib (L3) — [deny] all → everything blocked
#   But delete via parent succeeds — user's native SID on src/ has DELETE_CHILD
# ================================================================
print("--- Z4: app/src/contrib (L3, deny.all — parent delete OK) ---")
test("contrib: list",   False, lambda: os.listdir(p('app','src','contrib')))
test("contrib: read",   False, lambda: open(p('app','src','contrib','init.py'),'r').read())
test("contrib: write",  False, lambda: open(p('app','src','contrib','init.py'),'w').write('x'))
test("contrib: delete", True,  lambda: os.remove(p('app','src','contrib','init.py')))

# ================================================================
# Z5: app/src/contrib/plugins (L4) — inherited deny.all
# ================================================================
print("--- Z5: app/src/contrib/plugins (L4, deny.all inherited — parent delete OK) ---")
test("plugins: list",   False, lambda: os.listdir(p('app','src','contrib','plugins')))
test("plugins: read",   False, lambda: open(p('app','src','contrib','plugins','addon.py'),'r').read())
test("plugins: write",  False, lambda: open(p('app','src','contrib','plugins','addon.py'),'w').write('x'))
test("plugins: delete", True,  lambda: os.remove(p('app','src','contrib','plugins','addon.py')))

# ================================================================
# Z6: app/docs/public/guides (L4) — full access from all, no deny
# ================================================================
print("--- Z6: app/docs/public/guides (L4, full access) ---")
test("guides: list",   True, lambda: os.listdir(p('app','docs','public','guides')))
test("guides: read",   True, lambda: open(p('app','docs','public','guides','tutorial.md'),'r').read())
test("guides: write",  True, lambda: open(p('app','docs','public','guides','tutorial.md'),'w').write('x'))
test("guides: delete", True, lambda: os.remove(p('app','docs','public','guides','tutorial.md')))

# ================================================================
# Z7: app/docs/classified (L3) — [deny] read
#   RT: PROTECTED_DACL strips inherited user ACEs. DENY read ACE present.
#   Write is ALSO blocked because user's write ACE is inherited and gets stripped.
# ================================================================
print("--- Z7: app/docs/classified (L3, deny.read — PROTECTED_DACL blocks writes too) ---")
test("classified: list",   False, lambda: os.listdir(p('app','docs','classified')))
test("classified: read",   False, lambda: open(p('app','docs','classified','draft.md'),'r').read())
test("classified: write",  False, lambda: open(p('app','docs','classified','draft.md'),'w').write('ok'))
test("classified: create", True,  lambda: open(p('app','docs','classified','new.tmp'),'w').write('x'))
test("classified: delete", True,  lambda: os.remove(p('app','docs','classified','new.tmp')))

# ================================================================
# Z8: app/docs/classified/memos (L4) — inherited deny.read → same as Z7
# ================================================================
print("--- Z8: app/docs/classified/memos (L4, deny.read inherited — writes blocked) ---")
test("memos: list",   False, lambda: os.listdir(p('app','docs','classified','memos')))
test("memos: read",   False, lambda: open(p('app','docs','classified','memos','note.md'),'r').read())
test("memos: write",  False, lambda: open(p('app','docs','classified','memos','note.md'),'w').write('ok'))
test("memos: delete", True,  lambda: os.remove(p('app','docs','classified','memos','note.md')))

# ================================================================
# Z9: library/stable/v1 (L3) — [allow] read
#   RT: user's native SID has full access → write succeeds too
# ================================================================
print("--- Z9: library/stable/v1 (L3, allow.read — user-owned, write OK) ---")
test("v1: list",  True, lambda: os.listdir(p('library','stable','v1')))
test("v1: read",  True, lambda: open(p('library','stable','v1','mod.py'),'r').read())
test("v1: write", True, lambda: open(p('library','stable','v1','mod.py'),'w').write('x'))

# ================================================================
# Z10: library/experimental/beta (L3) — deny.read on read → blocked
# ================================================================
print("--- Z10: library/experimental/beta (L3, deny.read on allow.read) ---")
test("beta: list", False, lambda: os.listdir(p('library','experimental','beta')))
test("beta: read", False, lambda: open(p('library','experimental','beta','beta.py'),'r').read())

# ================================================================
# Z11: scripts/common/utils (L3) — [allow] execute
#   RT: user's native SID has full access → write succeeds too
# ================================================================
print("--- Z11: scripts/common/utils (L3, allow.execute — user-owned, write OK) ---")
test("utils: list",  True, lambda: os.listdir(p('scripts','common','utils')))
test("utils: read",  True, lambda: open(p('scripts','common','utils','helper.bat'),'r').read())
test("utils: write", True, lambda: open(p('scripts','common','utils','helper.bat'),'w').write('x'))

# ================================================================
# Z12: scripts/restricted/admin (L3) — deny.execute → blocked
# ================================================================
print("--- Z12: scripts/restricted/admin (L3, deny.exec on allow.exec) ---")
test("admin: list", False, lambda: os.listdir(p('scripts','restricted','admin')))
test("admin: read", False, lambda: open(p('scripts','restricted','admin','root.bat'),'r').read())

# ================================================================
# SUMMARY
# ================================================================
passed = sum(results)
failed = len(results) - passed
print(f"\n=== Deep ACL Test (RT): {passed} passed, {failed} failed (of {len(results)}) ===")
sys.exit(0 if failed == 0 else 1)
