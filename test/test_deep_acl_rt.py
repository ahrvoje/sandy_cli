"""RT version of deep ACL test — expectations adjusted for Restricted Token model.

Key RT differences:
  - allow.read/execute on user-owned paths don't restrict writes
  - a deny blocks only the level it names: deny.write keeps read and delete,
    deny.read keeps write, deny.execute keeps read
  - deny.all blocks everything, delete included
"""
import os, subprocess, sys

ROOT = os.path.join(os.environ['USERPROFILE'], 'test_deep')
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
# core/ has deny.write only: reading a file in it stays allowed
test("src: read (core/core.py — inside deny.write zone)", True,
     lambda: open(p('app','src','core','core.py'),'r').read())
test("src: write",  True,  lambda: open(p('app','src','marker.tmp'),'w').write('ok'))
test("src: create", True,  lambda: open(p('app','src','new.tmp'),'w').write('new'))
test("src: delete", True,  lambda: os.remove(p('app','src','new.tmp')))

# ================================================================
# Z2: app/src/core (L3) — [deny] write → read OK, write blocked, delete OK
# ================================================================
print("--- Z2: app/src/core (L3, deny.write — read OK, write blocked) ---")
test("core: list",   True,  lambda: os.listdir(p('app','src','core')))
test("core: read",   True,  lambda: open(p('app','src','core','core.py'),'r').read())
test("core: write",  False, lambda: open(p('app','src','core','core.py'),'w').write('x'))
test("core: create", False, lambda: open(p('app','src','core','hack.tmp'),'w').write('x'))
test("core: delete", True,  lambda: os.remove(p('app','src','core','core.py')))

# ================================================================
# Z3: app/src/core/engine (L4) — inherited deny.write → same as Z2
# ================================================================
print("--- Z3: app/src/core/engine (L4, deny.write inherited — read OK) ---")
test("engine: list",   True,  lambda: os.listdir(p('app','src','core','engine')))
test("engine: read",   True,  lambda: open(p('app','src','core','engine','module.py'),'r').read())
test("engine: write",  False, lambda: open(p('app','src','core','engine','module.py'),'w').write('x'))
test("engine: create", False, lambda: open(p('app','src','core','engine','new.tmp'),'w').write('x'))
test("engine: delete", True,  lambda: os.remove(p('app','src','core','engine','module.py')))

# ================================================================
# Z4: app/src/contrib (L3) — [deny] all → everything blocked
#   Delete too: the deny holds FILE_DELETE_CHILD, so the right of the user's
#   native SID on the folder does not delete the files.
# ================================================================
print("--- Z4: app/src/contrib (L3, deny.all — delete blocked too) ---")
test("contrib: list",   False, lambda: os.listdir(p('app','src','contrib')))
test("contrib: read",   False, lambda: open(p('app','src','contrib','init.py'),'r').read())
test("contrib: write",  False, lambda: open(p('app','src','contrib','init.py'),'w').write('x'))
test("contrib: delete", False, lambda: os.remove(p('app','src','contrib','init.py')))

# ================================================================
# Z5: app/src/contrib/plugins (L4) — inherited deny.all
# ================================================================
print("--- Z5: app/src/contrib/plugins (L4, deny.all inherited — delete blocked too) ---")
test("plugins: list",   False, lambda: os.listdir(p('app','src','contrib','plugins')))
test("plugins: read",   False, lambda: open(p('app','src','contrib','plugins','addon.py'),'r').read())
test("plugins: write",  False, lambda: open(p('app','src','contrib','plugins','addon.py'),'w').write('x'))
test("plugins: delete", False, lambda: os.remove(p('app','src','contrib','plugins','addon.py')))

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
#   Read and list are blocked.  Write is not: deny.read does not name it.
# ================================================================
print("--- Z7: app/docs/classified (L3, deny.read — read blocked, write OK) ---")
test("classified: list",   False, lambda: os.listdir(p('app','docs','classified')))
test("classified: read",   False, lambda: open(p('app','docs','classified','draft.md'),'r').read())
test("classified: write",  True,  lambda: open(p('app','docs','classified','draft.md'),'w').write('ok'))
test("classified: create", True,  lambda: open(p('app','docs','classified','new.tmp'),'w').write('x'))
test("classified: delete", True,  lambda: os.remove(p('app','docs','classified','new.tmp')))

# ================================================================
# Z8: app/docs/classified/memos (L4) — inherited deny.read → same as Z7
# ================================================================
print("--- Z8: app/docs/classified/memos (L4, deny.read inherited — write OK) ---")
test("memos: list",   False, lambda: os.listdir(p('app','docs','classified','memos')))
test("memos: read",   False, lambda: open(p('app','docs','classified','memos','note.md'),'r').read())
test("memos: write",  True,  lambda: open(p('app','docs','classified','memos','note.md'),'w').write('ok'))
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
# Z12: scripts/restricted/admin (L3) — deny.execute
#   Only execution is blocked: list and read stay allowed.  The same
#   program runs from scripts/common/utils (no deny there).
# ================================================================
print("--- Z12: scripts/restricted/admin (L3, deny.exec on allow.exec) ---")
test("admin: list", True,  lambda: os.listdir(p('scripts','restricted','admin')))
test("admin: read", True,  lambda: open(p('scripts','restricted','admin','root.bat'),'r').read())
test("utils: run tool.exe",  True,
     lambda: subprocess.run([p('scripts','common','utils','tool.exe')], capture_output=True, timeout=20))
test("admin: run tool.exe",  False,
     lambda: subprocess.run([p('scripts','restricted','admin','tool.exe')], capture_output=True, timeout=20))

# ================================================================
# SUMMARY
# ================================================================
passed = sum(results)
failed = len(results) - passed
print(f"\n=== Deep ACL Test (RT): {passed} passed, {failed} failed (of {len(results)}) ===")
sys.exit(0 if failed == 0 else 1)
