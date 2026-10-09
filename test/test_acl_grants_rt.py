"""RT version of ACL grants test — expectations adjusted for Restricted Token model.

Key RT differences from AppContainer:
  - allow.read/execute/append on user-owned paths don't restrict writes
    (user's native SID still has full access)
  - a deny blocks only the level it names: deny.write keeps read and
    delete, deny.read keeps write
  - deny.all blocks everything, delete included
"""
import os, sys

ROOT = os.path.join(os.environ['USERPROFILE'], 'test_acl')
results = []

def test(name, should_pass, fn):
    """Run fn. should_pass=True = expect success, False = expect PermissionError."""
    try:
        fn()
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
                print(f"  [FAIL] {name}: denied (SHOULD BE ALLOWED, winerror={e.winerror})")
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
# GROUP 1: workspace/src — inherits [allow] all → full control
# Same as AC — allow.all grants everything, no deny
# ================================================================
print("--- workspace/src (allow.all inherited) ---")
test("src: list dir",   True,  lambda: os.listdir(p('workspace','src')))
test("src: read file",  True,  lambda: open(p('workspace','src','code.py'),'r').read())
test("src: write file", True,  lambda: open(p('workspace','src','code.py'),'w').write('modified'))
test("src: create file", True, lambda: open(p('workspace','src','new.tmp'),'w').write('new'))
test("src: delete file", True, lambda: os.remove(p('workspace','src','new.tmp')))

# ================================================================
# GROUP 2: workspace/build — [deny] write overrides inherited all
#   Deny is surgical: read/list stay allowed, write/create are blocked,
#   delete stays allowed (deny.write is not deny.delete).
# ================================================================
print("--- workspace/build (deny.write — read OK, write blocked, delete OK) ---")
test("build: list dir",      True,  lambda: os.listdir(p('workspace','build')))
test("build: read file",     True,  lambda: open(p('workspace','build','artifact.bin'),'r').read())
test("build: overwrite file", False, lambda: open(p('workspace','build','artifact.bin'),'w').write('hack'))
test("build: create file",   False, lambda: open(p('workspace','build','deny_test.tmp'),'w').write('x'))
test("build: delete file",   True,  lambda: os.remove(p('workspace','build','artifact.bin')))

# ================================================================
# GROUP 3: workspace/secrets — [deny] all → everything blocked
#   Delete is blocked too: the deny holds FILE_DELETE_CHILD, so the right
#   of the user's native SID on the folder does not delete the files.
# ================================================================
print("--- workspace/secrets (deny.all — everything blocked, delete included) ---")
test("secrets: list dir",    False, lambda: os.listdir(p('workspace','secrets')))
test("secrets: read file",   False, lambda: open(p('workspace','secrets','key.pem'),'r').read())
test("secrets: write file",  False, lambda: open(p('workspace','secrets','key.pem'),'w').write('x'))
test("secrets: create file", False, lambda: open(p('workspace','secrets','new.tmp'),'w').write('x'))
test("secrets: delete file", False, lambda: os.remove(p('workspace','secrets','key.pem')))

# ================================================================
# GROUP 4: data/public — inherits [allow] read
#   RT: user's native SID already has full access to user-owned paths.
#   Restricting SID has read ACE, but user's SID bypasses → all ops succeed.
# ================================================================
print("--- data/public (allow.read — but user-owned, full access via native SID) ---")
test("public: list dir",     True, lambda: os.listdir(p('data','public')))
test("public: read file",    True, lambda: open(p('data','public','info.txt'),'r').read())
test("public: write file",   True, lambda: open(p('data','public','info.txt'),'w').write('x'))
test("public: create file",  True, lambda: open(p('data','public','new.tmp'),'w').write('x'))
test("public: delete file",  True, lambda: os.remove(p('data','public','new.tmp')))

# ================================================================
# GROUP 5: data/private — [deny] read on top of allow.read
#   Read and list are blocked.  Write is not: deny.read does not name it,
#   and the user's native SID gives write on user-owned paths.
# ================================================================
print("--- data/private (deny.read — read blocked, write OK) ---")
test("private: list dir",   False, lambda: os.listdir(p('data','private')))
test("private: read file",  False, lambda: open(p('data','private','hidden.txt'),'r').read())
test("private: write file", True,  lambda: open(p('data','private','hidden.txt'),'w').write('x'))

# ================================================================
# GROUP 6: logs — [allow] append
#   RT: user's native SID has full access → all ops succeed.
#   The restricting SID append ACE is additive, not restrictive.
# ================================================================
print("--- logs (allow.append — user-owned, full access via native SID) ---")
test("logs: list dir",       True, lambda: os.listdir(p('logs')))
test("logs: read file",      True, lambda: open(p('logs','app.log'),'r').read())
test("logs: overwrite file", True, lambda: open(p('logs','app.log'),'w').write('x'))

# ================================================================
# GROUP 7: tools — [allow] execute
#   RT: user's native SID has full access → all ops succeed.
# ================================================================
print("--- tools (allow.execute — user-owned, full access via native SID) ---")
test("tools: list dir",    True, lambda: os.listdir(p('tools')))
test("tools: read file",   True, lambda: open(p('tools','script.bat'),'r').read())
test("tools: write file",  True, lambda: open(p('tools','script.bat'),'w').write('x'))
test("tools: create file", True, lambda: open(p('tools','new.tmp'),'w').write('x'))
test("tools: delete file", True, lambda: os.remove(p('tools','new.tmp')))

# ================================================================
# SUMMARY
# ================================================================
passed = sum(results)
failed = len(results) - passed
print(f"\n=== ACL Grants Test (RT): {passed} passed, {failed} failed (of {len(results)}) ===")
sys.exit(0 if failed == 0 else 1)
