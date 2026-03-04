"""Test nuanced ACL grants with complex overlapping allow/deny.

Folder tree (created by test_acl_grants.bat):
  test_acl/
    workspace/          [allow] all
      src/              inherits all → full control
      build/            [deny] write → read OK, write/create blocked
      secrets/          [deny] all → everything blocked
    data/               [allow] read
      public/           inherits read → read-only
      private/          [deny] read → fully blocked (deny > allow)
    logs/               [allow] append → append only
    tools/              [allow] execute → read+exec, no write

DENY PRIORITY: if a path is in [deny], those permissions MUST be blocked
even if a parent [allow] would grant them.
"""
import os, sys

ROOT = r'C:\Users\H\test_acl'
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
        if e.winerror in (5, 1314):  # ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD
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
# ================================================================
print("--- workspace/src (allow.all inherited) ---")
test("src: list dir",   True,  lambda: os.listdir(p('workspace','src')))
test("src: read file",  True,  lambda: open(p('workspace','src','code.py'),'r').read())
test("src: write file", True,  lambda: open(p('workspace','src','code.py'),'w').write('modified'))
test("src: create file", True, lambda: open(p('workspace','src','new.tmp'),'w').write('new'))
test("src: delete file", True, lambda: os.remove(p('workspace','src','new.tmp')))

# ================================================================
# GROUP 2: workspace/build — [deny] write overrides inherited all
#   Read/list OK, write/create BLOCKED, delete OK (DELETE != WRITE)
# ================================================================
print("--- workspace/build (allow.all + deny.write) ---")
test("build: list dir",      True,  lambda: os.listdir(p('workspace','build')))
test("build: read file",     True,  lambda: open(p('workspace','build','artifact.bin'),'r').read())
test("build: overwrite file", False, lambda: open(p('workspace','build','artifact.bin'),'w').write('hack'))
test("build: create file",   False, lambda: open(p('workspace','build','deny_test.tmp'),'w').write('x'))
test("build: delete file",   True,  lambda: os.remove(p('workspace','build','artifact.bin')))

# ================================================================
# GROUP 3: workspace/secrets — [deny] all overrides inherited all
#   EVERYTHING blocked
# ================================================================
print("--- workspace/secrets (allow.all + deny.all) ---")
test("secrets: list dir",    False, lambda: os.listdir(p('workspace','secrets')))
test("secrets: read file",   False, lambda: open(p('workspace','secrets','key.pem'),'r').read())
test("secrets: write file",  False, lambda: open(p('workspace','secrets','key.pem'),'w').write('x'))
test("secrets: create file", False, lambda: open(p('workspace','secrets','new.tmp'),'w').write('x'))
test("secrets: delete file", False, lambda: os.remove(p('workspace','secrets','key.pem')))

# ================================================================
# GROUP 4: data/public — inherits [allow] read → read-only
# ================================================================
print("--- data/public (allow.read inherited) ---")
test("public: list dir",     True,  lambda: os.listdir(p('data','public')))
test("public: read file",    True,  lambda: open(p('data','public','info.txt'),'r').read())
test("public: write file",   False, lambda: open(p('data','public','info.txt'),'w').write('x'))
test("public: create file",  False, lambda: open(p('data','public','new.tmp'),'w').write('x'))
test("public: delete file",  False, lambda: os.remove(p('data','public','info.txt')))

# ================================================================
# GROUP 5: data/private — [deny] read overrides inherited read
#   Deny > Allow: even though parent grants read, this path is denied
# ================================================================
print("--- data/private (allow.read + deny.read = DENIED) ---")
test("private: list dir",   False, lambda: os.listdir(p('data','private')))
test("private: read file",  False, lambda: open(p('data','private','hidden.txt'),'r').read())
test("private: write file", False, lambda: open(p('data','private','hidden.txt'),'w').write('x'))

# ================================================================
# GROUP 6: logs — [allow] append → append only, no read/write
# ================================================================
print("--- logs (allow.append) ---")
test("logs: list dir",  False, lambda: os.listdir(p('logs')))
test("logs: read file", False, lambda: open(p('logs','app.log'),'r').read())
# Note: Python open('w') uses GENERIC_WRITE which includes FILE_WRITE_DATA
# (not in append mask), so overwrite should fail
test("logs: overwrite file", False, lambda: open(p('logs','app.log'),'w').write('x'))

# ================================================================
# GROUP 7: tools — [allow] execute → read + execute, no write/delete
# ================================================================
print("--- tools (allow.execute) ---")
test("tools: list dir",    True,  lambda: os.listdir(p('tools')))
test("tools: read file",   True,  lambda: open(p('tools','script.bat'),'r').read())
test("tools: write file",  False, lambda: open(p('tools','script.bat'),'w').write('x'))
test("tools: create file", False, lambda: open(p('tools','new.tmp'),'w').write('x'))
test("tools: delete file", False, lambda: os.remove(p('tools','script.bat')))

# ================================================================
# SUMMARY
# ================================================================
passed = sum(results)
failed = len(results) - passed
print(f"\n=== ACL Grants Test: {passed} passed, {failed} failed (of {len(results)}) ===")
sys.exit(0 if failed == 0 else 1)
