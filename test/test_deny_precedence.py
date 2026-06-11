import os, sys, pathlib

# Same-path deny precedence: when an [allow.*] and a [deny.*] rule target the
# SAME path, the explicit deny must win (Windows deny-before-allow semantics).
# A broad allow on the path must NOT cause Sandy to discard the deny.

ROOT = pathlib.Path(os.environ.get("TEST_ROOT", os.path.expanduser("~\\test_deny_prec")))

pass_count = 0
fail_count = 0

def test(name, condition, detail=""):
    global pass_count, fail_count
    if condition:
        print(f"  [PASS] {name}")
        pass_count += 1
    else:
        msg = f"  [FAIL] {name}"
        if detail:
            msg += f" -- {detail}"
        print(msg)
        fail_count += 1

def can_read(path):
    try:
        with open(path, "r") as f: f.read()
        return True
    except: return False

def can_write(path):
    try:
        with open(path, "w") as f: f.write("x")
        return True
    except: return False

readzone  = ROOT / "readzone"
writezone = ROOT / "writezone"

# =====================================================================
# allow.deep all + deny.deep read on the SAME path -> read denied
# =====================================================================
print("--- readzone: [allow all] + [deny read] same path ---")
test("readzone: explicit deny.read wins over allow.all",
     not can_read(readzone / "secret.txt"),
     "same-path deny.read was discarded; sandbox leaked a denied read")

# =====================================================================
# allow.deep all + deny.deep write on the SAME path -> write denied
# =====================================================================
print("--- writezone: [allow all] + [deny write] same path ---")
test("writezone: explicit deny.write wins over allow.all",
     not can_write(writezone / "protected.txt"),
     "same-path deny.write was discarded; sandbox allowed a denied write")

total = pass_count + fail_count
print()
print(f"=== Deny Precedence Test (RT): {pass_count} passed, {fail_count} failed (of {total}) ===")
sys.exit(0 if fail_count == 0 else 1)
