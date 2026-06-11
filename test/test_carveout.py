import os, sys, pathlib

ROOT = pathlib.Path(os.environ.get("TEST_ROOT", os.path.expanduser("~\\test_carveout")))

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
        with open(path, "w") as f: f.write("test")
        return True
    except: return False

def can_listdir(path):
    try:
        os.listdir(path)
        return True
    except: return False

arena      = ROOT / "arena"
open_zone  = arena / "open"
blocked    = arena / "blocked"
inner      = blocked / "inner"
carve      = blocked / "carve"
carve_sub  = carve / "sub"
slot       = blocked / "slot"
slot_inner = slot / "inner"

# =====================================================================
# Z1: arena/open — allow.deep all inherited, no deny in the chain
# =====================================================================
print("--- Z1: arena/open (allow.deep all inherited) ---")
test("open: list dir",    can_listdir(open_zone))
test("open: read file",   can_read(open_zone / "note.txt"))
test("open: create file", can_write(open_zone / "created.txt"))

# =====================================================================
# Z2: arena/blocked — deny.deep all overrides the arena allow
# =====================================================================
print("--- Z2: arena/blocked (deny.deep all) ---")
test("blocked: list dir: denied",    not can_listdir(blocked),
     "deny.deep must override the arena allow")
test("blocked: read file: denied",   not can_read(blocked / "secret.txt"))
test("blocked: create file: denied", not can_write(blocked / "intruder.txt"))

# =====================================================================
# Z3: arena/blocked/inner — deny inherited one level down
# =====================================================================
print("--- Z3: arena/blocked/inner (deny inherited) ---")
test("inner: read file: denied",   not can_read(inner / "hidden.txt"))
test("inner: create file: denied", not can_write(inner / "intruder.txt"))

# =====================================================================
# Z4: arena/blocked/carve — allow.deep write under the deny.
# The pipeline must strip the inherited deny ACEs from the WHOLE carve
# subtree before granting (STRIP_DENY subtree).  Reads pass via the
# user baseline once the deny is gone; writes via the grant.
# =====================================================================
print("--- Z4: arena/blocked/carve (allow.deep under deny -> subtree strip) ---")
test("carve: list dir",       can_listdir(carve),
     "inherited deny must be stripped from the carve dir")
test("carve: read file",      can_read(carve / "seed.txt"),
     "inherited deny must be stripped from files inside carve")
test("carve: overwrite file", can_write(carve / "seed.txt"))
test("carve: create file",    can_write(carve / "created.txt"))

# =====================================================================
# Z5: arena/blocked/carve/sub — strip and grant must propagate deep
# =====================================================================
print("--- Z5: arena/blocked/carve/sub (strip propagates) ---")
test("carve/sub: read file",   can_read(carve_sub / "nested.txt"),
     "subtree strip must reach nested levels")
test("carve/sub: create file", can_write(carve_sub / "created.txt"))

# =====================================================================
# Z6: arena/blocked/slot — allow.this all under the deny.
# Dir-only carve-out: the strip applies to the slot DIRECTORY only.
# Pre-existing children keep their inherited deny ACEs.
# =====================================================================
print("--- Z6: arena/blocked/slot (allow.this under deny -> dir-only strip) ---")
test("slot: list dir",    can_listdir(slot),
     "dir-only strip must clear the deny on the slot dir itself")
test("slot: create file", can_write(slot / "created.txt"))
test("slot: read pre-existing file: denied", not can_read(slot / "note.txt"),
     "pre-existing files must keep the inherited deny (strip is dir-only)")

# =====================================================================
# Z7: arena/blocked/slot/inner — dir-only strip must NOT recurse
# =====================================================================
print("--- Z7: arena/blocked/slot/inner (deny kept below this-carve) ---")
test("slot/inner: read file: denied",   not can_read(slot_inner / "deep.txt"),
     "dir-only strip must not recurse into subdirs")
test("slot/inner: create file: denied", not can_write(slot_inner / "intruder.txt"))

# =====================================================================
# Summary
# =====================================================================
total = pass_count + fail_count
print()
print(f"=== Carve-out Test (RT): {pass_count} passed, {fail_count} failed (of {total}) ===")
sys.exit(0 if fail_count == 0 else 1)
