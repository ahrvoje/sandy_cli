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
full       = blocked / "full"
full_sub   = full / "sub"
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
# Z4: arena/blocked/carve — allow.deep write under the deny.all.
# The nearer rule wins, right by right: the carve gives write, and only
# write.  The rights it does not name stay denied by the deny above it —
# an allow of one level must not hand back every other level.
# =====================================================================
print("--- Z4: arena/blocked/carve (allow.deep write under deny.all -> write only) ---")
test("carve: overwrite file", can_write(carve / "seed.txt"),
     "the allow on the carve must win over the deny inherited from blocked/")
test("carve: create file",    can_write(carve / "created.txt"))
test("carve: list dir: denied",  not can_listdir(carve),
     "allow.write must not remove the inherited deny of read")
test("carve: read file: denied", not can_read(carve / "seed.txt"),
     "allow.write must not remove the inherited deny of read")

# =====================================================================
# Z5: arena/blocked/carve/sub — both rules are inherited here; the allow
# from the nearer folder still comes first
# =====================================================================
print("--- Z5: arena/blocked/carve/sub (nearer inherited rule wins) ---")
test("carve/sub: create file",       can_write(carve_sub / "created.txt"))
test("carve/sub: read file: denied", not can_read(carve_sub / "nested.txt"))

# =====================================================================
# Z5b: arena/blocked/full — allow.deep all under the deny.all: a full
# carve-out, at every depth
# =====================================================================
print("--- Z5b: arena/blocked/full (allow.deep all under deny.all -> full access) ---")
test("full: list dir",        can_listdir(full))
test("full: read file",       can_read(full / "seed.txt"))
test("full: overwrite file",  can_write(full / "seed.txt"))
test("full/sub: read file",   can_read(full_sub / "nested.txt"))
test("full/sub: create file", can_write(full_sub / "created.txt"))

# =====================================================================
# Z6: arena/blocked/slot — allow.this all under the deny.
# Single-object carve-out: the allow applies to the slot DIRECTORY only.
# Its children keep the inherited deny.
# =====================================================================
print("--- Z6: arena/blocked/slot (allow.this under deny -> directory only) ---")
test("slot: list dir",    can_listdir(slot),
     "allow.this must win over the inherited deny on the slot dir itself")
test("slot: create file", can_write(slot / "created.txt"))
test("slot: read pre-existing file: denied", not can_read(slot / "note.txt"),
     "files in slot must keep the inherited deny (the allow is single-object)")

# =====================================================================
# Z7: arena/blocked/slot/inner — the single-object allow must NOT recurse
# =====================================================================
print("--- Z7: arena/blocked/slot/inner (deny kept below this-carve) ---")
test("slot/inner: read file: denied",   not can_read(slot_inner / "deep.txt"),
     "allow.this must not reach sub-directories")
test("slot/inner: create file: denied", not can_write(slot_inner / "intruder.txt"))

# =====================================================================
# Summary
# =====================================================================
total = pass_count + fail_count
print()
print(f"=== Carve-out Test (RT): {pass_count} passed, {fail_count} failed (of {total}) ===")
sys.exit(0 if fail_count == 0 else 1)
