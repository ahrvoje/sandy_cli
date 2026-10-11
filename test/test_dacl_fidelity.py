"""DACL fidelity test.

Host side (outside the sandbox):
  snapshot <root> <file>     write the DACL of every object under <root> as SDDL, with its P / AI flags
  compare <before> <after>   every object of <before> must have the identical DACL in <after>, and no
                             object of <after> may hold an ACE of a sandbox SID

Inside the sandbox:
  probe                      a denied object must stay denied: no DACL rewrite, no delete, no rename.
                             The rights that a deny does not name must stay usable.
  noop                       do nothing (the run is only there to grant and revoke)
"""
import ctypes, json, os, pathlib, re, sys
import subprocess
import tempfile
from ctypes import wintypes

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SDDL_REVISION_1 = 1
SANDBOX_SID = re.compile(r"S-1-15-2-[0-9-]+|S-1-9-[0-9-]+")

advapi32.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.POINTER(ctypes.c_void_p)]
advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
advapi32.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
kernel32.LocalFree.argtypes = [ctypes.c_void_p]

pass_count = 0
fail_count = 0


def test(name, condition, detail=""):
    global pass_count, fail_count
    if condition:
        print(f"  [PASS] {name}")
        pass_count += 1
    else:
        print(f"  [FAIL] {name}" + (f" -- {detail}" if detail else ""))
        fail_count += 1


# ---------------------------------------------------------------------
# Host side
# ---------------------------------------------------------------------
def dacl_sddl(path):
    sd = ctypes.c_void_p()
    err = advapi32.GetNamedSecurityInfoW(str(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                         None, None, None, None, ctypes.byref(sd))
    if err:
        return f"<error {err}>"
    text = wintypes.LPWSTR()
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                                                                  ctypes.byref(text), None)
    sddl = text.value or ""
    kernel32.LocalFree(text)
    kernel32.LocalFree(sd)
    return sddl


def snapshot(root, out_file):
    result = {root: dacl_sddl(root)}
    for base, dirs, files in os.walk(root):
        for entry in dirs + files:
            path = os.path.join(base, entry)
            result[path] = dacl_sddl(path)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    print(f"  snapshot: {len(result)} objects")
    return 0


def compare(before_file, after_file):
    with open(before_file, encoding="utf-8") as f:
        before = json.load(f)
    with open(after_file, encoding="utf-8") as f:
        after = json.load(f)
    root = min(before, key=len)
    changed = [p for p in before if after.get(p) != before[p]]
    for path in changed:
        print(f"    {os.path.relpath(path, root)}")
        print(f"      before: {before[path]}")
        print(f"      after : {after.get(path, '<object is gone>')}")
    test(f"DACL of all {len(before)} objects identical (flags and ACEs)", not changed,
         f"{len(changed)} object(s) changed")
    protected = [p for p in before if before[p].startswith("D:P")]
    test(f"snapshot holds protected DACLs ({len(protected)}) - the case that used to lose its protection",
         len(protected) >= 2)
    residue = [p for p in after if SANDBOX_SID.search(after[p])]
    for path in residue[:10]:
        print(f"    {os.path.relpath(path, root)}: {after[path]}")
    test("no ACE of a sandbox SID on any object", not residue, f"{len(residue)} object(s)")
    return 1 if fail_count else 0


def moved_inheritance(sandy):
    """Windows recomputes inherited ACEs after a same-volume move."""
    sandy = str(pathlib.Path(sandy).resolve())
    with tempfile.TemporaryDirectory(prefix="sandy_moved_acl_") as temp:
        root = pathlib.Path(temp)
        source, target = root / "source", root / "target"
        source.mkdir()
        target.mkdir()
        subprocess.run(["icacls", str(source), "/grant", "*S-1-5-32-546:(OI)(CI)(RX)"],
                       check=True, capture_output=True)
        moved = source / "moved.txt"
        moved.write_text("moved")
        native = target / "native.txt"
        native.write_text("native")
        # Establish normal auto-inherited DACL flags before testing the move.
        for parent in (source, target):
            subprocess.run(["icacls", str(parent), "/inheritance:e", "/T"],
                           check=True, capture_output=True)
        moved.rename(target / moved.name)
        moved = target / moved.name
        before = {p: dacl_sddl(p) for p in (target, native, moved)}
        test("moved file retains the former parent's Guests ACE before Sandy",
             ";;;BG)" in before[moved], before[moved])
        config = root / "moved.toml"
        config.write_text(f"[sandbox]\ntoken='appcontainer'\n[allow.deep]\nread=['{target}']\n", encoding="utf-8")
        result = subprocess.run([sandy, "-q", "-c", str(config), "-x",
                                 os.path.join(os.environ['SystemRoot'], 'System32', 'cmd.exe'),
                                 "/d", "/c", "exit 0"], capture_output=True, timeout=30)
        test("moved-file grant and cleanup succeed", result.returncode == 0, result.stderr.decode(errors="replace"))
        after = {p: dacl_sddl(p) for p in (target, native, moved)}
        for path in (target, native):
            test(f"{path.name}: DACL unchanged", before[path] == after[path],
                 f"before={before[path]} after={after[path]}")
        test("Windows removes the former parent's inherited ACE", ";;;BG)" not in after[moved])
        test("moved file now has the current parent's inheritance", after[moved] == after[native])
        test("no sandbox ACE remains", not any(SANDBOX_SID.search(value) for value in after.values()))
    return 1 if fail_count else 0


# ---------------------------------------------------------------------
# Inside the sandbox
# ---------------------------------------------------------------------
def can_read(path):
    try:
        with open(path, "r") as f:
            f.read()
        return True
    except OSError:
        return False


def can_append(path):
    try:
        with open(path, "a") as f:
            f.write("x")
        return True
    except OSError:
        return False


def can_delete(path):
    try:
        os.rmdir(path) if os.path.isdir(path) else os.remove(path)
        return True
    except OSError:
        return False


def can_rename(path):
    """Rename and rename back.  True when the first rename worked."""
    moved = str(path) + ".moved"
    try:
        os.rename(path, moved)
    except OSError:
        return False
    os.rename(moved, path)
    return True


def can_rewrite_dacl(path):
    """Try to replace the DACL with 'Everyone: full access'.  This needs WRITE_DAC and nothing else."""
    sd = ctypes.c_void_p()
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;FA;;;WD)", SDDL_REVISION_1,
                                                                  ctypes.byref(sd), None)
    ok = advapi32.SetFileSecurityW(str(path), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd)
    kernel32.LocalFree(sd)
    return bool(ok)


def probe():
    root = pathlib.Path(os.environ.get("TEST_ROOT", os.path.expanduser("~\\test_dacl_fidelity")))
    arena = root / "arena"
    secret, frozen, keep = arena / "secret", arena / "frozen", arena / "keep"

    print("--- secret/ (deny.deep all, protected DACL) ---")
    test("secret: read denied", not can_read(secret / "data.txt"))
    test("secret: DACL rewrite of the denied file blocked", not can_rewrite_dacl(secret / "data.txt"))
    test("secret: DACL rewrite of the denied folder blocked", not can_rewrite_dacl(secret))
    test("secret: read still denied after the rewrite attempts", not can_read(secret / "data.txt"))
    test("secret: delete of a denied file blocked", not can_delete(secret / "data.txt"))
    test("secret: rename of a denied file blocked", not can_rename(secret / "data.txt"))
    test("secret: delete of a denied empty folder blocked", not can_delete(secret / "empty"))
    test("secret: rename of the denied folder itself blocked", not can_rename(secret))
    test("secret: nested file read denied", not can_read(secret / "sub" / "deep.txt"))

    print("--- lockfile.txt (deny.this all on a protected file) ---")
    test("lockfile: read denied", not can_read(arena / "lockfile.txt"))
    test("lockfile: DACL rewrite blocked", not can_rewrite_dacl(arena / "lockfile.txt"))
    test("lockfile: delete blocked", not can_delete(arena / "lockfile.txt"))
    test("lockfile: rename blocked", not can_rename(arena / "lockfile.txt"))

    print("--- frozen/ (deny.deep write) ---")
    test("frozen: read still works (the deny names write only)", can_read(frozen / "note.txt"))
    test("frozen: write denied", not can_append(frozen / "note.txt"))
    test("frozen: DACL rewrite blocked", not can_rewrite_dacl(frozen / "note.txt"))
    test("frozen/carve: write works (allow.deep all on a nearer folder)", can_append(frozen / "carve" / "x.txt"))
    test("frozen/carve: create works", can_append(frozen / "carve" / "created.txt"))

    print("--- keep/victim.txt (deny.this delete) ---")
    test("victim: read still works", can_read(keep / "victim.txt"))
    test("victim: write still works", can_append(keep / "victim.txt"))
    test("victim: delete blocked", not can_delete(keep / "victim.txt"))
    test("victim: rename blocked", not can_rename(keep / "victim.txt"))
    test("victim: DACL rewrite blocked", not can_rewrite_dacl(keep / "victim.txt"))
    test("keep/: DACL rewrite of the parent blocked (the delete guard cannot be removed)",
         not can_rewrite_dacl(keep))
    test("keep/other.txt: rename works (the delete guard protects the denied file only)",
         can_rename(keep / "other.txt"))

    print(f"\n  PROBE: {pass_count} pass, {fail_count} fail")
    return 1 if fail_count else 0


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "probe"
    if mode == "snapshot":
        sys.exit(snapshot(sys.argv[2], sys.argv[3]))
    if mode == "compare":
        sys.exit(compare(sys.argv[2], sys.argv[3]))
    if mode == "noop":
        sys.exit(0)
    if mode == "moved":
        sys.exit(moved_inheritance(sys.argv[2]))
    if mode == "sddl":
        for path in sys.argv[2:]:
            value = dacl_sddl(path)
            if not value.startswith("D:"):
                raise RuntimeError(f"Cannot read DACL: {path}: {value}")
            print(value)
        sys.exit(0)
    sys.exit(probe())
