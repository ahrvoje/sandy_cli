"""
Experiment: Full ACL workflow with S-1-9 (Resource Manager Authority) SIDs
for Restricted Token multi-instance scenarios.

Tests:
  1. ALLOW ACE grant + read/write access
  2. DENY ACE + verify block takes precedence over ALLOW
  3. Two instances: overlapping ALLOW+DENY on same path
  4. Child item inheritance (OI|CI propagation to subfolders/files)
  5. Cleanup: remove one instance's ACEs, verify other's children survive

Must be run as Administrator.
"""

import ctypes
import ctypes.wintypes as wt
import os, sys, uuid, shutil

VP = ctypes.c_void_p
PVP = ctypes.POINTER(ctypes.c_void_p)

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

def _api(dll, name, restype, argtypes):
    fn = getattr(dll, name); fn.restype = restype; fn.argtypes = argtypes; return fn

# ====================== Structures ======================
class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_ubyte * 6)]

class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", VP), ("Attributes", ctypes.c_ulong)]

class TRUSTEE_W(ctypes.Structure):
    _fields_ = [("pMultipleTrustee", VP), ("MultipleTrusteeOperation", ctypes.c_int),
                ("TrusteeForm", ctypes.c_int), ("TrusteeType", ctypes.c_int), ("ptstrName", VP)]

class EXPLICIT_ACCESS_W(ctypes.Structure):
    _fields_ = [("grfAccessPermissions", wt.DWORD), ("grfAccessMode", ctypes.c_int),
                ("grfInheritance", wt.DWORD), ("Trustee", TRUSTEE_W)]

class ACE_HEADER(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", ctypes.c_ushort)]

class ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_ = [("AceCount", wt.DWORD), ("AclBytesInUse", wt.DWORD), ("AclBytesFree", wt.DWORD)]

# ====================== Constants ======================
TOKEN_ALL_ACCESS = 0xF01FF
SecurityImpersonation = 2
TokenImpersonation = 2
TokenUser = 1; TokenGroups = 2
SE_GROUP_LOGON_ID = 0xC0000000

GENERIC_READ = 0x80000000; GENERIC_WRITE = 0x40000000
FILE_ALL_ACCESS = 0x001F01FF
FILE_GENERIC_READ = 0x00120089; FILE_GENERIC_WRITE = 0x00120116
OPEN_EXISTING = 3; CREATE_ALWAYS = 2
FILE_SHARE_READ = 1; FILE_ATTRIBUTE_NORMAL = 0x80

DACL_SECURITY_INFORMATION = 4; PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SE_FILE_OBJECT = 1; ACL_REVISION = 2
SET_ACCESS = 2; DENY_ACCESS = 3
OBJECT_INHERIT_ACE = 1; CONTAINER_INHERIT_ACE = 2
ACCESS_ALLOWED_ACE_TYPE = 0; ACCESS_DENIED_ACE_TYPE = 1
TRUSTEE_IS_SID = 0; TRUSTEE_IS_WELL_KNOWN_GROUP = 5

SECURITY_NT_AUTHORITY = (0,0,0,0,0,5)
SECURITY_WORLD_AUTHORITY = (0,0,0,0,0,1)
SECURITY_RESOURCE_MANAGER_AUTHORITY = (0,0,0,0,0,9)
SECURITY_RESTRICTED_CODE_RID = 12
SECURITY_WORLD_RID = 0
SECURITY_BUILTIN_DOMAIN_RID = 32
DOMAIN_ALIAS_RID_USERS = 545
SECURITY_AUTHENTICATED_USER_RID = 11
INVALID_HANDLE = -1 & 0xFFFFFFFFFFFFFFFF

# ====================== API ======================
OpenProcessToken = _api(advapi32, "OpenProcessToken", wt.BOOL, [VP, wt.DWORD, PVP])
GetTokenInformation = _api(advapi32, "GetTokenInformation", wt.BOOL, [VP, ctypes.c_int, VP, wt.DWORD, ctypes.POINTER(wt.DWORD)])
AllocateAndInitializeSid = _api(advapi32, "AllocateAndInitializeSid", wt.BOOL,
    [ctypes.POINTER(SID_IDENTIFIER_AUTHORITY), ctypes.c_ubyte] + [wt.DWORD]*8 + [PVP])
FreeSid = _api(advapi32, "FreeSid", VP, [VP])
CreateRestrictedToken = _api(advapi32, "CreateRestrictedToken", wt.BOOL,
    [VP, wt.DWORD, wt.DWORD, ctypes.POINTER(SID_AND_ATTRIBUTES), wt.DWORD, VP, wt.DWORD, ctypes.POINTER(SID_AND_ATTRIBUTES), PVP])
DuplicateTokenEx = _api(advapi32, "DuplicateTokenEx", wt.BOOL, [VP, wt.DWORD, VP, ctypes.c_int, ctypes.c_int, PVP])
SetThreadToken = _api(advapi32, "SetThreadToken", wt.BOOL, [VP, VP])
RevertToSelf = _api(advapi32, "RevertToSelf", wt.BOOL, [])
ConvertSidToStringSidW = _api(advapi32, "ConvertSidToStringSidW", wt.BOOL, [VP, ctypes.POINTER(wt.LPWSTR)])
ConvertStringSidToSidW = _api(advapi32, "ConvertStringSidToSidW", wt.BOOL, [wt.LPCWSTR, PVP])
IsValidSid = _api(advapi32, "IsValidSid", wt.BOOL, [VP])
EqualSid = _api(advapi32, "EqualSid", wt.BOOL, [VP, VP])
GetNamedSecurityInfoW = _api(advapi32, "GetNamedSecurityInfoW", wt.DWORD,
    [wt.LPCWSTR, ctypes.c_int, wt.DWORD, PVP, PVP, PVP, PVP, PVP])
SetEntriesInAclW = _api(advapi32, "SetEntriesInAclW", wt.DWORD,
    [wt.DWORD, ctypes.POINTER(EXPLICIT_ACCESS_W), VP, PVP])
SetNamedSecurityInfoW = _api(advapi32, "SetNamedSecurityInfoW", wt.DWORD,
    [wt.LPWSTR, ctypes.c_int, wt.DWORD, VP, VP, VP, VP])
TreeSetNamedSecurityInfoW = _api(advapi32, "TreeSetNamedSecurityInfoW", wt.DWORD,
    [wt.LPWSTR, ctypes.c_int, wt.DWORD, VP, VP, VP, VP, wt.DWORD, VP, wt.DWORD, VP])
GetAclInformation = _api(advapi32, "GetAclInformation", wt.BOOL, [VP, VP, wt.DWORD, ctypes.c_int])
GetAce = _api(advapi32, "GetAce", wt.BOOL, [VP, wt.DWORD, PVP])
InitializeAcl = _api(advapi32, "InitializeAcl", wt.BOOL, [VP, wt.DWORD, wt.DWORD])
AddAce = _api(advapi32, "AddAce", wt.BOOL, [VP, wt.DWORD, wt.DWORD, VP, wt.DWORD])

CloseHandle = _api(kernel32, "CloseHandle", wt.BOOL, [VP])
LocalFree = _api(kernel32, "LocalFree", VP, [VP])
LocalAlloc = _api(kernel32, "LocalAlloc", VP, [wt.DWORD, ctypes.c_size_t])
CreateFileW = _api(kernel32, "CreateFileW", VP, [wt.LPCWSTR, wt.DWORD, wt.DWORD, VP, wt.DWORD, wt.DWORD, VP])
WriteFile = _api(kernel32, "WriteFile", wt.BOOL, [VP, VP, wt.DWORD, ctypes.POINTER(wt.DWORD), VP])

# ====================== Helpers ======================
_keepalive = []

def make_auth(*v):
    a = SID_IDENTIFIER_AUTHORITY()
    for i, x in enumerate(v): a.Value[i] = x
    return a

def alloc_sid(auth_t, count, *subs):
    auth = make_auth(*auth_t); p = VP()
    s = list(subs) + [0]*(8-len(subs))
    if not AllocateAndInitializeSid(ctypes.byref(auth), count, *s, ctypes.byref(p)):
        raise OSError(f"AllocateAndInitializeSid: {ctypes.get_last_error()}")
    return p

def sid_str(p):
    s = wt.LPWSTR()
    if ConvertSidToStringSidW(p, ctypes.byref(s)):
        r = s.value; LocalFree(s); return r
    return "?"

def uuid_to_sid(u):
    b = u.bytes
    return alloc_sid(SECURITY_RESOURCE_MANAGER_AUTHORITY, 4,
        int.from_bytes(b[0:4], 'little'), int.from_bytes(b[4:8], 'little'),
        int.from_bytes(b[8:12], 'little'), int.from_bytes(b[12:16], 'little'))

def get_user_sid(hToken):
    sz = wt.DWORD()
    GetTokenInformation(hToken, TokenUser, None, 0, ctypes.byref(sz))
    buf = (ctypes.c_byte * sz.value)()
    GetTokenInformation(hToken, TokenUser, buf, sz.value, ctypes.byref(sz))
    _keepalive.append(buf)
    return VP(VP.from_buffer_copy(buf, 0).value)

def get_logon_sid(hToken):
    sz = wt.DWORD()
    GetTokenInformation(hToken, TokenGroups, None, 0, ctypes.byref(sz))
    buf = (ctypes.c_byte * sz.value)()
    if not GetTokenInformation(hToken, TokenGroups, buf, sz.value, ctypes.byref(sz)): return None
    _keepalive.append(buf)
    count = ctypes.c_uint.from_buffer_copy(buf, 0).value
    sa_sz = ctypes.sizeof(SID_AND_ATTRIBUTES)
    off = ctypes.sizeof(ctypes.c_void_p)
    for i in range(count):
        sa = SID_AND_ATTRIBUTES.from_buffer_copy(buf, off + i * sa_sz)
        if sa.Attributes & SE_GROUP_LOGON_ID: return VP(sa.Sid)
    return None

def grant_access(path, psid, mask, mode=SET_ACCESS):
    """Add ALLOW or DENY ACE. mode=SET_ACCESS(2) for allow, DENY_ACCESS(3) for deny."""
    ea = EXPLICIT_ACCESS_W()
    ea.grfAccessPermissions = mask
    ea.grfAccessMode = mode
    ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP
    ea.Trustee.ptstrName = psid.value
    pOld = VP(); pSD = VP()
    if GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              None, None, ctypes.byref(pOld), None, ctypes.byref(pSD)) != 0: return False
    pNew = VP()
    rc = SetEntriesInAclW(1, ctypes.byref(ea), pOld, ctypes.byref(pNew))
    LocalFree(pSD)
    if rc != 0: return False
    # Apply with PROTECTED_DACL for deny (matches Sandy behavior)
    flags = DACL_SECURITY_INFORMATION
    if mode == DENY_ACCESS:
        flags |= PROTECTED_DACL_SECURITY_INFORMATION
    rc = SetNamedSecurityInfoW(path, SE_FILE_OBJECT, flags, None, None, pNew, None)
    LocalFree(pNew)
    return rc == 0

def remove_sid_from_dacl(path, psid):
    """Remove all ACEs matching psid. Returns count removed."""
    pOld = VP(); pSD = VP()
    if GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              None, None, ctypes.byref(pOld), None, ctypes.byref(pSD)) != 0: return 0
    info = ACL_SIZE_INFORMATION()
    if not GetAclInformation(pOld, ctypes.byref(info), ctypes.sizeof(info), 2):
        LocalFree(pSD); return 0
    removed = 0; new_size = 8
    for i in range(info.AceCount):
        pAce = VP()
        if not GetAce(pOld, i, ctypes.byref(pAce)): continue
        hdr = ACE_HEADER.from_address(pAce.value)
        ace_sid = VP(pAce.value + 8)
        if hdr.AceType in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE) and EqualSid(ace_sid, psid):
            removed += 1
        else:
            new_size += hdr.AceSize
    if removed == 0: LocalFree(pSD); return 0
    pNew = LocalAlloc(0x40, new_size)
    InitializeAcl(pNew, new_size, ACL_REVISION)
    for i in range(info.AceCount):
        pAce = VP()
        if not GetAce(pOld, i, ctypes.byref(pAce)): continue
        hdr = ACE_HEADER.from_address(pAce.value)
        ace_sid = VP(pAce.value + 8)
        if hdr.AceType in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE) and EqualSid(ace_sid, psid):
            continue
        AddAce(pNew, ACL_REVISION, 0xFFFFFFFF, pAce, hdr.AceSize)
    LocalFree(pSD)
    rc = SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, pNew, None)
    LocalFree(pNew)
    return removed if rc == 0 else 0

def count_sid_aces(path, psid, ace_type=None):
    """Count ACEs for psid on path. ace_type=0 for ALLOW, 1 for DENY, None for both."""
    pOld = VP(); pSD = VP()
    if GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              None, None, ctypes.byref(pOld), None, ctypes.byref(pSD)) != 0: return 0
    info = ACL_SIZE_INFORMATION()
    if not GetAclInformation(pOld, ctypes.byref(info), ctypes.sizeof(info), 2):
        LocalFree(pSD); return 0
    count = 0
    for i in range(info.AceCount):
        pAce = VP()
        if not GetAce(pOld, i, ctypes.byref(pAce)): continue
        hdr = ACE_HEADER.from_address(pAce.value)
        ace_sid = VP(pAce.value + 8)
        if hdr.AceType in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE) and EqualSid(ace_sid, psid):
            if ace_type is None or hdr.AceType == ace_type:
                count += 1
    LocalFree(pSD)
    return count

def create_restricted_token(unique_sid):
    hToken = VP()
    OpenProcessToken(VP(-1), TOKEN_ALL_ACCESS, ctypes.byref(hToken))
    user_sid = get_user_sid(hToken)
    logon_sid = get_logon_sid(hToken)
    sid_rest = alloc_sid(SECURITY_NT_AUTHORITY, 1, SECURITY_RESTRICTED_CODE_RID)
    sid_every = alloc_sid(SECURITY_WORLD_AUTHORITY, 1, SECURITY_WORLD_RID)
    sid_users = alloc_sid(SECURITY_NT_AUTHORITY, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS)
    sid_auth = alloc_sid(SECURITY_NT_AUTHORITY, 1, SECURITY_AUTHENTICATED_USER_RID)
    sids = [unique_sid, user_sid, sid_rest, sid_every, sid_users, sid_auth]
    if logon_sid: sids.append(logon_sid)
    Arr = (SID_AND_ATTRIBUTES * len(sids))()
    for i, s in enumerate(sids):
        Arr[i].Sid = s.value if isinstance(s, VP) else s; Arr[i].Attributes = 0
    hOut = VP()
    ok = CreateRestrictedToken(hToken, 0, 0, None, 0, None, len(sids), Arr, ctypes.byref(hOut))
    err = ctypes.get_last_error()
    CloseHandle(hToken)
    for s in [sid_rest, sid_every, sid_users, sid_auth]: FreeSid(s)
    if not ok: raise OSError(f"CreateRestrictedToken: err={err}")
    hImp = VP()
    if not DuplicateTokenEx(hOut, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenImpersonation, ctypes.byref(hImp)):
        CloseHandle(hOut); raise OSError(f"DuplicateTokenEx: err={ctypes.get_last_error()}")
    CloseHandle(hOut)
    return hImp

def try_read(hImp, path):
    if not SetThreadToken(None, hImp): return False
    try:
        h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        hv = h if isinstance(h, int) else (h.value if h else 0)
        if hv == 0 or hv == INVALID_HANDLE: return False
        CloseHandle(hv); return True
    finally: RevertToSelf()

def try_write(hImp, path):
    if not SetThreadToken(None, hImp): return False
    try:
        h = CreateFileW(path, GENERIC_WRITE, 0, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None)
        hv = h if isinstance(h, int) else (h.value if h else 0)
        if hv == 0 or hv == INVALID_HANDLE: return False
        data = b"test\n"; wr = wt.DWORD()
        WriteFile(hv, data, len(data), ctypes.byref(wr), None); CloseHandle(hv)
        return True
    finally: RevertToSelf()

def check(label, result, expected=True):
    ok = result == expected
    status = "PASS" if ok else "FAIL"
    val = "yes" if result else "no"
    exp = "yes" if expected else "no"
    print(f"    {label:50s} {val:4s} (expect {exp}) [{status}]")
    return 0 if ok else 1

# ====================== Main ======================
def main():
    print("=" * 70)
    print("  S-1-9 Full ACL Workflow: ALLOW, DENY, Overlap, Children")
    print("  Using SECURITY_RESOURCE_MANAGER_AUTHORITY for RT mode")
    print("=" * 70)

    root = os.path.join(os.environ["USERPROFILE"], "test_rt_full_acl")
    errors = 0

    try:
        if os.path.exists(root): shutil.rmtree(root)
        os.makedirs(root)

        # Create directory tree:
        #   root/
        #     shared/           ← both instances granted
        #       sub_a/          ← child folder
        #         deep.txt      ← deep child file
        #       file1.txt       ← child file
        #     denied/           ← deny applied here
        #       secret.txt
        shared = os.path.join(root, "shared")
        sub_a  = os.path.join(shared, "sub_a")
        denied = os.path.join(root, "denied")
        os.makedirs(sub_a)
        os.makedirs(denied)
        with open(os.path.join(shared, "file1.txt"), "w") as f: f.write("shared data\n")
        with open(os.path.join(sub_a, "deep.txt"), "w") as f: f.write("deep child\n")
        with open(os.path.join(denied, "secret.txt"), "w") as f: f.write("secret\n")

        sid_a = uuid_to_sid(uuid.uuid4())
        sid_b = uuid_to_sid(uuid.uuid4())
        str_a, str_b = sid_str(sid_a), sid_str(sid_b)

        print(f"\n  Instance A SID: {str_a}")
        print(f"  Instance B SID: {str_b}")

        # ========== TEST 1: Basic ALLOW grant ==========
        print("\n[TEST 1] ALLOW grant — both instances on shared/")
        grant_access(shared, sid_a, FILE_ALL_ACCESS)
        grant_access(shared, sid_b, FILE_ALL_ACCESS)
        # Also grant on files directly (no TreeSet in this POC)
        for f in [os.path.join(shared, "file1.txt"), os.path.join(sub_a, "deep.txt")]:
            grant_access(f, sid_a, FILE_ALL_ACCESS)
            grant_access(f, sid_b, FILE_ALL_ACCESS)
        grant_access(sub_a, sid_a, FILE_ALL_ACCESS)
        grant_access(sub_a, sid_b, FILE_ALL_ACCESS)

        token_a = create_restricted_token(sid_a)
        token_b = create_restricted_token(sid_b)

        errors += check("A reads shared/file1.txt", try_read(token_a, os.path.join(shared, "file1.txt")))
        errors += check("B reads shared/file1.txt", try_read(token_b, os.path.join(shared, "file1.txt")))
        errors += check("A reads shared/sub_a/deep.txt", try_read(token_a, os.path.join(sub_a, "deep.txt")))
        errors += check("B reads shared/sub_a/deep.txt", try_read(token_b, os.path.join(sub_a, "deep.txt")))
        errors += check("A writes shared/wa.txt", try_write(token_a, os.path.join(shared, "wa.txt")))
        errors += check("B writes shared/wb.txt", try_write(token_b, os.path.join(shared, "wb.txt")))

        # ========== TEST 2: DENY grant ==========
        print("\n[TEST 2] DENY ACE — A denied write on denied/")
        grant_access(denied, sid_a, FILE_ALL_ACCESS)  # allow read+write first
        grant_access(os.path.join(denied, "secret.txt"), sid_a, FILE_ALL_ACCESS)
        errors += check("A reads denied/secret.txt BEFORE deny", try_read(token_a, os.path.join(denied, "secret.txt")))
        errors += check("A writes denied/x.txt BEFORE deny", try_write(token_a, os.path.join(denied, "x.txt")))

        # Now add DENY for write
        grant_access(denied, sid_a, FILE_GENERIC_WRITE, mode=DENY_ACCESS)
        grant_access(os.path.join(denied, "secret.txt"), sid_a, FILE_GENERIC_WRITE, mode=DENY_ACCESS)

        # PROTECTED_DACL_SECURITY_INFORMATION strips inherited ACEs, so read
        # also fails — the User SID's inherited ALLOW ACE is gone.
        # This matches Sandy's actual RT deny behavior.
        errors += check("A reads denied/secret.txt AFTER deny (protected DACL)", try_read(token_a, os.path.join(denied, "secret.txt")), expected=False)
        errors += check("A writes denied/y.txt AFTER deny", try_write(token_a, os.path.join(denied, "y.txt")), expected=False)
        errors += check("DENY ACE exists for A on denied/",
                        count_sid_aces(denied, sid_a, ACCESS_DENIED_ACE_TYPE) > 0)
        errors += check("ALLOW ACE also exists for A on denied/",
                        count_sid_aces(denied, sid_a, ACCESS_ALLOWED_ACE_TYPE) > 0)

        # ========== TEST 3: Overlapping — B unaffected by A's deny ==========
        print("\n[TEST 3] B unaffected by A's DENY (per-instance isolation)")
        grant_access(denied, sid_b, FILE_ALL_ACCESS)
        grant_access(os.path.join(denied, "secret.txt"), sid_b, FILE_ALL_ACCESS)
        errors += check("B reads denied/secret.txt", try_read(token_b, os.path.join(denied, "secret.txt")))
        errors += check("B writes denied/z.txt", try_write(token_b, os.path.join(denied, "z.txt")))
        errors += check("DENY ACE count for B on denied/ = 0",
                        count_sid_aces(denied, sid_b, ACCESS_DENIED_ACE_TYPE) == 0)

        # ========== TEST 4: Child item inheritance ==========
        print("\n[TEST 4] Child item inheritance — create new children after grant")
        # Create new child after OI|CI grant was set
        new_child = os.path.join(shared, "sub_new")
        os.makedirs(new_child)
        new_file = os.path.join(new_child, "born_after.txt")
        with open(new_file, "w") as f: f.write("created after grant\n")

        # Check if inherited ACEs propagated
        a_on_child = count_sid_aces(new_child, sid_a)
        b_on_child = count_sid_aces(new_child, sid_b)
        a_on_file = count_sid_aces(new_file, sid_a)
        b_on_file = count_sid_aces(new_file, sid_b)
        print(f"    ACEs on new child dir:  A={a_on_child} B={b_on_child}")
        print(f"    ACEs on new child file: A={a_on_file} B={b_on_file}")
        errors += check("A has inherited ACE on new child dir", a_on_child > 0)
        errors += check("B has inherited ACE on new child dir", b_on_child > 0)
        errors += check("A can read new child file", try_read(token_a, new_file))
        errors += check("B can read new child file", try_read(token_b, new_file))

        # ========== TEST 5: Cleanup — remove A, B's children survive ==========
        print("\n[TEST 5] Cleanup — remove A's ACEs, B's children survive")
        # Remove A from shared/ and all children
        for p in [shared, sub_a, new_child,
                  os.path.join(shared, "file1.txt"),
                  os.path.join(sub_a, "deep.txt"),
                  new_file,
                  os.path.join(shared, "wa.txt")]:
            if os.path.exists(p): remove_sid_from_dacl(p, sid_a)

        # Remove A from denied/
        for p in [denied, os.path.join(denied, "secret.txt")]:
            if os.path.exists(p): remove_sid_from_dacl(p, sid_a)

        errors += check("A ACEs gone from shared/", count_sid_aces(shared, sid_a) == 0)
        errors += check("A ACEs gone from denied/", count_sid_aces(denied, sid_a) == 0)
        errors += check("B ACEs survive on shared/", count_sid_aces(shared, sid_b) > 0)
        errors += check("B ACEs survive on denied/", count_sid_aces(denied, sid_b) > 0)
        errors += check("B reads shared/file1.txt after A cleanup",
                        try_read(token_b, os.path.join(shared, "file1.txt")))
        errors += check("B reads sub_a/deep.txt after A cleanup",
                        try_read(token_b, os.path.join(sub_a, "deep.txt")))
        errors += check("B writes denied/final.txt after A cleanup",
                        try_write(token_b, os.path.join(denied, "final.txt")))
        errors += check("B reads new child file after A cleanup",
                        try_read(token_b, new_file))

        CloseHandle(token_a); CloseHandle(token_b)

    finally:
        if os.path.exists(root): shutil.rmtree(root, ignore_errors=True)

    print("\n" + "=" * 70)
    if errors == 0:
        print("  ALL TESTS PASSED")
        print("  S-1-9-<uuid> works for full ACL workflow:")
        print("    - ALLOW grants OK  DENY grants OK  Overlap isolation OK")
        print("    - Child inheritance OK  Selective cleanup OK")
    else:
        print(f"  {errors} TEST(S) FAILED")
    print("=" * 70)
    return errors

if __name__ == "__main__":
    sys.exit(main())


# [TEST 1] ALLOW grant — both instances on shared/
#     A reads, B reads, A reads deep child, B reads deep child,
#     A writes, B writes                                        6/6 PASS

# [TEST 2] DENY ACE — A denied write on denied/
#     A read/write BEFORE deny: OK
#     A read AFTER deny: blocked (PROTECTED_DACL strips inherited ACEs)
#     A write AFTER deny: blocked
#     Both DENY and ALLOW ACEs coexist for A                    6/6 PASS

# [TEST 3] B unaffected by A's DENY (per-instance isolation)
#     B reads and writes on denied/ path: OK
#     B has zero DENY ACEs                                      3/3 PASS

# [TEST 4] Child item inheritance (OI|CI)
#     New child dir created AFTER grant: inherits ACEs (A=1, B=1)
#     Both can read newly created children                      4/4 PASS

# [TEST 5] Cleanup — remove A, B survives
#     A ACEs gone from shared/ and denied/
#     B ACEs survive everywhere
#     B retains read/write on all paths                         8/8 PASS
