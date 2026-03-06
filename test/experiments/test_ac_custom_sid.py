"""
Experiment: Can AppContainer mode use custom authority SIDs (S-1-42-*)?

If YES → both RT and AC modes can use the same S-1-42-<uuid> SID scheme,
         eliminating the need for CreateAppContainerProfile entirely.

If NO  → AC must keep using S-1-15-2-* (AppContainer profile SIDs),
         and only RT mode benefits from custom authority SIDs.

Tests:
  1. CreateProcessW with SECURITY_CAPABILITIES using custom SID
  2. If process starts → test filesystem access with custom SID ACEs
  3. Compare with standard AppContainer SID (S-1-15-2-*) as baseline

Must be run as Administrator.
"""

import ctypes
import ctypes.wintypes as wt
import os, sys, uuid, shutil, subprocess, time

VP = ctypes.c_void_p
PVP = ctypes.POINTER(ctypes.c_void_p)

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
userenv  = ctypes.WinDLL("userenv",  use_last_error=True)

def _api(dll, name, restype, argtypes):
    fn = getattr(dll, name); fn.restype = restype; fn.argtypes = argtypes; return fn

# ====================== Structures ======================
class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_ubyte * 6)]

class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", VP), ("Attributes", ctypes.c_ulong)]

class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", VP),
        ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
        ("CapabilityCount", wt.DWORD),
        ("Reserved", wt.DWORD),
    ]

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR),
        ("lpTitle", wt.LPWSTR), ("dwX", wt.DWORD), ("dwY", wt.DWORD),
        ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD), ("dwXCountChars", wt.DWORD),
        ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
        ("lpReserved2", VP), ("hStdInput", VP), ("hStdOutput", VP), ("hStdError", VP),
    ]

class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFOW),
        ("lpAttributeList", VP),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", VP), ("hThread", VP),
        ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD),
    ]

# ====================== API ======================
AllocateAndInitializeSid = _api(advapi32, "AllocateAndInitializeSid", wt.BOOL,
    [ctypes.POINTER(SID_IDENTIFIER_AUTHORITY), ctypes.c_ubyte] + [wt.DWORD]*8 + [PVP])
FreeSid = _api(advapi32, "FreeSid", VP, [VP])
ConvertSidToStringSidW = _api(advapi32, "ConvertSidToStringSidW", wt.BOOL, [VP, ctypes.POINTER(wt.LPWSTR)])
IsValidSid = _api(advapi32, "IsValidSid", wt.BOOL, [VP])

GetNamedSecurityInfoW = _api(advapi32, "GetNamedSecurityInfoW", wt.DWORD,
    [wt.LPCWSTR, ctypes.c_int, wt.DWORD, PVP, PVP, PVP, PVP, PVP])

class TRUSTEE_W(ctypes.Structure):
    _fields_ = [("pMultipleTrustee", VP), ("MultipleTrusteeOperation", ctypes.c_int),
                ("TrusteeForm", ctypes.c_int), ("TrusteeType", ctypes.c_int), ("ptstrName", VP)]

class EXPLICIT_ACCESS_W(ctypes.Structure):
    _fields_ = [("grfAccessPermissions", wt.DWORD), ("grfAccessMode", ctypes.c_int),
                ("grfInheritance", wt.DWORD), ("Trustee", TRUSTEE_W)]

SetEntriesInAclW = _api(advapi32, "SetEntriesInAclW", wt.DWORD,
    [wt.DWORD, ctypes.POINTER(EXPLICIT_ACCESS_W), VP, PVP])
SetNamedSecurityInfoW = _api(advapi32, "SetNamedSecurityInfoW", wt.DWORD,
    [wt.LPWSTR, ctypes.c_int, wt.DWORD, VP, VP, VP, VP])

InitializeProcThreadAttributeList = _api(kernel32, "InitializeProcThreadAttributeList", wt.BOOL,
    [VP, wt.DWORD, wt.DWORD, ctypes.POINTER(ctypes.c_size_t)])
UpdateProcThreadAttribute = _api(kernel32, "UpdateProcThreadAttribute", wt.BOOL,
    [VP, wt.DWORD, ctypes.c_size_t, VP, ctypes.c_size_t, VP, VP])
DeleteProcThreadAttributeList = _api(kernel32, "DeleteProcThreadAttributeList", VP, [VP])
CreateProcessW = _api(kernel32, "CreateProcessW", wt.BOOL,
    [wt.LPCWSTR, wt.LPWSTR, VP, VP, wt.BOOL, wt.DWORD, VP, wt.LPCWSTR,
     ctypes.POINTER(STARTUPINFOEXW), ctypes.POINTER(PROCESS_INFORMATION)])
CloseHandle = _api(kernel32, "CloseHandle", wt.BOOL, [VP])
LocalFree = _api(kernel32, "LocalFree", VP, [VP])
WaitForSingleObject = _api(kernel32, "WaitForSingleObject", wt.DWORD, [VP, wt.DWORD])
GetExitCodeProcess = _api(kernel32, "GetExitCodeProcess", wt.BOOL, [VP, ctypes.POINTER(wt.DWORD)])
TerminateProcess = _api(kernel32, "TerminateProcess", wt.BOOL, [VP, wt.UINT])

CreateAppContainerProfile = _api(userenv, "CreateAppContainerProfile", ctypes.c_long,
    [wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, VP, wt.DWORD, PVP])
DeleteAppContainerProfile = _api(userenv, "DeleteAppContainerProfile", ctypes.c_long, [wt.LPCWSTR])
DeriveAppContainerSidFromAppContainerName = _api(userenv, "DeriveAppContainerSidFromAppContainerName",
    ctypes.c_long, [wt.LPCWSTR, PVP])

EXTENDED_STARTUPINFO_PRESENT = 0x00080000
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
CREATE_NO_WINDOW = 0x08000000
DACL_SECURITY_INFORMATION = 4
SE_FILE_OBJECT = 1
SET_ACCESS = 2
OBJECT_INHERIT_ACE = 1
CONTAINER_INHERIT_ACE = 2
FILE_ALL_ACCESS = 0x001F01FF
SANDY_SID_AUTHORITY = (0, 0, 0, 0, 0, 42)

# ====================== Helpers ======================
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

def uuid_to_custom_sid(u):
    """S-1-42-<uuid dwords> — custom Sandy authority."""
    b = u.bytes
    return alloc_sid(SANDY_SID_AUTHORITY, 4,
        int.from_bytes(b[0:4], 'little'), int.from_bytes(b[4:8], 'little'),
        int.from_bytes(b[8:12], 'little'), int.from_bytes(b[12:16], 'little'))

def grant_sid_access(path, psid, mask):
    ea = EXPLICIT_ACCESS_W()
    ea.grfAccessPermissions = mask; ea.grfAccessMode = SET_ACCESS
    ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    ea.Trustee.TrusteeForm = 0  # TRUSTEE_IS_SID
    ea.Trustee.TrusteeType = 5  # TRUSTEE_IS_WELL_KNOWN_GROUP
    ea.Trustee.ptstrName = psid.value
    pOld = VP(); pSD = VP()
    if GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              None, None, ctypes.byref(pOld), None, ctypes.byref(pSD)) != 0: return False
    pNew = VP()
    rc = SetEntriesInAclW(1, ctypes.byref(ea), pOld, ctypes.byref(pNew))
    LocalFree(pSD)
    if rc != 0: return False
    rc = SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, pNew, None)
    LocalFree(pNew)
    return rc == 0

def try_launch_appcontainer(sid, label, test_dir, probe_script):
    """Try to launch a process in AppContainer mode with the given SID.
    Returns (success, exit_code_or_error)."""
    sc = SECURITY_CAPABILITIES()
    sc.AppContainerSid = sid.value
    sc.Capabilities = None
    sc.CapabilityCount = 0

    # Build attribute list
    size = ctypes.c_size_t(0)
    InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    attr_buf = (ctypes.c_byte * size.value)()
    attr_list = ctypes.cast(attr_buf, VP)
    if not InitializeProcThreadAttributeList(attr_list, 1, 0, ctypes.byref(size)):
        return False, f"InitializeProcThreadAttributeList: {ctypes.get_last_error()}"

    if not UpdateProcThreadAttribute(attr_list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                      ctypes.byref(sc), ctypes.sizeof(sc), None, None):
        err = ctypes.get_last_error()
        DeleteProcThreadAttributeList(attr_list)
        return False, f"UpdateProcThreadAttribute: err={err}"

    si = STARTUPINFOEXW()
    si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
    si.lpAttributeList = attr_list

    pi = PROCESS_INFORMATION()
    python_exe = sys.executable
    cmd = f'"{python_exe}" "{probe_script}" "{test_dir}"'
    cmd_buf = ctypes.create_unicode_buffer(cmd)

    ok = CreateProcessW(None, cmd_buf, None, None, False,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                        None, None, ctypes.byref(si), ctypes.byref(pi))
    err = ctypes.get_last_error()
    DeleteProcThreadAttributeList(attr_list)

    if not ok:
        return False, f"CreateProcessW: err={err}"

    WaitForSingleObject(pi.hProcess, 10000)  # 10s timeout
    exit_code = wt.DWORD()
    GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))
    CloseHandle(pi.hProcess)
    CloseHandle(pi.hThread)
    return True, exit_code.value

# ====================== Main ======================
def main():
    print("=" * 65)
    print("  Experiment: Can AppContainer use custom authority SIDs?")
    print("  Testing S-1-42-<uuid> vs S-1-15-2-* (standard AC profile)")
    print("=" * 65)

    test_root = os.path.join(os.environ["USERPROFILE"], "test_ac_custom_sid")
    ac_name = f"Sandy_AC_Experiment_{uuid.uuid4()}"
    probe_script = os.path.join(test_root, "probe.py")

    try:
        if os.path.exists(test_root): shutil.rmtree(test_root)
        os.makedirs(test_root)

        # Write probe script — tries to read seed.txt and write result.txt
        with open(probe_script, "w") as f:
            f.write("""import sys, os
test_dir = sys.argv[1]
seed = os.path.join(test_dir, "seed.txt")
result = os.path.join(test_dir, "result.txt")
try:
    with open(seed) as f: data = f.read()
    with open(result, "w") as f: f.write(f"READ_OK:{data.strip()}")
    sys.exit(0)
except Exception as e:
    try:
        with open(result, "w") as f: f.write(f"FAIL:{e}")
    except: pass
    sys.exit(1)
""")
        seed = os.path.join(test_root, "seed.txt")
        with open(seed, "w") as f: f.write("hello_ac")

        # === Test A: Standard AppContainer SID (baseline) ===
        print("\n[TEST A] Standard AppContainer profile SID (S-1-15-2-*)")
        ac_sid = VP()
        hr = CreateAppContainerProfile(ac_name, "Experiment", "Test", None, 0, ctypes.byref(ac_sid))
        if hr != 0:
            DeriveAppContainerSidFromAppContainerName(ac_name, ctypes.byref(ac_sid))
        ac_str = sid_str(ac_sid)
        print(f"  SID: {ac_str}")

        # Grant AC SID access to test folder and files
        grant_sid_access(test_root, ac_sid, FILE_ALL_ACCESS)
        grant_sid_access(seed, ac_sid, FILE_ALL_ACCESS)
        grant_sid_access(probe_script, ac_sid, FILE_ALL_ACCESS)
        # AC needs access to Python too
        python_dir = os.path.dirname(sys.executable)
        grant_sid_access(python_dir, ac_sid, FILE_ALL_ACCESS)

        result_file = os.path.join(test_root, "result.txt")
        if os.path.exists(result_file): os.remove(result_file)

        ok, result = try_launch_appcontainer(ac_sid, "Standard AC", test_root, probe_script)
        if ok:
            print(f"  Process launched: YES (exit={result})")
            if os.path.exists(result_file):
                with open(result_file) as f: print(f"  Probe result: {f.read()}")
            else:
                print("  Probe result: no output file")
        else:
            print(f"  Process launched: NO — {result}")

        # === Test B: Custom authority SID (S-1-42-*) as AppContainer SID ===
        print("\n[TEST B] Custom authority SID (S-1-42-*) as AppContainer SID")
        custom_sid = uuid_to_custom_sid(uuid.uuid4())
        custom_str = sid_str(custom_sid)
        print(f"  SID: {custom_str}")

        grant_sid_access(test_root, custom_sid, FILE_ALL_ACCESS)
        grant_sid_access(seed, custom_sid, FILE_ALL_ACCESS)
        grant_sid_access(probe_script, custom_sid, FILE_ALL_ACCESS)

        if os.path.exists(result_file): os.remove(result_file)

        ok2, result2 = try_launch_appcontainer(custom_sid, "Custom Auth", test_root, probe_script)
        if ok2:
            print(f"  Process launched: YES (exit={result2})")
            if os.path.exists(result_file):
                with open(result_file) as f: print(f"  Probe result: {f.read()}")
            else:
                print("  Probe result: no output file")
        else:
            print(f"  Process launched: NO — {result2}")

        # === Summary ===
        print("\n" + "=" * 65)
        print("  RESULTS SUMMARY")
        print(f"  Standard AC SID (S-1-15-2-*): {'WORKS' if ok else 'FAILS'}")
        print(f"  Custom Auth SID (S-1-42-*):   {'WORKS' if ok2 else 'FAILS'}")
        if ok and ok2:
            print("  CONCLUSION: Both work! Unified SID approach is possible.")
        elif ok and not ok2:
            print("  CONCLUSION: Custom SIDs rejected for AppContainer.")
            print("  AC must keep using S-1-15-2-* profile SIDs.")
            print("  Only RT mode benefits from custom S-1-42-* SIDs.")
        elif not ok and not ok2:
            print("  CONCLUSION: Both failed — check admin privileges.")
        print("=" * 65)

    finally:
        DeleteAppContainerProfile(ac_name)
        if os.path.exists(test_root): shutil.rmtree(test_root, ignore_errors=True)

    return 0

if __name__ == "__main__":
    sys.exit(main())


# [TEST B] Custom authority SID (S-1-42-*) as AppContainer SID
#   SID: S-1-42-2731778700-2588207294-884848054-2569337814
#   Process launched: NO � CreateProcessW: err=4250

# =================================================================
#   RESULTS SUMMARY
#   Standard AC SID (S-1-15-2-*): WORKS
#   Custom Auth SID (S-1-42-*):   FAILS
#   CONCLUSION: Custom SIDs rejected for AppContainer.
#   AC must keep using S-1-15-2-* profile SIDs.
#   Only RT mode benefits from custom S-1-42-* SIDs.
# =================================================================

# Definitive answer. Error 4250 is HRESULT_FROM_WIN32(ERROR_INVALID_SID) — Windows validates the SID authority for AppContainer and rejects anything that isn't S-1-15-2-*.
# Windows validates that the SECURITY_CAPABILITIES.AppContainerSid is a real AppContainer authority (S-1-15-2-*). Custom authorities are rejected at process creation.
