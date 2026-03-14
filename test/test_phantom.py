"""Phantom test suite — completely original attack surface.

Theme: What can the sandbox OBSERVE, PERSIST, and LEAVE BEHIND?
None of these vectors appear in any existing Sandy test.

Vectors:
  P1. Alternate Data Stream persistence — ADS on granted files survive cleanup?
  P2. File attribute armor — READONLY/HIDDEN/SYSTEM on files blocks cleanup?
  P3. Hard link inode sharing — hard link shares ACE with target, cleanup coherent?
  P4. Volume/disk info leaks — GetVolumeInfo, GetDiskFreeSpace from sandbox
  P5. Token self-inspection — what does the AppContainer token reveal?
  P6. FindFirstFile through denied area — wildcard enum in denied zones
  P7. Directory change notifications — ReadDirectoryChangesW on denied subtrees
  P8. Memory-mapped file write — mmap bypass on deny.write?
  P9. SetFileTime/SetFileAttributes — timestamp/attribute forgery
  P10. DELETE_ON_CLOSE persistence — file created with DELETE_ON_CLOSE flag

Run inside AppContainer via test_phantom.bat.
"""
import os, sys, ctypes, ctypes.wintypes, struct, time

ROOT = os.path.join(os.environ.get('USERPROFILE', r'C:\Users\H'), 'test_phantom')
ARENA = os.path.join(ROOT, 'arena')
WORKSPACE = os.path.join(ARENA, 'workspace')
results = []

def test(name, should_pass, fn):
    try:
        result = fn()
        if should_pass:
            print(f"  [PASS] {name}")
            results.append(('PASS', name))
        else:
            print(f"  [FAIL] {name}: succeeded (SHOULD BE BLOCKED)")
            results.append(('FAIL', name))
    except PermissionError:
        if not should_pass:
            print(f"  [PASS] {name}: blocked")
            results.append(('PASS', name))
        else:
            print(f"  [FAIL] {name}: blocked (SHOULD WORK)")
            results.append(('FAIL', name))
    except OSError as e:
        if e.winerror in (5, 1314, 21, 6, 145, 17, 1):
            if not should_pass:
                print(f"  [PASS] {name}: blocked (w={e.winerror})")
                results.append(('PASS', name))
            else:
                print(f"  [FAIL] {name}: blocked (SHOULD WORK, w={e.winerror})")
                results.append(('FAIL', name))
        else:
            print(f"  [ERR]  {name}: OSError {e.winerror}: {e}")
            results.append(('ERR', name))
    except Exception as e:
        if not should_pass:
            print(f"  [PASS] {name}: blocked ({type(e).__name__})")
            results.append(('PASS', name))
        else:
            print(f"  [ERR]  {name}: {type(e).__name__}: {e}")
            results.append(('ERR', name))

def p(*parts):
    return os.path.join(ARENA, *parts)

def w(*parts):
    """Path in writable workspace zone."""
    return os.path.join(WORKSPACE, *parts)

kernel32 = ctypes.windll.kernel32


# ===========================================================================
# P1: Alternate Data Stream Persistence
#
# Write secret data into ADS (file.txt:hidden). Sandy's cleanup restores
# DACLs but does NOT delete file content. ADS data should persist after
# Sandy exits — this is a data persistence channel, not an ACL bypass.
# ===========================================================================
print("=== P1: Alternate Data Stream persistence ===")
ads_file = w('ads_target.txt')
ads_path = ads_file + ':phantom_data'
try:
    # Create the base file
    with open(ads_file, 'w') as f:
        f.write('visible content')
    # Write to ADS
    with open(ads_path, 'w') as f:
        f.write('HIDDEN_IN_ADS')
    # Read it back
    with open(ads_path, 'r') as f:
        content = f.read()
    if content == 'HIDDEN_IN_ADS':
        print("  [INFO] ADS write+read succeeded (data persistence channel)")
        results.append(('INFO', 'ads: write+read (persistence channel)'))
    else:
        print(f"  [ERR] ADS unexpected content: {content}")
        results.append(('ERR', 'ads: unexpected content'))
except Exception as e:
    print(f"  [INFO] ADS blocked: {e}")
    results.append(('INFO', f'ads: blocked ({e})'))

# ADS on denied folder should fail
try:
    with open(p('forbidden') + ':secret', 'w') as f:
        f.write('escape')
    print("  [FAIL] ADS on forbidden/ succeeded!")
    results.append(('FAIL', 'ads: write on denied folder'))
except (PermissionError, OSError):
    print("  [PASS] ADS on forbidden/: blocked")
    results.append(('PASS', 'ads: denied folder blocked'))


# ===========================================================================
# P2: File Attribute Armor
#
# Set READONLY attribute on files in arena. Does TreeSetNamedSecurityInfo
# fail when the file has READONLY set? This could interfere with cleanup.
# ===========================================================================
print("\n=== P2: File attribute armor ===")
armor_file = w('armored.txt')
try:
    with open(armor_file, 'w') as f:
        f.write('armor test')
    # Set READONLY
    kernel32.SetFileAttributesW(armor_file, 0x01)  # FILE_ATTRIBUTE_READONLY
    attrs = kernel32.GetFileAttributesW(armor_file)
    if attrs & 0x01:
        print("  [INFO] Set READONLY on armored.txt")
        results.append(('INFO', 'attr: READONLY set'))
    # Set HIDDEN + SYSTEM
    kernel32.SetFileAttributesW(armor_file, 0x01 | 0x02 | 0x04)  # RO+HIDDEN+SYSTEM
    attrs = kernel32.GetFileAttributesW(armor_file)
    if attrs & 0x06:
        print("  [INFO] Set HIDDEN+SYSTEM on armored.txt")
        results.append(('INFO', 'attr: HIDDEN+SYSTEM set'))
    # Verify we can't write to it now (READONLY)
    try:
        with open(armor_file, 'w') as f:
            f.write('overwrite')
        print("  [INFO] Write to READONLY file succeeded (Python ignores)")
        results.append(('INFO', 'attr: write to RO succeeded'))
    except PermissionError:
        print("  [INFO] Write to READONLY file blocked")
        results.append(('INFO', 'attr: write to RO blocked'))
except Exception as e:
    print(f"  [ERR] attribute test: {e}")
    results.append(('ERR', f'attr: {e}'))

# Set READONLY on denied folder
h_forbid = kernel32.CreateFileW(
    p('forbidden'), 0x0100, 0x7, None, 3, 0x02000000, None)  # FILE_WRITE_ATTRIBUTES
if h_forbid != ctypes.wintypes.HANDLE(-1).value and h_forbid != -1:
    print("  [FAIL] WRITE_ATTRIBUTES on forbidden/ succeeded!")
    results.append(('FAIL', 'attr: WRITE_ATTRIBUTES on denied'))
    kernel32.CloseHandle(h_forbid)
else:
    err = kernel32.GetLastError()
    print(f"  [PASS] WRITE_ATTRIBUTES on forbidden/: blocked (err={err})")
    results.append(('PASS', 'attr: denied blocked'))


# ===========================================================================
# P3: Hard Link Inode Sharing
#
# Create a hard link from arena/link.txt -> arena/original.txt.
# Both share the same NTFS inode and thus the same ACL.
# After cleanup, does the hard link retain any AppContainer ACEs?
# ===========================================================================
print("\n=== P3: Hard link inode sharing ===")
hl_orig = w('hl_original.txt')
hl_link = w('hl_linked.txt')
try:
    with open(hl_orig, 'w') as f:
        f.write('original data')
    ok = kernel32.CreateHardLinkW(hl_link, hl_orig, None)
    if ok:
        print("  [INFO] Hard link created: hl_linked.txt -> hl_original.txt")
        results.append(('INFO', 'hardlink: created'))
        # Both should be readable
        test("hardlink: read via link", True,
             lambda: open(hl_link, 'r').read())
        test("hardlink: read via original", True,
             lambda: open(hl_orig, 'r').read())
        # Delete original, link should still work
        os.remove(hl_orig)
        test("hardlink: read after original deleted", True,
             lambda: open(hl_link, 'r').read())
    else:
        err = kernel32.GetLastError()
        print(f"  [INFO] Hard link creation failed (err={err})")
        results.append(('INFO', f'hardlink: failed ({err})'))
except Exception as e:
    print(f"  [ERR] hardlink test: {e}")
    results.append(('ERR', f'hardlink: {e}'))

# Hard link TO denied zone should fail
try:
    ok_hl = kernel32.CreateHardLinkW(
        p('escape_link.txt'), p('forbidden', 'secret.txt'), None)
    if ok_hl:
        print("  [FAIL] hardlink: link TO forbidden/ succeeded!")
        results.append(('FAIL', 'hardlink: escape to denied'))
    else:
        err = kernel32.GetLastError()
        print(f"  [PASS] hardlink: link to forbidden/ blocked (err={err})")
        results.append(('PASS', 'hardlink: denied blocked'))
except Exception as e:
    print(f"  [PASS] hardlink: link to forbidden/ blocked ({e})")
    results.append(('PASS', 'hardlink: denied blocked'))


# ===========================================================================
# P4: Volume and Disk Information Leaks
#
# Can the sandbox learn about the system via volume metadata?
# Not an escape, but reveals system configuration.
# ===========================================================================
print("\n=== P4: Volume/disk info leaks ===")
try:
    import shutil
    total, used, free = shutil.disk_usage('C:\\')
    print(f"  [INFO] Disk C: total={total//1024//1024//1024}GB free={free//1024//1024//1024}GB")
    results.append(('INFO', f'disk: C: visible ({total//1024//1024//1024}GB)'))
except Exception as e:
    print(f"  [PASS] Disk info blocked: {e}")
    results.append(('PASS', 'disk: blocked'))

# Volume serial number
volName = ctypes.create_unicode_buffer(256)
volSerial = ctypes.wintypes.DWORD(0)
maxLen = ctypes.wintypes.DWORD(0)
fsFlags = ctypes.wintypes.DWORD(0)
fsName = ctypes.create_unicode_buffer(256)
ok = kernel32.GetVolumeInformationW(
    'C:\\', volName, 256, ctypes.byref(volSerial),
    ctypes.byref(maxLen), ctypes.byref(fsFlags), fsName, 256)
if ok:
    print(f"  [INFO] Volume: {volName.value}, SN={volSerial.value:08X}, FS={fsName.value}")
    results.append(('INFO', f'vol: {volName.value} SN={volSerial.value:08X}'))
else:
    print("  [PASS] Volume info blocked")
    results.append(('PASS', 'vol: blocked'))


# ===========================================================================
# P5: Token Self-Inspection
#
# What can the AppContainer process learn about its own token?
# Enumerate SID, integrity level, privileges.
# ===========================================================================
print("\n=== P5: Token self-inspection ===")
try:
    advapi32 = ctypes.windll.advapi32
    TOKEN_QUERY = 0x0008
    hToken = ctypes.c_void_p()
    kernel32.OpenProcessToken.restype = ctypes.wintypes.BOOL
    kernel32.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    if kernel32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(hToken)):
        # Check if we're in AppContainer (TokenIsAppContainer = 29)
        isAC = ctypes.wintypes.DWORD(0)
        retLen = ctypes.wintypes.DWORD(ctypes.sizeof(isAC))
        advapi32.GetTokenInformation(hToken, 29, ctypes.byref(isAC), ctypes.sizeof(isAC), ctypes.byref(retLen))
        if isAC.value:
            print("  [INFO] Token confirms: running as AppContainer")
            results.append(('INFO', 'token: is AppContainer'))
        else:
            print("  [INFO] Token says NOT AppContainer")
            results.append(('INFO', 'token: not AppContainer'))

        # Integrity level (TokenIntegrityLevel = 25)
        bufSize = ctypes.wintypes.DWORD(0)
        advapi32.GetTokenInformation(hToken, 25, None, 0, ctypes.byref(bufSize))
        if bufSize.value > 0:
            buf = ctypes.create_string_buffer(bufSize.value)
            if advapi32.GetTokenInformation(hToken, 25, buf, bufSize.value, ctypes.byref(bufSize)):
                # TOKEN_MANDATORY_LABEL struct: first field is SID_AND_ATTRIBUTES
                # On 64-bit: 8-byte pointer + 4-byte attributes
                # The RID of the integrity SID tells us the level
                pSid = ctypes.c_void_p.from_buffer_copy(buf, 0).value
                if pSid:
                    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
                    advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
                    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(ctypes.wintypes.DWORD)
                    advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD]
                    count = advapi32.GetSidSubAuthorityCount(pSid)[0]
                    if count > 0:
                        rid = advapi32.GetSidSubAuthority(pSid, count - 1)[0]
                        levels = {0x1000: 'Low', 0x2000: 'Medium', 0x3000: 'High', 0x4000: 'System'}
                        level_name = levels.get(rid, f'0x{rid:04X}')
                        print(f"  [INFO] Integrity level: {level_name} (RID=0x{rid:04X})")
                        results.append(('INFO', f'token: integrity={level_name}'))

        # Privilege count (TokenPrivileges = 3)
        bufSize2 = ctypes.wintypes.DWORD(0)
        advapi32.GetTokenInformation(hToken, 3, None, 0, ctypes.byref(bufSize2))
        if bufSize2.value > 0:
            buf2 = ctypes.create_string_buffer(bufSize2.value)
            if advapi32.GetTokenInformation(hToken, 3, buf2, bufSize2.value, ctypes.byref(bufSize2)):
                # First DWORD is PrivilegeCount
                count = ctypes.c_uint32.from_buffer_copy(buf2, 0).value
                print(f"  [INFO] Token privileges: {count} (should be 0 for AppContainer)")
                results.append(('INFO', f'token: {count} privileges'))

        kernel32.CloseHandle(hToken)
    else:
        print("  [ERR] Cannot open own token")
        results.append(('ERR', 'token: cannot open'))
except Exception as e:
    print(f"  [ERR] Token inspection: {e}")
    results.append(('ERR', f'token: {e}'))


# ===========================================================================
# P6: FindFirstFile Through Denied Area
#
# Can we enumerate denied directories using FindFirstFile wildcards
# even though os.listdir() is blocked?
# ===========================================================================
print("\n=== P6: FindFirstFile through denied area ===")
WIN32_FIND_DATAW = ctypes.wintypes.WIN32_FIND_DATAW

# Try wildcard on forbidden/
hFind = kernel32.FindFirstFileW(p('forbidden', '*'), ctypes.byref(WIN32_FIND_DATAW()))
if hFind != ctypes.wintypes.HANDLE(-1).value and hFind != -1:
    print("  [FAIL] FindFirstFile('forbidden/*') succeeded!")
    results.append(('FAIL', 'findfile: denied dir enumerable'))
    kernel32.FindClose(hFind)
else:
    print("  [PASS] FindFirstFile('forbidden/*'): blocked")
    results.append(('PASS', 'findfile: denied dir blocked'))

# Try specific filename in forbidden
hFind2 = kernel32.FindFirstFileW(p('forbidden', 'secret.txt'), ctypes.byref(WIN32_FIND_DATAW()))
if hFind2 != ctypes.wintypes.HANDLE(-1).value and hFind2 != -1:
    print("  [FAIL] FindFirstFile('forbidden/secret.txt') succeeded!")
    results.append(('FAIL', 'findfile: specific file in denied'))
    kernel32.FindClose(hFind2)
else:
    print("  [PASS] FindFirstFile('forbidden/secret.txt'): blocked")
    results.append(('PASS', 'findfile: specific file blocked'))


# ===========================================================================
# P7: ReadDirectoryChangesW on Arena — Can We See Denied Subtree Changes?
#
# Open a directory handle on arena/ and watch for changes.
# Does the notification report events in forbidden/ subdirectory?
# ===========================================================================
print("\n=== P7: Directory change notifications ===")
FILE_LIST_DIRECTORY = 0x0001
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

hDir = kernel32.CreateFileW(
    ARENA, FILE_LIST_DIRECTORY,
    0x7, None, 3,  # OPEN_EXISTING
    FILE_FLAG_BACKUP_SEMANTICS, None)

if hDir != ctypes.wintypes.HANDLE(-1).value and hDir != -1:
    print("  [INFO] Opened arena/ for directory monitoring")
    results.append(('INFO', 'dirwatch: handle obtained'))
    # We won't actually wait for changes (would block), just verify handle works
    kernel32.CloseHandle(hDir)
else:
    err = kernel32.GetLastError()
    print(f"  [INFO] Cannot open arena/ for monitoring (err={err})")
    results.append(('INFO', f'dirwatch: blocked ({err})'))


# ===========================================================================
# P8: Memory-Mapped File Write on Denied Folder
#
# Can we create a memory-mapped file in the readonly zone?
# Even though normal write is denied, does mmap bypass the check?
# ===========================================================================
print("\n=== P8: Memory-mapped file bypass ===")
import mmap
# Try mmap write in readonly zone
ro_file = p('readonly', 'report.txt')
try:
    with open(ro_file, 'r+b') as f:
        mm = mmap.mmap(f.fileno(), 0)
        mm[0:5] = b'PWNED'
        mm.close()
    print("  [FAIL] mmap write to readonly zone succeeded!")
    results.append(('FAIL', 'mmap: write to readonly'))
except (PermissionError, OSError, ValueError) as e:
    print(f"  [PASS] mmap write to readonly: blocked ({e})")
    results.append(('PASS', 'mmap: readonly blocked'))

# mmap in arena (should work)
mmap_file = w('mmap_test.bin')
try:
    with open(mmap_file, 'wb') as f:
        f.write(b'\x00' * 4096)
    with open(mmap_file, 'r+b') as f:
        mm = mmap.mmap(f.fileno(), 4096)
        mm[0:11] = b'HELLO_MMAP!'
        val = mm[0:11]
        mm.close()
    if val == b'HELLO_MMAP!':
        print("  [PASS] mmap in arena: read+write")
        results.append(('PASS', 'mmap: arena ok'))
    os.remove(mmap_file)
except Exception as e:
    print(f"  [ERR] mmap arena: {e}")
    results.append(('ERR', f'mmap: {e}'))


# ===========================================================================
# P9: Timestamp and Attribute Forgery
#
# SetFileTime to backdate files, SetFileAttributes to hide files.
# Can we forge timestamps in the arena? Can we mess with denied zone attrs?
# ===========================================================================
print("\n=== P9: Timestamp/attribute forgery ===")
ts_file = w('timestamp_victim.txt')
try:
    with open(ts_file, 'w') as f:
        f.write('timestamp test')
    # Set creation time to 2000-01-01 via SetFileTime
    h = kernel32.CreateFileW(ts_file, 0x0100, 0x7, None, 3, 0, None)  # FILE_WRITE_ATTRIBUTES
    if h != ctypes.wintypes.HANDLE(-1).value and h != -1:
        # FILETIME for 2000-01-01 00:00:00 UTC
        # 100ns intervals since 1601-01-01
        ft2000 = ctypes.wintypes.FILETIME()
        ft2000.dwLowDateTime = 0xD0BE4800
        ft2000.dwHighDateTime = 0x01BF53EB
        ok = kernel32.SetFileTime(h, ctypes.byref(ft2000), None, None)
        kernel32.CloseHandle(h)
        if ok:
            print("  [INFO] Set creation time to Y2K in arena")
            results.append(('INFO', 'timestamp: forged in arena'))
        else:
            print("  [INFO] SetFileTime failed")
            results.append(('INFO', 'timestamp: SetFileTime failed'))
    else:
        print("  [INFO] Cannot open for WRITE_ATTRIBUTES")
        results.append(('INFO', 'timestamp: no WRITE_ATTRIBUTES'))
    os.remove(ts_file)
except Exception as e:
    print(f"  [ERR] timestamp: {e}")
    results.append(('ERR', f'timestamp: {e}'))

# SetFileTime on denied zone
h2 = kernel32.CreateFileW(p('forbidden'), 0x0100, 0x7, None, 3, 0x02000000, None)
if h2 != ctypes.wintypes.HANDLE(-1).value and h2 != -1:
    print("  [FAIL] WRITE_ATTRIBUTES on forbidden/ succeeded!")
    results.append(('FAIL', 'timestamp: WRITE_ATTRIBUTES on denied'))
    kernel32.CloseHandle(h2)
else:
    print("  [PASS] WRITE_ATTRIBUTES on forbidden/: blocked")
    results.append(('PASS', 'timestamp: denied blocked'))


# ===========================================================================
# P10: DELETE_ON_CLOSE Persistence
#
# Create a file with FILE_FLAG_DELETE_ON_CLOSE. The file should vanish
# when we close the handle. Does it leave any ACL artifacts?
# ===========================================================================
print("\n=== P10: DELETE_ON_CLOSE and temporary files ===")
doc_file = w('delete_on_close.tmp')
FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000

h = kernel32.CreateFileW(
    doc_file, GENERIC_WRITE | GENERIC_READ,
    0, None, 2,  # CREATE_ALWAYS
    FILE_FLAG_DELETE_ON_CLOSE, None)
if h != ctypes.wintypes.HANDLE(-1).value and h != -1:
    # Write data
    data = b'delete_on_close_test'
    written = ctypes.wintypes.DWORD(0)
    kernel32.WriteFile(h, data, len(data), ctypes.byref(written), None)
    # File exists while handle is open
    exists_during = os.path.exists(doc_file)
    kernel32.CloseHandle(h)
    # File should be gone after close
    exists_after = os.path.exists(doc_file)
    if exists_during and not exists_after:
        print("  [PASS] DELETE_ON_CLOSE: file created then auto-deleted")
        results.append(('PASS', 'doc: auto-deleted'))
    elif exists_after:
        print("  [FAIL] DELETE_ON_CLOSE: file persists after close!")
        results.append(('FAIL', 'doc: persisted'))
    else:
        print("  [INFO] DELETE_ON_CLOSE: file never visible")
        results.append(('INFO', 'doc: never visible'))
else:
    err = kernel32.GetLastError()
    print(f"  [ERR] DELETE_ON_CLOSE: CreateFile failed ({err})")
    results.append(('ERR', f'doc: CreateFile failed ({err})'))


# ===========================================================================
# P11: Sparse File Attack — virtual size manipulation
#
# Create a sparse file with huge virtual size but tiny actual allocation.
# Does this affect cleanup performance or disk quota?
# ===========================================================================
print("\n=== P11: Sparse file manipulation ===")
sparse_file = w('sparse.dat')
FSCTL_SET_SPARSE = 0x000900C4
FSCTL_SET_ZERO_DATA = 0x000980C8
try:
    with open(sparse_file, 'wb') as f:
        f.write(b'\x00' * 1024)
    # Mark as sparse
    h = kernel32.CreateFileW(sparse_file, GENERIC_WRITE | GENERIC_READ,
                             0x7, None, 3, 0, None)
    if h != ctypes.wintypes.HANDLE(-1).value and h != -1:
        br = ctypes.wintypes.DWORD(0)
        ok = kernel32.DeviceIoControl(h, FSCTL_SET_SPARSE, None, 0, None, 0,
                                       ctypes.byref(br), None)
        if ok:
            # Extend to 1GB virtual size
            kernel32.SetFilePointer(h, 1024*1024*1024, None, 0)
            kernel32.SetEndOfFile(h)
            # Actual allocation should still be tiny
            size_high = ctypes.wintypes.DWORD(0)
            size_low = kernel32.GetCompressedFileSizeW(sparse_file, ctypes.byref(size_high))
            actual = size_low + (size_high.value << 32)
            print(f"  [INFO] Sparse file: 1GB virtual, {actual} bytes actual")
            results.append(('INFO', f'sparse: 1GB virt, {actual}B actual'))
        else:
            print("  [INFO] FSCTL_SET_SPARSE failed")
            results.append(('INFO', 'sparse: not supported'))
        kernel32.CloseHandle(h)
    os.remove(sparse_file)
except Exception as e:
    print(f"  [ERR] sparse: {e}")
    results.append(('ERR', f'sparse: {e}'))


# ===========================================================================
# SUMMARY
# ===========================================================================
passed = sum(1 for r in results if r[0] == 'PASS')
failed = sum(1 for r in results if r[0] == 'FAIL')
errors = sum(1 for r in results if r[0] == 'ERR')
skipped = sum(1 for r in results if r[0] == 'SKIP')
info = sum(1 for r in results if r[0] == 'INFO')

print(f"\n{'=' * 70}")
print(f"  PHANTOM TEST: {passed} passed, {failed} FAILED, {errors} errors, {skipped} skipped, {info} info")
print(f"  (of {len(results)} total)")
if failed > 0:
    print(f"\n  SANDY WAS BROKEN:")
    for status, name in results:
        if status == 'FAIL':
            print(f"    !! {name}")
print(f"{'=' * 70}")

sys.exit(0 if failed == 0 else 1)
