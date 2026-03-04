// =========================================================================
// SandboxACL.h — Permission grant utilities
//
// ACL helpers for granting file/folder and registry access to a SID.
// Used by both AppContainer and Restricted Token modes.
// =========================================================================
#pragma once

#include "SandboxTypes.h"

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Convert user-friendly registry path to Win32 object path
    // -----------------------------------------------------------------------
    inline std::wstring RegistryToWin32Path(const std::wstring& path)
    {
        if (_wcsnicmp(path.c_str(), L"HKCU\\", 5) == 0) return L"CURRENT_USER\\" + path.substr(5);
        if (_wcsnicmp(path.c_str(), L"HKLM\\", 5) == 0) return L"MACHINE\\" + path.substr(5);
        return path;
    }

    // -----------------------------------------------------------------------
    // Get the permission mask for an access level (for forensic logging)
    // -----------------------------------------------------------------------
    inline DWORD AccessMask(AccessLevel level) {
        switch (level) {
        case AccessLevel::Read:    return FILE_GENERIC_READ;
        case AccessLevel::Write:   return FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        case AccessLevel::Execute: return FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        case AccessLevel::Append:  return FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        case AccessLevel::Delete:  return DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        // FILE_DELETE_CHILD excluded: children inherit their own DELETE via
        // ACL inheritance.  Without this exclusion, a parent's FILE_DELETE_CHILD
        // lets the sandbox delete denied children and recreate them without deny.
        // WRITE_DAC excluded: prevents sandbox from modifying ACLs (e.g.
        // re-adding FILE_DELETE_CHILD to escalate back to full control).
        // WRITE_OWNER excluded: no legitimate sandbox use for ownership changes.
        case AccessLevel::All:     return FILE_ALL_ACCESS & ~(FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER);
        default:                   return 0;
        }
    }

    // -----------------------------------------------------------------------
    // Track granted ACLs for cleanup — restore original DACLs on exit
    // -----------------------------------------------------------------------
    struct ACLGrant {
        std::wstring path;
        SE_OBJECT_TYPE objType;
        std::wstring originalSDDL;
        BYTE objectId[16] = {};  // NTFS Object ID for rename-resilient cleanup
    };
    inline std::vector<ACLGrant> g_aclGrants;
    inline SRWLOCK g_aclGrantsLock = SRWLOCK_INIT;
    inline std::atomic<bool> g_cleanedUp{false};

    static const wchar_t* kGrantsParentKey = L"Software\\Sandy\\Grants";

    // Per-instance UUID — set once at startup, used for registry and container
    inline std::wstring g_instanceId;

    inline std::wstring GetGrantsRegKey() {
        return std::wstring(kGrantsParentKey) + L"\\" + g_instanceId;
    }

    // -----------------------------------------------------------------------
    // Read a REG_SZ value by enumeration index.  Returns false if the index
    // has no string data or is a metadata value (name starts with L'_').
    // On success, `name` and `data` are populated with the trimmed strings.
    // -----------------------------------------------------------------------
    inline bool ReadRegSzEnum(HKEY hKey, DWORD index,
                              std::wstring& name, std::wstring& data)
    {
        wchar_t vname[64];
        DWORD vnameLen = 64;
        DWORD dataSize = 0, dataType = 0;
        if (RegEnumValueW(hKey, index, vname, &vnameLen, nullptr, &dataType,
                          nullptr, &dataSize) != ERROR_SUCCESS)
            return false;
        if (vname[0] == L'_' || dataType != REG_SZ) return false;

        data.assign(dataSize / sizeof(wchar_t), L'\0');
        vnameLen = 64;
        if (RegEnumValueW(hKey, index, vname, &vnameLen, nullptr, nullptr,
                          reinterpret_cast<BYTE*>(&data[0]), &dataSize) != ERROR_SUCCESS)
            return false;
        while (!data.empty() && data.back() == L'\0') data.pop_back();
        name = vname;
        return true;
    }

    // -----------------------------------------------------------------------
    // Check if a PID is alive AND belongs to the sandy process that stored it.
    // Guards against PID reuse via creation time, and detects terminated
    // zombie processes (killed but not yet reaped) via WaitForSingleObject.
    // -----------------------------------------------------------------------
    inline bool IsProcessAlive(DWORD pid, ULONGLONG storedCreationTime)
    {
        if (!pid) return false;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
        if (!h) return false;

        // Check if process has actually exited (signaled = terminated)
        if (WaitForSingleObject(h, 0) != WAIT_TIMEOUT) {
            CloseHandle(h);
            return false;  // Process terminated (zombie awaiting handle cleanup)
        }

        bool alive = true;
        if (storedCreationTime != 0) {
            FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
            if (GetProcessTimes(h, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                ULARGE_INTEGER li;
                li.LowPart = ftCreate.dwLowDateTime;
                li.HighPart = ftCreate.dwHighDateTime;
                alive = (li.QuadPart == storedCreationTime);
            }
        }
        CloseHandle(h);
        return alive;
    }

    // -----------------------------------------------------------------------
    // Get the current process creation time as a 64-bit value
    // -----------------------------------------------------------------------
    inline ULONGLONG GetCurrentProcessCreationTime()
    {
        FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
        if (GetProcessTimes(GetCurrentProcess(), &ftCreate, &ftExit, &ftKernel, &ftUser)) {
            ULARGE_INTEGER li;
            li.LowPart = ftCreate.dwLowDateTime;
            li.HighPart = ftCreate.dwHighDateTime;
            return li.QuadPart;
        }
        return 0;
    }

    inline void PersistGrant(const std::wstring& path, SE_OBJECT_TYPE objType,
                             const std::wstring& sddl)
    {
        std::wstring regKey = GetGrantsRegKey();
        HKEY hKey = nullptr;
        DWORD disposition = 0;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr,
                0, KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC,
                nullptr, &hKey, &disposition) != ERROR_SUCCESS) {
            g_logger.Log((L"REG_PERSIST: FAILED to create key " + regKey).c_str());
            return;
        }

        // On first creation, store PID + creation time and deny Restricted SID write access.
        if (disposition == REG_CREATED_NEW_KEY) {
            DWORD pid = GetCurrentProcessId();
            RegSetValueExW(hKey, L"_pid", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&pid), sizeof(DWORD));

            // Store creation time for PID reuse detection
            ULONGLONG ct = GetCurrentProcessCreationTime();
            RegSetValueExW(hKey, L"_ctime", 0, REG_QWORD,
                           reinterpret_cast<const BYTE*>(&ct), sizeof(ULONGLONG));

            // Store container name for cleanup
            std::wstring containerName = ContainerNameFromId(g_instanceId);
            RegSetValueExW(hKey, L"_container", 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(containerName.c_str()),
                           static_cast<DWORD>((containerName.size() + 1) * sizeof(wchar_t)));

            // Deny Restricted SID (S-1-5-12) write access.
            SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
            PSID pRestricted = nullptr;
            if (AllocateAndInitializeSid(&ntAuth, 1, SECURITY_RESTRICTED_CODE_RID,
                    0, 0, 0, 0, 0, 0, 0, &pRestricted)) {
                EXPLICIT_ACCESSW deny{};
                deny.grfAccessPermissions = KEY_ALL_ACCESS;
                deny.grfAccessMode = DENY_ACCESS;
                deny.grfInheritance = NO_INHERITANCE;
                deny.Trustee.TrusteeForm = TRUSTEE_IS_SID;
                deny.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pRestricted);

                PACL pOldDacl = nullptr;
                PSECURITY_DESCRIPTOR pKeySD = nullptr;
                if (GetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, &pOldDacl, nullptr, &pKeySD) == ERROR_SUCCESS) {
                    PACL pNewDacl = nullptr;
                    if (SetEntriesInAclW(1, &deny, pOldDacl, &pNewDacl) == ERROR_SUCCESS) {
                        SetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                            nullptr, nullptr, pNewDacl, nullptr);
                        LocalFree(pNewDacl);
                    }
                    LocalFree(pKeySD);
                }
                FreeSid(pRestricted);
            }
        }

        // Use dedicated counter (_nextIdx) to avoid index collisions with
        // metadata values (_pid, _ctime, _container). Atomically read+increment.
        DWORD nextIdx = 0;
        DWORD idxSize = sizeof(nextIdx);
        RegQueryValueExW(hKey, L"_nextIdx", nullptr, nullptr,
                         reinterpret_cast<BYTE*>(&nextIdx), &idxSize);

        // Format: TYPE|PATH|SDDL
        std::wstring typeStr = (objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
        std::wstring data = typeStr + L"|" + path + L"|" + sddl;

        wchar_t valueName[32];
        swprintf(valueName, 32, L"%lu", nextIdx);
        RegSetValueExW(hKey, valueName, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(data.c_str()),
                       static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t)));

        // Increment and store counter
        nextIdx++;
        RegSetValueExW(hKey, L"_nextIdx", 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&nextIdx), sizeof(nextIdx));

        // Stamp NTFS Object ID for rename-resilient cleanup.
        // If the sandboxed process renames a granted path, the Object ID
        // follows the inode and lets us find it during cleanup.
        if (objType == SE_FILE_OBJECT) {
            HANDLE hFile = CreateFileW(path.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                FILE_OBJECTID_BUFFER oidBuf = {};
                DWORD bytes = 0;
                if (DeviceIoControl(hFile, FSCTL_CREATE_OR_GET_OBJECT_ID,
                        nullptr, 0, &oidBuf, sizeof(oidBuf), &bytes, nullptr)) {
                    wchar_t oidName[32];
                    swprintf(oidName, 32, L"_oid_%lu", nextIdx - 1);
                    RegSetValueExW(hKey, oidName, 0, REG_BINARY,
                                   oidBuf.ObjectId, 16);
                    g_logger.Log((L"OID_STAMP: " + path).c_str());
                }
                CloseHandle(hFile);
            }
        }

        RegCloseKey(hKey);

        g_logger.Log((L"REG_PERSIST: [" + std::to_wstring(nextIdx - 1) + L"] " + data).c_str());
    }

    // -----------------------------------------------------------------------
    // Clear this instance's persisted grants from registry
    // -----------------------------------------------------------------------
    inline void ClearPersistedGrants()
    {
        std::wstring regKey = GetGrantsRegKey();
        LSTATUS r = RegDeleteKeyW(HKEY_CURRENT_USER, regKey.c_str());
        g_logger.Log((L"REG_CLEAR: " + regKey + (r == ERROR_SUCCESS ? L" -> OK" : L" -> NOT_FOUND")).c_str());
        // Try to remove parent key if empty (best-effort, fails if subkeys remain)
        RegDeleteKeyW(HKEY_CURRENT_USER, kGrantsParentKey);
    }

    // -----------------------------------------------------------------------
    // Tree security progress callback — logs per-object errors during
    // TreeSetNamedSecurityInfoW so failures are not silently swallowed.
    // -----------------------------------------------------------------------
    inline void WINAPI TreeSecurityProgress(
        LPWSTR pObjectName, DWORD Status,
        PPROG_INVOKE_SETTING pInvokeSetting, PVOID Args, BOOL SecuritySet)
    {
        (void)pInvokeSetting; (void)Args; (void)SecuritySet;
        if (Status != ERROR_SUCCESS && pObjectName) {
            wchar_t msg[512];
            swprintf(msg, 512, L"ACL_TREE_ERROR: %s (error %lu)", pObjectName, Status);
            g_logger.Log(msg);
        }
    }

    // -----------------------------------------------------------------------
    // Grant access to a file/folder or registry key with specific permissions
    // -----------------------------------------------------------------------
    inline bool GrantObjectAccess(PSID pSid, const std::wstring& path,
                                  AccessLevel level, SE_OBJECT_TYPE objType = SE_FILE_OBJECT)
    {
        DWORD permissions = AccessMask(level);

        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = permissions;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);

        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            path.c_str(), objType, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS)
            return false;

        // Build new DACL in memory (no system state modified yet)
        PACL pNewDacl = nullptr;
        rc = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
        if (rc != ERROR_SUCCESS) {
            LocalFree(pSD);
            return false;
        }

        // Save original DACL as SDDL (write-ahead for crash recovery).
        // Done after SetEntriesInAcl succeeds but before SetNamedSecurityInfoW
        // modifies the object — no rollback needed on failure above.
        {
            LPWSTR origSddl = nullptr;
            if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &origSddl, nullptr)) {
                AcquireSRWLockExclusive(&g_aclGrantsLock);
                PersistGrant(path, objType, origSddl);
                g_aclGrants.push_back({ path, objType, origSddl });
                // Stamp NTFS Object ID into in-memory entry for rename-resilient cleanup
                if (objType == SE_FILE_OBJECT) {
                    HANDLE hOid = CreateFileW(path.c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
                    if (hOid != INVALID_HANDLE_VALUE) {
                        FILE_OBJECTID_BUFFER ob = {};
                        DWORD b = 0;
                        if (DeviceIoControl(hOid, FSCTL_CREATE_OR_GET_OBJECT_ID,
                                nullptr, 0, &ob, sizeof(ob), &b, nullptr))
                            memcpy(g_aclGrants.back().objectId, ob.ObjectId, 16);
                        CloseHandle(hOid);
                    }
                }
                ReleaseSRWLockExclusive(&g_aclGrantsLock);
                LocalFree(origSddl);
            }
        }
        LocalFree(pSD);

        // Apply the new DACL.
        // For directories, use TreeSetNamedSecurityInfo to synchronously
        // propagate inheritable ACEs to all children.  SetNamedSecurityInfoW
        // does NOT propagate to existing child files, causing AppContainer
        // processes to fail with STATUS_ACCESS_DENIED (0xC0000022).
        DWORD attr = (objType == SE_FILE_OBJECT) ? GetFileAttributesW(path.c_str()) : 0;
        bool isDir = (objType == SE_FILE_OBJECT) && (attr != INVALID_FILE_ATTRIBUTES)
                     && (attr & FILE_ATTRIBUTE_DIRECTORY);
        if (isDir) {
            rc = TreeSetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()), objType,
                DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDacl, nullptr,
                TREE_SEC_INFO_SET, TreeSecurityProgress, ProgressInvokeOnError, nullptr);
        } else {
            rc = SetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()), objType,
                DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDacl, nullptr);
        }
        LocalFree(pNewDacl);

        // Log SDDL of the resulting DACL for forensic analysis
        if (rc == ERROR_SUCCESS) {
            PACL pResultDacl = nullptr;
            PSECURITY_DESCRIPTOR pResultSD = nullptr;
            if (GetNamedSecurityInfoW(path.c_str(), objType,
                    DACL_SECURITY_INFORMATION, nullptr, nullptr,
                    &pResultDacl, nullptr, &pResultSD) == ERROR_SUCCESS) {
                LPWSTR sddl = nullptr;
                if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        pResultSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                        &sddl, nullptr)) {
                    std::wstring logMsg = L"GRANT_SDDL: " + path + L" -> " + sddl;
                    g_logger.Log(logMsg.c_str());
                    LocalFree(sddl);
                }
                LocalFree(pResultSD);
            }
        }

        return rc == ERROR_SUCCESS;
    }

    // -----------------------------------------------------------------------
    // Deny access to a file/folder.
    //
    // Strategy depends on SID type:
    // - Restricted mode: uses real DENY_ACCESS ACEs (kernel enforces them).
    // - AppContainer mode: DENY ACEs are IGNORED by the Windows kernel for
    //   AppContainer SIDs.  Instead, we revoke the existing ALLOW ACE and
    //   re-add a narrower ALLOW with the denied bits subtracted.
    //
    // Respects the access level parameter for fine-grained denial.
    // -----------------------------------------------------------------------
    inline bool DenyObjectAccess(PSID pSid, const std::wstring& path,
                                  AccessLevel level, bool isAppContainer,
                                  SE_OBJECT_TYPE objType = SE_FILE_OBJECT)
    {
        DWORD denyMask = AccessMask(level);

        // --- Read current DACL ---
        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            path.c_str(), objType, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS)
            return false;

        // Save original DACL (write-ahead for crash recovery)
        {
            LPWSTR origSddl = nullptr;
            if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &origSddl, nullptr)) {
                AcquireSRWLockExclusive(&g_aclGrantsLock);
                PersistGrant(path, objType, origSddl);
                g_aclGrants.push_back({ path, objType, origSddl });
                // Stamp NTFS Object ID for rename-resilient cleanup
                if (objType == SE_FILE_OBJECT) {
                    HANDLE hOid = CreateFileW(path.c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
                    if (hOid != INVALID_HANDLE_VALUE) {
                        FILE_OBJECTID_BUFFER ob = {};
                        DWORD b = 0;
                        if (DeviceIoControl(hOid, FSCTL_CREATE_OR_GET_OBJECT_ID,
                                nullptr, 0, &ob, sizeof(ob), &b, nullptr))
                            memcpy(g_aclGrants.back().objectId, ob.ObjectId, 16);
                        CloseHandle(hOid);
                    }
                }
                ReleaseSRWLockExclusive(&g_aclGrantsLock);
                LocalFree(origSddl);
            }
        }

        PACL pNewDacl = nullptr;

        if (isAppContainer) {
            // AppContainer: DENY ACEs don't work.  Instead, build a new DACL
            // that replaces the SID's ALLOW ACE with a reduced-mask one.
            // We must handle INHERITED ACEs (from parent grant's TreeSet)
            // which REVOKE_ACCESS cannot remove.

            // Find existing allowed permissions for this SID (any ACE type)
            DWORD existingMask = 0;
            ACL_SIZE_INFORMATION aclInfo = {};
            if (GetAclInformation(pOldDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
                for (DWORD i = 0; i < aclInfo.AceCount; i++) {
                    PACE_HEADER pAceHdr = nullptr;
                    if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr)))
                        continue;
                    if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                        auto* pAce = reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr);
                        PSID aceSid = &pAce->SidStart;
                        if (EqualSid(aceSid, pSid))
                            existingMask |= pAce->Mask;
                    }
                }
            }

            // Compute reduced mask — only strip bits unique to the denied op
            DWORD sharedBits = SYNCHRONIZE | FILE_READ_ATTRIBUTES | READ_CONTROL
                             | STANDARD_RIGHTS_READ | STANDARD_RIGHTS_WRITE
                             | STANDARD_RIGHTS_EXECUTE;
            DWORD denyOnlyBits = denyMask & ~sharedBits;
            DWORD reducedMask = existingMask & ~denyOnlyBits;

            // Build new ACL manually: copy all ACEs EXCEPT our SID's,
            // then optionally add a single reduced-mask ACE for our SID.
            // This handles both explicit and inherited ACEs.
            DWORD sidLen = GetLengthSid(pSid);
            DWORD newAclSize = sizeof(ACL);
            // First pass: compute size for non-SID ACEs
            for (DWORD i = 0; i < aclInfo.AceCount; i++) {
                PACE_HEADER pAceHdr = nullptr;
                if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr)))
                    continue;
                bool isSidAce = false;
                if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                    auto* pAce = reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr);
                    isSidAce = EqualSid(&pAce->SidStart, pSid);
                }
                if (!isSidAce)
                    newAclSize += pAceHdr->AceSize;
            }
            // Add space for the reduced ACE (if non-zero)
            if (reducedMask != 0) {
                newAclSize += sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + sidLen;
            }

            pNewDacl = reinterpret_cast<PACL>(LocalAlloc(LPTR, newAclSize));
            if (!pNewDacl || !InitializeAcl(pNewDacl, newAclSize, ACL_REVISION)) {
                LocalFree(pSD);
                return false;
            }

            // Second pass: copy non-SID ACEs
            for (DWORD i = 0; i < aclInfo.AceCount; i++) {
                PACE_HEADER pAceHdr = nullptr;
                if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr)))
                    continue;
                bool isSidAce = false;
                if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                    auto* pAce = reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr);
                    isSidAce = EqualSid(&pAce->SidStart, pSid);
                }
                if (!isSidAce)
                    AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pAceHdr, pAceHdr->AceSize);
            }

            // Add reduced ACE (inheritable for dirs, applies to children)
            if (reducedMask != 0) {
                DWORD aceFlags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
                DWORD aceSize = sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + sidLen;
                auto* pNewAce = reinterpret_cast<ACCESS_ALLOWED_ACE*>(LocalAlloc(LPTR, aceSize));
                if (pNewAce) {
                    pNewAce->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
                    pNewAce->Header.AceFlags = static_cast<BYTE>(aceFlags);
                    pNewAce->Header.AceSize = static_cast<WORD>(aceSize);
                    pNewAce->Mask = reducedMask;
                    CopySid(sidLen, &pNewAce->SidStart, pSid);
                    AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pNewAce, aceSize);
                    LocalFree(pNewAce);
                }
            }

            wchar_t msg[256];
            swprintf(msg, 256, L"DENY_AC: existing=0x%08X deny=0x%08X reduced=0x%08X",
                     existingMask, denyMask, reducedMask);
            g_logger.Log(msg);

        } else {
            // Restricted mode: real DENY ACEs work
            EXPLICIT_ACCESSW ea{};
            ea.grfAccessPermissions = denyMask;
            ea.grfAccessMode = DENY_ACCESS;
            ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
            ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);
            rc = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
        }

        LocalFree(pSD);

        if (rc != ERROR_SUCCESS || !pNewDacl)
            return false;

        // Apply the modified DACL.
        // For directories, use TREE_SEC_INFO_RESET with PROTECTED_DACL to
        // completely replace the DACL and break inheritance.  The parent
        // grant's TreeSet propagated an inheritable (I)(F) ACE; without
        // PROTECTED_DACL, Windows re-applies the inherited ACE even after
        // we reset, making the deny ineffective.
        DWORD siFlags = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        DWORD attr = (objType == SE_FILE_OBJECT) ? GetFileAttributesW(path.c_str()) : 0;
        bool isDir = (objType == SE_FILE_OBJECT) && (attr != INVALID_FILE_ATTRIBUTES)
                     && (attr & FILE_ATTRIBUTE_DIRECTORY);
        if (isDir) {
            rc = TreeSetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()), objType,
                siFlags, nullptr, nullptr, pNewDacl, nullptr,
                TREE_SEC_INFO_RESET, TreeSecurityProgress, ProgressInvokeOnError, nullptr);
        } else {
            rc = SetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()), objType,
                siFlags, nullptr, nullptr, pNewDacl, nullptr);
        }
        LocalFree(pNewDacl);

        // Log resulting DACL
        if (rc == ERROR_SUCCESS) {
            PACL pResultDacl = nullptr;
            PSECURITY_DESCRIPTOR pResultSD = nullptr;
            if (GetNamedSecurityInfoW(path.c_str(), objType,
                    DACL_SECURITY_INFORMATION, nullptr, nullptr,
                    &pResultDacl, nullptr, &pResultSD) == ERROR_SUCCESS) {
                LPWSTR sddl = nullptr;
                if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        pResultSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                        &sddl, nullptr)) {
                    std::wstring logMsg = L"DENY_SDDL: " + path + L" -> " + sddl;
                    g_logger.Log(logMsg.c_str());
                    LocalFree(sddl);
                }
                LocalFree(pResultSD);
            }
        }

        return rc == ERROR_SUCCESS;
    }

    // -----------------------------------------------------------------------
    // Resolve a path via NTFS Object ID if the original path is gone.
    // Returns the new path if found, or empty string if not resolvable.
    // -----------------------------------------------------------------------
    inline std::wstring ResolveByObjectId(const std::wstring& originalPath,
                                          const BYTE objectId[16])
    {
        // Check if OID is all zeros (not stamped)
        bool hasOid = false;
        for (int i = 0; i < 16; i++) {
            if (objectId[i] != 0) { hasOid = true; break; }
        }
        if (!hasOid) return {};

        // Extract volume root from original path (e.g. "C:" from "C:\Users\...")
        if (originalPath.size() < 2 || originalPath[1] != L':') return {};
        std::wstring volPath = L"\\\\.\\" + originalPath.substr(0, 2);

        HANDLE hVol = CreateFileW(volPath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (hVol == INVALID_HANDLE_VALUE) return {};

        FILE_ID_DESCRIPTOR fid = {};
        fid.dwSize = sizeof(fid);
        fid.Type = ObjectIdType;
        memcpy(&fid.ObjectId, objectId, 16);

        HANDLE hFile = OpenFileById(hVol, &fid,
            GENERIC_READ | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, FILE_FLAG_BACKUP_SEMANTICS);
        CloseHandle(hVol);

        if (hFile == INVALID_HANDLE_VALUE) return {};

        wchar_t newPath[1024] = {};
        DWORD len = GetFinalPathNameByHandleW(hFile, newPath, 1024, 0);
        CloseHandle(hFile);

        if (len == 0 || len >= 1024) return {};

        // GetFinalPathNameByHandle returns \\?\C:\... — strip the \\?\ prefix
        std::wstring result = newPath;
        if (result.substr(0, 4) == L"\\\\?\\")
            result = result.substr(4);

        g_logger.Log((L"OID_RESOLVE: " + originalPath + L" -> " + result).c_str());
        return result;
    }

    // -----------------------------------------------------------------------
    // Restore a single object's DACL from its saved SDDL string.
    // Uses TreeSetNamedSecurityInfo for directories to propagate to children.
    // Falls back to NTFS Object ID lookup if path has been renamed.
    // -----------------------------------------------------------------------
    inline void RestoreDacl(const std::wstring& path, const std::wstring& sddl,
                            SE_OBJECT_TYPE objType,
                            const BYTE objectId[16] = nullptr)
    {
        std::wstring resolvedPath = path;

        // If the original path no longer exists, try to find it by Object ID
        if (objType == SE_FILE_OBJECT &&
            GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES &&
            objectId != nullptr) {
            std::wstring newPath = ResolveByObjectId(path, objectId);
            if (!newPath.empty()) {
                resolvedPath = newPath;
            } else {
                g_logger.Log((L"ACL_RESTORE_SKIP: path gone, OID not found: " + path).c_str());
                return;
            }
        }

        PSECURITY_DESCRIPTOR pSD = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.c_str(), SDDL_REVISION_1, &pSD, nullptr))
            return;

        BOOL present = FALSE, defaulted = FALSE;
        PACL pDacl = nullptr;
        if (GetSecurityDescriptorDacl(pSD, &present, &pDacl, &defaulted) && present) {
            DWORD attrs = (objType == SE_FILE_OBJECT) ? GetFileAttributesW(resolvedPath.c_str()) : 0;
            bool isDir = (objType == SE_FILE_OBJECT)
                         && (attrs != INVALID_FILE_ATTRIBUTES)
                         && (attrs & FILE_ATTRIBUTE_DIRECTORY);
            if (isDir) {
                TreeSetNamedSecurityInfoW(
                    const_cast<LPWSTR>(resolvedPath.c_str()), objType,
                    DACL_SECURITY_INFORMATION, nullptr, nullptr, pDacl, nullptr,
                    TREE_SEC_INFO_SET, TreeSecurityProgress, ProgressInvokeOnError, nullptr);
            } else {
                SetNamedSecurityInfoW(
                    const_cast<LPWSTR>(resolvedPath.c_str()), objType,
                    DACL_SECURITY_INFORMATION, nullptr, nullptr, pDacl, nullptr);
            }
            g_logger.Log((L"ACL_RESTORE: " + resolvedPath).c_str());
        }
        LocalFree(pSD);
    }

    // -----------------------------------------------------------------------
    // Helper: restore grants from a single registry subkey.
    // Skips paths in protectedPaths (still needed by live instances).
    // -----------------------------------------------------------------------
    inline void RestoreGrantsFromKey(HKEY hKey,
                                      const std::set<std::wstring>& protectedPaths = {})
    {
        // Use RegEnumValueW to iterate all values (avoids index-offset bug
        // where _pid, _ctime, _container consume indices 0-2).
        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        for (DWORD vi = 0; vi < valueCount; vi++) {
            std::wstring vname, data;
            if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;

            // Parse TYPE|PATH|SDDL — use rfind for last '|' (safe for paths with '|')
            auto sep1 = data.find(L'|');
            if (sep1 == std::wstring::npos) continue;
            auto sep2 = data.rfind(L'|');
            if (sep2 == std::wstring::npos || sep2 <= sep1) continue;

            std::wstring typeStr = data.substr(0, sep1);
            std::wstring path = data.substr(sep1 + 1, sep2 - sep1 - 1);
            std::wstring sddl = data.substr(sep2 + 1);

            // Skip paths still needed by live instances
            if (protectedPaths.count(path)) {
                g_logger.Log((L"ACL_SKIP_STALE: " + path + L" (live instance active)").c_str());
                continue;
            }

            // Look up stored NTFS Object ID for rename-resilient restore
            BYTE oid[16] = {};
            std::wstring oidName = L"_oid_" + vname;
            DWORD oidSize = 16;
            RegQueryValueExW(hKey, oidName.c_str(), nullptr, nullptr, oid, &oidSize);

            SE_OBJECT_TYPE objType = (typeStr == L"REG") ? SE_REGISTRY_KEY : SE_FILE_OBJECT;
            RestoreDacl(path, sddl, objType, oid);
        }
    }

    // -----------------------------------------------------------------------
    // Collect paths granted by OTHER sandy instances (from registry).
    // Used to avoid revoking ACEs that another live instance still needs.
    // -----------------------------------------------------------------------
    inline bool ReadPidAndCtime(HKEY hKey, DWORD& pid, ULONGLONG& ctime)
    {
        pid = 0; ctime = 0;
        DWORD size = sizeof(DWORD);
        RegQueryValueExW(hKey, L"_pid", nullptr, nullptr,
                         reinterpret_cast<BYTE*>(&pid), &size);
        size = sizeof(ULONGLONG);
        RegQueryValueExW(hKey, L"_ctime", nullptr, nullptr,
                         reinterpret_cast<BYTE*>(&ctime), &size);
        return pid != 0;
    }

    inline std::set<std::wstring> GetOtherInstancePaths(const std::wstring& excludeId)
    {
        std::set<std::wstring> paths;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return paths;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[128];
            DWORD nameLen = 128;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;

            if (excludeId == name) continue;  // skip our own instance

            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + name;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            // Only collect paths from LIVE instances (Bug 6 fix)
            DWORD pid = 0; ULONGLONG ctime = 0;
            ReadPidAndCtime(hKey, pid, ctime);
            if (!IsProcessAlive(pid, ctime)) {
                RegCloseKey(hKey);
                continue;  // dead instance — don't protect its paths
            }

            DWORD valueCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &valueCount, nullptr, nullptr, nullptr, nullptr);

            for (DWORD vi = 0; vi < valueCount; vi++) {
                std::wstring vname, data;
                if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;

                auto sep1 = data.find(L'|');
                auto sep2 = data.rfind(L'|');
                if (sep1 != std::wstring::npos && sep2 != std::wstring::npos && sep2 > sep1) {
                    std::wstring path = data.substr(sep1 + 1, sep2 - sep1 - 1);
                    paths.insert(path);
                }
            }
            RegCloseKey(hKey);
        }
        RegCloseKey(hParent);
        return paths;
    }

    // -----------------------------------------------------------------------
    // Restore all DACLs to their pre-grant state (called on exit)
    // Thread-safe: protects g_aclGrants against CTRL+C signal handler race.
    // Multi-instance safe: skips paths still needed by other sandy instances.
    // -----------------------------------------------------------------------
    inline void RevokeAllGrants()
    {
        // Guard against double cleanup (Ctrl+C handler vs normal exit race)
        if (g_cleanedUp.exchange(true)) return;

        AcquireSRWLockExclusive(&g_aclGrantsLock);

        // Check which paths other instances still need
        std::set<std::wstring> otherPaths = GetOtherInstancePaths(g_instanceId);

        // Collect all original grant paths (for ancestor check).
        // Used to skip renamed children covered by a parent TreeSet.
        std::set<std::wstring> allGrantPaths;
        for (const auto& grant : g_aclGrants)
            allGrantPaths.insert(grant.path);

        for (auto it = g_aclGrants.rbegin(); it != g_aclGrants.rend(); ++it) {
            if (otherPaths.count(it->path)) {
                g_logger.Log((L"ACL_SKIP: " + it->path + L" (other instance active)").c_str());
                continue;
            }

            // If the path was renamed (doesn't exist), check if a parent path
            // is also in the grants list.  If so, skip this entry — the parent's
            // TreeSetNamedSecurityInfo will propagate clean ACEs to the renamed
            // child.  Restoring the child's intermediate SDDL would create
            // explicit ACEs that TreeSet can't remove (SDDL round-trip loses
            // the INHERITED_ACE flag).
            if (it->objType == SE_FILE_OBJECT &&
                GetFileAttributesW(it->path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                bool hasParentGrant = false;
                for (const auto& grantPath : allGrantPaths) {
                    if (grantPath == it->path) continue;
                    // Check if grantPath is an ancestor of this path
                    if (it->path.size() > grantPath.size() &&
                        _wcsnicmp(it->path.c_str(), grantPath.c_str(), grantPath.size()) == 0 &&
                        (it->path[grantPath.size()] == L'\\' || it->path[grantPath.size()] == L'/')) {
                        hasParentGrant = true;
                        break;
                    }
                }
                if (hasParentGrant) {
                    g_logger.Log((L"ACL_SKIP_CHILD: " + it->path +
                                  L" (renamed, parent TreeSet will handle)").c_str());
                    continue;
                }
            }

            RestoreDacl(it->path, it->originalSDDL, it->objType, it->objectId);
        }
        g_aclGrants.clear();
        ReleaseSRWLockExclusive(&g_aclGrantsLock);
        ClearPersistedGrants();
    }

    // -----------------------------------------------------------------------
    // Restore stale grants from registry (cleanup after crash/power loss).
    // Only processes dead PIDs. Skips paths still needed by live instances.
    // Also deletes stale AppContainer profiles using stored container name.
    // -----------------------------------------------------------------------
    inline void RestoreStaleGrants()
    {
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return;  // no stale grants

        // Enumerate all UUID subkeys
        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        std::vector<std::wstring> subKeys;
        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[128];
            DWORD nameLen = 128;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                subKeys.push_back(name);
        }
        RegCloseKey(hParent);
        // Helper: read _container string from a subkey
        auto readContainer = [](HKEY hKey) -> std::wstring {
            DWORD size = 0;
            if (RegQueryValueExW(hKey, L"_container", nullptr, nullptr,
                                 nullptr, &size) != ERROR_SUCCESS)
                return {};
            std::wstring val(size / sizeof(wchar_t), L'\0');
            RegQueryValueExW(hKey, L"_container", nullptr, nullptr,
                             reinterpret_cast<BYTE*>(&val[0]), &size);
            while (!val.empty() && val.back() == L'\0') val.pop_back();
            return val;
        };

        // Helper: collect grant paths from a subkey
        auto collectPaths = [](HKEY hKey, std::set<std::wstring>& outPaths) {
            DWORD valueCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &valueCount, nullptr, nullptr, nullptr, nullptr);
            for (DWORD vi = 0; vi < valueCount; vi++) {
                std::wstring vname, data;
                if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;
                auto sep1 = data.find(L'|');
                auto sep2 = data.rfind(L'|');
                if (sep1 != std::wstring::npos && sep2 != std::wstring::npos && sep2 > sep1)
                    outPaths.insert(data.substr(sep1 + 1, sep2 - sep1 - 1));
            }
        };

        // Separate live vs stale instances
        std::set<std::wstring> livePaths;
        std::vector<std::wstring> staleKeys;

        for (const auto& subKey : subKeys) {
            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + subKey;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS) {
                staleKeys.push_back(subKey);
                continue;
            }

            DWORD pid = 0; ULONGLONG ctime = 0;
            ReadPidAndCtime(hKey, pid, ctime);
            if (IsProcessAlive(pid, ctime)) {
                collectPaths(hKey, livePaths);
                g_logger.Log((L"STALE_CHECK: " + subKey + L" -> ALIVE (PID=" + std::to_wstring(pid) + L")").c_str());
            } else {
                staleKeys.push_back(subKey);
                g_logger.Log((L"STALE_CHECK: " + subKey + L" -> DEAD (PID=" + std::to_wstring(pid) + L")").c_str());
            }
            RegCloseKey(hKey);
        }

        // Restore and delete only stale (dead PID) subkeys
        for (const auto& subKey : staleKeys) {
            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + subKey;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) == ERROR_SUCCESS) {
                // Delete AppContainer profile if stored
                std::wstring containerName = readContainer(hKey);
                if (!containerName.empty()) {
                    HRESULT hr = DeleteAppContainerProfile(containerName.c_str());
                    g_logger.Log((L"PROFILE_DELETE: " + containerName +
                        (SUCCEEDED(hr) ? L" -> OK" : L" -> FAILED")).c_str());
                }

                RestoreGrantsFromKey(hKey, livePaths);
                RegCloseKey(hKey);
            }
            // Use RegDeleteTreeW — robust even if subkeys exist (Bug 4 fix)
            LSTATUS delResult = RegDeleteTreeW(HKEY_CURRENT_USER, fullKey.c_str());
            if (delResult != ERROR_SUCCESS) {
                wchar_t msg[256];
                swprintf(msg, 256, L"REG_DELETE_FAIL: %ls -> error %lu", fullKey.c_str(), delResult);
                g_logger.Log(msg);
                // Fallback: try RegDeleteKeyW in case RegDeleteTreeW has issues
                delResult = RegDeleteKeyW(HKEY_CURRENT_USER, fullKey.c_str());
                if (delResult != ERROR_SUCCESS) {
                    swprintf(msg, 256, L"REG_DELETE_FALLBACK_FAIL: %ls -> error %lu", fullKey.c_str(), delResult);
                    g_logger.Log(msg);
                }
            }
            g_logger.Log((L"REG_DELETE: " + fullKey).c_str());
        }

        // Remove parent key if now empty
        RegDeleteKeyW(HKEY_CURRENT_USER, kGrantsParentKey);
    }

} // namespace Sandbox
