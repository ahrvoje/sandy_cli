// =========================================================================
// SandboxACL.h — Pure ACL operations (grant, deny, remove)
//
// Low-level helpers for modifying file/registry DACLs and removing
// specific SID ACEs.  Multi-instance safe: never replaces entire DACLs.
// Grant tracking, persistence, and revocation are in SandboxGrants.h.
// =========================================================================
#pragma once

#include "SandboxTypes.h"

namespace Sandbox {

    // Callback type for recording grants (defined in SandboxGrants.h)
    // Receives: path, object type, SID string, trapped SIDs, isDeny flag, isPeek flag
    typedef void (*RecordGrantFn)(const std::wstring&, SE_OBJECT_TYPE, const std::wstring&, const std::wstring&, bool, bool);

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
    // Map access level to Win32 permission mask
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
        // WRITE_DAC excluded: prevents sandbox from modifying ACLs.
        // WRITE_OWNER excluded: no legitimate sandbox use for ownership changes.
        case AccessLevel::All:     return FILE_ALL_ACCESS & ~(FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER);
        // Peek: just enough to traverse a directory (lstat + readdir).
        // No GENERIC_READ (avoids reading file contents), no inheritance.
        case AccessLevel::Peek:    return FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES |
                                          FILE_READ_EA | READ_CONTROL | SYNCHRONIZE;
        default:                   return 0;
        }
    }

    // -----------------------------------------------------------------------
    // TreeSet progress callback — logs per-object errors
    // -----------------------------------------------------------------------
    inline void WINAPI TreeSecurityProgress(
        LPWSTR pObjectName, DWORD Status,
        PPROG_INVOKE_SETTING pInvokeSetting, PVOID Args, BOOL SecuritySet)
    {
        (void)pInvokeSetting; (void)Args; (void)SecuritySet;
        if (Status != ERROR_SUCCESS && pObjectName)
            g_logger.LogFmt(L"ACL_TREE_ERROR: %s (error %lu)", pObjectName, Status);
    }

    // -----------------------------------------------------------------------
    // Grant access to a file/folder or registry key
    //
    // Returns ERROR_SUCCESS (0) on success, or the exact Win32 error code.
    // Steps:
    //   1. Read current DACL
    //   2. Build new DACL with the ALLOW ACE added
    //   3. Record grant (path + SID string) via RecordGrant()
    //   4. Apply the new DACL (TreeSet for directories)
    //   5. Log resulting SDDL
    // -----------------------------------------------------------------------
    inline DWORD GrantObjectAccess(PSID pSid, const std::wstring& path,
                                  AccessLevel level,
                                  RecordGrantFn recordFn = nullptr,
                                  SE_OBJECT_TYPE objType = SE_FILE_OBJECT)
    {
        DWORD permissions = AccessMask(level);

        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = permissions;
        ea.grfAccessMode = GRANT_ACCESS;  // GRANT_ACCESS unions with existing ACE for same SID
        // Peek: non-recursive — ACE applies only to this directory, not children
        ea.grfInheritance = (level == AccessLevel::Peek)
            ? 0
            : (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);

        // 1. Read current DACL
        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            path.c_str(), objType, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS) return rc;

        // 2. Build new DACL
        PACL pNewDacl = nullptr;
        rc = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
        if (rc != ERROR_SUCCESS) { LocalFree(pSD); return rc; }
        LocalFree(pSD);

        // 3. (moved below — record only after ACL application succeeds)

        // 4. Apply new DACL
        DWORD attr = (objType == SE_FILE_OBJECT) ? GetFileAttributesW(path.c_str()) : 0;
        bool isDir = (objType == SE_FILE_OBJECT) && (attr != INVALID_FILE_ATTRIBUTES)
                     && (attr & FILE_ATTRIBUTE_DIRECTORY);
        if (level == AccessLevel::Peek && isDir) {
            // Peek: use SetKernelObjectSecurity — the raw kernel API that does NOT
            // trigger auto-inheritance propagation.  SetSecurityInfo/SetNamedSecurityInfoW
            // both walk all children to re-evaluate inherited ACEs on directories like
            // C:\Users\H (65+ seconds).  SetKernelObjectSecurity writes the DACL to
            // this single object only.
            HANDLE hDir = CreateFileW(path.c_str(), WRITE_DAC | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (hDir == INVALID_HANDLE_VALUE) {
                rc = GetLastError();
            } else {
                // Build a self-relative security descriptor with the new DACL
                SECURITY_DESCRIPTOR sd;
                InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
                SetSecurityDescriptorDacl(&sd, TRUE, pNewDacl, FALSE);
                if (SetKernelObjectSecurity(hDir, DACL_SECURITY_INFORMATION, &sd)) {
                    rc = ERROR_SUCCESS;
                } else {
                    rc = GetLastError();
                }
                CloseHandle(hDir);
            }
        } else if (isDir && level != AccessLevel::Peek) {
            // Use SetNamedSecurityInfoW (not TreeSet) — inheritable ACEs propagate
            // to children via Windows auto-inheritance, which respects
            // PROTECTED_DACL on children (e.g. deny paths from other instances).
            rc = SetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()), objType,
                DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDacl, nullptr);
        } else {
            rc = SetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()), objType,
                DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDacl, nullptr);
        }
        LocalFree(pNewDacl);

        // 3. Record the grant AFTER successful ACL application
        if (rc == ERROR_SUCCESS && recordFn) {
            LPWSTR sidStr = nullptr;
            if (ConvertSidToStringSidW(pSid, &sidStr)) {
                recordFn(path, objType, sidStr, L"", false, level == AccessLevel::Peek);
                LocalFree(sidStr);
            }
        }

        // 5. Log resulting SDDL
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
                    g_logger.Log((L"GRANT_SDDL: " + path + L" -> " + sddl).c_str());
                    LocalFree(sddl);
                }
                LocalFree(pResultSD);
            }
        }
        return rc;
    }

    // -----------------------------------------------------------------------
    // Deny access to a file/folder (Restricted Token only)
    //
    // Returns ERROR_SUCCESS (0) on success, or the exact Win32 error code.
    // Uses real DENY_ACCESS ACEs — the kernel evaluates deny-before-allow
    // normally for Restricted Token SIDs.
    //
    // AppContainer mode does NOT support deny: the Windows kernel ignores
    // DENY ACEs for AppContainer SIDs (S-1-15-2-*).  This is rejected at
    // config validation time in SandboxConfig.h.
    // -----------------------------------------------------------------------
    inline DWORD DenyObjectAccess(PSID pSid, const std::wstring& path,
                                  AccessLevel level,
                                  RecordGrantFn recordFn = nullptr,
                                  SE_OBJECT_TYPE objType = SE_FILE_OBJECT)
    {
        DWORD denyMask = AccessMask(level);

        // Read current DACL
        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            path.c_str(), objType, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS) return rc;

        // Build new DACL with DENY ACE
        PACL pNewDacl = nullptr;
        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = denyMask;
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);
        rc = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);

        LocalFree(pSD);
        if (rc != ERROR_SUCCESS || !pNewDacl)
            return (rc != ERROR_SUCCESS) ? rc : ERROR_NOT_ENOUGH_MEMORY;

        // Apply — standard SetNamedSecurityInfoW with auto-inheritance
        rc = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(path.c_str()), objType,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDacl, nullptr);
        LocalFree(pNewDacl);

        // Record the grant AFTER successful ACL application
        if (rc == ERROR_SUCCESS && recordFn) {
            LPWSTR sidStr = nullptr;
            if (ConvertSidToStringSidW(pSid, &sidStr)) {
                recordFn(path, objType, sidStr, L"", true, false);
                LocalFree(sidStr);
            }
        }

        // Log resulting DACL
        if (rc == ERROR_SUCCESS) {
            g_logger.LogFmt(L"DENY_RT: %s -> mask=0x%08X", path.c_str(), denyMask);
            PACL pResultDacl = nullptr;
            PSECURITY_DESCRIPTOR pResultSD = nullptr;
            if (GetNamedSecurityInfoW(path.c_str(), objType,
                    DACL_SECURITY_INFORMATION, nullptr, nullptr,
                    &pResultDacl, nullptr, &pResultSD) == ERROR_SUCCESS) {
                LPWSTR sddl = nullptr;
                if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        pResultSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                        &sddl, nullptr)) {
                    g_logger.Log((L"DENY_SDDL: " + path + L" -> " + sddl).c_str());
                    LocalFree(sddl);
                }
                LocalFree(pResultSD);
            }
        }
        return rc;
    }
    // -----------------------------------------------------------------------
    // RemoveSidFromDacl — remove all ACEs for a specific SID from an object.
    //
    // Multi-instance safe: only removes ACEs matching the given SID string.
    // Other ACEs (from other instances, users, system) are untouched.
    // Uses TreeSet for directories to propagate to children.
    // Returns number of ACEs removed.
    // -----------------------------------------------------------------------
    inline int RemoveSidFromDacl(const std::wstring& path,
                                  const std::wstring& sidString,
                                  SE_OBJECT_TYPE objType,
                                  bool wasDenied = false,
                                  bool skipTreeSet = false)
    {
        // Convert SID string to binary SID
        PSID pTargetSid = nullptr;
        if (!ConvertStringSidToSidW(sidString.c_str(), &pTargetSid))
            return 0;

        // Read current DACL
        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            path.c_str(), objType, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS) {
            LocalFree(pTargetSid);
                        return 0;
        }

        // Walk ACE list, build new DACL without matching ACEs
        ACL_SIZE_INFORMATION aclInfo = {};
        if (!GetAclInformation(pOldDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
            LocalFree(pSD);
            LocalFree(pTargetSid);
                        return 0;
        }

        // Helper: check if an ACE SID matches our target
        auto shouldRemove = [&](PSID pAceSid) -> bool {
            return EqualSid(pAceSid, pTargetSid);
        };

        int removed = 0;
        DWORD newAclSize = sizeof(ACL);
        // First pass: compute size of new ACL
        for (DWORD i = 0; i < aclInfo.AceCount; i++) {
            PACE_HEADER pAceHdr = nullptr;
            if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr))) continue;

            PSID pAceSid = nullptr;
            if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE)
                pAceSid = &reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr)->SidStart;
            else if (pAceHdr->AceType == ACCESS_DENIED_ACE_TYPE)
                pAceSid = &reinterpret_cast<ACCESS_DENIED_ACE*>(pAceHdr)->SidStart;

            if (pAceSid && shouldRemove(pAceSid)) {
                removed++;
            } else {
                newAclSize += pAceHdr->AceSize;
            }
        }

        if (removed == 0) {
            LocalFree(pSD);
            LocalFree(pTargetSid);
                        return 0;
        }

        // Second pass: build new ACL
        PACL pNewDacl = reinterpret_cast<PACL>(LocalAlloc(LPTR, newAclSize));
        if (!pNewDacl || !InitializeAcl(pNewDacl, newAclSize, ACL_REVISION)) {
            LocalFree(pSD);
            LocalFree(pTargetSid);
                        if (pNewDacl) LocalFree(pNewDacl);
            return 0;
        }

        for (DWORD i = 0; i < aclInfo.AceCount; i++) {
            PACE_HEADER pAceHdr = nullptr;
            if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr))) continue;

            PSID pAceSid = nullptr;
            if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE)
                pAceSid = &reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr)->SidStart;
            else if (pAceHdr->AceType == ACCESS_DENIED_ACE_TYPE)
                pAceSid = &reinterpret_cast<ACCESS_DENIED_ACE*>(pAceHdr)->SidStart;

            if (pAceSid && shouldRemove(pAceSid))
                continue;  // skip — this is ours or a trapped SID
            AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pAceHdr, pAceHdr->AceSize);
        }

        LocalFree(pSD);
        LocalFree(pTargetSid);
        
        // Apply cleaned DACL
        // If this was a deny entry, re-enable inheritance with UNPROTECTED_DACL
        DWORD siFlags = DACL_SECURITY_INFORMATION;
        if (wasDenied) siFlags |= UNPROTECTED_DACL_SECURITY_INFORMATION;

        DWORD attrs = (objType == SE_FILE_OBJECT) ? GetFileAttributesW(path.c_str()) : 0;
        bool isDir = (objType == SE_FILE_OBJECT)
                     && (attrs != INVALID_FILE_ATTRIBUTES)
                     && (attrs & FILE_ATTRIBUTE_DIRECTORY);
        if (isDir && !skipTreeSet) {
            // Use SetNamedSecurityInfoW (not TreeSet) — removing our ACE from
            // the root lets auto-inheritance remove inherited copies from
            // children, while respecting PROTECTED_DACL on deny paths.
            rc = SetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()), objType,
                siFlags, nullptr, nullptr, pNewDacl, nullptr);
        } else if (isDir && skipTreeSet) {
            // Peek cleanup: SetKernelObjectSecurity does NOT propagate to children
            HANDLE hDir = CreateFileW(path.c_str(), WRITE_DAC | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (hDir == INVALID_HANDLE_VALUE) {
                rc = GetLastError();
            } else {
                SECURITY_DESCRIPTOR sd;
                InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
                SetSecurityDescriptorDacl(&sd, TRUE, pNewDacl, FALSE);
                rc = SetKernelObjectSecurity(hDir, siFlags, &sd)
                     ? ERROR_SUCCESS : GetLastError();
                CloseHandle(hDir);
            }
        } else {
            rc = SetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()), objType,
                siFlags, nullptr, nullptr, pNewDacl, nullptr);
        }
        LocalFree(pNewDacl);

        if (rc == ERROR_SUCCESS) {
            g_logger.LogFmt(L"ACL_REMOVE: %s -> %d ACEs removed for SID %s",
                            path.c_str(), removed, sidString.c_str());
            return removed;
        }

        g_logger.LogFmt(L"ACL_REMOVE: %s -> FAILED (0x%08X: %s)",
                        path.c_str(), rc, GetSystemErrorMessage(rc).c_str());
        return 0;
    }

} // namespace Sandbox

