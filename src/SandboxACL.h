// =========================================================================
// SandboxACL.h — Pure ACL operations (grant, deny, restore)
//
// Low-level helpers for modifying and restoring file/registry DACLs.
// Grant tracking, persistence, and revocation are in SandboxGrants.h.
// =========================================================================
#pragma once

#include "SandboxTypes.h"

namespace Sandbox {

    // Callback type for recording grants (defined in SandboxGrants.h)
    typedef void (*RecordGrantFn)(const std::wstring&, SE_OBJECT_TYPE, PSECURITY_DESCRIPTOR);

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
        if (Status != ERROR_SUCCESS && pObjectName) {
            wchar_t msg[512];
            swprintf(msg, 512, L"ACL_TREE_ERROR: %s (error %lu)", pObjectName, Status);
            g_logger.Log(msg);
        }
    }

    // -----------------------------------------------------------------------
    // Grant access to a file/folder or registry key
    //
    // Steps:
    //   1. Read current DACL
    //   2. Build new DACL with the ALLOW ACE added
    //   3. Record the grant (in-memory + registry) via RecordGrant()
    //   4. Apply the new DACL (TreeSet for directories)
    //   5. Log resulting SDDL
    //
    // RecordGrant (from SandboxGrants.h) must be called AFTER this
    // function — but the caller passes pSD so RecordGrant can snapshot
    // the original DACL.  This is done via the recordFn callback.
    // -----------------------------------------------------------------------
    inline bool GrantObjectAccess(PSID pSid, const std::wstring& path,
                                  AccessLevel level,
                                  RecordGrantFn recordFn = nullptr,
                                  SE_OBJECT_TYPE objType = SE_FILE_OBJECT)
    {
        DWORD permissions = AccessMask(level);

        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = permissions;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);

        // 1. Read current DACL
        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            path.c_str(), objType, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS) return false;

        // 2. Build new DACL
        PACL pNewDacl = nullptr;
        rc = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
        if (rc != ERROR_SUCCESS) { LocalFree(pSD); return false; }

        // 3. Record the grant (write-ahead before modifying the object)
        if (recordFn) recordFn(path, objType, pSD);
        LocalFree(pSD);

        // 4. Apply new DACL
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
        return rc == ERROR_SUCCESS;
    }

    // -----------------------------------------------------------------------
    // Deny access to a file/folder
    //
    // Strategy depends on SID type:
    // - Restricted: real DENY_ACCESS ACEs (kernel enforces them)
    // - AppContainer: DENY ACEs are IGNORED by kernel.  Instead, revoke
    //   the existing ALLOW ACE and re-add a narrower one.
    // -----------------------------------------------------------------------
    inline bool DenyObjectAccess(PSID pSid, const std::wstring& path,
                                  AccessLevel level, bool isAppContainer,
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
        if (rc != ERROR_SUCCESS) return false;

        // Record the grant (write-ahead)
        if (recordFn) recordFn(path, objType, pSD);

        PACL pNewDacl = nullptr;

        if (isAppContainer) {
            // AppContainer: DENY ACEs don't work — subtract bits from ALLOW ACE

            // Find existing allowed permissions for this SID
            DWORD existingMask = 0;
            ACL_SIZE_INFORMATION aclInfo = {};
            if (GetAclInformation(pOldDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
                for (DWORD i = 0; i < aclInfo.AceCount; i++) {
                    PACE_HEADER pAceHdr = nullptr;
                    if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr)))
                        continue;
                    if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                        auto* pAce = reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr);
                        if (EqualSid(&pAce->SidStart, pSid))
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

            // Build new ACL manually
            DWORD sidLen = GetLengthSid(pSid);
            DWORD newAclSize = sizeof(ACL);
            for (DWORD i = 0; i < aclInfo.AceCount; i++) {
                PACE_HEADER pAceHdr = nullptr;
                if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr))) continue;
                bool isSidAce = false;
                if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                    auto* pAce = reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr);
                    isSidAce = EqualSid(&pAce->SidStart, pSid);
                }
                if (!isSidAce) newAclSize += pAceHdr->AceSize;
            }
            if (reducedMask != 0)
                newAclSize += sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + sidLen;

            pNewDacl = reinterpret_cast<PACL>(LocalAlloc(LPTR, newAclSize));
            if (!pNewDacl || !InitializeAcl(pNewDacl, newAclSize, ACL_REVISION)) {
                LocalFree(pSD);
                return false;
            }

            // Copy non-SID ACEs
            for (DWORD i = 0; i < aclInfo.AceCount; i++) {
                PACE_HEADER pAceHdr = nullptr;
                if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr))) continue;
                bool isSidAce = false;
                if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                    auto* pAce = reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr);
                    isSidAce = EqualSid(&pAce->SidStart, pSid);
                }
                if (!isSidAce)
                    AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pAceHdr, pAceHdr->AceSize);
            }

            // Add reduced ACE
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
        if (rc != ERROR_SUCCESS || !pNewDacl) return false;

        // Apply with PROTECTED_DACL to break inheritance from parent grants
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
                    g_logger.Log((L"DENY_SDDL: " + path + L" -> " + sddl).c_str());
                    LocalFree(sddl);
                }
                LocalFree(pResultSD);
            }
        }
        return rc == ERROR_SUCCESS;
    }

    // -----------------------------------------------------------------------
    // RestoreDacl — restore a single object's DACL from saved SDDL.
    // Uses TreeSet for directories. Falls back to NTFS Object ID if renamed.
    // -----------------------------------------------------------------------
    inline void RestoreDacl(const std::wstring& path, const std::wstring& sddl,
                            SE_OBJECT_TYPE objType,
                            const BYTE objectId[16] = nullptr)
    {
        std::wstring resolvedPath = path;

        // If original path is gone, try Object ID lookup
        if (objType == SE_FILE_OBJECT &&
            GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES &&
            objectId != nullptr) {
            // ResolveByObjectId is in SandboxGrants.h — forward-declared here
            // to avoid circular dependency.  The caller (RevokeAllGrants) always
            // resolves before calling RestoreDacl, so objectId path is rare.
            bool hasOid = false;
            for (int i = 0; i < 16; i++) if (objectId[i]) { hasOid = true; break; }
            if (!hasOid) {
                g_logger.Log((L"ACL_RESTORE_SKIP: path gone, OID not found: " + path).c_str());
                return;
            }
            // Volume-level Object ID lookup
            if (path.size() < 2 || path[1] != L':') return;
            std::wstring volPath = L"\\\\.\\" + path.substr(0, 2);
            HANDLE hVol = CreateFileW(volPath.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (hVol == INVALID_HANDLE_VALUE) {
                g_logger.Log((L"ACL_RESTORE_SKIP: path gone, OID not found: " + path).c_str());
                return;
            }
            FILE_ID_DESCRIPTOR fid = {};
            fid.dwSize = sizeof(fid);
            fid.Type = ObjectIdType;
            memcpy(&fid.ObjectId, objectId, 16);
            HANDLE hFile = OpenFileById(hVol, &fid, GENERIC_READ | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, FILE_FLAG_BACKUP_SEMANTICS);
            CloseHandle(hVol);
            if (hFile == INVALID_HANDLE_VALUE) {
                g_logger.Log((L"ACL_RESTORE_SKIP: path gone, OID not found: " + path).c_str());
                return;
            }
            wchar_t newPath[1024] = {};
            DWORD len = GetFinalPathNameByHandleW(hFile, newPath, 1024, 0);
            CloseHandle(hFile);
            if (len == 0 || len >= 1024) return;
            resolvedPath = newPath;
            if (resolvedPath.substr(0, 4) == L"\\\\?\\")
                resolvedPath = resolvedPath.substr(4);
            g_logger.Log((L"OID_RESOLVE: " + path + L" -> " + resolvedPath).c_str());
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

} // namespace Sandbox
