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
    // Receives: path, object type, SID string, trapped SIDs, isDeny flag
    typedef void (*RecordGrantFn)(const std::wstring&, SE_OBJECT_TYPE, const std::wstring&, const std::wstring&, bool);

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
        if (Status != ERROR_SUCCESS && pObjectName)
            g_logger.LogFmt(L"ACL_TREE_ERROR: %s (error %lu)", pObjectName, Status);
    }

    // -----------------------------------------------------------------------
    // Grant access to a file/folder or registry key
    //
    // Steps:
    //   1. Read current DACL
    //   2. Build new DACL with the ALLOW ACE added
    //   3. Record grant (path + SID string) via RecordGrant()
    //   4. Apply the new DACL (TreeSet for directories)
    //   5. Log resulting SDDL
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
        LocalFree(pSD);

        // 3. Record the grant (path + SID string for ACE-level removal)
        if (recordFn) {
            LPWSTR sidStr = nullptr;
            if (ConvertSidToStringSidW(pSid, &sidStr)) {
                recordFn(path, objType, sidStr, L"", false);
                LocalFree(sidStr);
            }
        }

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

        // Before PROTECTED_DACL — scan for inherited AppContainer SIDs
        // that will become trapped as explicit ACEs.  We record them so
        // cleanup can remove them and re-enable inheritance.
        std::wstring trappedSids;
        {
            ACL_SIZE_INFORMATION scanInfo = {};
            if (GetAclInformation(pOldDacl, &scanInfo, sizeof(scanInfo), AclSizeInformation)) {
                for (DWORD i = 0; i < scanInfo.AceCount; i++) {
                    PACE_HEADER pAceHdr = nullptr;
                    if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr)))
                        continue;
                    // Only care about inherited ACEs — those will become explicit
                    if (!(pAceHdr->AceFlags & INHERITED_ACE)) continue;

                    PSID pAceSid = nullptr;
                    if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE)
                        pAceSid = &reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr)->SidStart;
                    else if (pAceHdr->AceType == ACCESS_DENIED_ACE_TYPE)
                        pAceSid = &reinterpret_cast<ACCESS_DENIED_ACE*>(pAceHdr)->SidStart;
                    if (!pAceSid) continue;

                    // Check if this is an AppContainer SID (S-1-15-2-*)
                    LPWSTR aceSidStr = nullptr;
                    if (ConvertSidToStringSidW(pAceSid, &aceSidStr)) {
                        if (wcsncmp(aceSidStr, L"S-1-15-2-", 9) == 0) {
                            // Don't record our own SID as trapped
                            LPWSTR ourSidStr = nullptr;
                            bool isOurs = false;
                            if (ConvertSidToStringSidW(pSid, &ourSidStr)) {
                                isOurs = (wcscmp(aceSidStr, ourSidStr) == 0);
                                LocalFree(ourSidStr);
                            }
                            if (!isOurs) {
                                if (!trappedSids.empty()) trappedSids += L";";
                                trappedSids += aceSidStr;
                            }
                        }
                        LocalFree(aceSidStr);
                    }
                }
            }
            if (!trappedSids.empty()) {
                g_logger.Log((L"DENY_TRAPPED: " + path + L" -> " + trappedSids).c_str());
            }
        }

        // Record the grant (path + SID + trapped SIDs for ACE-level removal)
        if (recordFn) {
            LPWSTR sidStr = nullptr;
            if (ConvertSidToStringSidW(pSid, &sidStr)) {
                recordFn(path, objType, sidStr, trappedSids, true);
                LocalFree(sidStr);
            }
        }

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

            g_logger.LogFmt(L"DENY_AC: existing=0x%08X deny=0x%08X reduced=0x%08X",
                            existingMask, denyMask, reducedMask);

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
                                  const std::wstring& trappedSids = L"",
                                  bool skipTreeSet = false)
    {
        // Convert SID string to binary SID
        PSID pTargetSid = nullptr;
        if (!ConvertStringSidToSidW(sidString.c_str(), &pTargetSid))
            return 0;

        // Build set of trapped SIDs to also remove
        std::vector<PSID> trappedSidPtrs;
        std::vector<std::wstring> trappedTokens;
        if (!trappedSids.empty()) {
            std::wistringstream ss(trappedSids);
            std::wstring token;
            while (std::getline(ss, token, L';')) {
                if (token.empty()) continue;
                trappedTokens.push_back(token);
                PSID pTrap = nullptr;
                if (ConvertStringSidToSidW(token.c_str(), &pTrap))
                    trappedSidPtrs.push_back(pTrap);
            }
        }

        // Read current DACL
        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            path.c_str(), objType, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS) {
            LocalFree(pTargetSid);
            for (auto p : trappedSidPtrs) LocalFree(p);
            return 0;
        }

        // Walk ACE list, build new DACL without matching ACEs
        ACL_SIZE_INFORMATION aclInfo = {};
        if (!GetAclInformation(pOldDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
            LocalFree(pSD);
            LocalFree(pTargetSid);
            for (auto p : trappedSidPtrs) LocalFree(p);
            return 0;
        }

        // Helper: check if an ACE SID matches our target or any trapped SID
        auto shouldRemove = [&](PSID pAceSid) -> bool {
            if (EqualSid(pAceSid, pTargetSid)) return true;
            for (auto pTrap : trappedSidPtrs) {
                if (EqualSid(pAceSid, pTrap)) return true;
            }
            return false;
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
            for (auto p : trappedSidPtrs) LocalFree(p);
            return 0;
        }

        // Second pass: build new ACL
        PACL pNewDacl = reinterpret_cast<PACL>(LocalAlloc(LPTR, newAclSize));
        if (!pNewDacl || !InitializeAcl(pNewDacl, newAclSize, ACL_REVISION)) {
            LocalFree(pSD);
            LocalFree(pTargetSid);
            for (auto p : trappedSidPtrs) LocalFree(p);
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
        for (auto p : trappedSidPtrs) LocalFree(p);

        // Apply cleaned DACL
        // If this was a deny entry, re-enable inheritance with UNPROTECTED_DACL
        DWORD siFlags = DACL_SECURITY_INFORMATION;
        if (wasDenied) siFlags |= UNPROTECTED_DACL_SECURITY_INFORMATION;

        DWORD attrs = (objType == SE_FILE_OBJECT) ? GetFileAttributesW(path.c_str()) : 0;
        bool isDir = (objType == SE_FILE_OBJECT)
                     && (attrs != INVALID_FILE_ATTRIBUTES)
                     && (attrs & FILE_ATTRIBUTE_DIRECTORY);
        if (isDir && !skipTreeSet) {
            rc = TreeSetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()), objType,
                siFlags, nullptr, nullptr, pNewDacl, nullptr,
                TREE_SEC_INFO_SET, TreeSecurityProgress, ProgressInvokeOnError, nullptr);
        } else {
            rc = SetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()), objType,
                siFlags, nullptr, nullptr, pNewDacl, nullptr);
        }
        LocalFree(pNewDacl);

        if (rc == ERROR_SUCCESS)
            g_logger.LogFmt(L"ACL_REMOVE: %s -> %d ACEs removed for SID %s%s%s",
                            path.c_str(), removed, sidString.c_str(),
                            trappedSids.empty() ? L"" : L" +trapped:",
                            trappedSids.empty() ? L"" : trappedSids.c_str());
        return removed;
    }

} // namespace Sandbox

