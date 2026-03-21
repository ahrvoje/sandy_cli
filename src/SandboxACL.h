// =========================================================================
// SandboxACL.h — Pure ACL operations (grant, deny, remove)
//
// Low-level helpers for modifying file/registry DACLs and removing
// specific SID ACEs.  Multi-instance safe: never replaces entire DACLs.
// Grant tracking, persistence, and revocation are in SandboxGrants.h.
//
// DACL Protection Invariant:
//   All filesystem DACL writes go through WriteDaclToObject(), which
//   preserves existing SE_DACL_PROTECTED by default.  Individual
//   functions (grant, deny, remove, rollback) never decide SI flags
//   independently — they pass a DaclProtectionIntent to the helper.
// =========================================================================
#pragma once

#include "SandboxTypes.h"

namespace Sandbox {

    enum class AceRemovalMode {
        AllForSid,
        AllowOnly,
        DenyOnly,
    };

    // DACL protection intent — used by ALL filesystem DACL writes.
    //   PreserveExisting — keep whatever protection the DACL already has (DEFAULT)
    //   ForceUnprotected — set UNPROTECTED_DACL (cleanup: resume inheritance)
    //   ForceProtected   — set PROTECTED_DACL   (carve-out: block parent deny re-inheritance)
    enum class DaclProtectionIntent {
        PreserveExisting,
        ForceUnprotected,
        ForceProtected,
    };

    struct AceRemovalResult {
        int   removed = 0;
        DWORD error = ERROR_SUCCESS;
        bool  targetMissing = false;

        bool Succeeded() const { return error == ERROR_SUCCESS; }
    };

    // Callback type for recording grants (defined in SandboxGrants.h)
    // Receives: path, object type, SID string, trapped SIDs, isDeny flag, isThis flag
    typedef void (*RecordGrantFn)(const std::wstring&, SE_OBJECT_TYPE, const std::wstring&, const std::wstring&, bool, bool);

    // Forward declaration — defined later in this file.  Needed by P1 ACE
    // rollback logic in GrantObjectAccess/DenyObjectAccess.
    inline AceRemovalResult RemoveSidFromDaclDetailed(const std::wstring& path,
                                                     const std::wstring& sidString,
                                                     SE_OBJECT_TYPE objType,
                                                     DaclProtectionIntent protection,
                                                     bool skipTreeSet,
                                                     AceRemovalMode removalMode);

    // -----------------------------------------------------------------------
    // AclMutexGuard -- serialize DACL read-modify-write across Sandy instances.
    //
    // Windows has no atomic ACE-add/remove API.  Every DACL mutation is:
    //   GetNamedSecurityInfoW -> build new ACL -> Set*SecurityInfo
    // Without serialization, concurrent instances can lose each other's ACEs.
    //
    // Uses a named mutex per path (CRC32 hash) for filesystem objects, or a
    // single named mutex for Desktop/WinSta objects.  Mutex is auto-released
    // by the OS if the holder crashes (WAIT_ABANDONED is treated as acquired).
    // -----------------------------------------------------------------------
    // Global mutex name — one mutex serializes all Sandy DACL operations.
    // Per-path mutexes cannot protect against SetNamedSecurityInfoW inheritance
    // propagation (parent deep grant rewrites child DACLs under a different
    // mutex).  A single global mutex is correct and the performance cost only
    // affects concurrent Sandy instances, which is the exact case that needs
    // serialization.
    constexpr const wchar_t* kAclGlobalMutex = L"Local\\Sandy_ACL";

    struct AclMutexGuard
    {
        HANDLE hMutex = nullptr;

        explicit AclMutexGuard(const std::wstring& /*path*/)
        {
            Acquire(kAclGlobalMutex);
        }

        explicit AclMutexGuard(const wchar_t* fixedName)
        {
            Acquire(fixedName);
        }

        ~AclMutexGuard()
        {
            if (hMutex) {
                ReleaseMutex(hMutex);
                CloseHandle(hMutex);
            }
        }

        AclMutexGuard(const AclMutexGuard&) = delete;
        AclMutexGuard& operator=(const AclMutexGuard&) = delete;

    private:
        void Acquire(const wchar_t* name)
        {
            hMutex = CreateMutexW(nullptr, FALSE, name);
            if (hMutex) {
                DWORD wait = WaitForSingleObject(hMutex, INFINITE);
                if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
                    g_logger.LogFmt(L"ACL_MUTEX: wait failed acquiring %ls (result %lu)", name, wait);
                    CloseHandle(hMutex);
                    hMutex = nullptr;
                }
            }
        }
    };



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
    // Map access level to Win32 file permission mask
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
        // Run: execute-only — OS loader can run the binary, sandbox can't read it.
        case AccessLevel::Run:     return FILE_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        // Stat: check existence, size, timestamps only.
        case AccessLevel::Stat:    return FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        // Touch: modify timestamps/attributes, no data read/write.
        case AccessLevel::Touch:   return FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        // Create: create new files/subdirs, no overwrite/read of existing.
        case AccessLevel::Create:  return FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY |
                                          FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        default:                   return 0;
        }
    }

    // -----------------------------------------------------------------------
    // Map access level to Win32 registry permission mask
    //
    // Registry and file permission bits are disjoint namespaces.
    // FILE_GENERIC_READ (0x00120089) != KEY_READ (0x00020019) — using file
    // masks for registry grants silently grants wrong bits and misses
    // KEY_NOTIFY (0x10), causing KEY_READ opens to fail.
    // -----------------------------------------------------------------------
    inline DWORD RegistryAccessMask(AccessLevel level) {
        switch (level) {
        case AccessLevel::Read:    return KEY_READ;
        case AccessLevel::Write:   return KEY_READ | KEY_WRITE;
        case AccessLevel::All:     return KEY_ALL_ACCESS & ~(WRITE_DAC | WRITE_OWNER);
        default:                   return KEY_READ;  // safe fallback
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
    // WriteDaclToObject — the ONLY way Sandy writes filesystem DACLs.
    //
    // Centralizes the SE_DACL_PROTECTED decision so individual callers
    // never have to reason about protection flags.  Default behavior
    // (PreserveExisting) reads the existing SD control and preserves
    // PROTECTED_DACL if already set.  This prevents any DACL write from
    // silently stripping carve-out protection.
    //
    // Parameters:
    //   path        — target object path
    //   objType     — SE_FILE_OBJECT or SE_REGISTRY_KEY
    //   pNewDacl    — new DACL to apply (caller-allocated, caller-freed)
    //   pExistingSD — security descriptor from GetNamedSecurityInfoW
    //                 (used to read SE_DACL_PROTECTED; may be nullptr)
    //   protection  — how to handle DACL protection flags
    //   directoryOnly — true = SetKernelObjectSecurity (no child propagation)
    // -----------------------------------------------------------------------
    inline DWORD WriteDaclToObject(
        const std::wstring& path,
        SE_OBJECT_TYPE objType,
        PACL pNewDacl,
        PSECURITY_DESCRIPTOR pExistingSD,
        DaclProtectionIntent protection,
        bool directoryOnly)
    {
        // Read existing protection state from the SD we already fetched
        SECURITY_DESCRIPTOR_CONTROL existingControl = 0;
        DWORD sdRevision = 0;
        if (pExistingSD)
            GetSecurityDescriptorControl(pExistingSD, &existingControl, &sdRevision);

        // Compute SECURITY_INFORMATION flags
        DWORD siFlags = DACL_SECURITY_INFORMATION;
        if (protection == DaclProtectionIntent::ForceProtected) {
            siFlags |= PROTECTED_DACL_SECURITY_INFORMATION;
        } else if (protection == DaclProtectionIntent::ForceUnprotected) {
            siFlags |= UNPROTECTED_DACL_SECURITY_INFORMATION;
        } else if (existingControl & SE_DACL_PROTECTED) {
            // PreserveExisting: keep the protection that's already there
            siFlags |= PROTECTED_DACL_SECURITY_INFORMATION;
        }

        DWORD attrs = (objType == SE_FILE_OBJECT) ? GetFileAttributesW(path.c_str()) : 0;
        bool isDir = (objType == SE_FILE_OBJECT)
                     && (attrs != INVALID_FILE_ATTRIBUTES)
                     && (attrs & FILE_ATTRIBUTE_DIRECTORY);

        DWORD rc;
        if (isDir && directoryOnly) {
            // SetKernelObjectSecurity: writes DACL to this single object only,
            // no child propagation.  Used for This-scope grants and peek cleanup.
            HANDLE hDir = CreateFileW(path.c_str(), WRITE_DAC | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (hDir == INVALID_HANDLE_VALUE) {
                rc = GetLastError();
            } else {
                SECURITY_DESCRIPTOR sd;
                InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
                SetSecurityDescriptorDacl(&sd, TRUE, pNewDacl, FALSE);
                if (existingControl & SE_DACL_PROTECTED)
                    SetSecurityDescriptorControl(&sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
                else if (protection == DaclProtectionIntent::ForceProtected)
                    SetSecurityDescriptorControl(&sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
                rc = SetKernelObjectSecurity(hDir, siFlags, &sd)
                     ? ERROR_SUCCESS : GetLastError();
                CloseHandle(hDir);
            }
        } else {
            // SetNamedSecurityInfoW: applies DACL with auto-inheritance.
            // For directories, Windows propagates inheritable ACEs to children
            // while respecting PROTECTED_DACL on children.
            rc = SetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()), objType,
                siFlags, nullptr, nullptr, pNewDacl, nullptr);
        }
        return rc;
    }

    // -----------------------------------------------------------------------
    // RollbackAceBySid — emergency ACE removal using binary SID directly.
    //
    // Used when ConvertSidToStringSidW fails and we need to undo an
    // already-applied ACE without going through the string-SID path.
    // Returns true if the ACE was successfully removed.
    // -----------------------------------------------------------------------
    inline bool RollbackAceBySid(PSID pSid, const std::wstring& path,
                                 SE_OBJECT_TYPE objType, AceRemovalMode removalMode)
    {
        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            path.c_str(), objType, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS) return false;

        ACL_SIZE_INFORMATION aclInfo = {};
        if (!GetAclInformation(pOldDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
            LocalFree(pSD);
            return false;
        }

        auto shouldRemove = [&](BYTE aceType, PSID pAceSid) -> bool {
            if (!EqualSid(pAceSid, pSid)) return false;
            switch (removalMode) {
            case AceRemovalMode::AllowOnly: return aceType == ACCESS_ALLOWED_ACE_TYPE;
            case AceRemovalMode::DenyOnly:  return aceType == ACCESS_DENIED_ACE_TYPE;
            default:                        return aceType == ACCESS_ALLOWED_ACE_TYPE ||
                                                   aceType == ACCESS_DENIED_ACE_TYPE;
            }
        };

        int removed = 0;
        DWORD newAclSize = sizeof(ACL);
        for (DWORD i = 0; i < aclInfo.AceCount; i++) {
            PACE_HEADER pAceHdr = nullptr;
            if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr))) continue;
            PSID pAceSid = nullptr;
            if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE)
                pAceSid = &reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr)->SidStart;
            else if (pAceHdr->AceType == ACCESS_DENIED_ACE_TYPE)
                pAceSid = &reinterpret_cast<ACCESS_DENIED_ACE*>(pAceHdr)->SidStart;
            if (pAceSid && shouldRemove(pAceHdr->AceType, pAceSid))
                removed++;
            else
                newAclSize += pAceHdr->AceSize;
        }
        if (removed == 0) { LocalFree(pSD); return true; }

        PACL pNewDacl = reinterpret_cast<PACL>(LocalAlloc(LPTR, newAclSize));
        if (!pNewDacl || !InitializeAcl(pNewDacl, newAclSize, ACL_REVISION)) {
            LocalFree(pSD); if (pNewDacl) LocalFree(pNewDacl);
            return false;
        }
        for (DWORD i = 0; i < aclInfo.AceCount; i++) {
            PACE_HEADER pAceHdr = nullptr;
            if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr))) continue;
            PSID pAceSid = nullptr;
            if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE)
                pAceSid = &reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr)->SidStart;
            else if (pAceHdr->AceType == ACCESS_DENIED_ACE_TYPE)
                pAceSid = &reinterpret_cast<ACCESS_DENIED_ACE*>(pAceHdr)->SidStart;
            if (pAceSid && shouldRemove(pAceHdr->AceType, pAceSid)) continue;
            AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pAceHdr, pAceHdr->AceSize);
        }

        // Use centralized DACL write — preserves PROTECTED_DACL if already set
        rc = WriteDaclToObject(path, objType, pNewDacl, pSD,
                               DaclProtectionIntent::PreserveExisting, false);
        LocalFree(pNewDacl);
        LocalFree(pSD);

        g_logger.LogFmt(L"ROLLBACK_ACE: %s -> %s (%d ACEs)",
                        path.c_str(), rc == ERROR_SUCCESS ? L"OK" : L"FAILED", removed);
        return rc == ERROR_SUCCESS;
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
                                  SE_OBJECT_TYPE objType = SE_FILE_OBJECT,
                                  GrantScope scope = GrantScope::Deep)
    {
        AclMutexGuard aclLock(path);
        DWORD permissions = (objType == SE_REGISTRY_KEY)
                          ? RegistryAccessMask(level)
                          : AccessMask(level);

        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = permissions;
        ea.grfAccessMode = GRANT_ACCESS;  // GRANT_ACCESS unions with existing ACE for same SID
        // This scope: ACE applies only to this object, not children
        ea.grfInheritance = (scope == GrantScope::This)
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

        // 3. (moved below — record only after ACL application succeeds)

        // 4. Apply new DACL via centralized helper.
        //    PreserveExisting: if the target already has PROTECTED_DACL (e.g.
        //    set by a prior carve-out strip), it is preserved — the grant
        //    does not silently strip protection.
        bool directoryOnly = (scope == GrantScope::This);
        rc = WriteDaclToObject(path, objType, pNewDacl, pSD,
                               DaclProtectionIntent::PreserveExisting, directoryOnly);
        LocalFree(pNewDacl);
        LocalFree(pSD);

        // 3. Record the grant AFTER successful ACL application
        if (rc == ERROR_SUCCESS && recordFn) {
            LPWSTR sidStr = nullptr;
            if (ConvertSidToStringSidW(pSid, &sidStr)) {
                recordFn(path, objType, sidStr, L"", false, scope == GrantScope::This);
                LocalFree(sidStr);
            } else {
                // SID conversion failed — ACE is on disk but no cleanup record.
                // P1: Roll back the untracked ACE using binary SID directly
                // (re-calling ConvertSidToStringSidW would hit the same failure).
                DWORD convErr = GetLastError();
                g_logger.LogFmt(L"GRANT_RECORD: ConvertSidToStringSidW failed (error %lu) — "
                               L"rolling back untracked ACE on %s", convErr, path.c_str());
                RollbackAceBySid(pSid, path, objType, AceRemovalMode::AllowOnly);
                return ERROR_NOT_ENOUGH_MEMORY;
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
                                  SE_OBJECT_TYPE objType = SE_FILE_OBJECT,
                                  GrantScope scope = GrantScope::Deep)
    {
        AclMutexGuard aclLock(path);
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
        ea.grfInheritance = (scope == GrantScope::This)
            ? 0
            : (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);
        rc = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);

        if (rc != ERROR_SUCCESS || !pNewDacl) {
            LocalFree(pSD);
            return (rc != ERROR_SUCCESS) ? rc : ERROR_NOT_ENOUGH_MEMORY;
        }

        // Apply via centralized helper — preserves existing PROTECTED_DACL
        bool directoryOnly = (scope == GrantScope::This);
        rc = WriteDaclToObject(path, objType, pNewDacl, pSD,
                               DaclProtectionIntent::PreserveExisting, directoryOnly);
        LocalFree(pNewDacl);
        LocalFree(pSD);

        // Record the grant AFTER successful ACL application
        if (rc == ERROR_SUCCESS && recordFn) {
            LPWSTR sidStr = nullptr;
            if (ConvertSidToStringSidW(pSid, &sidStr)) {
                recordFn(path, objType, sidStr, L"", true, scope == GrantScope::This);
                LocalFree(sidStr);
            } else {
                // SID conversion failed — ACE is on disk but no cleanup record.
                // P1: Roll back the untracked deny ACE using binary SID directly
                // (re-calling ConvertSidToStringSidW would hit the same failure).
                DWORD convErr = GetLastError();
                g_logger.LogFmt(L"DENY_RECORD: ConvertSidToStringSidW failed (error %lu) — "
                               L"rolling back untracked deny ACE on %s", convErr, path.c_str());
                RollbackAceBySid(pSid, path, objType, AceRemovalMode::DenyOnly);
                return ERROR_NOT_ENOUGH_MEMORY;
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
    // Uses SetNamedSecurityInfoW/auto-inheritance for directory cleanup.
    inline bool IsMissingSecurityTargetError(DWORD rc)
    {
        return rc == ERROR_FILE_NOT_FOUND ||
               rc == ERROR_PATH_NOT_FOUND ||
               rc == ERROR_NOT_FOUND;
    }

    // Returns a structured result so callers can distinguish "already clean"
    // from an actual ACL mutation failure.
    // -----------------------------------------------------------------------
    inline AceRemovalResult RemoveSidFromDaclDetailed(const std::wstring& path,
                                                     const std::wstring& sidString,
                                                     SE_OBJECT_TYPE objType,
                                                     DaclProtectionIntent protection = DaclProtectionIntent::PreserveExisting,
                                                     bool skipTreeSet = false,
                                                     AceRemovalMode removalMode = AceRemovalMode::AllForSid)
    {
        AclMutexGuard aclLock(path);
        AceRemovalResult result;

        // Convert SID string to binary SID
        PSID pTargetSid = nullptr;
        if (!ConvertStringSidToSidW(sidString.c_str(), &pTargetSid)) {
            result.error = GetLastError();
            return result;
        }

        // Read current DACL
        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            path.c_str(), objType, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS) {
            LocalFree(pTargetSid);
            result.error = IsMissingSecurityTargetError(rc) ? ERROR_SUCCESS : rc;
            result.targetMissing = IsMissingSecurityTargetError(rc);
            if (!result.targetMissing) {
                g_logger.LogFmt(L"ACL_REMOVE: %s -> FAILED (0x%08X: %s)",
                                path.c_str(), rc, GetSystemErrorMessage(rc).c_str());
            }
            return result;
        }

        // Walk ACE list, build new DACL without matching ACEs
        ACL_SIZE_INFORMATION aclInfo = {};
        if (!GetAclInformation(pOldDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
            LocalFree(pSD);
            LocalFree(pTargetSid);
            result.error = GetLastError();
            g_logger.LogFmt(L"ACL_REMOVE: %s -> FAILED (0x%08X: %s)",
                            path.c_str(), result.error,
                            GetSystemErrorMessage(result.error).c_str());
            return result;
        }

        // Helper: check if an ACE SID matches our target
        auto shouldRemove = [&](BYTE aceType, PSID pAceSid) -> bool {
            if (!EqualSid(pAceSid, pTargetSid))
                return false;

            switch (removalMode) {
            case AceRemovalMode::AllowOnly:
                return aceType == ACCESS_ALLOWED_ACE_TYPE;
            case AceRemovalMode::DenyOnly:
                return aceType == ACCESS_DENIED_ACE_TYPE;
            case AceRemovalMode::AllForSid:
            default:
                return aceType == ACCESS_ALLOWED_ACE_TYPE ||
                       aceType == ACCESS_DENIED_ACE_TYPE;
            }
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

            if (pAceSid && shouldRemove(pAceHdr->AceType, pAceSid)) {
                removed++;
            } else {
                newAclSize += pAceHdr->AceSize;
            }
        }

        if (removed == 0) {
            LocalFree(pSD);
            LocalFree(pTargetSid);
            return result;
        }

        // Second pass: build new ACL
        PACL pNewDacl = reinterpret_cast<PACL>(LocalAlloc(LPTR, newAclSize));
        if (!pNewDacl || !InitializeAcl(pNewDacl, newAclSize, ACL_REVISION)) {
            LocalFree(pSD);
            LocalFree(pTargetSid);
            result.error = GetLastError();
            if (pNewDacl) LocalFree(pNewDacl);
            g_logger.LogFmt(L"ACL_REMOVE: %s -> FAILED (0x%08X: %s)",
                            path.c_str(), result.error,
                            GetSystemErrorMessage(result.error).c_str());
            return result;
        }

        for (DWORD i = 0; i < aclInfo.AceCount; i++) {
            PACE_HEADER pAceHdr = nullptr;
            if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr))) continue;

            PSID pAceSid = nullptr;
            if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE)
                pAceSid = &reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr)->SidStart;
            else if (pAceHdr->AceType == ACCESS_DENIED_ACE_TYPE)
                pAceSid = &reinterpret_cast<ACCESS_DENIED_ACE*>(pAceHdr)->SidStart;

            if (pAceSid && shouldRemove(pAceHdr->AceType, pAceSid))
                continue;  // skip — this is ours or a trapped SID
            AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pAceHdr, pAceHdr->AceSize);
        }

        LocalFree(pTargetSid);

        // Apply cleaned DACL via centralized helper
        rc = WriteDaclToObject(path, objType, pNewDacl, pSD,
                               protection, skipTreeSet);
        LocalFree(pNewDacl);
        LocalFree(pSD);

        if (rc == ERROR_SUCCESS) {
            g_logger.LogFmt(L"ACL_REMOVE: %s -> %d ACEs removed for SID %s",
                            path.c_str(), removed, sidString.c_str());
            result.removed = removed;
            return result;
        }

        result.error = rc;
        g_logger.LogFmt(L"ACL_REMOVE: %s -> FAILED (0x%08X: %s)",
                        path.c_str(), rc, GetSystemErrorMessage(rc).c_str());
        return result;
    }

    // Returns number of ACEs removed.
    // -----------------------------------------------------------------------
    inline int RemoveSidFromDacl(const std::wstring& path,
                                 const std::wstring& sidString,
                                 SE_OBJECT_TYPE objType,
                                 DaclProtectionIntent protection = DaclProtectionIntent::PreserveExisting,
                                 bool skipTreeSet = false,
                                 AceRemovalMode removalMode = AceRemovalMode::AllForSid)
    {
        return RemoveSidFromDaclDetailed(path, sidString, objType,
                                         protection, skipTreeSet, removalMode).removed;
    }

} // namespace Sandbox

