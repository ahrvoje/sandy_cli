// =========================================================================
// SandboxACL.h — Pure ACL operations (add ACEs, remove ACEs)
//
// Low-level helpers for modifying file/registry DACLs and removing
// specific SID ACEs.  Multi-instance safe: never replaces entire DACLs.
// Grant tracking, persistence, and revocation are in SandboxGrants.h.
//
// DACL invariants (structural — no caller can break them):
//   1. Every DACL write goes through WriteDaclToObject(), which keeps the
//      object's SE_DACL_PROTECTED state as it found it.  Sandy has no code
//      path that turns DACL protection on or off.
//   2. ACEs are added only by AddAcesToObject() and removed only by
//      RemoveSidFromDaclDetailed().  Both go through RebuildDacl(), which
//      copies every other ACE byte for byte and in order.
//   3. The cleanup record is persisted before the DACL is written.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include <functional>

namespace Sandbox {

    struct AceRemovalResult {
        int   removed = 0;
        DWORD error = ERROR_SUCCESS;
        bool  targetMissing = false;

        bool Succeeded() const { return error == ERROR_SUCCESS; }
    };

    // -----------------------------------------------------------------------
    // OwnerAce — the "OWNER RIGHTS" companion of a deny rule.
    //
    // Windows gives the owner of an object READ_CONTROL | WRITE_DAC before it
    // reads the DACL, so a deny ACE cannot take WRITE_DAC away from the
    // owner.  When the user SID is a restricting SID (strict = false), the
    // sandboxed process is that owner and could rewrite the DACL of a denied
    // object.  An ACE for OWNER RIGHTS (S-1-3-4) switches the implicit grant
    // off; the DACL then decides, and the deny ACE comes first.  The ACE
    // grants the owner exactly what Windows granted implicitly, so nobody
    // else sees a difference.
    //   None       — no companion ACE was written
    //   ObjectOnly — companion applies to the object itself
    //   Inherit    — companion applies to the object and all descendants
    // -----------------------------------------------------------------------
    enum class OwnerAce { None, ObjectOnly, Inherit };

    constexpr DWORD kOwnerAceMask = READ_CONTROL | WRITE_DAC;

    // One ACE that Sandy adds for the run/profile SID.
    struct AceSpec {
        bool  deny = false;   // ACCESS_DENIED_ACE, else ACCESS_ALLOWED_ACE
        BYTE  flags = 0;      // OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE
        DWORD mask = 0;
    };

    // What cleanup must know about one DACL write (persisted by SandboxGrants.h).
    struct GrantRecordSpec {
        std::wstring   path;
        SE_OBJECT_TYPE objType = SE_FILE_OBJECT;
        std::wstring   sidString;
        bool           hasDeny = false;
        bool           objectOnly = false;   // no inheritable ACE: cleanup needs no child walk
        OwnerAce       ownerAce = OwnerAce::None;
    };

    // Callback type for recording grants (defined in SandboxGrants.h).
    // Called BEFORE the DACL is written.  Returns false when the record could
    // not be persisted; the DACL is then left untouched.
    typedef bool (*RecordGrantFn)(const GrantRecordSpec&);

    // -----------------------------------------------------------------------
    // AclMutexGuard -- serialize DACL read-modify-write across Sandy instances.
    //
    // Windows has no atomic ACE-add/remove API.  Every DACL mutation is:
    //   GetNamedSecurityInfoW -> build new ACL -> Set*SecurityInfo
    // Without serialization, concurrent instances can lose each other's ACEs.
    //
    // Uses one named mutex for filesystem, registry, and desktop objects.
    // The mutex is auto-released
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
            if (!fixedName || !*fixedName) return;
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
            if (!hMutex) {
                g_logger.LogFmt(L"ACL_MUTEX: CreateMutexW failed for %ls (error %lu) — proceeding unserialized",
                                name, GetLastError());
                return;
            }
            DWORD wait = WaitForSingleObject(hMutex, INFINITE);
            if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
                g_logger.LogFmt(L"ACL_MUTEX: wait failed acquiring %ls (result %lu)", name, wait);
                CloseHandle(hMutex);
                hMutex = nullptr;
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
    // Map access level to the mask of a DENY ACE
    //
    // A deny mask is NOT the allow mask of the same level.  Every allow mask
    // carries the rights each open needs (SYNCHRONIZE, READ_CONTROL,
    // FILE_READ_ATTRIBUTES); a deny on those blocks every open, whatever the
    // level.  A deny mask holds only the rights that make the level what it
    // is, so one level can be denied and the others stay usable.
    //
    // Every deny also holds WRITE_DAC | WRITE_OWNER: the denied process must
    // not be able to edit the rule away.  Delete and All also hold
    // FILE_DELETE_CHILD: without it, the right to delete children that the
    // parent directory gives through another SID deletes the denied files.
    // -----------------------------------------------------------------------
    constexpr DWORD kDenyTamperMask = WRITE_DAC | WRITE_OWNER;

    inline DWORD DenyMask(AccessLevel level) {
        DWORD mask = 0;
        switch (level) {
        case AccessLevel::Read:    mask = FILE_READ_DATA | FILE_READ_EA; break;
        case AccessLevel::Write:   mask = FILE_WRITE_DATA | FILE_APPEND_DATA |
                                          FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES; break;
        case AccessLevel::Execute:
        case AccessLevel::Run:     mask = FILE_EXECUTE; break;
        case AccessLevel::Append:  mask = FILE_APPEND_DATA; break;
        case AccessLevel::Delete:  mask = DELETE | FILE_DELETE_CHILD; break;
        case AccessLevel::All:     mask = FILE_ALL_ACCESS; break;
        // Windows also gives FILE_READ_ATTRIBUTES through the list right of
        // the parent directory, so this deny holds only where listing the
        // parent is denied too.
        case AccessLevel::Stat:    mask = FILE_READ_ATTRIBUTES; break;
        case AccessLevel::Touch:   mask = FILE_WRITE_ATTRIBUTES; break;
        case AccessLevel::Create:  mask = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY; break;
        default:                   return 0;
        }
        return mask | kDenyTamperMask;
    }

    // Does a deny of this level stop deletion of the named object?
    inline bool DenyBlocksDelete(AccessLevel level) {
        return level == AccessLevel::Delete || level == AccessLevel::All;
    }

    // -----------------------------------------------------------------------
    // Inheritance flags of a recursive (.deep) rule on a directory.
    //
    // FILE_ADD_FILE and FILE_ADD_SUBDIRECTORY have the same bit values as
    // FILE_WRITE_DATA and FILE_APPEND_DATA.  If files inherited a `create`
    // rule, it would be a rule about overwriting existing files.  `create`
    // therefore inherits to sub-directories only.
    // -----------------------------------------------------------------------
    inline BYTE DeepInheritFlags(AccessLevel level) {
        return level == AccessLevel::Create
            ? static_cast<BYTE>(CONTAINER_INHERIT_ACE)
            : static_cast<BYTE>(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
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

    // True when the object can have children that inherit ACEs.
    inline bool IsAclContainer(const std::wstring& path, SE_OBJECT_TYPE objType)
    {
        if (objType != SE_FILE_OBJECT)
            return true;  // registry keys
        DWORD attrs = GetFileAttributesW(path.c_str());
        return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
    }

    // -----------------------------------------------------------------------
    // WriteDaclToObject — the ONLY way Sandy writes filesystem DACLs.
    //
    // The DACL protection state (SE_DACL_PROTECTED, "inheritance disabled")
    // of the object is read from the SD we already fetched and written back
    // unchanged.  There is no parameter to change it.
    //
    // Parameters:
    //   path        — target object path
    //   objType     — SE_FILE_OBJECT or SE_REGISTRY_KEY
    //   pNewDacl    — new DACL to apply (caller-allocated, caller-freed)
    //   pExistingSD — security descriptor from GetNamedSecurityInfoW
    //                 (used to read the control flags; may be nullptr)
    //   directoryOnly — true = SetKernelObjectSecurity (no child propagation)
    // -----------------------------------------------------------------------
    inline DWORD WriteDaclToObject(
        const std::wstring& path,
        SE_OBJECT_TYPE objType,
        PACL pNewDacl,
        PSECURITY_DESCRIPTOR pExistingSD,
        bool directoryOnly)
    {
        // Read existing protection state from the SD we already fetched
        SECURITY_DESCRIPTOR_CONTROL existingControl = 0;
        DWORD sdRevision = 0;
        if (pExistingSD)
            GetSecurityDescriptorControl(pExistingSD, &existingControl, &sdRevision);

        DWORD siFlags = DACL_SECURITY_INFORMATION;
        if (existingControl & SE_DACL_PROTECTED)
            siFlags |= PROTECTED_DACL_SECURITY_INFORMATION;

        bool isDir = (objType == SE_FILE_OBJECT) && IsAclContainer(path, objType);

        DWORD rc;
        if (isDir && directoryOnly) {
            // SetKernelObjectSecurity: writes DACL to this single object only,
            // no child propagation.  Used for object-only ACE sets.
            HANDLE hDir = CreateFileW(path.c_str(), WRITE_DAC | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (hDir == INVALID_HANDLE_VALUE) {
                rc = GetLastError();
            } else {
                SECURITY_DESCRIPTOR sd;
                InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
                SetSecurityDescriptorDacl(&sd, TRUE, pNewDacl, FALSE);
                // The kernel keeps SE_DACL_AUTO_INHERITED only when the
                // request bit comes with it.
                SECURITY_DESCRIPTOR_CONTROL keep =
                    existingControl & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED);
                if (keep & SE_DACL_AUTO_INHERITED)
                    keep |= SE_DACL_AUTO_INHERIT_REQ;
                SetSecurityDescriptorControl(&sd,
                    SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ, keep);
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
    // ACE inspection helpers
    // -----------------------------------------------------------------------
    inline bool IsDenyAceType(BYTE aceType)
    {
        return aceType == ACCESS_DENIED_ACE_TYPE ||
               aceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
               aceType == ACCESS_DENIED_CALLBACK_ACE_TYPE ||
               aceType == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE;
    }

    // SID of a plain allow/deny ACE; nullptr for every other ACE type.
    inline PSID SimpleAceSid(PACE_HEADER pAceHdr)
    {
        if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE)
            return &reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr)->SidStart;
        if (pAceHdr->AceType == ACCESS_DENIED_ACE_TYPE)
            return &reinterpret_cast<ACCESS_DENIED_ACE*>(pAceHdr)->SidStart;
        return nullptr;
    }

    // OWNER RIGHTS (S-1-3-4); nullptr if Windows cannot build it.
    inline PSID OwnerRightsSid()
    {
        static BYTE sidBuf[SECURITY_MAX_SID_SIZE];
        static DWORD sidSize = sizeof(sidBuf);
        static bool ok = CreateWellKnownSid(WinCreatorOwnerRightsSid, nullptr, sidBuf, &sidSize) != 0;
        return ok ? static_cast<PSID>(sidBuf) : nullptr;
    }

    inline bool IsOwnerRightsAce(PACE_HEADER pAceHdr)
    {
        PSID pOwnerRights = OwnerRightsSid();
        PSID pAceSid = SimpleAceSid(pAceHdr);
        return pOwnerRights && pAceSid && EqualSid(pAceSid, pOwnerRights);
    }

    // The exact ACE Sandy writes as deny companion: explicit, allow,
    // OWNER RIGHTS, READ_CONTROL | WRITE_DAC, the given inheritance flags.
    inline bool IsSandyOwnerAce(PACE_HEADER pAceHdr, BYTE inheritFlags)
    {
        return pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE &&
               pAceHdr->AceFlags == inheritFlags &&
               reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr)->Mask == kOwnerAceMask &&
               IsOwnerRightsAce(pAceHdr);
    }

    inline BYTE OwnerAceInheritFlags(OwnerAce ownerAce)
    {
        return ownerAce == OwnerAce::Inherit
            ? static_cast<BYTE>(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
            : static_cast<BYTE>(0);
    }

    // An OWNER RIGHTS ACE that says something else than Sandy's companion
    // ACE is a policy of the user.  The implicit owner grant is already off
    // on such an object, and one more allow ACE would widen that policy.
    inline bool HasForeignOwnerRightsAce(PACL pDacl)
    {
        ACL_SIZE_INFORMATION aclInfo = {};
        if (!GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation))
            return true;  // cannot tell — add nothing
        for (DWORD i = 0; i < aclInfo.AceCount; i++) {
            PACE_HEADER pAceHdr = nullptr;
            if (!GetAce(pDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr)))
                return true;
            if (!IsOwnerRightsAce(pAceHdr))
                continue;
            bool sameAsOurs = pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE &&
                reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAceHdr)->Mask == kOwnerAceMask;
            if (!sameAsOurs)
                return true;
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // RebuildDacl — the only place where Sandy builds a DACL.
    //
    // Copies `pOld`, leaves out the ACEs for which `drop` returns true, and
    // adds `added` at their canonical places: new explicit denies after the
    // explicit denies already there, new explicit allows after the last
    // explicit ACE; both before the first inherited ACE.  Each kept ACE is
    // copied byte for byte and in its old order.
    //
    // Returns a new ACL (caller must LocalFree) or nullptr with the last
    // error set.  The caller must not write a DACL when this fails: a DACL
    // without unrelated ACEs would destroy the access of other principals.
    // -----------------------------------------------------------------------
    struct NewAce {
        PSID  sid;
        bool  deny;
        BYTE  flags;
        DWORD mask;
    };

    inline PACL RebuildDacl(PACL pOld,
                            const std::function<bool(PACE_HEADER)>& drop,
                            const std::vector<NewAce>& added)
    {
        ACL_SIZE_INFORMATION aclInfo = {};
        if (!GetAclInformation(pOld, &aclInfo, sizeof(aclInfo), AclSizeInformation))
            return nullptr;

        std::vector<PACE_HEADER> kept;
        kept.reserve(aclInfo.AceCount);
        size_t newAclSize = sizeof(ACL);
        for (DWORD i = 0; i < aclInfo.AceCount; i++) {
            PACE_HEADER pAceHdr = nullptr;
            if (!GetAce(pOld, i, reinterpret_cast<LPVOID*>(&pAceHdr)))
                return nullptr;
            if (drop && drop(pAceHdr))
                continue;
            kept.push_back(pAceHdr);
            newAclSize += pAceHdr->AceSize;
        }
        for (const auto& ace : added)
            newAclSize += sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(ace.sid);
        if (newAclSize > MAXWORD) {  // AclSize is a 16-bit field
            SetLastError(ERROR_ALLOTTED_SPACE_EXCEEDED);
            return nullptr;
        }

        size_t explicitEnd = 0;
        while (explicitEnd < kept.size() && !(kept[explicitEnd]->AceFlags & INHERITED_ACE))
            explicitEnd++;
        size_t denyEnd = 0;
        while (denyEnd < explicitEnd && IsDenyAceType(kept[denyEnd]->AceType))
            denyEnd++;

        PACL pNew = reinterpret_cast<PACL>(LocalAlloc(LPTR, newAclSize));
        if (!pNew)
            return nullptr;
        const DWORD revision = pOld->AclRevision;
        auto copyKept = [&](size_t from, size_t to) {
            for (size_t i = from; i < to; i++) {
                if (!AddAce(pNew, revision, MAXDWORD, kept[i], kept[i]->AceSize))
                    return false;
            }
            return true;
        };
        auto addNew = [&](bool deny) {
            for (const auto& ace : added) {
                if (ace.deny != deny)
                    continue;
                BOOL ok = deny
                    ? AddAccessDeniedAceEx(pNew, ACL_REVISION, ace.flags, ace.mask, ace.sid)
                    : AddAccessAllowedAceEx(pNew, ACL_REVISION, ace.flags, ace.mask, ace.sid);
                if (!ok)
                    return false;
            }
            return true;
        };

        bool built = InitializeAcl(pNew, static_cast<DWORD>(newAclSize), revision) &&
                     copyKept(0, denyEnd) && addNew(true) &&
                     copyKept(denyEnd, explicitEnd) && addNew(false) &&
                     copyKept(explicitEnd, kept.size());
        if (!built) {
            DWORD err = GetLastError();
            LocalFree(pNew);
            SetLastError(err);
            return nullptr;
        }
        return pNew;
    }

    inline void LogResultingSddl(const std::wstring& path, SE_OBJECT_TYPE objType)
    {
        PACL pResultDacl = nullptr;
        PSECURITY_DESCRIPTOR pResultSD = nullptr;
        if (GetNamedSecurityInfoW(path.c_str(), objType,
                DACL_SECURITY_INFORMATION, nullptr, nullptr,
                &pResultDacl, nullptr, &pResultSD) != ERROR_SUCCESS)
            return;
        LPWSTR sddl = nullptr;
        if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                pResultSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                &sddl, nullptr)) {
            g_logger.Log((L"GRANT_SDDL: " + path + L" -> " + sddl).c_str());
            LocalFree(sddl);
        }
        LocalFree(pResultSD);
    }

    // -----------------------------------------------------------------------
    // AddAcesToObject — add the ACEs of one sandbox SID to a file, folder or
    // registry key.  The only function that adds Sandy ACEs.
    //
    // Returns ERROR_SUCCESS (0) on success, or the exact Win32 error code.
    // Steps:
    //   1. Read current DACL
    //   2. Persist the cleanup record via recordFn (write-ahead)
    //   3. Build the new DACL: old ACEs unchanged + `aces` (+ owner companion)
    //   4. Apply it in one write (auto-inheritance unless every ACE is
    //      object-only)
    //   5. Log resulting SDDL
    //
    // An allow and a deny for the same object need no special handling: the
    // canonical order (explicit deny, explicit allow, inherited) makes the
    // deny win on the object and makes a rule on a nearer object win over a
    // rule inherited from farther up.
    //
    // neutralizeOwner — add the OWNER RIGHTS companion (see OwnerAce) when
    // `aces` holds a deny.  Pass true when the user SID is a restricting SID
    // of the sandbox token.
    // -----------------------------------------------------------------------
    inline DWORD AddAcesToObject(const std::wstring& path,
                                 SE_OBJECT_TYPE objType,
                                 PSID pSid,
                                 const std::wstring& sidString,
                                 const std::vector<AceSpec>& aces,
                                 bool neutralizeOwner,
                                 RecordGrantFn recordFn)
    {
        AclMutexGuard aclLock(path);

        // 1. Read current DACL
        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            path.c_str(), objType, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS) return rc;

        // A NULL DACL gives everyone full access.  A DACL with only our ACEs
        // in its place would take that access away from everyone else.
        if (!pOldDacl) {
            LocalFree(pSD);
            return ERROR_INVALID_ACL;
        }

        bool hasDeny = false;
        bool inheritable = false;
        for (const auto& ace : aces) {
            hasDeny = hasDeny || ace.deny;
            inheritable = inheritable || (ace.flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE));
        }

        OwnerAce ownerAce = OwnerAce::None;
        if (neutralizeOwner && hasDeny && OwnerRightsSid() && !HasForeignOwnerRightsAce(pOldDacl))
            ownerAce = inheritable ? OwnerAce::Inherit : OwnerAce::ObjectOnly;

        // 2. Record first.  A record without ACEs is a no-op for cleanup;
        //    ACEs without a record can never be found again.
        if (recordFn) {
            GrantRecordSpec record;
            record.path = path;
            record.objType = objType;
            record.sidString = sidString;
            record.hasDeny = hasDeny;
            record.objectOnly = !inheritable;
            record.ownerAce = ownerAce;
            if (!recordFn(record)) {
                LocalFree(pSD);
                return ERROR_WRITE_FAULT;
            }
        }

        // 3. Build new DACL
        std::vector<NewAce> added;
        added.reserve(aces.size() + 1);
        for (const auto& ace : aces)
            added.push_back({ pSid, ace.deny, ace.flags, ace.mask });
        if (ownerAce != OwnerAce::None)
            added.push_back({ OwnerRightsSid(), false, OwnerAceInheritFlags(ownerAce), kOwnerAceMask });

        PACL pNewDacl = RebuildDacl(pOldDacl, nullptr, added);
        if (!pNewDacl) {
            rc = GetLastError();
            LocalFree(pSD);
            return rc != ERROR_SUCCESS ? rc : ERROR_NOT_ENOUGH_MEMORY;
        }

        // 4. Apply new DACL via centralized helper.
        rc = WriteDaclToObject(path, objType, pNewDacl, pSD, !inheritable);
        LocalFree(pNewDacl);
        LocalFree(pSD);

        // 5. Log resulting SDDL
        if (rc == ERROR_SUCCESS)
            LogResultingSddl(path, objType);
        return rc;
    }

    // -----------------------------------------------------------------------
    // RemoveSidFromDaclDetailed — remove all ACEs for a specific SID from an object.
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
    //
    // ownerAce — the record says an OWNER RIGHTS companion was written with
    // the ACEs.  It went onto the object in the same DACL write as the deny
    // ACEs of this SID, so one copy is removed if, and only if, an explicit
    // deny of this SID is still on the object.  Without that proof nothing
    // but the SID's own ACEs is touched (the write never happened, or an
    // earlier cleanup already removed both).
    //
    // An object that holds no ACE of the SID can still have descendants that
    // do: Windows writes the children first and the object last, so a
    // killed grant leaves inherited copies below a clean root.  Unless
    // skipTreeSet is set, the DACL is written back unchanged to make Windows
    // compute the inheritance of the whole tree again.
    // -----------------------------------------------------------------------
    inline AceRemovalResult RemoveSidFromDaclDetailed(const std::wstring& path,
                                                     const std::wstring& sidString,
                                                     SE_OBJECT_TYPE objType,
                                                     bool skipTreeSet = false,
                                                     OwnerAce ownerAce = OwnerAce::None)
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

        // NULL DACL (FAT volumes, explicitly null-DACL objects) holds no ACEs
        // to remove — and GetAclInformation would dereference null.
        if (!pOldDacl) {
            LocalFree(pSD);
            LocalFree(pTargetSid);
            return result;
        }

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

        auto isTargetAce = [&](PACE_HEADER pAceHdr) -> bool {
            PSID pAceSid = SimpleAceSid(pAceHdr);
            return pAceSid && EqualSid(pAceSid, pTargetSid);
        };

        // First pass: what does this SID hold on the object?
        int removed = 0;
        bool explicitDenyPresent = false;
        for (DWORD i = 0; i < aclInfo.AceCount; i++) {
            PACE_HEADER pAceHdr = nullptr;
            if (!GetAce(pOldDacl, i, reinterpret_cast<LPVOID*>(&pAceHdr))) continue;
            if (!isTargetAce(pAceHdr)) continue;
            removed++;
            if (pAceHdr->AceType == ACCESS_DENIED_ACE_TYPE && !(pAceHdr->AceFlags & INHERITED_ACE))
                explicitDenyPresent = true;
        }

        if (removed == 0) {
            if (!skipTreeSet && IsAclContainer(path, objType)) {
                // Not an error when it fails: a DACL we cannot write now is a
                // DACL the grant could not write either.
                rc = WriteDaclToObject(path, objType, pOldDacl, pSD, false);
                if (rc == ERROR_SUCCESS)
                    g_logger.LogFmt(L"ACL_REPROPAGATE: %s -> OK", path.c_str());
                else
                    g_logger.LogFmt(L"ACL_REPROPAGATE: %s -> skipped (0x%08X: %s)",
                                    path.c_str(), rc, GetSystemErrorMessage(rc).c_str());
            }
            LocalFree(pSD);
            LocalFree(pTargetSid);
            return result;
        }

        // Second pass: build new ACL without the SID's ACEs
        const bool dropOwnerAce = ownerAce != OwnerAce::None && explicitDenyPresent;
        const BYTE ownerFlags = OwnerAceInheritFlags(ownerAce);
        bool ownerAceDropped = false;
        PACL pNewDacl = RebuildDacl(pOldDacl, [&](PACE_HEADER pAceHdr) -> bool {
            if (isTargetAce(pAceHdr))
                return true;
            if (dropOwnerAce && !ownerAceDropped && IsSandyOwnerAce(pAceHdr, ownerFlags)) {
                ownerAceDropped = true;  // exactly one copy: other instances own the rest
                return true;
            }
            return false;
        }, {});
        LocalFree(pTargetSid);
        if (!pNewDacl) {
            // Writing a DACL missing unrelated ACEs would destroy other
            // principals' access — abort and leave the original untouched.
            result.error = GetLastError();
            if (result.error == ERROR_SUCCESS) result.error = ERROR_NOT_ENOUGH_MEMORY;
            g_logger.LogFmt(L"ACL_REMOVE: %s -> ABORTED (0x%08X: %s)",
                            path.c_str(), result.error,
                            GetSystemErrorMessage(result.error).c_str());
            LocalFree(pSD);
            return result;
        }

        // Apply cleaned DACL via centralized helper
        rc = WriteDaclToObject(path, objType, pNewDacl, pSD, skipTreeSet);
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

} // namespace Sandbox

