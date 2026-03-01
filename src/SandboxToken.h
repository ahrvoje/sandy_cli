// =========================================================================
// SandboxToken.h — Restricted token creation and desktop access
//
// Creates a restricted sandbox token with configurable integrity level.
// Only used when tokenMode == Restricted.
// =========================================================================
#pragma once

#include "SandboxTypes.h"

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Create a restricted sandbox token (alternative to AppContainer).
    // Uses restricting SIDs + configurable integrity level.
    // il: Low = stronger isolation (may break some apps), Medium = wider compat.
    // -----------------------------------------------------------------------
    inline HANDLE CreateRestrictedSandboxToken(IntegrityLevel il)
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
            return nullptr;

        // --- Enumerate token groups -> build deny-only list ---
        DWORD groupSize = 0;
        GetTokenInformation(hToken, TokenGroups, nullptr, 0, &groupSize);
        std::vector<BYTE> groupBuf(groupSize);
        auto* pGroups = reinterpret_cast<TOKEN_GROUPS*>(groupBuf.data());
        if (!GetTokenInformation(hToken, TokenGroups, pGroups, groupSize, &groupSize)) {
            CloseHandle(hToken);
            return nullptr;
        }

        // Get user SID (needed for restricting SIDs)
        DWORD userSize = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &userSize);
        std::vector<BYTE> userBuf(userSize);
        auto* pUser = reinterpret_cast<TOKEN_USER*>(userBuf.data());
        GetTokenInformation(hToken, TokenUser, pUser, userSize, &userSize);

        // Logon SID — needed for desktop access
        PSID pLogonSid = nullptr;
        for (DWORD i = 0; i < pGroups->GroupCount; i++) {
            if ((pGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) != 0) {
                pLogonSid = pGroups->Groups[i].Sid;
                break;
            }
        }

        // --- Build restricting SID list ---
        // The dual access check ensures both normal SIDs AND restricting SIDs
        // must allow access. This limits the token's effective access to only
        // resources that have explicit ACEs for the restricting SIDs.
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        PSID pRestrictedSid = nullptr;
        AllocateAndInitializeSid(&ntAuth, 1, SECURITY_RESTRICTED_CODE_RID,
            0, 0, 0, 0, 0, 0, 0, &pRestrictedSid);

        // Everyone (S-1-1-0) — always included because many system objects
        // (DLLs, registry keys, pipe namespace) use Everyone ACEs. Without
        // Everyone in restricting SIDs, the dual access check fails and the
        // process can't even load its initial DLLs.
        SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
        PSID pEveryoneSid = nullptr;
        AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID,
            0, 0, 0, 0, 0, 0, 0, &pEveryoneSid);

        // BUILTIN\Users (S-1-5-32-545) — system directories grant read to Users.
        PSID pUsersSid = nullptr;
        AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &pUsersSid);

        std::vector<SID_AND_ATTRIBUTES> restrictSids;
        restrictSids.push_back({ pUser->User.Sid, 0 });
        restrictSids.push_back({ pRestrictedSid, 0 });
        restrictSids.push_back({ pUsersSid, 0 });
        if (pLogonSid) restrictSids.push_back({ pLogonSid, 0 });
        if (pEveryoneSid) restrictSids.push_back({ pEveryoneSid, 0 });

        // Authenticated Users (S-1-5-11) — many system objects (WinSxS
        // manifests, CRT DLLs, API set resolvers) grant access to
        // Authenticated Users. Without this, the DLL loader can fail with
        // STATUS_DLL_NOT_FOUND for complex executables like Python.
        PSID pAuthUsersSid = nullptr;
        AllocateAndInitializeSid(&ntAuth, 1, SECURITY_AUTHENTICATED_USER_RID,
            0, 0, 0, 0, 0, 0, 0, &pAuthUsersSid);
        if (pAuthUsersSid) restrictSids.push_back({ pAuthUsersSid, 0 });

        // --- Enumerate privileges -> delete all except SeChangeNotifyPrivilege ---
        DWORD privSize = 0;
        GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &privSize);
        std::vector<BYTE> privBuf(privSize);
        auto* pPrivs = reinterpret_cast<TOKEN_PRIVILEGES*>(privBuf.data());
        GetTokenInformation(hToken, TokenPrivileges, pPrivs, privSize, &privSize);

        LUID changeNotifyLuid;
        LookupPrivilegeValueW(nullptr, SE_CHANGE_NOTIFY_NAME, &changeNotifyLuid);

        std::vector<LUID_AND_ATTRIBUTES> deletePrivs;
        for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
            if (pPrivs->Privileges[i].Luid.LowPart == changeNotifyLuid.LowPart &&
                pPrivs->Privileges[i].Luid.HighPart == changeNotifyLuid.HighPart)
                continue;
            deletePrivs.push_back(pPrivs->Privileges[i]);
        }

        // --- Create restricted token ---
        // No deny-only groups (0 flags) — restricting SIDs + Low integrity
        // provide strong isolation via dual access check.
        HANDLE hRestricted = nullptr;
        BOOL ok = CreateRestrictedToken(
            hToken,
            0,          // no flags — groups stay active, restricting SIDs do the work
            0, nullptr, // no deny-only SIDs
            static_cast<DWORD>(deletePrivs.size()), deletePrivs.data(),
            static_cast<DWORD>(restrictSids.size()), restrictSids.data(),
            &hRestricted);

        // --- Set integrity level ---
        // Low (0x1000): strongest isolation, blocks writes to Medium objects.
        //   May break apps that depend on api-ms-win-core-path API set.
        // Medium: inherits parent's level; relies solely on restricting SIDs.
        if (ok && hRestricted && il == IntegrityLevel::Low) {
            SID_IDENTIFIER_AUTHORITY mlAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;
            PSID pLowSid = nullptr;
            if (AllocateAndInitializeSid(&mlAuth, 1, SECURITY_MANDATORY_LOW_RID,
                    0, 0, 0, 0, 0, 0, 0, &pLowSid)) {
                TOKEN_MANDATORY_LABEL tml = {};
                tml.Label.Sid = pLowSid;
                tml.Label.Attributes = SE_GROUP_INTEGRITY;
                SetTokenInformation(hRestricted, TokenIntegrityLevel,
                    &tml, sizeof(tml) + GetLengthSid(pLowSid));
                FreeSid(pLowSid);
            }
        }

        // Cleanup
        if (pAuthUsersSid) FreeSid(pAuthUsersSid);
        if (pRestrictedSid) FreeSid(pRestrictedSid);
        if (pEveryoneSid) FreeSid(pEveryoneSid);
        if (pUsersSid) FreeSid(pUsersSid);
        CloseHandle(hToken);

        return ok ? hRestricted : nullptr;
    }

    // -----------------------------------------------------------------------
    // Grant a SID access to the current window station and desktop.
    // Required for CreateProcessAsUser — without this, processes using a
    // restricted token get STATUS_ACCESS_DENIED when attaching to the desktop.
    // -----------------------------------------------------------------------
    inline bool GrantDesktopAccess(PSID pSid) {
        auto grantObj = [&](HANDLE hObj) -> bool {
            SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
            PSECURITY_DESCRIPTOR pSD = nullptr;
            PACL pOldDacl = nullptr;
            if (GetSecurityInfo(hObj, SE_WINDOW_OBJECT, si,
                    nullptr, nullptr, &pOldDacl, nullptr, &pSD) != ERROR_SUCCESS)
                return false;

            EXPLICIT_ACCESS_W ea{};
            ea.grfAccessPermissions = GENERIC_ALL;
            ea.grfAccessMode = SET_ACCESS;
            ea.grfInheritance = NO_INHERITANCE;
            ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);

            PACL pNewDacl = nullptr;
            if (SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl) != ERROR_SUCCESS) {
                LocalFree(pSD);
                return false;
            }

            bool ok = SetSecurityInfo(hObj, SE_WINDOW_OBJECT, si,
                          nullptr, nullptr, pNewDacl, nullptr) == ERROR_SUCCESS;
            LocalFree(pNewDacl);
            LocalFree(pSD);
            return ok;
        };

        HWINSTA hWinSta = GetProcessWindowStation();
        HDESK hDesktop = OpenDesktopW(L"Default", 0, FALSE,
            READ_CONTROL | WRITE_DAC | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS |
            DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU | DESKTOP_SWITCHDESKTOP);

        bool ok = true;
        if (hWinSta) ok &= grantObj(hWinSta);
        if (hDesktop) {
            ok &= grantObj(hDesktop);
            CloseDesktop(hDesktop);
        }
        return ok;
    }

} // namespace Sandbox
