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
        case AccessLevel::Execute: return FILE_GENERIC_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        case AccessLevel::Append:  return FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        case AccessLevel::Delete:  return DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        case AccessLevel::All:     return FILE_ALL_ACCESS;
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
    };
    inline std::vector<ACLGrant> g_aclGrants;
    inline SRWLOCK g_aclGrantsLock = SRWLOCK_INIT;

    static const wchar_t* kGrantsParentKey = L"Software\\Sandy\\Grants";

    inline std::wstring GetGrantsRegKey() {
        wchar_t buf[128];
        swprintf(buf, 128, L"Software\\Sandy\\Grants\\%lu", GetCurrentProcessId());
        return buf;
    }

    // -----------------------------------------------------------------------
    // Persist a grant to registry (write-ahead, before modifying DACL)
    // Uses PID-specific subkey to isolate concurrent sandy instances.
    // Denies Restricted SID (S-1-5-12) access to prevent sandbox tampering.
    // -----------------------------------------------------------------------
    inline void PersistGrant(const std::wstring& path, SE_OBJECT_TYPE objType,
                             const std::wstring& sddl)
    {
        std::wstring regKey = GetGrantsRegKey();
        HKEY hKey = nullptr;
        DWORD disposition = 0;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr,
                0, KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC,
                nullptr, &hKey, &disposition) != ERROR_SUCCESS)
            return;

        // On first creation, deny Restricted SID (S-1-5-12) write access.
        // This blocks restricted-token children from tampering with our grants,
        // because S-1-5-12 is in their restricting SIDs list — the deny ACE
        // causes the restricting SID access check to fail.
        if (disposition == REG_CREATED_NEW_KEY) {
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

        // Count existing values to generate next index
        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        // Format: TYPE|PATH|SDDL
        std::wstring typeStr = (objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
        std::wstring data = typeStr + L"|" + path + L"|" + sddl;

        wchar_t valueName[32];
        swprintf(valueName, 32, L"%lu", valueCount);
        RegSetValueExW(hKey, valueName, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(data.c_str()),
                       static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }

    // -----------------------------------------------------------------------
    // Clear this instance's persisted grants from registry
    // -----------------------------------------------------------------------
    inline void ClearPersistedGrants()
    {
        std::wstring regKey = GetGrantsRegKey();
        RegDeleteKeyW(HKEY_CURRENT_USER, regKey.c_str());
        // Try to remove parent key if empty (best-effort, fails if subkeys remain)
        RegDeleteKeyW(HKEY_CURRENT_USER, kGrantsParentKey);
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
                ReleaseSRWLockExclusive(&g_aclGrantsLock);
                LocalFree(origSddl);
            }
        }
        LocalFree(pSD);

        rc = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(path.c_str()), objType,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDacl, nullptr);
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
    // Helper: restore grants from a single registry subkey
    // -----------------------------------------------------------------------
    inline void RestoreGrantsFromKey(HKEY hKey)
    {
        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        for (LONG i = static_cast<LONG>(valueCount) - 1; i >= 0; i--) {
            wchar_t valueName[32];
            swprintf(valueName, 32, L"%ld", i);

            DWORD dataSize = 0;
            if (RegQueryValueExW(hKey, valueName, nullptr, nullptr, nullptr, &dataSize) != ERROR_SUCCESS)
                continue;

            std::wstring data(dataSize / sizeof(wchar_t), L'\0');
            if (RegQueryValueExW(hKey, valueName, nullptr, nullptr,
                                 reinterpret_cast<BYTE*>(&data[0]), &dataSize) != ERROR_SUCCESS)
                continue;

            while (!data.empty() && data.back() == L'\0') data.pop_back();

            // Parse TYPE|PATH|SDDL — use rfind for last '|' (safe for paths with '|')
            auto sep1 = data.find(L'|');
            if (sep1 == std::wstring::npos) continue;
            auto sep2 = data.rfind(L'|');
            if (sep2 == std::wstring::npos || sep2 <= sep1) continue;

            std::wstring typeStr = data.substr(0, sep1);
            std::wstring path = data.substr(sep1 + 1, sep2 - sep1 - 1);
            std::wstring sddl = data.substr(sep2 + 1);
            SE_OBJECT_TYPE objType = (typeStr == L"REG") ? SE_REGISTRY_KEY : SE_FILE_OBJECT;

            PSECURITY_DESCRIPTOR pSD = nullptr;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.c_str(), SDDL_REVISION_1, &pSD, nullptr)) {
                BOOL present = FALSE, defaulted = FALSE;
                PACL pDacl = nullptr;
                if (GetSecurityDescriptorDacl(pSD, &present, &pDacl, &defaulted) && present) {
                    SetNamedSecurityInfoW(
                        const_cast<LPWSTR>(path.c_str()), objType,
                        DACL_SECURITY_INFORMATION, nullptr, nullptr, pDacl, nullptr);
                    g_logger.Log((L"ACL_RESTORE: " + path).c_str());
                }
                LocalFree(pSD);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Restore all DACLs to their pre-grant state (called on exit)
    // Thread-safe: protects g_aclGrants against CTRL+C signal handler race.
    // -----------------------------------------------------------------------
    inline void RevokeAllGrants()
    {
        AcquireSRWLockExclusive(&g_aclGrantsLock);
        for (auto it = g_aclGrants.rbegin(); it != g_aclGrants.rend(); ++it) {
            PSECURITY_DESCRIPTOR pSD = nullptr;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    it->originalSDDL.c_str(), SDDL_REVISION_1, &pSD, nullptr)) {
                BOOL present = FALSE, defaulted = FALSE;
                PACL pDacl = nullptr;
                if (GetSecurityDescriptorDacl(pSD, &present, &pDacl, &defaulted) && present) {
                    SetNamedSecurityInfoW(
                        const_cast<LPWSTR>(it->path.c_str()), it->objType,
                        DACL_SECURITY_INFORMATION, nullptr, nullptr, pDacl, nullptr);
                    g_logger.Log((L"ACL_RESTORE: " + it->path).c_str());
                }
                LocalFree(pSD);
            }
        }
        g_aclGrants.clear();
        ReleaseSRWLockExclusive(&g_aclGrantsLock);
        ClearPersistedGrants();
    }

    // -----------------------------------------------------------------------
    // Restore stale grants from registry (startup recovery after crash/power loss)
    // Enumerates ALL PID subkeys to recover from any crashed instance.
    // -----------------------------------------------------------------------
    inline void RestoreStaleGrants()
    {
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return;  // no stale grants

        // Enumerate all PID subkeys
        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        std::vector<std::wstring> subKeys;
        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[64];
            DWORD nameLen = 64;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                subKeys.push_back(name);
        }
        RegCloseKey(hParent);

        // Restore and delete each subkey
        for (const auto& subKey : subKeys) {
            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + subKey;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) == ERROR_SUCCESS) {
                RestoreGrantsFromKey(hKey);
                RegCloseKey(hKey);
            }
            RegDeleteKeyW(HKEY_CURRENT_USER, fullKey.c_str());
        }

        // Remove parent key if now empty
        RegDeleteKeyW(HKEY_CURRENT_USER, kGrantsParentKey);
    }

} // namespace Sandbox
