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

    // Per-instance UUID — set once at startup, used for registry and container
    inline std::wstring g_instanceId;

    inline std::wstring GetGrantsRegKey() {
        return std::wstring(kGrantsParentKey) + L"\\" + g_instanceId;
    }

    // -----------------------------------------------------------------------
    // Persist a grant to registry (write-ahead, before modifying DACL)
    // Uses instance UUID subkey to isolate concurrent sandy instances.
    // Stores PID as value for liveness checks during stale cleanup.
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
                nullptr, &hKey, &disposition) != ERROR_SUCCESS) {
            g_logger.Log((L"REG_PERSIST: FAILED to create key " + regKey).c_str());
            return;
        }

        // On first creation, store PID and deny Restricted SID write access.
        if (disposition == REG_CREATED_NEW_KEY) {
            // Store PID for liveness checks
            DWORD pid = GetCurrentProcessId();
            RegSetValueExW(hKey, L"_pid", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&pid), sizeof(DWORD));

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

        g_logger.Log((L"REG_PERSIST: [" + std::to_wstring(valueCount) + L"] " + data).c_str());
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
                TREE_SEC_INFO_SET, nullptr, ProgressInvokeNever, nullptr);
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
    // Helper: restore grants from a single registry subkey.
    // Skips paths in protectedPaths (still needed by live instances).
    // -----------------------------------------------------------------------
    inline void RestoreGrantsFromKey(HKEY hKey,
                                      const std::set<std::wstring>& protectedPaths = {})
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

            // Skip paths still needed by live instances
            if (protectedPaths.count(path)) {
                g_logger.Log((L"ACL_SKIP_STALE: " + path + L" (live instance active)").c_str());
                continue;
            }

            SE_OBJECT_TYPE objType = (typeStr == L"REG") ? SE_REGISTRY_KEY : SE_FILE_OBJECT;

            PSECURITY_DESCRIPTOR pSD = nullptr;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.c_str(), SDDL_REVISION_1, &pSD, nullptr)) {
                BOOL present = FALSE, defaulted = FALSE;
                PACL pDacl = nullptr;
                if (GetSecurityDescriptorDacl(pSD, &present, &pDacl, &defaulted) && present) {
                    // Use TreeSetNamedSecurityInfo for dirs to propagate removal
                    DWORD a2 = (objType == SE_FILE_OBJECT) ? GetFileAttributesW(path.c_str()) : 0;
                    bool dir2 = (objType == SE_FILE_OBJECT) && (a2 != INVALID_FILE_ATTRIBUTES)
                                && (a2 & FILE_ATTRIBUTE_DIRECTORY);
                    if (dir2) {
                        TreeSetNamedSecurityInfoW(
                            const_cast<LPWSTR>(path.c_str()), objType,
                            DACL_SECURITY_INFORMATION, nullptr, nullptr, pDacl, nullptr,
                            TREE_SEC_INFO_SET, nullptr, ProgressInvokeNever, nullptr);
                    } else {
                        SetNamedSecurityInfoW(
                            const_cast<LPWSTR>(path.c_str()), objType,
                            DACL_SECURITY_INFORMATION, nullptr, nullptr, pDacl, nullptr);
                    }
                    g_logger.Log((L"ACL_RESTORE: " + path).c_str());
                }
                LocalFree(pSD);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Collect paths granted by OTHER sandy instances (from registry).
    // Used to avoid revoking ACEs that another live instance still needs.
    // -----------------------------------------------------------------------
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

            // Read this instance's grants
            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + name;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            DWORD valueCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &valueCount, nullptr, nullptr, nullptr, nullptr);

            for (DWORD vi = 0; vi < valueCount; vi++) {
                wchar_t vname[64];
                DWORD vnameLen = 64;
                DWORD dataSize = 0;
                DWORD dataType = 0;
                if (RegEnumValueW(hKey, vi, vname, &vnameLen, nullptr, &dataType,
                                  nullptr, &dataSize) != ERROR_SUCCESS)
                    continue;

                // Skip metadata values (_pid, _container)
                if (vname[0] == L'_') continue;
                if (dataType != REG_SZ) continue;

                std::wstring data(dataSize / sizeof(wchar_t), L'\0');
                vnameLen = 64;
                RegEnumValueW(hKey, vi, vname, &vnameLen, nullptr, nullptr,
                              reinterpret_cast<BYTE*>(&data[0]), &dataSize);
                while (!data.empty() && data.back() == L'\0') data.pop_back();

                // Parse TYPE|PATH|SDDL — extract just the path
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
        AcquireSRWLockExclusive(&g_aclGrantsLock);

        // Check which paths other instances still need
        std::set<std::wstring> otherPaths = GetOtherInstancePaths(g_instanceId);

        for (auto it = g_aclGrants.rbegin(); it != g_aclGrants.rend(); ++it) {
            if (otherPaths.count(it->path)) {
                // Another instance still has a grant for this path — leave ACE intact
                g_logger.Log((L"ACL_SKIP: " + it->path + L" (other instance active)").c_str());
                continue;
            }
            PSECURITY_DESCRIPTOR pSD = nullptr;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    it->originalSDDL.c_str(), SDDL_REVISION_1, &pSD, nullptr)) {
                BOOL present = FALSE, defaulted = FALSE;
                PACL pDacl = nullptr;
                if (GetSecurityDescriptorDacl(pSD, &present, &pDacl, &defaulted) && present) {
                    DWORD a3 = (it->objType == SE_FILE_OBJECT) ? GetFileAttributesW(it->path.c_str()) : 0;
                    bool dir3 = (it->objType == SE_FILE_OBJECT) && (a3 != INVALID_FILE_ATTRIBUTES)
                                && (a3 & FILE_ATTRIBUTE_DIRECTORY);
                    if (dir3) {
                        TreeSetNamedSecurityInfoW(
                            const_cast<LPWSTR>(it->path.c_str()), it->objType,
                            DACL_SECURITY_INFORMATION, nullptr, nullptr, pDacl, nullptr,
                            TREE_SEC_INFO_SET, nullptr, ProgressInvokeNever, nullptr);
                    } else {
                        SetNamedSecurityInfoW(
                            const_cast<LPWSTR>(it->path.c_str()), it->objType,
                            DACL_SECURITY_INFORMATION, nullptr, nullptr, pDacl, nullptr);
                    }
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

        // Helper: read _pid DWORD from a subkey
        auto readPid = [](HKEY hKey) -> DWORD {
            DWORD pid = 0, size = sizeof(DWORD);
            RegQueryValueExW(hKey, L"_pid", nullptr, nullptr,
                             reinterpret_cast<BYTE*>(&pid), &size);
            return pid;
        };

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
                wchar_t vname[64];
                DWORD vnameLen = 64;
                DWORD dataSize = 0, dataType = 0;
                if (RegEnumValueW(hKey, vi, vname, &vnameLen, nullptr, &dataType,
                                  nullptr, &dataSize) != ERROR_SUCCESS)
                    continue;
                if (vname[0] == L'_' || dataType != REG_SZ) continue;
                std::wstring data(dataSize / sizeof(wchar_t), L'\0');
                vnameLen = 64;
                RegEnumValueW(hKey, vi, vname, &vnameLen, nullptr, nullptr,
                              reinterpret_cast<BYTE*>(&data[0]), &dataSize);
                while (!data.empty() && data.back() == L'\0') data.pop_back();
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

            DWORD pid = readPid(hKey);
            HANDLE h = pid ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) : nullptr;
            if (h) {
                // PID is alive — collect its paths and skip cleanup
                CloseHandle(h);
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
            RegDeleteKeyW(HKEY_CURRENT_USER, fullKey.c_str());
            g_logger.Log((L"REG_DELETE: " + fullKey).c_str());
        }

        // Remove parent key if now empty
        RegDeleteKeyW(HKEY_CURRENT_USER, kGrantsParentKey);
    }

} // namespace Sandbox
