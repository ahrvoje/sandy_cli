// =========================================================================
// SandboxGrants.h — Grant tracking, persistence, and revocation
//
// Tracks all ACL modifications made during a sandbox session, persists
// them to the registry for crash recovery, and removes only our ACEs
// on exit.  Multi-instance safe: only touches ACEs for our own SID.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include "SandboxACL.h"
#include <set>
#include <atomic>

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Grant record — one per modified object
    // -----------------------------------------------------------------------
    struct ACLGrant {
        std::wstring       path;
        SE_OBJECT_TYPE     objType;
        std::wstring       sidString;
        // SID of the principal granted/denied
        std::wstring       trappedSids;    // semicolon-separated trapped AC SIDs (deny entries only)
        bool               wasDenied = false;
    };

    // -----------------------------------------------------------------------
    // Global state — guarded by SRW lock
    // -----------------------------------------------------------------------
    inline std::vector<ACLGrant> g_aclGrants;
    inline SRWLOCK               g_aclGrantsLock = SRWLOCK_INIT;
    inline std::atomic<bool>     g_cleanedUp{false};

    // Per-instance UUID — set once at startup
    inline std::wstring g_instanceId;

    // Registry keys for grant persistence
    static const wchar_t* kGrantsParentKey = L"Software\\Sandy\\Grants";

    inline std::wstring GetGrantsRegKey() {
        return std::wstring(kGrantsParentKey) + L"\\" + g_instanceId;
    }

    // -----------------------------------------------------------------------
    // Registry helper: read REG_SZ value by enumeration index.
    // Skips metadata values (name starts with '_').
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
    // Process liveness check — guards against PID reuse via creation time
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

    inline bool IsProcessAlive(DWORD pid, ULONGLONG storedCreationTime)
    {
        if (!pid) return false;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
        if (!h) return false;

        // Zombie check — signaled = terminated
        if (WaitForSingleObject(h, 0) != WAIT_TIMEOUT) {
            CloseHandle(h);
            return false;
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

    // -----------------------------------------------------------------------
    // Save a grant to the in-memory list AND the registry.
    // Called by GrantObjectAccess and DenyObjectAccess via RecordGrantCallback.
    // Stores SID string (for ACE-level removal) — no SDDL snapshot.
    // -----------------------------------------------------------------------
    inline void RecordGrant(const std::wstring& path, SE_OBJECT_TYPE objType,
                            const std::wstring& sidString,
                            const std::wstring& trappedSids = L"")
    {
        AcquireSRWLockExclusive(&g_aclGrantsLock);

        // --- Persist to registry ---
        std::wstring regKey = GetGrantsRegKey();
        HKEY hKey = nullptr;
        DWORD disposition = 0;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr,
                0, KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC,
                nullptr, &hKey, &disposition) == ERROR_SUCCESS) {

            // On first creation, store identity and protect the key
            if (disposition == REG_CREATED_NEW_KEY) {
                DWORD pid = GetCurrentProcessId();
                RegSetValueExW(hKey, L"_pid", 0, REG_DWORD,
                               reinterpret_cast<const BYTE*>(&pid), sizeof(DWORD));

                ULONGLONG ct = GetCurrentProcessCreationTime();
                RegSetValueExW(hKey, L"_ctime", 0, REG_QWORD,
                               reinterpret_cast<const BYTE*>(&ct), sizeof(ULONGLONG));

                std::wstring containerName = ContainerNameFromId(g_instanceId);
                RegSetValueExW(hKey, L"_container", 0, REG_SZ,
                               reinterpret_cast<const BYTE*>(containerName.c_str()),
                               static_cast<DWORD>((containerName.size() + 1) * sizeof(wchar_t)));

                // Deny Restricted SID (S-1-5-12) write access to prevent tampering
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

            // Get next index
            DWORD nextIdx = 0;
            DWORD idxSize = sizeof(nextIdx);
            RegQueryValueExW(hKey, L"_nextIdx", nullptr, nullptr,
                             reinterpret_cast<BYTE*>(&nextIdx), &idxSize);

            // Format: TYPE|PATH|SID  or  TYPE|PATH|SID|TRAPPED:sid1;sid2
            std::wstring typeStr = (objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
            std::wstring data = typeStr + L"|" + path + L"|" + sidString;
            if (!trappedSids.empty()) {
                data += L"|TRAPPED:" + trappedSids;
            }

            wchar_t valueName[32];
            swprintf(valueName, 32, L"%lu", nextIdx);
            RegSetValueExW(hKey, valueName, 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(data.c_str()),
                           static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t)));

            // Increment counter
            nextIdx++;
            RegSetValueExW(hKey, L"_nextIdx", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&nextIdx), sizeof(nextIdx));

            g_logger.Log((L"REG_PERSIST: [" + std::to_wstring(nextIdx - 1) + L"] " + data).c_str());
            RegCloseKey(hKey);
        }

        // --- Save to in-memory list ---
        ACLGrant grant = { path, objType, sidString, trappedSids, !trappedSids.empty() };
        g_aclGrants.push_back(std::move(grant));

        ReleaseSRWLockExclusive(&g_aclGrantsLock);
    }

    // -----------------------------------------------------------------------
    // Clear this instance's persisted grants from registry
    // -----------------------------------------------------------------------
    inline void ClearPersistedGrants()
    {
        std::wstring regKey = GetGrantsRegKey();
        LSTATUS r = RegDeleteKeyW(HKEY_CURRENT_USER, regKey.c_str());
        g_logger.Log((L"REG_CLEAR: " + regKey + (r == ERROR_SUCCESS ? L" -> OK" : L" -> NOT_FOUND")).c_str());
        RegDeleteKeyW(HKEY_CURRENT_USER, kGrantsParentKey);
    }

    // -----------------------------------------------------------------------
    // Collect path+SID pairs granted by OTHER live sandy instances.
    // Returns set of "path|sid" strings for precise skip logic.
    // -----------------------------------------------------------------------
    inline std::set<std::wstring> GetOtherInstancePathSids(const std::wstring& excludeId)
    {
        std::set<std::wstring> pathSids;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return pathSids;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[128];
            DWORD nameLen = 128;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;
            if (excludeId == name) continue;

            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + name;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            DWORD pid = 0; ULONGLONG ctime = 0;
            ReadPidAndCtime(hKey, pid, ctime);
            if (!IsProcessAlive(pid, ctime)) {
                RegCloseKey(hKey);
                continue;
            }

            DWORD valueCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &valueCount, nullptr, nullptr, nullptr, nullptr);
            for (DWORD vi = 0; vi < valueCount; vi++) {
                std::wstring vname, data;
                if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;
                // Format: TYPE|PATH|SID or TYPE|PATH|SID|TRAPPED:...
                auto sep1 = data.find(L'|');
                if (sep1 == std::wstring::npos) continue;
                auto sep2 = data.find(L'|', sep1 + 1);
                if (sep2 == std::wstring::npos) continue;
                std::wstring path = data.substr(sep1 + 1, sep2 - sep1 - 1);
                // SID ends at next pipe (if TRAPPED suffix) or end of string
                std::wstring sidPart = data.substr(sep2 + 1);
                auto sep3 = sidPart.find(L'|');
                std::wstring sid = (sep3 != std::wstring::npos)
                    ? sidPart.substr(0, sep3) : sidPart;
                pathSids.insert(path + L"|" + sid);
            }
            RegCloseKey(hKey);
        }
        RegCloseKey(hParent);
        return pathSids;
    }

    // -----------------------------------------------------------------------
    // Collect deny paths from OTHER live sandy instances.
    // Returns set of paths where another instance has a deny entry
    // (identified by TRAPPED: suffix in the registry value).
    // Used to prevent TreeSet from propagating into children with
    // PROTECTED_DACL set by another instance's deny rules.
    // -----------------------------------------------------------------------
    inline std::set<std::wstring> GetOtherInstanceDenyPaths(const std::wstring& excludeId)
    {
        std::set<std::wstring> denyPaths;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return denyPaths;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[128];
            DWORD nameLen = 128;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;
            if (excludeId == name) continue;

            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + name;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            DWORD pid = 0; ULONGLONG ctime = 0;
            ReadPidAndCtime(hKey, pid, ctime);
            if (!IsProcessAlive(pid, ctime)) {
                RegCloseKey(hKey);
                continue;
            }

            DWORD valueCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &valueCount, nullptr, nullptr, nullptr, nullptr);
            for (DWORD vi = 0; vi < valueCount; vi++) {
                std::wstring vname, data;
                if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;
                // Only care about deny entries (have |TRAPPED: suffix)
                if (data.find(L"|TRAPPED:") == std::wstring::npos) continue;
                // Extract path
                auto sep1 = data.find(L'|');
                if (sep1 == std::wstring::npos) continue;
                auto sep2 = data.find(L'|', sep1 + 1);
                if (sep2 == std::wstring::npos) continue;
                denyPaths.insert(data.substr(sep1 + 1, sep2 - sep1 - 1));
            }
            RegCloseKey(hKey);
        }
        RegCloseKey(hParent);
        return denyPaths;
    }

    // -----------------------------------------------------------------------
    // RevokeAllGrants — remove all ACEs we added, using SID-based removal.
    // Multi-instance safe: only removes ACEs for our SID.
    // For shared SIDs (RT mode), skips paths used by other live instances.
    // Skips TreeSet when another instance has a deny on a child path
    // (to avoid propagating into children with PROTECTED_DACL).
    // Thread-safe, double-cleanup guarded.
    // -----------------------------------------------------------------------
    inline void RevokeAllGrants()
    {
        if (g_cleanedUp.exchange(true)) return;

        AcquireSRWLockExclusive(&g_aclGrantsLock);

        // Collect path+SID pairs from other live instances.
        // Only skip removal when another instance uses the SAME SID on the SAME path
        // (RT shared SID case). AppContainer instances have unique SIDs, so their
        // ACE removal never interferes even on overlapping paths.
        std::set<std::wstring> otherPathSids = GetOtherInstancePathSids(g_instanceId);

        // Collect deny paths from other live instances.
        // If our cleanup path is a parent of a deny path, we must skip TreeSet
        // to avoid propagating into children with PROTECTED_DACL.
        std::set<std::wstring> otherDenyPaths = GetOtherInstanceDenyPaths(g_instanceId);

        // Helper: check if any deny path is a child of the given path
        auto hasChildDeny = [&](const std::wstring& parentPath) -> bool {
            std::wstring prefix = parentPath;
            // Ensure prefix ends with backslash for correct prefix matching
            if (!prefix.empty() && prefix.back() != L'\\') prefix += L'\\';
            for (const auto& dp : otherDenyPaths) {
                if (dp.length() > prefix.length() &&
                    _wcsnicmp(dp.c_str(), prefix.c_str(), prefix.length()) == 0)
                    return true;
            }
            return false;
        };

        // Deduplicate: same path may appear multiple times (grant + deny)
        std::set<std::wstring> processed;
        int removed = 0, skipped = 0;
        for (auto it = g_aclGrants.rbegin(); it != g_aclGrants.rend(); ++it) {
            // Skip if already processed this path
            if (processed.count(it->path)) continue;
            processed.insert(it->path);

            // Skip only when another instance uses the same SID on the same path
            std::wstring pathSidKey = it->path + L"|" + it->sidString;
            if (otherPathSids.count(pathSidKey)) {
                g_logger.Log((L"ACL_SKIP: " + it->path + L" (same SID active in other instance)").c_str());
                skipped++;
                continue;
            }

            // For non-deny directory grants: skip TreeSet if another instance
            // has a deny on a child path (to preserve PROTECTED_DACL)
            bool needSkipTree = false;
            if (!it->wasDenied && it->objType == SE_FILE_OBJECT) {
                DWORD attrs = GetFileAttributesW(it->path.c_str());
                if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                    if (hasChildDeny(it->path)) {
                        needSkipTree = true;
                        g_logger.Log((L"ACL_NOTREE: " + it->path + L" (child has active deny in other instance)").c_str());
                    }
                }
            }

            int n = RemoveSidFromDacl(it->path, it->sidString, it->objType,
                                  it->wasDenied, it->trappedSids, needSkipTree);
            removed += n;
        }
        g_logger.LogFmt(L"REVOKE_SUMMARY: %d ACEs removed, %d paths skipped", removed, skipped);
        g_aclGrants.clear();
        ReleaseSRWLockExclusive(&g_aclGrantsLock);
        ClearPersistedGrants();
    }

    // -----------------------------------------------------------------------
    // RestoreGrantsFromKey — remove ACEs from a single registry subkey.
    // Parses TYPE|PATH|SID format and removes the SID's ACEs.
    // -----------------------------------------------------------------------
    inline void RestoreGrantsFromKey(HKEY hKey,
                                      const std::set<std::wstring>& protectedPaths = {})
    {
        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        std::set<std::wstring> processed;
        for (DWORD vi = 0; vi < valueCount; vi++) {
            std::wstring vname, data;
            if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;

            auto sep1 = data.find(L'|');
            if (sep1 == std::wstring::npos) continue;
            std::wstring typeStr = data.substr(0, sep1);
            std::wstring rest = data.substr(sep1 + 1);

            // Find second pipe (separating path from SID)
            auto sep2 = rest.find(L'|');
            if (sep2 == std::wstring::npos) continue;
            std::wstring path = rest.substr(0, sep2);
            std::wstring sidAndTrapped = rest.substr(sep2 + 1);

            // Check for TRAPPED: suffix (format: SID|TRAPPED:sid1;sid2)
            std::wstring sidString;
            std::wstring trappedSids;
            bool wasDenied = false;
            auto trapSep = sidAndTrapped.find(L"|TRAPPED:");
            if (trapSep != std::wstring::npos) {
                sidString = sidAndTrapped.substr(0, trapSep);
                trappedSids = sidAndTrapped.substr(trapSep + 9); // skip "|TRAPPED:"
                wasDenied = true;
            } else {
                sidString = sidAndTrapped;
            }

            if (processed.count(path)) continue;
            processed.insert(path);

            if (protectedPaths.count(path)) {
                g_logger.Log((L"ACL_SKIP_STALE: " + path + L" (live instance active)").c_str());
                continue;
            }

            SE_OBJECT_TYPE objType = (typeStr == L"REG") ? SE_REGISTRY_KEY : SE_FILE_OBJECT;
            RemoveSidFromDacl(path, sidString, objType, wasDenied, trappedSids);
        }
    }

    // -----------------------------------------------------------------------
    // RestoreStaleGrants — cleanup after crash/power loss.
    // Processes dead PIDs only. Also deletes stale AppContainer profiles.
    // -----------------------------------------------------------------------
    inline void RestoreStaleGrants()
    {
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return;

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

        // Read _container from a subkey
        auto readContainer = [](HKEY hKey) -> std::wstring {
            DWORD size = 0;
            if (RegQueryValueExW(hKey, L"_container", nullptr, nullptr, nullptr, &size) != ERROR_SUCCESS)
                return {};
            std::wstring val(size / sizeof(wchar_t), L'\0');
            RegQueryValueExW(hKey, L"_container", nullptr, nullptr,
                             reinterpret_cast<BYTE*>(&val[0]), &size);
            while (!val.empty() && val.back() == L'\0') val.pop_back();
            return val;
        };

        // Collect paths from a subkey
        auto collectPaths = [](HKEY hKey, std::set<std::wstring>& outPaths) {
            DWORD valueCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &valueCount, nullptr, nullptr, nullptr, nullptr);
            for (DWORD vi = 0; vi < valueCount; vi++) {
                std::wstring vname, data;
                if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;
                // Format: TYPE|PATH|SID or TYPE|PATH|SID|TRAPPED:...
                auto sep1 = data.find(L'|');
                if (sep1 == std::wstring::npos) continue;
                auto sep2 = data.find(L'|', sep1 + 1);
                if (sep2 == std::wstring::npos) continue;
                outPaths.insert(data.substr(sep1 + 1, sep2 - sep1 - 1));
            }
        };

        // Separate live vs stale
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

        // Remove stale ACEs and delete registry subkeys
        for (const auto& subKey : staleKeys) {
            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + subKey;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) == ERROR_SUCCESS) {
                std::wstring containerName = readContainer(hKey);
                if (!containerName.empty()) {
                    HRESULT hr = DeleteAppContainerProfile(containerName.c_str());
                    g_logger.Log((L"PROFILE_DELETE: " + containerName +
                        (SUCCEEDED(hr) ? L" -> OK" : L" -> FAILED")).c_str());
                }
                RestoreGrantsFromKey(hKey, livePaths);
                RegCloseKey(hKey);
            }
            LSTATUS delResult = RegDeleteTreeW(HKEY_CURRENT_USER, fullKey.c_str());
            if (delResult != ERROR_SUCCESS) {
                g_logger.LogFmt(L"REG_DELETE_FAIL: %ls -> error %lu", fullKey.c_str(), delResult);
                delResult = RegDeleteKeyW(HKEY_CURRENT_USER, fullKey.c_str());
                if (delResult != ERROR_SUCCESS)
                    g_logger.LogFmt(L"REG_DELETE_FALLBACK_FAIL: %ls -> error %lu", fullKey.c_str(), delResult);
            }
            g_logger.Log((L"REG_DELETE: " + fullKey).c_str());
        }

        RegDeleteKeyW(HKEY_CURRENT_USER, kGrantsParentKey);
    }

} // namespace Sandbox
