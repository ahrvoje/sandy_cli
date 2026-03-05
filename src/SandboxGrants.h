// =========================================================================
// SandboxGrants.h — Grant tracking, persistence, and revocation
//
// Tracks all ACL modifications made during a sandbox session, persists
// them to the registry for crash recovery, and restores original DACLs
// on exit.  Multi-instance safe: skips paths used by other live instances.
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
        std::wstring       originalSDDL;
        BYTE               objectId[16] = {};  // NTFS Object ID for rename-resilient cleanup
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
    // Stamp NTFS Object ID on a file/directory for rename-resilient cleanup.
    // Returns the 16-byte Object ID (or all zeros on failure).
    // -----------------------------------------------------------------------
    inline void StampObjectId(const std::wstring& path, BYTE outId[16])
    {
        memset(outId, 0, 16);
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return;
        FILE_OBJECTID_BUFFER ob = {};
        DWORD b = 0;
        if (DeviceIoControl(hFile, FSCTL_CREATE_OR_GET_OBJECT_ID,
                nullptr, 0, &ob, sizeof(ob), &b, nullptr))
            memcpy(outId, ob.ObjectId, 16);
        CloseHandle(hFile);
    }

    // -----------------------------------------------------------------------
    // Save a grant to the in-memory list AND the registry (write-ahead).
    // Called by GrantObjectAccess and DenyObjectAccess before modifying DACLs.
    // -----------------------------------------------------------------------
    inline void RecordGrant(const std::wstring& path, SE_OBJECT_TYPE objType,
                            PSECURITY_DESCRIPTOR pSD)
    {
        LPWSTR origSddl = nullptr;
        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &origSddl, nullptr))
            return;

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

            // Format: TYPE|PATH|SDDL
            std::wstring typeStr = (objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
            std::wstring data = typeStr + L"|" + path + L"|" + origSddl;

            wchar_t valueName[32];
            swprintf(valueName, 32, L"%lu", nextIdx);
            RegSetValueExW(hKey, valueName, 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(data.c_str()),
                           static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t)));

            // Stamp NTFS Object ID for rename-resilient cleanup
            if (objType == SE_FILE_OBJECT) {
                BYTE oid[16] = {};
                StampObjectId(path, oid);
                bool hasOid = false;
                for (int i = 0; i < 16; i++) if (oid[i]) { hasOid = true; break; }
                if (hasOid) {
                    wchar_t oidName[32];
                    swprintf(oidName, 32, L"_oid_%lu", nextIdx);
                    RegSetValueExW(hKey, oidName, 0, REG_BINARY, oid, 16);
                    g_logger.Log((L"OID_STAMP: " + path).c_str());
                }
            }

            // Increment counter
            nextIdx++;
            RegSetValueExW(hKey, L"_nextIdx", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&nextIdx), sizeof(nextIdx));

            g_logger.Log((L"REG_PERSIST: [" + std::to_wstring(nextIdx - 1) + L"] " + data).c_str());
            RegCloseKey(hKey);
        }

        // --- Save to in-memory list ---
        ACLGrant grant = { path, objType, origSddl };
        if (objType == SE_FILE_OBJECT)
            StampObjectId(path, grant.objectId);
        g_aclGrants.push_back(std::move(grant));

        ReleaseSRWLockExclusive(&g_aclGrantsLock);
        LocalFree(origSddl);
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
    // Resolve a path via NTFS Object ID if original path is gone
    // -----------------------------------------------------------------------
    inline std::wstring ResolveByObjectId(const std::wstring& originalPath,
                                          const BYTE objectId[16])
    {
        bool hasOid = false;
        for (int i = 0; i < 16; i++) { if (objectId[i]) { hasOid = true; break; } }
        if (!hasOid) return {};

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

        std::wstring result = newPath;
        if (result.substr(0, 4) == L"\\\\?\\")
            result = result.substr(4);

        g_logger.Log((L"OID_RESOLVE: " + originalPath + L" -> " + result).c_str());
        return result;
    }

    // -----------------------------------------------------------------------
    // Collect paths granted by OTHER live sandy instances
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
                auto sep1 = data.find(L'|');
                auto sep2 = data.rfind(L'|');
                if (sep1 != std::wstring::npos && sep2 != std::wstring::npos && sep2 > sep1)
                    paths.insert(data.substr(sep1 + 1, sep2 - sep1 - 1));
            }
            RegCloseKey(hKey);
        }
        RegCloseKey(hParent);
        return paths;
    }

    // -----------------------------------------------------------------------
    // RevokeAllGrants — restore all DACLs to pre-grant state.
    // Thread-safe, multi-instance safe, double-cleanup guarded.
    // -----------------------------------------------------------------------
    inline void RevokeAllGrants()
    {
        if (g_cleanedUp.exchange(true)) return;

        AcquireSRWLockExclusive(&g_aclGrantsLock);

        std::set<std::wstring> otherPaths = GetOtherInstancePaths(g_instanceId);

        // Collect all grant paths for ancestor-skip logic
        std::set<std::wstring> allGrantPaths;
        for (const auto& grant : g_aclGrants)
            allGrantPaths.insert(grant.path);

        // Restore in reverse order
        for (auto it = g_aclGrants.rbegin(); it != g_aclGrants.rend(); ++it) {
            if (otherPaths.count(it->path)) {
                g_logger.Log((L"ACL_SKIP: " + it->path + L" (other instance active)").c_str());
                continue;
            }

            // Skip renamed children covered by a parent TreeSet
            if (it->objType == SE_FILE_OBJECT &&
                GetFileAttributesW(it->path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                bool hasParentGrant = false;
                for (const auto& grantPath : allGrantPaths) {
                    if (grantPath == it->path) continue;
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
    // RestoreGrantsFromKey — restore grants from a single registry subkey
    // -----------------------------------------------------------------------
    inline void RestoreGrantsFromKey(HKEY hKey,
                                      const std::set<std::wstring>& protectedPaths = {})
    {
        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        for (DWORD vi = 0; vi < valueCount; vi++) {
            std::wstring vname, data;
            if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;

            auto sep1 = data.find(L'|');
            if (sep1 == std::wstring::npos) continue;
            auto sep2 = data.rfind(L'|');
            if (sep2 == std::wstring::npos || sep2 <= sep1) continue;

            std::wstring typeStr = data.substr(0, sep1);
            std::wstring path = data.substr(sep1 + 1, sep2 - sep1 - 1);
            std::wstring sddl = data.substr(sep2 + 1);

            if (protectedPaths.count(path)) {
                g_logger.Log((L"ACL_SKIP_STALE: " + path + L" (live instance active)").c_str());
                continue;
            }

            BYTE oid[16] = {};
            std::wstring oidName = L"_oid_" + vname;
            DWORD oidSize = 16;
            RegQueryValueExW(hKey, oidName.c_str(), nullptr, nullptr, oid, &oidSize);

            SE_OBJECT_TYPE objType = (typeStr == L"REG") ? SE_REGISTRY_KEY : SE_FILE_OBJECT;
            RestoreDacl(path, sddl, objType, oid);
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
                auto sep1 = data.find(L'|');
                auto sep2 = data.rfind(L'|');
                if (sep1 != std::wstring::npos && sep2 != std::wstring::npos && sep2 > sep1)
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

        // Restore and delete stale (dead PID) subkeys only
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
                wchar_t msg[256];
                swprintf(msg, 256, L"REG_DELETE_FAIL: %ls -> error %lu", fullKey.c_str(), delResult);
                g_logger.Log(msg);
                delResult = RegDeleteKeyW(HKEY_CURRENT_USER, fullKey.c_str());
                if (delResult != ERROR_SUCCESS) {
                    swprintf(msg, 256, L"REG_DELETE_FALLBACK_FAIL: %ls -> error %lu", fullKey.c_str(), delResult);
                    g_logger.Log(msg);
                }
            }
            g_logger.Log((L"REG_DELETE: " + fullKey).c_str());
        }

        RegDeleteKeyW(HKEY_CURRENT_USER, kGrantsParentKey);
    }

} // namespace Sandbox
