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
#include "SandboxRegistry.h"
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
        bool               wasPeek = false;     // peek = non-recursive, skip tree-set on cleanup
    };

    // -----------------------------------------------------------------------
    // Global state — guarded by SRW lock
    // -----------------------------------------------------------------------
    inline std::vector<ACLGrant> g_aclGrants;
    inline SRWLOCK               g_aclGrantsLock = SRWLOCK_INIT;
    inline std::atomic<bool>     g_cleanedUp{false};

    // When false, RecordGrant skips registry writes (in-memory only).
    // Used during --create-profile where grants are persisted to
    // Sandy\Profiles\<name> instead of Sandy\Grants\<instanceId>.
    inline bool                  g_grantPersistence = true;

    // Staging profile key — when non-null, RecordGrant also writes each
    // grant record to this HKEY incrementally (for crash-safe profile creation).
    inline HKEY                  g_stagingProfileKey = nullptr;
    inline DWORD                 g_stagingGrantIdx = 0;
    // Tracks whether grant metadata persistence is still healthy for the
    // current operation. If this flips false, callers should fail closed:
    // ACLs without durable cleanup inventory are not safe to keep.
    inline std::atomic<bool>     g_grantTrackingHealthy{ true };

    // Per-instance UUID — set once at startup
    inline std::wstring g_instanceId;

    // Registry keys for grant persistence
    static const wchar_t* kGrantsParentKey = L"Software\\Sandy\\Grants";

    inline std::wstring GetGrantsRegKey() {
        return std::wstring(kGrantsParentKey) + L"\\" + g_instanceId;
    }

    inline void ResetGrantTrackingHealth()
    {
        g_grantTrackingHealthy.store(true);
    }

    inline void MarkGrantTrackingFailure(const wchar_t* stage,
                                         const std::wstring& detail = L"")
    {
        g_grantTrackingHealthy.store(false);
        if (!detail.empty())
            g_logger.LogFmt(L"GRANT_TRACKING: %ls FAILED (%ls)", stage, detail.c_str());
        else
            g_logger.LogFmt(L"GRANT_TRACKING: %ls FAILED", stage);
    }

    inline bool GrantTrackingHealthy()
    {
        return g_grantTrackingHealthy.load();
    }

    inline void BeginStagingGrantCapture(HKEY hKey)
    {
        ResetGrantTrackingHealth();
        g_grantPersistence = false;
        g_stagingProfileKey = hKey;
        g_stagingGrantIdx = 0;
    }

    inline DWORD EndStagingGrantCapture()
    {
        DWORD captured = g_stagingGrantIdx;
        g_stagingProfileKey = nullptr;
        g_stagingGrantIdx = 0;
        g_grantPersistence = true;
        return captured;
    }

    inline void AbortStagingGrantCapture()
    {
        g_stagingProfileKey = nullptr;
        g_stagingGrantIdx = 0;
        g_grantPersistence = true;
    }

    // -----------------------------------------------------------------------
    // Parsed grant record — output of ParseGrantRecord.
    // -----------------------------------------------------------------------
    struct GrantRecord {
        std::wstring type;          // "FILE" or "REG"
        std::wstring path;
        std::wstring sidString;
        std::wstring trappedSids;   // semicolon-separated trapped AC SIDs
        bool         wasDenied = false;
        bool         wasPeek = false;
        bool         wasDeferred = false;  // F2/R11: cleanup deferred due to live child deny
    };

    // -----------------------------------------------------------------------
    // ValidateSidPrefix — lightweight SID structure check.
    //
    // A valid SID string has the form S-<revision>-<authority>-...
    // We require at least S-<digit>-<digit> (e.g. "S-1-5").
    // -----------------------------------------------------------------------
    inline bool ValidateSidPrefix(const std::wstring& s)
    {
        // Minimum: "S-1-5" (5 chars)
        if (s.size() < 5) return false;
        if (s[0] != L'S' || s[1] != L'-') return false;
        // Revision must start with a digit
        if (!iswdigit(s[2])) return false;
        // Find dash after revision
        auto dash2 = s.find(L'-', 2);
        if (dash2 == std::wstring::npos || dash2 + 1 >= s.size()) return false;
        // Authority must start with a digit
        if (!iswdigit(s[dash2 + 1])) return false;
        return true;
    }

    // -----------------------------------------------------------------------
    // ParseGrantRecord — strict parser for persisted grant records.
    //
    // Expected format: TYPE|PATH|SID[|DENY:1][|TRAPPED:sid1;sid2]
    //   TYPE:  "FILE" or "REG"
    //   PATH:  non-empty, must be absolute (drive letter, UNC, or HKEY)
    //   SID:   must match S-<revision>-<authority>-... structure
    //   Flags: only DENY:1, PEEK:1, and TRAPPED:<sids> are recognized;
    //          any unknown |KEY:... suffix rejects the record.
    //
    // On failure, sets `reason` with a diagnostic string for logging.
    // Returns false on malformed input; caller should skip + log.
    // -----------------------------------------------------------------------
    inline bool ParseGrantRecord(const std::wstring& data, GrantRecord& out,
                                 const wchar_t** reason = nullptr)
    {
        auto reject = [&](const wchar_t* msg) -> bool {
            if (reason) *reason = msg;
            return false;
        };

        // --- Field 1: TYPE ---
        auto sep1 = data.find(L'|');
        if (sep1 == std::wstring::npos) return reject(L"missing TYPE|PATH separator");
        out.type = data.substr(0, sep1);
        if (out.type != L"FILE" && out.type != L"REG")
            return reject(L"TYPE is not FILE or REG");

        // --- Field 2: PATH ---
        auto sep2 = data.find(L'|', sep1 + 1);
        if (sep2 == std::wstring::npos) return reject(L"missing PATH|SID separator");
        out.path = data.substr(sep1 + 1, sep2 - sep1 - 1);
        if (out.path.empty()) return reject(L"empty PATH");
        // Reject paths containing pipe (would indicate corrupt record)
        if (out.path.find(L'|') != std::wstring::npos)
            return reject(L"PATH contains pipe character");
        // Require absolute path (drive letter, UNC, or HKEY for registry)
        bool isAbsolute = (out.path.size() >= 2 && iswalpha(out.path[0]) && out.path[1] == L':') ||
                          (out.path.size() >= 2 && out.path[0] == L'\\' && out.path[1] == L'\\') ||
                          (out.path.compare(0, 4, L"HKEY") == 0) ||
                          (out.path.compare(0, 13, L"CURRENT_USER\\") == 0) ||
                          (out.path.compare(0, 8, L"MACHINE\\") == 0);
        if (!isAbsolute)
            return reject(L"PATH is not absolute");

        // --- Field 3+: SID and optional flags ---
        std::wstring remaining = data.substr(sep2 + 1);
        auto pipePos = remaining.find(L'|');
        out.sidString = (pipePos != std::wstring::npos)
                        ? remaining.substr(0, pipePos) : remaining;

        // Validate SID: must match S-<revision>-<authority>-... structure
        if (!ValidateSidPrefix(out.sidString))
            return reject(L"SID does not match S-<rev>-<auth> format");

        // Parse optional |KEY:VALUE suffixes
        out.wasDenied = false;
        out.wasPeek = false;
        out.trappedSids.clear();
        if (pipePos != std::wstring::npos) {
            remaining = remaining.substr(pipePos);
            while (!remaining.empty() && remaining[0] == L'|') {
                remaining = remaining.substr(1);
                if (remaining.compare(0, 6, L"DENY:1") == 0) {
                    out.wasDenied = true;
                    remaining = remaining.substr(6);
                } else if (remaining.compare(0, 6, L"PEEK:1") == 0) {
                    out.wasPeek = true;
                    remaining = remaining.substr(6);
                } else if (remaining.compare(0, 10, L"DEFERRED:1") == 0) {
                    out.wasDeferred = true;
                    remaining = remaining.substr(10);
                } else if (remaining.compare(0, 8, L"TRAPPED:") == 0) {
                    remaining = remaining.substr(8);
                    auto nextPipe = remaining.find(L'|');
                    out.trappedSids = (nextPipe != std::wstring::npos)
                                     ? remaining.substr(0, nextPipe) : remaining;
                    remaining = (nextPipe != std::wstring::npos)
                                ? remaining.substr(nextPipe) : L"";
                    // Validate each trapped SID substring
                    if (!out.trappedSids.empty()) {
                        std::wstring buf = out.trappedSids;
                        size_t pos = 0;
                        while (pos < buf.size()) {
                            auto semi = buf.find(L';', pos);
                            std::wstring one = (semi != std::wstring::npos)
                                ? buf.substr(pos, semi - pos) : buf.substr(pos);
                            if (!one.empty() && !ValidateSidPrefix(one))
                                return reject(L"TRAPPED SID has invalid format");
                            pos = (semi != std::wstring::npos) ? semi + 1 : buf.size();
                        }
                    }
                    out.wasDenied = true; // backward compat: trapped always means deny
                } else {
                    return reject(L"unknown flag suffix");
                }
            }
            // Reject trailing garbage after all known flags
            if (!remaining.empty())
                return reject(L"trailing garbage after flags");
        }
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
    // Save a grant to the in-memory list, and optionally to the registry.
    //
    // Registry persistence is controlled by g_grantPersistence:
    //   true  (default) — writes to Sandy\Grants\<instanceId> for crash recovery
    //   false           — in-memory only (used during --create-profile, where
    //                     grants are persisted to Sandy\Profiles\<name> instead)
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // HardenRegistryKeyAgainstRestricted — deny Restricted SID (S-1-5-12)
    // write access on a registry key to prevent sandboxed-child tampering.
    //
    // F5/R11: extracted from RecordGrant so it can be shared with
    // PersistLiveState — both paths create coordination metadata that
    // must be protected uniformly.
    // -----------------------------------------------------------------------
    inline void HardenRegistryKeyAgainstRestricted(HKEY hKey)
    {
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

    inline void RecordGrant(const std::wstring& path, SE_OBJECT_TYPE objType,
                            const std::wstring& sidString,
                            const std::wstring& trappedSids = L"",
                            bool isDeny = false,
                            bool isPeek = false)
    {
        AcquireSRWLockExclusive(&g_aclGrantsLock);

        // --- Persist to registry (live instance crash recovery) ---
        if (g_grantPersistence) {
            std::wstring regKey = GetGrantsRegKey();
            HKEY hKey = nullptr;
            DWORD disposition = 0;
            if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr,
                    0, KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC,
                    nullptr, &hKey, &disposition) == ERROR_SUCCESS) {

                // On first creation, store identity and protect the key
                if (disposition == REG_CREATED_NEW_KEY) {
                    DWORD pid = GetCurrentProcessId();
                    if (RegSetValueExW(hKey, L"_pid", 0, REG_DWORD,
                                       reinterpret_cast<const BYTE*>(&pid), sizeof(DWORD)) != ERROR_SUCCESS)
                        MarkGrantTrackingFailure(L"persist _pid", regKey);

                    ULONGLONG ct = GetCurrentProcessCreationTime();
                    if (RegSetValueExW(hKey, L"_ctime", 0, REG_QWORD,
                                       reinterpret_cast<const BYTE*>(&ct), sizeof(ULONGLONG)) != ERROR_SUCCESS)
                        MarkGrantTrackingFailure(L"persist _ctime", regKey);

                    std::wstring containerName = ContainerNameFromId(g_instanceId);
                    if (RegSetValueExW(hKey, L"_container", 0, REG_SZ,
                                       reinterpret_cast<const BYTE*>(containerName.c_str()),
                                       static_cast<DWORD>((containerName.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS)
                        MarkGrantTrackingFailure(L"persist _container", regKey);

                    // F5/R11: Deny Restricted SID write access (shared helper)
                    HardenRegistryKeyAgainstRestricted(hKey);
                }

                // Get next index
                DWORD nextIdx = 0;
                DWORD idxSize = sizeof(nextIdx);
                RegQueryValueExW(hKey, L"_nextIdx", nullptr, nullptr,
                                 reinterpret_cast<BYTE*>(&nextIdx), &idxSize);

                // Format: TYPE|PATH|SID  or  TYPE|PATH|SID|DENY:1|TRAPPED:sid1;sid2
                std::wstring typeStr = (objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
                std::wstring data = typeStr + L"|" + path + L"|" + sidString;
                // Persist deny flag explicitly
                if (isDeny) {
                    data += L"|DENY:1";
                }
                if (!trappedSids.empty()) {
                    data += L"|TRAPPED:" + trappedSids;
                }
                if (isPeek) {
                    data += L"|PEEK:1";
                }

                wchar_t valueName[32];
                swprintf(valueName, 32, L"%lu", nextIdx);
                if (RegSetValueExW(hKey, valueName, 0, REG_SZ,
                                   reinterpret_cast<const BYTE*>(data.c_str()),
                                   static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS)
                    MarkGrantTrackingFailure(L"persist grant record", regKey);

                // Increment counter
                nextIdx++;
                if (RegSetValueExW(hKey, L"_nextIdx", 0, REG_DWORD,
                                   reinterpret_cast<const BYTE*>(&nextIdx), sizeof(nextIdx)) != ERROR_SUCCESS)
                    MarkGrantTrackingFailure(L"persist _nextIdx", regKey);

                g_logger.Log((L"REG_PERSIST: [" + std::to_wstring(nextIdx - 1) + L"] " + data).c_str());
                RegCloseKey(hKey);
            } else {
                MarkGrantTrackingFailure(L"open grants key", regKey);
            }
        }

        // --- Save to in-memory list ---
        ACLGrant grant = { path, objType, sidString, trappedSids, isDeny, isPeek };
        g_aclGrants.push_back(std::move(grant));

        // --- Incremental staging profile write (crash-safe profile creation) ---
        if (g_stagingProfileKey) {
            std::wstring typeStr = (objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
            std::wstring data = typeStr + L"|" + path + L"|" + sidString;
            if (isDeny) data += L"|DENY:1";
            if (!trappedSids.empty()) data += L"|TRAPPED:" + trappedSids;
            if (isPeek) data += L"|PEEK:1";

            wchar_t valName[32];
            swprintf(valName, 32, L"%lu", g_stagingGrantIdx);
            if (RegSetValueExW(g_stagingProfileKey, valName, 0, REG_SZ,
                               reinterpret_cast<const BYTE*>(data.c_str()),
                               static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS)
                MarkGrantTrackingFailure(L"persist staging grant");
            g_stagingGrantIdx++;
        }

        ReleaseSRWLockExclusive(&g_aclGrantsLock);
    }

    // -----------------------------------------------------------------------
    // Clear this instance's persisted grants from registry.
    // Only deletes the instance subkey — parent keys (Sandy, Grants) are
    // permanent and never deleted.
    // -----------------------------------------------------------------------
    inline void ClearPersistedGrants()
    {
        std::wstring regKey = GetGrantsRegKey();
        LSTATUS r = RegDeleteTreeW(HKEY_CURRENT_USER, regKey.c_str());
        g_logger.Log((L"REG_CLEAR: " + regKey + (r == ERROR_SUCCESS ? L" -> OK" : L" -> NOT_FOUND")).c_str());
    }

    // -----------------------------------------------------------------------
    // PersistLiveState — create a lightweight live-state record for this
    // instance under Grants\<instanceId>.
    //
    // Used by profile-mode runs (which skip grant persistence) to register
    // PID/ctime/container metadata so GetLiveContainerNames() can detect
    // them. No grant values are written — just the identity fields.
    // -----------------------------------------------------------------------
    inline bool PersistLiveState(const std::wstring& containerName,
                                 const std::wstring& profileName = L"")
    {
        std::wstring regKey = GetGrantsRegKey();
        HKEY hKey = nullptr;
        DWORD disposition = 0;
        // F5/R11: Request WRITE_DAC so we can harden the key against tampering
        if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr,
                0, KEY_SET_VALUE | WRITE_DAC, nullptr, &hKey, &disposition) != ERROR_SUCCESS)
            return false;

        DWORD pid = GetCurrentProcessId();
        bool ok = true;
        if (RegSetValueExW(hKey, L"_pid", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&pid), sizeof(DWORD)) != ERROR_SUCCESS)
            ok = false;

        ULONGLONG ct = GetCurrentProcessCreationTime();
        if (RegSetValueExW(hKey, L"_ctime", 0, REG_QWORD,
                           reinterpret_cast<const BYTE*>(&ct), sizeof(ULONGLONG)) != ERROR_SUCCESS)
            ok = false;

        if (!containerName.empty())
            if (RegSetValueExW(hKey, L"_container", 0, REG_SZ,
                               reinterpret_cast<const BYTE*>(containerName.c_str()),
                               static_cast<DWORD>((containerName.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS)
                ok = false;

        // F2/R8: Persist profile name for type-agnostic liveness detection
        if (!profileName.empty())
            if (RegSetValueExW(hKey, L"_profile_name", 0, REG_SZ,
                               reinterpret_cast<const BYTE*>(profileName.c_str()),
                               static_cast<DWORD>((profileName.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS)
                ok = false;

        // Mark as profile-mode (no grants to restore)
        DWORD profileFlag = 1;
        if (RegSetValueExW(hKey, L"_profile_mode", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&profileFlag), sizeof(DWORD)) != ERROR_SUCCESS)
            ok = false;

        // F5/R11: Harden live-state key against restricted-token tampering
        // (same protection applied to normal live grant keys in RecordGrant)
        HardenRegistryKeyAgainstRestricted(hKey);

        RegCloseKey(hKey);
        if (ok)
            g_logger.LogFmt(L"LIVE_STATE: persisted for %ls (PID %lu)", containerName.c_str(), pid);
        else
            g_logger.LogFmt(L"LIVE_STATE: persistence FAILED for %ls (PID %lu)", containerName.c_str(), pid);
        return ok;
    }

    // -----------------------------------------------------------------------
    // ClearLiveState — delete the lightweight live-state record.
    // Same as ClearPersistedGrants() but semantically for profile-mode runs.
    // -----------------------------------------------------------------------
    inline void ClearLiveState()
    {
        ClearPersistedGrants();
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
                GrantRecord rec;
                if (!ParseGrantRecord(data, rec)) continue;
                pathSids.insert(rec.path + L"|" + rec.sidString);
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
                GrantRecord rec;
                if (!ParseGrantRecord(data, rec)) continue;
                if (!rec.wasDenied) continue;
                denyPaths.insert(rec.path);
            }
            RegCloseKey(hKey);
        }
        RegCloseKey(hParent);
        return denyPaths;
    }

    // -----------------------------------------------------------------------
    // GetLiveContainerNames — enumerate container monikers from live instances.
    //
    // Reads _container, _pid, _ctime from each Grants\<uuid> subkey.
    // Returns the set of container names whose owning Sandy instance is
    // still alive. Used by --cleanup and startup cleanup to avoid
    // tearing down live AppContainer profiles/loopback exemptions.
    // -----------------------------------------------------------------------
    inline std::set<std::wstring> GetLiveContainerNames()
    {
        std::set<std::wstring> live;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return live;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[128];
            DWORD nameLen = 128;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;

            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + name;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            DWORD pid = 0; ULONGLONG ctime = 0;
            ReadPidAndCtime(hKey, pid, ctime);
            if (IsProcessAlive(pid, ctime)) {
                std::wstring container = ReadRegSz(hKey, L"_container");
                if (!container.empty())
                    live.insert(container);
            }
            RegCloseKey(hKey);
        }
        RegCloseKey(hParent);
        return live;
    }

    // -----------------------------------------------------------------------
    // GetLiveProfileNames — enumerate profile names from live instances.
    //
    // F2/R8: Reads _profile_name, _pid, _ctime from each Grants\<uuid> subkey.
    // Returns profile names whose owning Sandy instance is still alive.
    // Type-agnostic: covers both AppContainer and restricted-token profiles.
    // -----------------------------------------------------------------------
    inline std::set<std::wstring> GetLiveProfileNames()
    {
        std::set<std::wstring> live;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return live;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[128];
            DWORD nameLen = 128;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;

            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + name;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            DWORD pid = 0; ULONGLONG ctime = 0;
            ReadPidAndCtime(hKey, pid, ctime);
            if (IsProcessAlive(pid, ctime)) {
                std::wstring profName = ReadRegSz(hKey, L"_profile_name");
                if (!profName.empty())
                    live.insert(profName);
            }
            RegCloseKey(hKey);
        }
        RegCloseKey(hParent);
        return live;
    }

    // -----------------------------------------------------------------------
    // GetSavedProfileContainerNames — enumerate container names from saved
    // profiles (Software\Sandy\Profiles\*).
    //
    // These are permanent containers created by --create-profile and must
    // NEVER be deleted by --cleanup or startup cleanup.  Independent of
    // SandboxSavedProfile.h to avoid circular includes.
    // -----------------------------------------------------------------------
    inline std::set<std::wstring> GetSavedProfileContainerNames()
    {
        std::set<std::wstring> names;
        static const wchar_t* profilesKey = L"Software\\Sandy\\Profiles";
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, profilesKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return names;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[256];
            DWORD nameLen = 256;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;

            std::wstring fullKey = std::wstring(profilesKey) + L"\\" + name;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            std::wstring container = ReadRegSz(hKey, L"_container");
            if (!container.empty())
                names.insert(container);
            RegCloseKey(hKey);
        }
        RegCloseKey(hParent);
        return names;
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

        // Deduplicate: same path may appear for allow + deny — use composite key
        std::set<std::wstring> processed;
        int removed = 0, skipped = 0, deferred = 0;
        for (auto it = g_aclGrants.rbegin(); it != g_aclGrants.rend(); ++it) {
            // Composite key: path + deny/allow type — allows both records to be processed
            std::wstring dedupKey = it->path + L"|" + (it->wasDenied ? L"D" : L"A");
            if (processed.count(dedupKey)) continue;
            processed.insert(dedupKey);

            // Skip only when another instance uses the same SID on the same path
            std::wstring pathSidKey = it->path + L"|" + it->sidString;
            if (otherPathSids.count(pathSidKey)) {
                g_logger.Log((L"ACL_SKIP: " + it->path + L" (same SID active in other instance)").c_str());
                skipped++;
                continue;
            }

            // For non-deny directory grants: skip TreeSet if another instance
            // has a deny on a child path (to preserve PROTECTED_DACL)
            // Peek grants are non-recursive (no inheritance) — always skip tree-set
            bool needSkipTree = it->wasPeek;
            if (!it->wasDenied && !needSkipTree && it->objType == SE_FILE_OBJECT) {
                DWORD attrs = GetFileAttributesW(it->path.c_str());
                if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                    if (hasChildDeny(it->path)) {
                        needSkipTree = true;
                        deferred++;
                        g_logger.Log((L"ACL_NOTREE: " + it->path + L" (child has active deny in other instance, deferring to stale recovery)").c_str());
                    }
                }
            }

            int n = RemoveSidFromDacl(it->path, it->sidString, it->objType,
                                  it->wasDenied, it->trappedSids, needSkipTree);
            removed += n;
        }
        g_logger.LogFmt(L"REVOKE_SUMMARY: %d ACEs removed, %d paths skipped, %d deferred", removed, skipped, deferred);
        g_aclGrants.clear();
        ReleaseSRWLockExclusive(&g_aclGrantsLock);

        // If any grants were deferred (tree-skip), keep registry state so
        // RestoreStaleGrants can finish the job when conflicting denies are gone.
        if (deferred == 0) {
            ClearPersistedGrants();
        } else {
            // F2/R11: Persist DEFERRED:1 marker on records that were deferred
            // so the retry path knows to re-check the overlap condition.
            std::wstring regKey = GetGrantsRegKey();
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0,
                              KEY_READ | KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                DWORD valueCount = 0;
                RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                 &valueCount, nullptr, nullptr, nullptr, nullptr);
                for (DWORD vi = 0; vi < valueCount; vi++) {
                    std::wstring vname, data;
                    if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;
                    // Skip metadata values
                    if (!vname.empty() && vname[0] == L'_') continue;
                    // If the record doesn't already have DEFERRED:1, append it
                    if (data.find(L"|DEFERRED:1") == std::wstring::npos) {
                        data += L"|DEFERRED:1";
                        RegSetValueExW(hKey, vname.c_str(), 0, REG_SZ,
                                       reinterpret_cast<const BYTE*>(data.c_str()),
                                       static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t)));
                    }
                }
                RegCloseKey(hKey);
            }
            g_logger.LogFmt(L"REVOKE_DEFER: %d path(s) kept in registry with DEFERRED marker for stale recovery", deferred);
        }
    }

    // -----------------------------------------------------------------------
    // RestoreGrantsFromKey — remove ACEs from a single registry subkey.
    // Parses TYPE|PATH|SID format and removes the SID's ACEs.
    //
    // F3/R8: Returns false if any recorded ACL removal failed on a path
    // that still exists, indicating metadata should be preserved for retry.
    // -----------------------------------------------------------------------
    inline bool RestoreGrantsFromKey(HKEY hKey,
                                      const std::set<std::wstring>& protectedPathSids = {})
    {
        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        bool allOk = true;
        std::set<std::wstring> processed;
        for (DWORD vi = 0; vi < valueCount; vi++) {
            std::wstring vname, data;
            if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;

            GrantRecord rec;
            const wchar_t* parseReason = nullptr;
            if (!ParseGrantRecord(data, rec, &parseReason)) {
                g_logger.LogFmt(L"GRANT_PARSE: malformed record (%ls), skipping: %ls",
                                parseReason ? parseReason : L"unknown", data.c_str());
                continue;
            }

            // Composite dedup key: path + deny/allow type
            std::wstring dedupKey = rec.path + L"|" + (rec.wasDenied ? L"D" : L"A");
            if (processed.count(dedupKey)) continue;
            processed.insert(dedupKey);

            // Skip when a live instance still uses the same SID on the same path
            std::wstring pathSidKey = rec.path + L"|" + rec.sidString;
            if (protectedPathSids.count(pathSidKey)) {
                g_logger.Log((L"ACL_SKIP_STALE: " + rec.path + L" (live instance with same SID active)").c_str());
                continue;
            }

            SE_OBJECT_TYPE objType = (rec.type == L"REG") ? SE_REGISTRY_KEY : SE_FILE_OBJECT;

            // F2/R11: For deferred records, re-check the child-deny overlap
            // condition before allowing recursive tree cleanup.  If the
            // condition that caused deferral is still present, skip tree-set
            // and preserve metadata for next retry.
            bool skipTreeSet = rec.wasPeek;
            if (rec.wasDeferred && !skipTreeSet && objType == SE_FILE_OBJECT) {
                auto otherDenies = GetOtherInstanceDenyPaths(g_instanceId);
                std::wstring prefix = rec.path;
                if (!prefix.empty() && prefix.back() != L'\\') prefix += L'\\';
                for (const auto& dp : otherDenies) {
                    if (dp.length() > prefix.length() &&
                        _wcsnicmp(dp.c_str(), prefix.c_str(), prefix.length()) == 0) {
                        skipTreeSet = true;
                        g_logger.LogFmt(L"DEFERRED_RECHECK: %ls still has live child deny, keeping deferred",
                                        rec.path.c_str());
                        allOk = false;  // preserve metadata for next retry
                        break;
                    }
                }
            }

            int n = RemoveSidFromDacl(rec.path, rec.sidString, objType,
                              rec.wasDenied, rec.trappedSids, skipTreeSet);

            // F4/R10: If the target still exists but no ACEs were removed,
            // the revert may have failed — mark for metadata preservation.
            // Symmetric for both FILE and REG records.
            if (n == 0) {
                bool targetExists = false;
                if (rec.type == L"FILE") {
                    DWORD attrs = GetFileAttributesW(rec.path.c_str());
                    targetExists = (attrs != INVALID_FILE_ATTRIBUTES);
                } else if (rec.type == L"REG") {
                    HKEY hTest = nullptr;
                    HKEY root = HKEY_CURRENT_USER;
                    std::wstring subPath = rec.path;
                    if (subPath.compare(0, 13, L"CURRENT_USER\\") == 0) {
                        subPath = subPath.substr(13);
                    } else if (subPath.compare(0, 8, L"MACHINE\\") == 0) {
                        root = HKEY_LOCAL_MACHINE;
                        subPath = subPath.substr(8);
                    }
                    if (RegOpenKeyExW(root, subPath.c_str(), 0, KEY_READ, &hTest) == ERROR_SUCCESS) {
                        targetExists = true;
                        RegCloseKey(hTest);
                    }
                }
                if (targetExists) {
                    g_logger.LogFmt(L"ACL_RESTORE_FAIL: %ls (target exists but no ACEs removed)",
                                    rec.path.c_str());
                    allOk = false;
                }
            }
            printf("  [ACL]  restored %ls %ls\n", rec.type.c_str(), rec.path.c_str());
        }
        return allOk;
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

        // Collect path+SID pairs from a subkey (compound key for precise skip logic)
        auto collectPathSids = [](HKEY hKey, std::set<std::wstring>& outPathSids) {
            DWORD valueCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &valueCount, nullptr, nullptr, nullptr, nullptr);
            for (DWORD vi = 0; vi < valueCount; vi++) {
                std::wstring vname, data;
                if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;
                GrantRecord rec;
                if (!ParseGrantRecord(data, rec)) continue;
                outPathSids.insert(rec.path + L"|" + rec.sidString);
            }
        };

        // Separate live vs stale
        std::set<std::wstring> livePathSids;
        std::vector<std::pair<std::wstring, DWORD>> staleKeys; // {subKey, pid}

        for (const auto& subKey : subKeys) {
            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + subKey;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS) {
                staleKeys.push_back({ subKey, 0 });
                continue;
            }

            DWORD pid = 0; ULONGLONG ctime = 0;
            ReadPidAndCtime(hKey, pid, ctime);
            if (IsProcessAlive(pid, ctime)) {
                collectPathSids(hKey, livePathSids);
                g_logger.Log((L"STALE_CHECK: " + subKey + L" -> ALIVE (PID=" + std::to_wstring(pid) + L")").c_str());
            } else {
                staleKeys.push_back({ subKey, pid });
                g_logger.Log((L"STALE_CHECK: " + subKey + L" -> DEAD (PID=" + std::to_wstring(pid) + L")").c_str());
            }
            RegCloseKey(hKey);
        }

        // Fetch saved-profile container names once — these are permanent and
        // must NEVER be deleted by stale cleanup (only by --delete-profile).
        std::set<std::wstring> savedProfileContainers = GetSavedProfileContainerNames();

        // Remove stale ACEs and delete registry subkeys
        for (const auto& stale : staleKeys) {
            const auto& subKey = stale.first;
            DWORD stalePid = stale.second;
            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + subKey;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) == ERROR_SUCCESS) {
                std::wstring containerName = ReadRegSz(hKey, L"_container");
                if (!containerName.empty()) {
                    // Check if this is a profile-mode entry or a saved-profile container
                    DWORD profileMode = 0;
                    DWORD pmSize = sizeof(profileMode);
                    RegQueryValueExW(hKey, L"_profile_mode", nullptr, nullptr,
                                     reinterpret_cast<BYTE*>(&profileMode), &pmSize);
                    bool isSavedContainer = savedProfileContainers.count(containerName) > 0;

                    if (profileMode == 1 || isSavedContainer) {
                        g_logger.LogFmt(L"PROFILE_SKIP: %ls (saved profile container, not deleting)",
                                        containerName.c_str());
                        printf("  [PROFILE] %ls -> skipped (saved profile)\n",
                               containerName.c_str());
                    } else {
                        HRESULT hr = DeleteAppContainerProfile(containerName.c_str());
                        g_logger.Log((L"PROFILE_DELETE: " + containerName +
                            (SUCCEEDED(hr) ? L" -> OK" : L" -> FAILED")).c_str());
                        printf("  [PROFILE] %ls -> %s\n", containerName.c_str(),
                               SUCCEEDED(hr) ? "deleted" : "FAILED");
                    }
                }
                bool cleanOk = RestoreGrantsFromKey(hKey, livePathSids);
                RegCloseKey(hKey);

                // F2/R9: Preserve metadata for retry if ACL revert was incomplete
                if (!cleanOk) {
                    g_logger.LogFmt(L"STALE_PRESERVE: %ls ACL revert incomplete, keeping metadata for retry",
                                    subKey.c_str());
                    printf("  [GRANTS] instance %ls (PID %lu) -> ACL revert incomplete, metadata preserved\n",
                           subKey.c_str(), (unsigned long)stalePid);
                    continue;
                }
            }
            LSTATUS delResult = RegDeleteTreeW(HKEY_CURRENT_USER, fullKey.c_str());
            if (delResult != ERROR_SUCCESS) {
                g_logger.LogFmt(L"REG_DELETE_FAIL: %ls -> error %lu", fullKey.c_str(), delResult);
                delResult = RegDeleteKeyW(HKEY_CURRENT_USER, fullKey.c_str());
                if (delResult != ERROR_SUCCESS)
                    g_logger.LogFmt(L"REG_DELETE_FALLBACK_FAIL: %ls -> error %lu", fullKey.c_str(), delResult);
            }
            g_logger.Log((L"REG_DELETE: " + fullKey).c_str());
            printf("  [GRANTS] instance %ls (PID %lu) -> cleaned\n",
                   subKey.c_str(), (unsigned long)stalePid);
        }
    }

} // namespace Sandbox
