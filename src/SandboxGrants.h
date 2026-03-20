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
#include "SandboxRecoveryLedger.h"
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
        bool               wasThis = false;     // this scope (non-recursive) — skip tree-set on cleanup
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
    inline std::atomic<bool>     g_preserveGrantMetadata{ false };
    inline std::atomic<bool>     g_deferredCleanupRequested{ false };

    inline std::set<std::wstring> GetSavedProfileContainerNames();

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

    inline void ResetGrantMetadataPreservation()
    {
        g_preserveGrantMetadata.store(false);
    }

    inline void ResetDeferredCleanupRequest()
    {
        g_deferredCleanupRequested.store(false);
    }

    inline void RequestGrantMetadataPreservation(const wchar_t* reason)
    {
        g_preserveGrantMetadata.store(true);
        if (reason && *reason)
            g_logger.LogFmt(L"GRANT_METADATA: preservation requested (%ls)", reason);
    }

    inline bool PreserveGrantMetadataRequested()
    {
        return g_preserveGrantMetadata.load();
    }

    inline void RequestDeferredCleanup(const wchar_t* reason)
    {
        g_deferredCleanupRequested.store(true);
        if (reason && *reason)
            g_logger.LogFmt(L"CLEANUP_RETRY: requested (%ls)", reason);
    }

    inline bool DeferredCleanupRequested()
    {
        return g_deferredCleanupRequested.load();
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
        bool         wasThis = false;
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
        if (out.type == L"FILE")
            out.path = NormalizeFsPath(out.path);
        // Require absolute path (drive letter, UNC, or HKEY for registry)
        bool isAbsolute = (out.path.size() >= 3 && iswalpha(out.path[0]) && out.path[1] == L':' && out.path[2] == L'\\') ||
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
        out.wasThis = false;
        out.trappedSids.clear();
        if (pipePos != std::wstring::npos) {
            remaining = remaining.substr(pipePos);
            while (!remaining.empty() && remaining[0] == L'|') {
                remaining = remaining.substr(1);
                if (remaining.compare(0, 6, L"DENY:1") == 0) {
                    out.wasDenied = true;
                    remaining = remaining.substr(6);
                } else if (remaining.compare(0, 6, L"PEEK:1") == 0) {
                    out.wasThis = true;  // backward compat: PEEK:1 → wasThis
                    remaining = remaining.substr(6);
                } else if (remaining.compare(0, 6, L"THIS:1") == 0) {
                    out.wasThis = true;
                    remaining = remaining.substr(6);
                } else if (remaining.compare(0, 10, L"DEFERRED:1") == 0) {
                    // Legacy flag from removed deferred-cleanup mechanism; just skip it
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
        // Creation time is mandatory for identity validation (resilience.md §Liveness).
        // Without it we cannot distinguish a reused PID from the original process.
        if (storedCreationTime == 0) return false;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
        if (!h) return false;

        // Zombie check — signaled = terminated
        if (WaitForSingleObject(h, 0) != WAIT_TIMEOUT) {
            CloseHandle(h);
            return false;
        }

        // Creation-time match — fail closed on GetProcessTimes failure
        FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
        if (!GetProcessTimes(h, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
            CloseHandle(h);
            return false;
        }
        ULARGE_INTEGER li;
        li.LowPart = ftCreate.dwLowDateTime;
        li.HighPart = ftCreate.dwHighDateTime;
        bool alive = (li.QuadPart == storedCreationTime);
        CloseHandle(h);
        return alive;
    }

    inline bool ReadPidAndCtime(HKEY hKey, DWORD& pid, ULONGLONG& ctime)
    {
        // P1/R5: Check return codes — a concurrent instance may have written
        // _pid but not yet _ctime.  Returning partial data (pid set, ctime 0)
        // causes IsProcessAlive to reject the entry as dead, triggering
        // false stale recovery that destroys the live instance's key.
        DWORD tempPid = 0;
        DWORD size = sizeof(DWORD);
        LSTATUS pidStatus = RegQueryValueExW(hKey, L"_pid", nullptr, nullptr,
                         reinterpret_cast<BYTE*>(&tempPid), &size);
        if (pidStatus != ERROR_SUCCESS) {
            pid = 0; ctime = 0;
            return false;
        }
        ULONGLONG tempCtime = 0;
        size = sizeof(ULONGLONG);
        LSTATUS ctimeStatus = RegQueryValueExW(hKey, L"_ctime", nullptr, nullptr,
                         reinterpret_cast<BYTE*>(&tempCtime), &size);
        if (ctimeStatus != ERROR_SUCCESS) {
            pid = 0; ctime = 0;
            return false;
        }
        pid = tempPid;
        ctime = tempCtime;
        return pid != 0 && ctime != 0;
    }

    // -----------------------------------------------------------------------
    // GrantLedgerEntry — resolved snapshot of one Grants\<instanceId> subkey.
    //
    // Liveness semantics are defined HERE, not in callers:
    //   isCommitted=false → treat as alive (fail closed, writer initializing)
    //   isCommitted=true  → isAlive = IsProcessAlive(pid, ctime)
    // -----------------------------------------------------------------------
    struct GrantLedgerEntry {
        std::wstring instanceId;
        DWORD        pid = 0;
        ULONGLONG    ctime = 0;
        bool         isAlive = false;
        bool         isCommitted = false;
        std::wstring container;
        std::wstring profileName;
        bool         profileMode = false;
    };

    inline std::vector<GrantLedgerEntry> SnapshotGrantLedgers()
    {
        std::vector<GrantLedgerEntry> entries;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return entries;

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

        for (const auto& subKey : subKeys) {
            GrantLedgerEntry e;
            e.instanceId = subKey;

            std::wstring fullKey = GetRecoveryLedgerKey(RecoveryLedgerKind::Grants, subKey);
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS) {
                // Key disappeared between snapshot and open — treat as stale
                entries.push_back(std::move(e));
                continue;
            }

            e.isCommitted = ReadPidAndCtime(hKey, e.pid, e.ctime);
            e.container = ReadRegSz(hKey, L"_container");
            e.profileName = ReadRegSz(hKey, L"_profile_name");

            DWORD pm = 0, pmSize = sizeof(pm);
            if (RegQueryValueExW(hKey, L"_profile_mode", nullptr, nullptr,
                                 reinterpret_cast<BYTE*>(&pm), &pmSize) == ERROR_SUCCESS)
                e.profileMode = (pm == 1);

            RegCloseKey(hKey);

            // Liveness: uncommitted = alive (fail closed), committed = check
            e.isAlive = e.isCommitted ? IsProcessAlive(e.pid, e.ctime) : true;
            entries.push_back(std::move(e));
        }
        return entries;
    }

    // -----------------------------------------------------------------------
    // TransientContainerEntry — resolved snapshot of one
    // TransientContainers\<instanceId> subkey.
    // -----------------------------------------------------------------------
    struct TransientContainerEntry {
        std::wstring instanceId;
        DWORD        pid = 0;
        ULONGLONG    ctime = 0;
        bool         isAlive = false;
        bool         isCommitted = false;
        std::wstring container;
    };

    inline std::vector<TransientContainerEntry> SnapshotTransientContainerLedgers()
    {
        std::vector<TransientContainerEntry> entries;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kTransientContainersParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return entries;

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

        for (const auto& subKey : subKeys) {
            TransientContainerEntry e;
            e.instanceId = subKey;

            std::wstring fullKey = GetTransientContainerRegKey(subKey);
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS) {
                entries.push_back(std::move(e));
                continue;
            }

            e.isCommitted = ReadPidAndCtime(hKey, e.pid, e.ctime);
            e.container = ReadRegSz(hKey, L"_container");
            RegCloseKey(hKey);

            e.isAlive = e.isCommitted ? IsProcessAlive(e.pid, e.ctime) : true;
            entries.push_back(std::move(e));
        }
        return entries;
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
    inline bool HardenRegistryKeyAgainstRestricted(HKEY hKey)
    {
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        PSID pRestricted = nullptr;
        if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_RESTRICTED_CODE_RID,
                0, 0, 0, 0, 0, 0, 0, &pRestricted)) {
            g_logger.Log(L"HARDEN_KEY: AllocateAndInitializeSid FAILED");
            return false;
        }

        EXPLICIT_ACCESSW deny{};
        deny.grfAccessPermissions = KEY_ALL_ACCESS;
        deny.grfAccessMode = DENY_ACCESS;
        deny.grfInheritance = NO_INHERITANCE;
        deny.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        deny.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pRestricted);

        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pKeySD = nullptr;
        DWORD gsErr = GetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                nullptr, nullptr, &pOldDacl, nullptr, &pKeySD);
        if (gsErr != ERROR_SUCCESS) {
            g_logger.LogFmt(L"HARDEN_KEY: GetSecurityInfo FAILED (0x%08X)", gsErr);
            FreeSid(pRestricted);
            return false;
        }

        PACL pNewDacl = nullptr;
        DWORD seErr = SetEntriesInAclW(1, &deny, pOldDacl, &pNewDacl);
        if (seErr != ERROR_SUCCESS) {
            g_logger.LogFmt(L"HARDEN_KEY: SetEntriesInAclW FAILED (0x%08X)", seErr);
            LocalFree(pKeySD);
            FreeSid(pRestricted);
            return false;
        }

        DWORD siErr = SetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, pNewDacl, nullptr);
        LocalFree(pNewDacl);
        LocalFree(pKeySD);
        FreeSid(pRestricted);
        if (siErr != ERROR_SUCCESS) {
            g_logger.LogFmt(L"HARDEN_KEY: SetSecurityInfo FAILED (0x%08X)", siErr);
            return false;
        }
        return true;
    }

    inline void InitializeRunLedger(const std::wstring& containerName)
    {
        if (!g_grantPersistence) return;

        std::wstring regKey = GetGrantsRegKey();
        HKEY hKey = nullptr;
        DWORD disposition = 0;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr,
                0, KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC,
                nullptr, &hKey, &disposition) == ERROR_SUCCESS) {

            // On first creation, store identity and protect the key
            if (disposition == REG_CREATED_NEW_KEY) {
                // P1/liveness: Write _ctime and _container BEFORE _pid.
                // _pid is the commit marker — ReadPidAndCtime reads _pid
                // first, so once _pid is visible ALL other metadata fields
                // (_ctime, _container) are guaranteed already present.
                ULONGLONG ct = GetCurrentProcessCreationTime();
                if (RegSetValueExW(hKey, L"_ctime", 0, REG_QWORD,
                                   reinterpret_cast<const BYTE*>(&ct), sizeof(ULONGLONG)) != ERROR_SUCCESS)
                    MarkGrantTrackingFailure(L"persist _ctime", regKey);

                if (!containerName.empty()) {
                    if (RegSetValueExW(hKey, L"_container", 0, REG_SZ,
                                       reinterpret_cast<const BYTE*>(containerName.c_str()),
                                       static_cast<DWORD>((containerName.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS)
                        MarkGrantTrackingFailure(L"persist _container", regKey);
                }

                // _pid LAST — this is the commit marker.
                DWORD pid = GetCurrentProcessId();
                if (RegSetValueExW(hKey, L"_pid", 0, REG_DWORD,
                                   reinterpret_cast<const BYTE*>(&pid), sizeof(DWORD)) != ERROR_SUCCESS)
                    MarkGrantTrackingFailure(L"persist _pid", regKey);

                // F5/R11: Deny Restricted SID write access (shared helper)
                if (!HardenRegistryKeyAgainstRestricted(hKey))
                    MarkGrantTrackingFailure(L"harden grants key", regKey);
            }
            RegCloseKey(hKey);
        } else {
            MarkGrantTrackingFailure(L"create grants key", regKey);
        }
    }

    inline void RecordGrant(const std::wstring& path, SE_OBJECT_TYPE objType,
                            const std::wstring& sidString,
                            const std::wstring& trappedSids = L"",
                            bool isDeny = false,
                            bool isThis = false)
    {
        std::wstring normalizedPath = (objType == SE_FILE_OBJECT)
            ? NormalizeFsPath(path)
            : path;

        // P1: Registry paths containing '|' would produce malformed grant records
        // (TYPE|PATH|SID splits fail). Fail closed: skip the record so stale
        // cleanup doesn't silently leave an ACE behind.
        if (objType == SE_REGISTRY_KEY && normalizedPath.find(L'|') != std::wstring::npos) {
            g_logger.LogFmt(L"GRANT_RECORD: REJECTED registry path containing pipe: %ls", normalizedPath.c_str());
            MarkGrantTrackingFailure(L"registry path contains pipe", normalizedPath);
            return;
        }

        AcquireSRWLockExclusive(&g_aclGrantsLock);

        // --- Persist to registry (live instance crash recovery) ---
        if (g_grantPersistence) {
            std::wstring regKey = GetGrantsRegKey();
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0,
                    KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {

                // Get next index
                DWORD nextIdx = 0;
                DWORD idxSize = sizeof(nextIdx);
                RegQueryValueExW(hKey, L"_nextIdx", nullptr, nullptr,
                                 reinterpret_cast<BYTE*>(&nextIdx), &idxSize);

                // Format: TYPE|PATH|SID  or  TYPE|PATH|SID|DENY:1|TRAPPED:sid1;sid2
                std::wstring typeStr = (objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
                std::wstring data = typeStr + L"|" + normalizedPath + L"|" + sidString;
                // Persist deny flag explicitly
                if (isDeny) {
                    data += L"|DENY:1";
                }
                if (!trappedSids.empty()) {
                    data += L"|TRAPPED:" + trappedSids;
                }
                if (isThis) {
                    data += L"|THIS:1";
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
        ACLGrant grant = { normalizedPath, objType, sidString, trappedSids, isDeny, isThis };
        g_aclGrants.push_back(std::move(grant));

        // --- Incremental staging profile write (crash-safe profile creation) ---
        if (g_stagingProfileKey) {
            std::wstring typeStr = (objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
            std::wstring data = typeStr + L"|" + normalizedPath + L"|" + sidString;
            if (isDeny) data += L"|DENY:1";
            if (!trappedSids.empty()) data += L"|TRAPPED:" + trappedSids;
            if (isThis) data += L"|THIS:1";

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
        // P1: Guard against empty g_instanceId — GetGrantsRegKey() would return
        // the parent path "Software\Sandy\Grants\" and RegDeleteTreeW would
        // wipe ALL instances' recovery data.
        if (g_instanceId.empty()) {
            g_logger.Log(L"REG_CLEAR: SKIPPED (g_instanceId is empty — would delete parent key)");
            return;
        }
        std::wstring regKey = GetGrantsRegKey();
        LSTATUS r = DeleteRegTreeBestEffort(HKEY_CURRENT_USER, regKey);
        g_logger.Log((L"REG_CLEAR: " + regKey + (r == ERROR_SUCCESS ? L" -> OK" : L" -> NOT_FOUND")).c_str());
    }

    inline bool PersistTransientContainerCleanup(const std::wstring& instanceId,
                                                 const std::wstring& containerName)
    {
        if (instanceId.empty() || containerName.empty()) return false;

        std::wstring regKey = GetTransientContainerRegKey(instanceId);
        HKEY hKey = nullptr;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr, 0,
                            KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC,
                            nullptr, &hKey, nullptr) != ERROR_SUCCESS)
            return false;

        bool ok = true;
        // P1/liveness: Write _ctime and _container BEFORE _pid.
        // _pid is the commit marker — once visible, all metadata is present.
        ok &= TryWriteRegQword(hKey, L"_ctime", GetCurrentProcessCreationTime());
        ok &= TryWriteRegSz(hKey, L"_container", containerName);
        DWORD pid = GetCurrentProcessId();
        ok &= TryWriteRegDword(hKey, L"_pid", pid);
        if (!HardenRegistryKeyAgainstRestricted(hKey))
            g_logger.Log(L"TRANSIENT_CONTAINER: WARN — key hardening failed (best-effort)");
        RegCloseKey(hKey);

        if (ok)
            g_logger.LogFmt(L"TRANSIENT_CONTAINER: preserved %ls for retry under instance %ls",
                            containerName.c_str(), instanceId.c_str());
        else
            g_logger.LogFmt(L"TRANSIENT_CONTAINER: FAILED to preserve %ls for retry under instance %ls",
                            containerName.c_str(), instanceId.c_str());
        return ok;
    }

    inline bool ClearTransientContainerCleanup(const std::wstring& instanceId)
    {
        if (instanceId.empty()) return true;

        std::wstring regKey = GetTransientContainerRegKey(instanceId);
        LSTATUS st = DeleteRegTreeBestEffort(HKEY_CURRENT_USER, regKey);
        bool ok = (st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND || st == ERROR_PATH_NOT_FOUND);
        if (ok)
            g_logger.LogFmt(L"TRANSIENT_CONTAINER: cleared retry metadata for instance %ls", instanceId.c_str());
        else
            g_logger.LogFmt(L"TRANSIENT_CONTAINER: failed to clear retry metadata for instance %ls (error %lu)",
                            instanceId.c_str(), st);
        return ok;
    }

    inline std::vector<std::wstring> FindTransientContainerCleanupInstanceIds(const std::wstring& containerName)
    {
        std::vector<std::wstring> instanceIds;
        if (containerName.empty()) return instanceIds;

        std::wstring lookup = NormalizeLookupKey(containerName);
        for (const auto& e : SnapshotTransientContainerLedgers()) {
            if (NormalizeLookupKey(e.container) == lookup)
                instanceIds.push_back(e.instanceId);
        }
        return instanceIds;
    }

    inline bool ClearTransientContainerCleanupByContainerName(const std::wstring& containerName)
    {
        bool allOk = true;
        for (const auto& instanceId : FindTransientContainerCleanupInstanceIds(containerName)) {
            if (!ClearTransientContainerCleanup(instanceId))
                allOk = false;
        }
        return allOk;
    }

    inline bool PersistTransientContainerCleanupForOrphanedContainer(const std::wstring& containerName)
    {
        auto instanceIds = FindTransientContainerCleanupInstanceIds(containerName);
        if (!instanceIds.empty())
            return PersistTransientContainerCleanup(instanceIds.front(), containerName);
        return PersistTransientContainerCleanup(containerName, containerName);
    }

    inline bool DeleteTransientContainerNow(const std::wstring& containerName,
                                            const wchar_t* contextTag)
    {
        if (containerName.empty()) return true;

        HRESULT hr = DeleteAppContainerProfile(containerName.c_str());
        bool ok = SUCCEEDED(hr) || AppContainerMissing(hr);
        g_logger.LogFmt(L"%ls: transient container %ls -> %s",
                        contextTag, containerName.c_str(),
                        ok ? L"deleted-or-absent" : L"FAILED");
        return ok;
    }

    inline bool TeardownTransientContainerForCurrentRun(const std::wstring& containerName,
                                                        const wchar_t* contextTag)
    {
        if (containerName.empty()) return true;

        if (DeleteTransientContainerNow(containerName, contextTag)) {
            ClearTransientContainerCleanup(g_instanceId);
            return true;
        }

        RequestDeferredCleanup(L"transient container teardown incomplete");
        if (!PersistTransientContainerCleanup(g_instanceId, containerName)) {
            RequestGrantMetadataPreservation(L"transient container delete failed and retry metadata could not be persisted");
            return false;
        }
        return false;
    }

    inline void RestoreTransientContainers()
    {
        std::set<std::wstring> savedProfileContainers = GetSavedProfileContainerNames();
        auto entries = SnapshotTransientContainerLedgers();

        for (const auto& e : entries) {
            if (e.container.empty()) {
                ClearTransientContainerCleanup(e.instanceId);
                continue;
            }

            if (savedProfileContainers.count(NormalizeLookupKey(e.container)) > 0) {
                g_logger.LogFmt(L"TRANSIENT_RETRY_SKIP: %ls is profile-owned; clearing stale retry metadata for instance %ls",
                                e.container.c_str(), e.instanceId.c_str());
                ClearTransientContainerCleanup(e.instanceId);
                continue;
            }

            if (DeleteTransientContainerNow(e.container, L"TRANSIENT_RETRY"))
                ClearTransientContainerCleanup(e.instanceId);
        }
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

        bool ok = true;
        // P1/liveness: Write _ctime, _container, _profile_name, and
        // _profile_mode BEFORE _pid.  _pid is the commit marker — once
        // visible, all metadata fields are guaranteed present.
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

        // _pid LAST — this is the commit marker.
        DWORD pid = GetCurrentProcessId();
        if (RegSetValueExW(hKey, L"_pid", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&pid), sizeof(DWORD)) != ERROR_SUCCESS)
            ok = false;

        // F5/R11: Harden live-state key against restricted-token tampering
        // (same protection applied to normal live grant keys in RecordGrant)
        if (!HardenRegistryKeyAgainstRestricted(hKey))
            ok = false;

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

    // GetOtherInstanceDenyPaths / GetOtherInstancePathSids removed:
    // Both AC and RT SIDs are unique per instance and cleanup removes ACEs
    // by owning SID only, so cross-instance coordination is unnecessary.

    // -----------------------------------------------------------------------
    // GetLiveContainerNames — returns container names whose owning Sandy
    // instance is still alive (includes uncommitted = fail closed).
    // -----------------------------------------------------------------------
    inline std::set<std::wstring> GetLiveContainerNames()
    {
        std::set<std::wstring> live;
        for (const auto& e : SnapshotGrantLedgers()) {
            if (e.isAlive && !e.container.empty())
                live.insert(NormalizeLookupKey(e.container));
        }
        return live;
    }

    // -----------------------------------------------------------------------
    // GetLiveProfileNames — returns profile names whose owning Sandy
    // instance is still alive (includes uncommitted = fail closed).
    // -----------------------------------------------------------------------
    inline std::set<std::wstring> GetLiveProfileNames()
    {
        std::set<std::wstring> live;
        for (const auto& e : SnapshotGrantLedgers()) {
            if (e.isAlive && !e.profileName.empty())
                live.insert(NormalizeLookupKey(e.profileName));
        }
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

        // P1: Snapshot subkey names first to avoid index-shift races.
        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        std::vector<std::wstring> subKeys;
        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[256];
            DWORD nameLen = 256;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                subKeys.push_back(name);
        }
        RegCloseKey(hParent);

        for (const auto& subKey : subKeys) {
            std::wstring fullKey = std::wstring(profilesKey) + L"\\" + subKey;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            std::wstring container = ReadRegSz(hKey, L"_container");
            if (!container.empty())
                names.insert(NormalizeLookupKey(container));
            RegCloseKey(hKey);
        }
        return names;
    }

    // -----------------------------------------------------------------------
    // RevokeAllGrants — remove all ACEs we added, using SID-based removal.
    // Multi-instance safe: both AC and RT SIDs are unique per instance,
    // so removing ACEs by SID cannot interfere with other instances.
    // Thread-safe, double-cleanup guarded.
    // -----------------------------------------------------------------------
    inline void RevokeAllGrants()
    {
        if (g_cleanedUp.exchange(true)) return;

        AcquireSRWLockExclusive(&g_aclGrantsLock);

        // Pre-scan: detect paths that have at least one deep (non-this) entry.
        // When a path has both allow.deep and allow.this entries, cleanup must
        // use SetNamedSecurityInfoW (skipTreeSet=false) so inherited copies of
        // the deep ACE are removed from children via auto-inheritance.
        std::set<std::wstring> pathsNeedingTreeSet;
        for (const auto& g : g_aclGrants) {
            if (!g.wasThis) {
                std::wstring key = g.path + L"|" + (g.wasDenied ? L"D" : L"A");
                pathsNeedingTreeSet.insert(key);
            }
        }

        // Deduplicate: same path may appear for allow + deny
        std::set<std::wstring> processed;
        int removed = 0;
        for (auto it = g_aclGrants.rbegin(); it != g_aclGrants.rend(); ++it) {
            std::wstring dedupKey = it->path + L"|" + (it->wasDenied ? L"D" : L"A");
            if (processed.count(dedupKey)) continue;
            processed.insert(dedupKey);

            // skipTreeSet=true only when ALL entries for this key are this-scope.
            // If any entry is deep, must use SetNamedSecurityInfoW to cascade.
            bool skipTree = it->wasThis && !pathsNeedingTreeSet.count(dedupKey);
            int n = RemoveSidFromDacl(it->path, it->sidString, it->objType,
                                   it->wasDenied ? DaclProtectionIntent::ForceUnprotected
                                                 : DaclProtectionIntent::PreserveExisting,
                                   skipTree);
            removed += n;
        }
        g_logger.LogFmt(L"REVOKE_SUMMARY: %d ACEs removed", removed);
        g_aclGrants.clear();
        ReleaseSRWLockExclusive(&g_aclGrantsLock);

        if (PreserveGrantMetadataRequested()) {
            g_logger.Log(L"REVOKE_PRESERVE: registry metadata kept for additional teardown retry");
        } else {
            ClearPersistedGrants();
        }
    }

    // -----------------------------------------------------------------------
    // RestoreGrantsFromKey — remove ACEs from a single registry subkey.
    // Parses TYPE|PATH|SID format and removes the SID's ACEs.
    // Since SIDs are unique per instance, no cross-instance checks needed.
    // Returns true only when every reachable ACL rollback completed or the
    // target object was already absent.
    // -----------------------------------------------------------------------
    inline bool RestoreGrantsFromKey(HKEY hKey)
    {
        bool allOk = true;
        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        // Pre-scan: detect paths that have deep (non-this) entries.
        // Same fix as RevokeAllGrants: dual-scope paths must use tree-set.
        std::set<std::wstring> deepPaths;
        for (DWORD pre = 0; pre < valueCount; pre++) {
            std::wstring pvname, pdata;
            if (!ReadRegSzEnum(hKey, pre, pvname, pdata)) continue;
            GrantRecord pr;
            if (!ParseGrantRecord(pdata, pr, nullptr)) continue;
            if (!pr.wasThis) {
                deepPaths.insert(pr.path + L"|" + (pr.wasDenied ? L"D" : L"A"));
            }
        }

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

            SE_OBJECT_TYPE objType = (rec.type == L"REG") ? SE_REGISTRY_KEY : SE_FILE_OBJECT;

            bool skipTree = rec.wasThis && !deepPaths.count(dedupKey);
            AceRemovalResult removal = RemoveSidFromDaclDetailed(rec.path, rec.sidString, objType,
                                                                 rec.wasDenied ? DaclProtectionIntent::ForceUnprotected
                                                                               : DaclProtectionIntent::PreserveExisting,
                                                                 skipTree);
            if (removal.removed > 0) {
                printf("  [ACL]  restored %ls %ls\n", rec.type.c_str(), rec.path.c_str());
                continue;
            }
            if (!removal.Succeeded()) {
                allOk = false;
                g_logger.LogFmt(L"ACL_RESTORE: %s %s -> FAILED (0x%08X)",
                                rec.type.c_str(), rec.path.c_str(), removal.error);
            } else if (removal.targetMissing) {
                g_logger.LogFmt(L"ACL_RESTORE: %s %s -> target already absent",
                                rec.type.c_str(), rec.path.c_str());
            }
        }
        return allOk;
    }

    // -----------------------------------------------------------------------
    // RestoreStaleGrants — cleanup after crash/power loss.
    // Uses SnapshotGrantLedgers() — liveness resolved once, no ad-hoc loops.
    // -----------------------------------------------------------------------
    inline void RestoreStaleGrants()
    {
        RestoreTransientContainers();

        auto snapshot = SnapshotGrantLedgers();

        // Separate live vs stale using pre-resolved liveness
        std::vector<const GrantLedgerEntry*> staleEntries;
        for (const auto& e : snapshot) {
            if (e.isAlive) {
                g_logger.Log((L"STALE_CHECK: " + e.instanceId + L" -> ALIVE (PID=" +
                              std::to_wstring(e.pid) + L")").c_str());
            } else {
                staleEntries.push_back(&e);
                g_logger.Log((L"STALE_CHECK: " + e.instanceId + L" -> DEAD (PID=" +
                              std::to_wstring(e.pid) + L")").c_str());
            }
        }

        // Fetch saved-profile container names once — these are permanent and
        // must NEVER be deleted by stale cleanup (only by --delete-profile).
        std::set<std::wstring> savedProfileContainers = GetSavedProfileContainerNames();

        // Remove stale ACEs and delete registry subkeys
        for (const auto* ep : staleEntries) {
            const auto& e = *ep;
            std::wstring fullKey = GetRecoveryLedgerKey(RecoveryLedgerKind::Grants, e.instanceId);
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) == ERROR_SUCCESS) {
                bool containerRetryReady = true;
                if (!e.container.empty()) {
                    bool isSavedContainer = savedProfileContainers.count(
                        NormalizeLookupKey(e.container)) > 0;

                    if (e.profileMode || isSavedContainer) {
                        g_logger.LogFmt(L"PROFILE_SKIP: %ls (saved profile container, not deleting)",
                                        e.container.c_str());
                        printf("  [PROFILE] %ls -> skipped (saved profile)\n",
                               e.container.c_str());
                    } else {
                        bool containerDeleted = DeleteTransientContainerNow(e.container, L"STALE_RECOVERY");
                        if (!containerDeleted) {
                            containerRetryReady = PersistTransientContainerCleanup(e.instanceId, e.container);
                            if (!containerRetryReady)
                                g_logger.LogFmt(L"STALE_PRESERVE: %ls container retry persistence failed, keeping grant metadata",
                                                e.instanceId.c_str());
                        }
                        printf("  [PROFILE] %ls -> %s\n", e.container.c_str(),
                               containerDeleted ? "deleted" : (containerRetryReady ? "deferred for retry" : "FAILED"));
                    }
                }
                bool grantsRestored = RestoreGrantsFromKey(hKey);
                RegCloseKey(hKey);

                if (!grantsRestored || !containerRetryReady) {
                    if (!grantsRestored)
                        g_logger.LogFmt(L"STALE_PRESERVE: %ls ACL rollback incomplete, keeping grant metadata",
                                        e.instanceId.c_str());
                    if (!containerRetryReady)
                        g_logger.LogFmt(L"STALE_PRESERVE: %ls transient container retry metadata incomplete, keeping grant metadata",
                                        e.instanceId.c_str());
                    printf("  [GRANTS] instance %ls (PID %lu) -> metadata preserved for retry\n",
                           e.instanceId.c_str(), (unsigned long)e.pid);
                    continue;
                }
            }
            LSTATUS delResult = DeleteRegTreeBestEffort(HKEY_CURRENT_USER, fullKey);
            if (delResult != ERROR_SUCCESS &&
                delResult != ERROR_FILE_NOT_FOUND &&
                delResult != ERROR_PATH_NOT_FOUND)
                g_logger.LogFmt(L"REG_DELETE_FAIL: %ls -> error %lu", fullKey.c_str(), delResult);
            g_logger.Log((L"REG_DELETE: " + fullKey).c_str());
            printf("  [GRANTS] instance %ls (PID %lu) -> cleaned\n",
                   e.instanceId.c_str(), (unsigned long)e.pid);
        }
    }

} // namespace Sandbox
