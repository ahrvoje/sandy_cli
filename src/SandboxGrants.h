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
#include "SandboxToken.h"
#include "SandboxRecoveryLedger.h"
#include "SandboxRegistry.h"
#include "SandboxProfileRegistry.h"
#include <set>
#include <atomic>
#include <cstdarg>

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Grant record — one per DACL write
    // -----------------------------------------------------------------------
    struct ACLGrant {
        std::wstring       path;
        SE_OBJECT_TYPE     objType;
        std::wstring       sidString;
        // SID of the principal granted/denied
        bool               wasThis = false;     // no inheritable ACE — skip tree-set on cleanup
        OwnerAce           ownerAce = OwnerAce::None;
    };

    // -----------------------------------------------------------------------
    // Recovery progress lines ("[ACL] restored ...", "[GRANTS] ... cleaned").
    //
    // `--cleanup`, `--create-profile` and `--delete-profile` show them on
    // stdout.  A sandbox run must not: its stdout belongs to the child, and a
    // caller that parses the child's output must not find Sandy text in it.
    // BeginRunSession() turns the console copy off; the session log keeps the
    // matching entries.
    // -----------------------------------------------------------------------
    inline bool g_recoveryConsoleOutput = true;

    inline void RecoveryPrintf(const char* fmt, ...)
    {
        if (!g_recoveryConsoleOutput) return;
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }

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
        OwnerAce     ownerAce = OwnerAce::None;
    };

    // -----------------------------------------------------------------------
    // FormatGrantRecord — the one writer of the persisted record format.
    // ParseGrantRecord below is its inverse.
    // -----------------------------------------------------------------------
    inline std::wstring FormatGrantRecord(const GrantRecordSpec& spec, const std::wstring& path)
    {
        std::wstring data = (spec.objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
        data += L"|" + path + L"|" + spec.sidString;
        if (spec.hasDeny)
            data += L"|DENY:1";
        if (spec.objectOnly)
            data += L"|THIS:1";
        if (spec.ownerAce == OwnerAce::Inherit)
            data += L"|OWNER:I";
        else if (spec.ownerAce == OwnerAce::ObjectOnly)
            data += L"|OWNER:O";
        return data;
    }

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
    // Expected format: TYPE|PATH|SID[|DENY:1][|THIS:1][|OWNER:I|OWNER:O]
    //   TYPE:  "FILE" or "REG"
    //   PATH:  non-empty, must be absolute (drive letter, UNC, or HKEY)
    //   SID:   must match S-<revision>-<authority>-... structure
    //   Flags: DENY:1, THIS:1, OWNER:I, OWNER:O, and the legacy PEEK:1,
    //          DEFERRED:1 and TRAPPED:<sids> are recognized;
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
        out.ownerAce = OwnerAce::None;
        out.trappedSids.clear();
        if (pipePos != std::wstring::npos) {
            remaining = remaining.substr(pipePos);
            while (!remaining.empty() && remaining[0] == L'|') {
                remaining = remaining.substr(1);
                if (remaining.compare(0, 6, L"DENY:1") == 0) {
                    out.wasDenied = true;
                    remaining = remaining.substr(6);
                } else if (remaining.compare(0, 7, L"OWNER:I") == 0) {
                    out.ownerAce = OwnerAce::Inherit;
                    remaining = remaining.substr(7);
                } else if (remaining.compare(0, 7, L"OWNER:O") == 0) {
                    out.ownerAce = OwnerAce::ObjectOnly;
                    remaining = remaining.substr(7);
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
        if (!h) {
            // ERROR_ACCESS_DENIED proves the PID exists but is not openable
            // from this context (elevation boundary, protected process).
            // Treat as alive: deferring stale cleanup is recoverable, but
            // declaring a live instance dead destroys its grants/container
            // mid-run.  Other open failures (invalid PID) mean dead.
            return GetLastError() == ERROR_ACCESS_DENIED;
        }

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
    //   isCommitted=false → Incomplete (fail closed, writer initializing)
    //   isCommitted=true  → Active or Stale based on PID + creation time
    // -----------------------------------------------------------------------
    struct GrantLedgerEntry {
        std::wstring instanceId;
        DWORD        pid = 0;
        ULONGLONG    ctime = 0;
        bool         isCommitted = false;
        RecoveryLedgerLiveness liveness = RecoveryLedgerLiveness::Incomplete;
        std::wstring container;
        std::wstring profileName;
        bool         profileMode = false;
    };

    inline RecoveryLedgerLiveness ResolveRecoveryLedgerLiveness(bool isCommitted,
                                                                DWORD pid,
                                                                ULONGLONG ctime)
    {
        if (!isCommitted)
            return RecoveryLedgerLiveness::Incomplete;
        return IsProcessAlive(pid, ctime)
            ? RecoveryLedgerLiveness::Active
            : RecoveryLedgerLiveness::Stale;
    }

    inline std::vector<GrantLedgerEntry> SnapshotGrantLedgers()
    {
        std::vector<GrantLedgerEntry> entries;
        for (const auto& subKey : EnumRecoveryLedgerInstanceIds(RecoveryLedgerKind::Grants)) {
            GrantLedgerEntry e;
            e.instanceId = subKey;

            HKEY hKey = nullptr;
            if (!OpenRecoveryLedgerKey(RecoveryLedgerKind::Grants, subKey, KEY_READ, hKey)) {
                // Key disappeared between snapshot and open — treat as stale
                e.liveness = RecoveryLedgerLiveness::Stale;
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
            e.liveness = ResolveRecoveryLedgerLiveness(e.isCommitted, e.pid, e.ctime);
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
        bool         isCommitted = false;
        RecoveryLedgerLiveness liveness = RecoveryLedgerLiveness::Incomplete;
        std::wstring container;
    };

    inline std::vector<TransientContainerEntry> SnapshotTransientContainerLedgers()
    {
        std::vector<TransientContainerEntry> entries;
        for (const auto& subKey : EnumRecoveryLedgerInstanceIds(RecoveryLedgerKind::TransientContainerRetry)) {
            TransientContainerEntry e;
            e.instanceId = subKey;

            HKEY hKey = nullptr;
            if (!OpenRecoveryLedgerKey(RecoveryLedgerKind::TransientContainerRetry, subKey, KEY_READ, hKey)) {
                e.liveness = RecoveryLedgerLiveness::Stale;
                entries.push_back(std::move(e));
                continue;
            }

            e.isCommitted = ReadPidAndCtime(hKey, e.pid, e.ctime);
            e.container = ReadRegSz(hKey, L"_container");
            RegCloseKey(hKey);

            e.liveness = ResolveRecoveryLedgerLiveness(e.isCommitted, e.pid, e.ctime);
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

    // Returns false when the record could not be persisted where the current
    // operation keeps its cleanup inventory.  The caller (AddAcesToObject)
    // then leaves the DACL untouched: ACEs without a record can never be
    // found again.
    inline bool RecordGrant(const GrantRecordSpec& spec)
    {
        std::wstring normalizedPath = (spec.objType == SE_FILE_OBJECT)
            ? NormalizeFsPath(spec.path)
            : spec.path;

        // P1: Registry paths containing '|' would produce malformed grant records
        // (TYPE|PATH|SID splits fail). Fail closed: skip the record so stale
        // cleanup doesn't silently leave an ACE behind.
        if (spec.objType == SE_REGISTRY_KEY && normalizedPath.find(L'|') != std::wstring::npos) {
            g_logger.LogFmt(L"GRANT_RECORD: REJECTED registry path containing pipe: %ls", normalizedPath.c_str());
            MarkGrantTrackingFailure(L"registry path contains pipe", normalizedPath);
            return false;
        }

        const std::wstring data = FormatGrantRecord(spec, normalizedPath);
        bool persisted = true;

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

                wchar_t valueName[32];
                swprintf(valueName, 32, L"%lu", nextIdx);
                if (RegSetValueExW(hKey, valueName, 0, REG_SZ,
                                   reinterpret_cast<const BYTE*>(data.c_str()),
                                   static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS) {
                    MarkGrantTrackingFailure(L"persist grant record", regKey);
                    persisted = false;
                }

                // Increment counter
                nextIdx++;
                if (RegSetValueExW(hKey, L"_nextIdx", 0, REG_DWORD,
                                   reinterpret_cast<const BYTE*>(&nextIdx), sizeof(nextIdx)) != ERROR_SUCCESS) {
                    MarkGrantTrackingFailure(L"persist _nextIdx", regKey);
                    persisted = false;
                }

                g_logger.Log((L"REG_PERSIST: [" + std::to_wstring(nextIdx - 1) + L"] " + data).c_str());
                RegCloseKey(hKey);
            } else {
                MarkGrantTrackingFailure(L"open grants key", regKey);
                persisted = false;
            }
        }

        // --- Save to in-memory list ---
        ACLGrant grant = { normalizedPath, spec.objType, spec.sidString, spec.objectOnly, spec.ownerAce };
        g_aclGrants.push_back(std::move(grant));

        // --- Incremental staging profile write (crash-safe profile creation) ---
        if (g_stagingProfileKey) {
            wchar_t valName[32];
            swprintf(valName, 32, L"%lu", g_stagingGrantIdx);
            if (RegSetValueExW(g_stagingProfileKey, valName, 0, REG_SZ,
                               reinterpret_cast<const BYTE*>(data.c_str()),
                               static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS) {
                MarkGrantTrackingFailure(L"persist staging grant");
                persisted = false;
            }
            g_stagingGrantIdx++;
        }

        ReleaseSRWLockExclusive(&g_aclGrantsLock);
        return persisted;
    }

    // -----------------------------------------------------------------------
    // PersistDesktopGrantIntent — record, before the ACEs are written, that
    // this run puts ACEs for `sidString` on the window station and desktop.
    // Stale recovery reads `_desktop_sid` and removes them after a kill.
    // -----------------------------------------------------------------------
    inline bool PersistDesktopGrantIntent(const std::wstring& sidString)
    {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, GetGrantsRegKey().c_str(), 0,
                          KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
            return false;
        bool ok = TryWriteRegSz(hKey, L"_desktop_sid", sidString);
        RegCloseKey(hKey);
        return ok;
    }

    // -----------------------------------------------------------------------
    // The hook payload is run-owned, including on saved-profile runs. Persist
    // its name before creation so a crash cannot strand an untracked DLL.
    inline bool PersistPipeHookPath(const std::wstring& path)
    {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, GetGrantsRegKey().c_str(), 0,
                          KEY_SET_VALUE, &key) != ERROR_SUCCESS)
            return false;
        bool ok = TryWriteRegSz(key, L"_pipe_hook", path) && RegFlushKey(key) == ERROR_SUCCESS;
        RegCloseKey(key);
        g_logger.LogFmt(L"PIPEHOOK: cleanup intent %s -> %s", path.c_str(), ok ? L"OK" : L"FAILED");
        return ok;
    }

    inline bool RemoveRecordedPipeHook(HKEY key, const std::wstring& instanceId)
    {
        std::wstring path = ReadRegSz(key, L"_pipe_hook");
        if (path.empty()) return true;
        std::wstring suffix = L"\\sandy_pipe_hook_" + instanceId + L".dll";
        if (path.size() <= suffix.size() ||
            path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0) {
            g_logger.Log(L"PIPEHOOK: invalid cleanup path; keeping recovery record");
            return false;
        }
        BOOL removed = DeleteFileW(path.c_str());
        DWORD error = removed ? ERROR_SUCCESS : GetLastError();
        bool ok = removed || error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
        g_logger.LogFmt(L"PIPEHOOK: remove %s -> %s (error %lu)",
                        path.c_str(), ok ? L"removed-or-absent" : L"FAILED", error);
        return ok;
    }

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
        HKEY key = nullptr;
        LSTATUS opened = RegOpenKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, KEY_QUERY_VALUE, &key);
        if (opened == ERROR_SUCCESS) {
            bool removed = RemoveRecordedPipeHook(key, g_instanceId);
            RegCloseKey(key);
            if (!removed) return;
        } else if (opened != ERROR_FILE_NOT_FOUND && opened != ERROR_PATH_NOT_FOUND) {
            g_logger.LogFmt(L"PIPEHOOK: cleanup ledger unreadable (error %lu); keeping metadata", opened);
            return;
        }
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
            if (e.liveness == RecoveryLedgerLiveness::Active) {
                g_logger.LogFmt(L"TRANSIENT_RETRY_SKIP: %ls still owned by live instance %ls",
                                e.container.c_str(), e.instanceId.c_str());
                continue;
            }
            if (e.liveness == RecoveryLedgerLiveness::Incomplete) {
                g_logger.LogFmt(L"TRANSIENT_RETRY_SKIP: retry metadata incomplete for instance %ls (fail closed)",
                                e.instanceId.c_str());
                continue;
            }

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
            if (RecoveryLedgerBlocksCleanup(e.liveness) && !e.container.empty())
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
            if (RecoveryLedgerBlocksCleanup(e.liveness) && !e.profileName.empty())
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
        for (const auto& entry : EnumSavedProfileRegistrySummaries()) {
            if (!entry.containerName.empty())
                names.insert(NormalizeLookupKey(entry.containerName));
        }
        return names;
    }

    // -----------------------------------------------------------------------
    // GrantCleanupTarget — the recorded DACL writes of one owner, merged to
    // one entry per object.  The child walk is skipped only when no record
    // of the object placed an inheritable ACE.
    // -----------------------------------------------------------------------
    struct GrantCleanupTarget {
        std::wstring   path;
        SE_OBJECT_TYPE objType = SE_FILE_OBJECT;
        std::wstring   sidString;
        bool           skipTreeSet = true;
        OwnerAce       ownerAce = OwnerAce::None;
    };

    inline void AddGrantCleanupTarget(std::vector<GrantCleanupTarget>& plan,
                                      const std::wstring& path,
                                      SE_OBJECT_TYPE objType,
                                      const std::wstring& sidString,
                                      bool objectOnly,
                                      OwnerAce ownerAce)
    {
        for (auto& target : plan) {
            if (target.objType != objType || target.sidString != sidString ||
                _wcsicmp(target.path.c_str(), path.c_str()) != 0)
                continue;
            target.skipTreeSet = target.skipTreeSet && objectOnly;
            if (ownerAce != OwnerAce::None && target.ownerAce != OwnerAce::Inherit)
                target.ownerAce = ownerAce;
            return;
        }
        plan.push_back({ path, objType, sidString, objectOnly, ownerAce });
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

        // Serialize the entire cleanup sequence across Sandy instances.
        // Individual RemoveSidFromDacl calls already acquire this mutex,
        // but Windows named mutexes are recursive (same-thread reacquisition
        // succeeds), so this outer lock prevents interleaving of multi-path
        // cleanup where SetNamedSecurityInfoW auto-inheritance from one
        // instance can interfere with another's concurrent revocations.
        AclMutexGuard cleanupLock(kAclGlobalMutex);

        AcquireSRWLockExclusive(&g_aclGrantsLock);

        std::vector<GrantCleanupTarget> plan;
        for (const auto& g : g_aclGrants)
            AddGrantCleanupTarget(plan, g.path, g.objType, g.sidString, g.wasThis, g.ownerAce);

        int removed = 0;
        for (auto it = plan.rbegin(); it != plan.rend(); ++it)
            removed += RemoveSidFromDacl(it->path, it->sidString, it->objType,
                                         it->skipTreeSet, it->ownerAce);
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
        // Serialize the entire stale-recovery cleanup across Sandy instances.
        // Same rationale as the outer lock in RevokeAllGrants: prevents
        // interleaving of multi-path ACE removal and auto-inheritance.
        AclMutexGuard cleanupLock(kAclGlobalMutex);

        bool allOk = true;
        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        std::vector<GrantCleanupTarget> plan;
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

            SE_OBJECT_TYPE objType = (rec.type == L"REG") ? SE_REGISTRY_KEY : SE_FILE_OBJECT;
            AddGrantCleanupTarget(plan, rec.path, objType, rec.sidString, rec.wasThis, rec.ownerAce);
        }

        for (const auto& target : plan) {
            const wchar_t* type = (target.objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
            AceRemovalResult removal = RemoveSidFromDaclDetailed(target.path, target.sidString,
                                                                 target.objType,
                                                                 target.skipTreeSet, target.ownerAce);
            if (removal.removed > 0) {
                RecoveryPrintf("  [ACL]  restored %ls %ls\n", type, target.path.c_str());
                continue;
            }
            if (!removal.Succeeded()) {
                allOk = false;
                g_logger.LogFmt(L"ACL_RESTORE: %s %s -> FAILED (0x%08X)",
                                type, target.path.c_str(), removal.error);
            } else if (removal.targetMissing) {
                g_logger.LogFmt(L"ACL_RESTORE: %s %s -> target already absent",
                                type, target.path.c_str());
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
            if (e.liveness == RecoveryLedgerLiveness::Stale) {
                staleEntries.push_back(&e);
                g_logger.Log((L"STALE_CHECK: " + e.instanceId + L" -> DEAD (PID=" +
                              std::to_wstring(e.pid) + L")").c_str());
            } else if (e.liveness == RecoveryLedgerLiveness::Incomplete) {
                g_logger.Log((L"STALE_CHECK: " + e.instanceId + L" -> INCOMPLETE (fail closed)").c_str());
            } else {
                g_logger.Log((L"STALE_CHECK: " + e.instanceId + L" -> ALIVE (PID=" +
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
                        RecoveryPrintf("  [PROFILE] %ls -> skipped (saved profile)\n",
                                       e.container.c_str());
                    } else {
                        bool containerDeleted = DeleteTransientContainerNow(e.container, L"STALE_RECOVERY");
                        if (!containerDeleted) {
                            containerRetryReady = PersistTransientContainerCleanup(e.instanceId, e.container);
                            if (!containerRetryReady)
                                g_logger.LogFmt(L"STALE_PRESERVE: %ls container retry persistence failed, keeping grant metadata",
                                                e.instanceId.c_str());
                        }
                        RecoveryPrintf("  [PROFILE] %ls -> %s\n", e.container.c_str(),
                                       containerDeleted ? "deleted" : (containerRetryReady ? "deferred for retry" : "FAILED"));
                    }
                }
                // Desktop/WinSta ACEs of a killed restricted run.  Best
                // effort: they live on the window objects of the session
                // that run used, and they end with that session.
                std::wstring desktopSid = ReadRegSz(hKey, L"_desktop_sid");
                if (!desktopSid.empty() && !RevokeDesktopAccessForSid(desktopSid))
                    g_logger.LogFmt(L"STALE_RECOVERY: desktop ACE removal incomplete for %ls",
                                    desktopSid.c_str());
                bool grantsRestored = RestoreGrantsFromKey(hKey);
                grantsRestored &= RemoveRecordedPipeHook(hKey, e.instanceId);
                RegCloseKey(hKey);

                if (!grantsRestored || !containerRetryReady) {
                    if (!grantsRestored)
                        g_logger.LogFmt(L"STALE_PRESERVE: %ls ACL rollback incomplete, keeping grant metadata",
                                        e.instanceId.c_str());
                    if (!containerRetryReady)
                        g_logger.LogFmt(L"STALE_PRESERVE: %ls transient container retry metadata incomplete, keeping grant metadata",
                                        e.instanceId.c_str());
                    RecoveryPrintf("  [GRANTS] instance %ls (PID %lu) -> metadata preserved for retry\n",
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
            RecoveryPrintf("  [GRANTS] instance %ls (PID %lu) -> cleaned\n",
                           e.instanceId.c_str(), (unsigned long)e.pid);
        }
    }

} // namespace Sandbox
