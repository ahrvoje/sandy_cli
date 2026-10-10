#pragma once
// =========================================================================
// Sandbox.h — Sandbox orchestrator (single unified pipeline)
//
// One linear pipeline: RunPipeline().  Mode-specific steps use simple
// conditionals.  All cleanup is managed by SandboxGuard (RAII).
// =========================================================================

#include "framework.h"
#include "SandboxConfig.h"
#include "SandboxACL.h"
#include "SandboxGrants.h"
#include "SandboxGuard.h"
#include "SandboxToken.h"
#include "SandboxCleanup.h"
#include "SandboxCapabilities.h"
#include "SandboxEnvironment.h"
#include "SandboxProcess.h"
#include "SandboxPipeHook.h"
#include <atomic>


namespace Sandbox {

    struct ExecutionIdentity;

    // Global launch ownership handles for emergency cleanup coordination.
    // The process handle tracks the root process; the job handle tracks the
    // whole sandbox-owned process tree when descendants are allowed.
    // Atomic: written by the main pipeline thread, read concurrently by the
    // console-ctrl handler thread (Ctrl+C / close events).
    inline std::atomic<HANDLE> g_childProcess{ nullptr };
    inline std::atomic<HANDLE> g_childJob{ nullptr };
    // Shared: a thread that uses the handles.  Exclusive: the main thread,
    // when it withdraws them before it closes them.
    inline SRWLOCK             g_childHandlesLock = SRWLOCK_INIT;

    // -----------------------------------------------------------------------
    // Shutdown request — set by the console-ctrl handler.
    //
    // The main thread is the only owner of cleanup.  A signal never cleans
    // up on its own thread: it sets this flag and ends the child tree; the
    // main thread then leaves its wait (or stops at its next step) and runs
    // the same teardown as a normal exit.  Two threads can therefore never
    // be inside cleanup at the same time, and the process cannot end while
    // one of them is half way through it.
    // -----------------------------------------------------------------------
    inline std::atomic<bool> g_shutdownRequested{ false };

    inline bool ShutdownRequested()
    {
        return g_shutdownRequested.load();
    }

    // End the sandboxed process tree, if one is running.  Safe from any thread.
    inline void TerminateRunningChild()
    {
        AcquireSRWLockShared(&g_childHandlesLock);
        if (HANDLE hJob = g_childJob)
            TerminateJobObject(hJob, 1);
        else if (HANDLE hChild = g_childProcess)
            TerminateProcess(hChild, 1);
        ReleaseSRWLockShared(&g_childHandlesLock);
    }

    // Publish / withdraw the child handles for TerminateRunningChild.
    inline void PublishChildHandles(HANDLE hProcess, HANDLE hJob)
    {
        AcquireSRWLockExclusive(&g_childHandlesLock);
        g_childProcess = hProcess;
        g_childJob = hJob;
        ReleaseSRWLockExclusive(&g_childHandlesLock);
    }

    // Emergency cleanup only needs the transient AppContainer teardown target.
    // Run-ledger presence and cleanup-task retention are derived from the
    // recovery ledger itself rather than mirrored in separate shadow flags.
    struct EmergencyCleanupState {
        bool         deleteContainerOnExit = false;
        std::wstring containerName;
        bool         persistentProfile = false;
    };

    inline EmergencyCleanupState g_emergencyCleanupState;
    inline SRWLOCK               g_emergencyCleanupStateLock = SRWLOCK_INIT;

    inline void ResetEmergencyCleanupState();
    inline void ConfigureEmergencyCleanupState(const std::wstring& containerName,
                                               bool deleteContainerOnExit,
                                               bool persistentProfile = false);
    inline EmergencyCleanupState SnapshotEmergencyCleanupState();

    // -----------------------------------------------------------------------
    // RecordGrant callback — bridges SandboxACL.h → SandboxGrants.h
    // -----------------------------------------------------------------------
    inline bool RecordGrantCallback(const GrantRecordSpec& spec)
    {
        return RecordGrant(spec);
    }

    // -----------------------------------------------------------------------
    // ApplyAccessPipeline — one DACL write per configured object.
    //
    // All allow + deny entries are grouped by the object they name.  Each
    // object gets its ACEs in one write, shallowest path first.  Windows then
    // decides which rule wins, from the canonical ACE order alone:
    //   - on one object, an explicit deny comes before an explicit allow;
    //   - an ACE on a nearer object comes before an ACE inherited from
    //     farther up, so the most specific (deepest) rule wins, right by
    //     right.
    // Sandy never strips an inherited deny and never changes DACL protection.
    // -----------------------------------------------------------------------

    struct PipelineEntry {
        std::wstring path;
        AccessLevel  access;
        bool         isDeny;
        int          depth;
        GrantScope   scope = GrantScope::Deep;
    };

    using AccessPipeline = std::vector<PipelineEntry>;

    static int PathDepth(const std::wstring& p) {
        std::wstring normalized = NormalizeFsPath(p);
        int d = 0;
        for (auto c : normalized) if (c == L'\\') d++;
        // Drive root "C:\" has a trailing backslash that doesn't count as a
        // depth separator — it has zero meaningful path components.
        if (!normalized.empty() && normalized.back() == L'\\') d--;
        return d;
    }

    inline void AppendPipelineEntries(const std::vector<FolderEntry>& entries,
                                      bool isDeny,
                                      AccessPipeline& pipeline)
    {
        for (const auto& e : entries) {
            if (e.path.empty()) continue;
            pipeline.push_back({ e.path, e.access, isDeny, PathDepth(e.path), e.scope });
        }
    }

    inline AccessPipeline BuildAccessPipeline(const SandboxConfig& config)
    {
        AccessPipeline pipeline;
        pipeline.reserve(config.folders.size() + config.denyFolders.size());
        AppendPipelineEntries(config.folders, false, pipeline);
        AppendPipelineEntries(config.denyFolders, true, pipeline);

        std::stable_sort(pipeline.begin(), pipeline.end(),
            [](const PipelineEntry& a, const PipelineEntry& b) {
                if (a.depth != b.depth) return a.depth < b.depth;
                // deny before allow at same depth
                if (a.isDeny != b.isDeny) return a.isDeny;
                return false;
            });
        return pipeline;
    }

    inline std::wstring SidToStringOrEmpty(PSID pSid)
    {
        std::wstring sidStr;
        LPWSTR s = nullptr;
        if (ConvertSidToStringSidW(pSid, &s)) {
            sidStr = s;
            LocalFree(s);
        }
        return sidStr;
    }

    inline void LogAccessPipelinePlan(const AccessPipeline& pipeline)
    {
        g_logger.LogFmt(L"PIPELINE: sorted %zu entries by path depth:", pipeline.size());
        for (const auto& e : pipeline) {
            g_logger.LogFmt(L"    %s [%-7s] %s%s",
                e.isDeny ? L"DENY " : L"ALLOW",
                AccessTag(e.access), e.path.c_str(),
                e.scope == GrantScope::This ? L"  (this object only)" : L"");
        }
    }

    // The delete guard of a denied object: one object-only deny ACE on its
    // parent directory.  Windows lets a process delete or rename an object
    // when it holds FILE_DELETE_CHILD on the parent, whatever the DACL of the
    // object says.  WRITE_DAC | WRITE_OWNER keep the guard itself in place.
    constexpr DWORD kDeleteGuardMask = FILE_DELETE_CHILD | kDenyTamperMask;

    // -----------------------------------------------------------------------
    // PathRules — every configured rule that names one filesystem object.
    //
    // "Dirs" masks belong to rules that inherit to sub-directories only
    // (see DeepInheritFlags).
    // -----------------------------------------------------------------------
    struct PathRules {
        std::wstring               path;
        std::vector<PipelineEntry> entries;        // the rules, for the log
        DWORD allowDeep = 0, allowDeepDirs = 0, allowThis = 0;
        DWORD denyDeep  = 0, denyDeepDirs  = 0, denyThis  = 0;
        bool  deleteGuard = false;                 // guards a denied child of this directory
    };

    // "C:\a\b" -> "C:\a", "C:\a" -> "C:\"; empty when the path has no parent.
    inline std::wstring ParentDirectory(const std::wstring& path)
    {
        size_t slash = path.find_last_of(L'\\');
        if (slash == std::wstring::npos || slash + 1 >= path.size())
            return {};
        std::wstring parent = path.substr(0, slash);
        if (!parent.empty() && parent.back() == L':')
            parent += L'\\';
        return parent;
    }

    // Can this user delete children of `directory` through the directory
    // itself?  If not, no token made from the user's token can either, and
    // the directory needs no delete guard.
    inline bool UserCanDeleteChildren(const std::wstring& directory)
    {
        HANDLE h = CreateFileW(directory.c_str(), FILE_DELETE_CHILD,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            return false;
        CloseHandle(h);
        return true;
    }

    // Group the pipeline by object.  Config paths are normalized at ingest,
    // so a case-insensitive compare identifies the object.
    inline std::vector<PathRules> BuildPathPlan(const AccessPipeline& pipeline)
    {
        std::vector<PathRules> plan;
        auto indexOf = [&plan](const std::wstring& path) -> size_t {
            for (size_t i = 0; i < plan.size(); i++) {
                if (_wcsicmp(plan[i].path.c_str(), path.c_str()) == 0)
                    return i;
            }
            plan.emplace_back();
            plan.back().path = path;
            return plan.size() - 1;
        };

        for (const auto& e : pipeline) {
            PathRules& rules = plan[indexOf(e.path)];
            rules.entries.push_back(e);
            const DWORD mask = e.isDeny ? DenyMask(e.access) : AccessMask(e.access);
            const bool dirsOnly = DeepInheritFlags(e.access) == CONTAINER_INHERIT_ACE;
            if (e.scope == GrantScope::This)
                (e.isDeny ? rules.denyThis : rules.allowThis) |= mask;
            else if (dirsOnly)
                (e.isDeny ? rules.denyDeepDirs : rules.allowDeepDirs) |= mask;
            else
                (e.isDeny ? rules.denyDeep : rules.allowDeep) |= mask;
        }

        for (const auto& e : pipeline) {
            if (!e.isDeny || !DenyBlocksDelete(e.access))
                continue;
            std::wstring parent = ParentDirectory(e.path);
            if (parent.empty() || !UserCanDeleteChildren(parent))
                continue;
            PathRules& guard = plan[indexOf(parent)];
            guard.denyThis |= kDeleteGuardMask;
            guard.deleteGuard = true;
        }
        return plan;
    }

    // -----------------------------------------------------------------------
    // CompilePathAces — the ACEs that express the rules of one object.
    //
    // Same-object precedence is decided here, once:
    //   - a deny beats an allow of the same scope (the ACE order does it);
    //   - an allow.this beats a deny.deep on the directory itself: the
    //     single-object rule is the more specific one.  The recursive deny
    //     becomes inherit-only, and the directory keeps the denied rights
    //     that the allow.this does not name.  Descendants keep the full deny.
    // -----------------------------------------------------------------------
    inline std::vector<AceSpec> CompilePathAces(const PathRules& rules, bool isDirectory)
    {
        const BYTE kAllDescendants = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        const BYTE kSubDirectories = CONTAINER_INHERIT_ACE;
        std::vector<AceSpec> aces;

        if (!isDirectory) {
            // A file has no descendants: every rule is a rule about the file.
            DWORD deny = ((rules.denyDeep | rules.denyDeepDirs) & ~rules.allowThis) | rules.denyThis;
            DWORD allow = rules.allowDeep | rules.allowDeepDirs | rules.allowThis;
            if (deny)  aces.push_back({ true, 0, deny });
            if (allow) aces.push_back({ false, 0, allow });
            return aces;
        }

        DWORD objectDeny = rules.denyThis;
        auto addDeepDeny = [&](DWORD mask, BYTE inheritFlags) {
            if (!mask)
                return;
            if (mask & rules.allowThis) {
                aces.push_back({ true, static_cast<BYTE>(inheritFlags | INHERIT_ONLY_ACE), mask });
                objectDeny |= mask & ~rules.allowThis;
            } else {
                aces.push_back({ true, inheritFlags, mask });
            }
        };
        addDeepDeny(rules.denyDeep, kAllDescendants);
        addDeepDeny(rules.denyDeepDirs, kSubDirectories);
        if (objectDeny)
            aces.push_back({ true, 0, objectDeny });

        if (rules.allowDeep)     aces.push_back({ false, kAllDescendants, rules.allowDeep });
        if (rules.allowDeepDirs) aces.push_back({ false, kSubDirectories, rules.allowDeepDirs });
        if (rules.allowThis)     aces.push_back({ false, 0, rules.allowThis });
        return aces;
    }

    inline bool ApplyPathRules(PSID pSid,
                               const std::wstring& sidStr,
                               const PathRules& rules,
                               bool neutralizeOwner)
    {
        DWORD attrs = GetFileAttributesW(rules.path.c_str());
        bool isDirectory = attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
        DWORD rc = AddAcesToObject(rules.path, SE_FILE_OBJECT, pSid, sidStr,
                                   CompilePathAces(rules, isDirectory),
                                   neutralizeOwner, RecordGrantCallback);

        for (const auto& entry : rules.entries) {
            const wchar_t* verb = entry.isDeny ? L"DENY" : L"GRANT";
            if (rc == ERROR_SUCCESS) {
                g_logger.LogFmt(L"%s: [%s] %s -> OK (mask=0x%08X)",
                                verb, AccessTag(entry.access), entry.path.c_str(),
                                entry.isDeny ? DenyMask(entry.access) : AccessMask(entry.access));
            } else {
                g_logger.LogFmt(L"%s: [%s] %s -> FAILED (0x%08X: %s)",
                                verb, AccessTag(entry.access), entry.path.c_str(),
                                rc, GetSystemErrorMessage(rc).c_str());
            }
        }
        if (rules.deleteGuard) {
            if (rc == ERROR_SUCCESS)
                g_logger.LogFmt(L"DENY_GUARD: %s -> OK (denied child cannot be deleted or renamed)",
                                rules.path.c_str());
            else
                g_logger.LogFmt(L"DENY_GUARD: %s -> FAILED (0x%08X: %s)",
                                rules.path.c_str(), rc, GetSystemErrorMessage(rc).c_str());
        }
        return rc == ERROR_SUCCESS;
    }

    inline bool ExecuteAccessPipeline(PSID pSid, const AccessPipeline& pipeline, bool neutralizeOwner)
    {
        if (pipeline.empty())
            return true;

        // No SID string, no cleanup record; no record, no ACE.
        std::wstring sidStr = SidToStringOrEmpty(pSid);
        if (sidStr.empty()) {
            g_logger.LogFmt(L"ERROR: SID conversion failed (error %lu) — no grants applied", GetLastError());
            return false;
        }

        bool allOk = true;
        for (const auto& rules : BuildPathPlan(pipeline)) {
            if (ShutdownRequested()) {
                g_logger.Log(L"PIPELINE: interrupted — remaining grants skipped");
                return false;
            }
            if (!ApplyPathRules(pSid, sidStr, rules, neutralizeOwner))
                allOk = false;
        }
        return allOk;
    }

    inline bool ApplyAccessPipeline(PSID pSid, const SandboxConfig& config)
    {
        AccessPipeline pipeline = BuildAccessPipeline(config);
        LogAccessPipelinePlan(pipeline);
        // strict = false puts the user SID in the restricting list: the
        // sandboxed process is then an owner of the user's objects (OwnerAce).
        bool neutralizeOwner = IsRestrictedTokenMode(config.tokenMode) && !config.strict;
        return ExecuteAccessPipeline(pSid, pipeline, neutralizeOwner);
    }

    // -----------------------------------------------------------------------
    // GrantRegistryAccess — apply configured registry key grants.
    // -----------------------------------------------------------------------
    inline bool GrantRegistryAccess(PSID pSid, const SandboxConfig& config)
    {
        bool allOk = true;
        std::wstring sidStr = SidToStringOrEmpty(pSid);
        struct RegGrant { const std::vector<std::wstring>& keys; AccessLevel level; const wchar_t* tag; };
        for (auto& rg : { RegGrant{config.registryRead, AccessLevel::Read, L"R"},
                          RegGrant{config.registryWrite, AccessLevel::Write, L"W"} }) {
            for (const auto& key : rg.keys) {
                std::wstring win32Path = RegistryToWin32Path(key);
                DWORD rc = sidStr.empty()
                    ? static_cast<DWORD>(ERROR_INVALID_SID)
                    : AddAcesToObject(win32Path, SE_REGISTRY_KEY, pSid, sidStr,
                                      { { false, CONTAINER_INHERIT_ACE, RegistryAccessMask(rg.level) } },
                                      false, RecordGrantCallback);
                bool ok = (rc == ERROR_SUCCESS);
                if (!ok) allOk = false;
                if (ok) {
                    g_logger.LogFmt(L"GRANT_REG: [%s] %s -> OK", rg.tag, key.c_str());
                } else {
                    g_logger.LogFmt(L"GRANT_REG: [%s] %s -> FAILED (0x%08X: %s)",
                                    rg.tag, key.c_str(), rc, GetSystemErrorMessage(rc).c_str());
                }
            }
        }
        return allOk;
    }


    // -----------------------------------------------------------------------
    // SetupResult — output of Phase 1 (token/SID setup)
    // -----------------------------------------------------------------------
    struct SetupResult {
        PSID   pSid = nullptr;
        HANDLE hRestrictedToken = nullptr;
        bool   containerCreated = false;
        bool   ok = false;
    };

    // -----------------------------------------------------------------------
    // SetupAppContainer — create AppContainer profile and get SID.
    // -----------------------------------------------------------------------
    inline SetupResult SetupAppContainer(const std::wstring& containerName, SandboxGuard& guard)
    {
        SetupResult r;
        PSID pContainerSid = nullptr;
        HRESULT hr = CreateAppContainerProfile(
            containerName.c_str(), L"Sandy Sandbox",
            L"Sandboxed environment for running executables",
            nullptr, 0, &pContainerSid);
        if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
            hr = DeriveAppContainerSidFromAppContainerName(containerName.c_str(), &pContainerSid);
            r.containerCreated = false;
        } else {
            r.containerCreated = SUCCEEDED(hr);
        }
        if (FAILED(hr) || !pContainerSid) {
            g_logger.LogFmt(L"ERROR: AppContainer creation failed (0x%08X)", hr);
            return r;
        }
        r.pSid = pContainerSid;
        guard.Add([pContainerSid]() { FreeSid(pContainerSid); });

        g_logger.Log(L"MODE: appcontainer");
        g_logger.LogFmt(L"CONTAINER: %s", r.containerCreated ? L"created" : L"reused existing");
        LPWSTR sidStr = nullptr;
        if (ConvertSidToStringSidW(pContainerSid, &sidStr)) {
            g_logger.LogFmt(L"CONTAINER_SID: %s", sidStr);
            LocalFree(sidStr);
        }
        r.ok = true;
        return r;
    }

    // -----------------------------------------------------------------------
    // SetupRestrictedToken — create per-instance SID and restricted token.
    // -----------------------------------------------------------------------
    inline SetupResult SetupRestrictedToken(const SandboxConfig& config, SandboxGuard& guard)
    {
        SetupResult r;

        // Generate per-instance grant SID (S-1-9-<uuid>)
        PSID pGrantSid = AllocateInstanceSid();
        if (!pGrantSid) {
            g_logger.LogFmt(L"ERROR: SID allocation failed (error %lu)", GetLastError());
            return r;
        }
        r.pSid = pGrantSid;
        guard.Add([pGrantSid]() { FreeSid(pGrantSid); });

        // Create restricted token with per-instance SID
        r.hRestrictedToken = CreateRestrictedSandboxToken(config.integrity, pGrantSid, config.strict);
        if (!r.hRestrictedToken) {
            g_logger.LogFmt(L"ERROR: restricted token creation failed (error %lu)", GetLastError());
            return r;
        }
        // Capture the handle by value — `r` is a local returned by value, so a
        // by-reference capture would dangle by the time the guard runs.
        HANDLE hRestrictedToken = r.hRestrictedToken;
        guard.Add([hRestrictedToken]() { CloseHandle(hRestrictedToken); });

        LPWSTR sidStr = nullptr;
        if (ConvertSidToStringSidW(pGrantSid, &sidStr)) {
            g_logger.LogFmt(L"RT_SID: %s", sidStr);
            LocalFree(sidStr);
        }
        g_logger.Log(config.integrity == IntegrityLevel::Low
                     ? L"MODE: restricted token (Low integrity)"
                     : L"MODE: restricted token (Medium integrity)");
        r.ok = true;
        return r;
    }

    // -----------------------------------------------------------------------
    // ExecutionIdentity — ownership model for one sandbox run.
    //
    // This is more explicit than the old "profile mode" switch:
    // it tells the pipeline who owns the SID/container/grants and therefore
    // which parts of cleanup are legal for this run to perform.
    //
    // Transient run:
    //   pSid/hToken may be empty on entry and will be created by RunPipeline.
    //   grantsPreexisting = false, deleteContainerOnExit = true for AC.
    //
    // Persistent profile run:
    //   pSid/hToken/containerName are pre-resolved by the caller.
    //   grantsPreexisting = true, deleteContainerOnExit = false.
    // -----------------------------------------------------------------------
    struct ExecutionIdentity {
        PSID         pSid = nullptr;
        HANDLE       hToken = nullptr;
        std::wstring containerName;
        std::wstring profileName;
        bool         persistentProfile = false;
        bool         grantsPreexisting = false;
        bool         deleteContainerOnExit = false;
    };

    struct ResolvedRunIdentity {
        PSID         pSid = nullptr;
        HANDLE       hRestrictedToken = nullptr;
        std::wstring containerName;
    };

    struct LaunchPreparationState {
        CapabilityState       caps = {};
        SECURITY_CAPABILITIES sc = {};
        AttributeListState    attrs = {};
        std::vector<wchar_t>  envBlock;
        HANDLE                hStdin = nullptr;
        HANDLE                hStdinFile = nullptr;
        bool                  pipeHookActive = false;  // inject the pipe-hook DLL before resume
        std::wstring          hookDllPath;              // extracted DLL to inject
        const wchar_t*        failedStep = nullptr;  // set when PrepareLaunchState returns false
    };

    enum class ChildStartStatus {
        Ready,
        LaunchFailed,
        JobAssignmentFailed,
        WatchdogFailed,
        InjectionFailed,
        Interrupted
    };

    // Not copyable: the watchdog thread holds a pointer to timeoutCtx.
    struct ManagedChildState {
        ChildStartStatus     status = ChildStartStatus::LaunchFailed;
        DWORD                launchError = 0;
        PROCESS_INFORMATION  pi{};
        HANDLE               hJob = nullptr;
        TimeoutContext       timeoutCtx;
        HANDLE               hTimeoutThread = nullptr;

        ManagedChildState() = default;
        ManagedChildState(const ManagedChildState&) = delete;
        ManagedChildState& operator=(const ManagedChildState&) = delete;
    };

    inline void ResetEmergencyCleanupState()
    {
        AcquireSRWLockExclusive(&g_emergencyCleanupStateLock);
        g_emergencyCleanupState = {};
        ReleaseSRWLockExclusive(&g_emergencyCleanupStateLock);
    }

    inline void ConfigureEmergencyCleanupState(const std::wstring& containerName,
                                               bool deleteContainerOnExit,
                                               bool persistentProfile)
    {
        AcquireSRWLockExclusive(&g_emergencyCleanupStateLock);
        g_emergencyCleanupState.deleteContainerOnExit = deleteContainerOnExit;
        g_emergencyCleanupState.containerName = deleteContainerOnExit ? containerName : L"";
        g_emergencyCleanupState.persistentProfile = persistentProfile;
        ReleaseSRWLockExclusive(&g_emergencyCleanupStateLock);
    }

    inline EmergencyCleanupState SnapshotEmergencyCleanupState()
    {
        AcquireSRWLockShared(&g_emergencyCleanupStateLock);
        EmergencyCleanupState snapshot = g_emergencyCleanupState;
        ReleaseSRWLockShared(&g_emergencyCleanupStateLock);
        return snapshot;
    }

    inline bool ResolveRunIdentity(const SandboxConfig& config,
                                   const ExecutionIdentity& identity,
                                   SandboxGuard& guard,
                                   ResolvedRunIdentity& resolved)
    {
        resolved.containerName = identity.containerName;
        if (identity.pSid) {
            resolved.pSid = identity.pSid;
            resolved.hRestrictedToken = identity.hToken;
            return true;
        }

        auto setup = (config.tokenMode == TokenMode::Restricted)
            ? SetupRestrictedToken(config, guard)
            : SetupAppContainer(resolved.containerName, guard);
        if (!setup.ok)
            return false;

        resolved.pSid = setup.pSid;
        resolved.hRestrictedToken = setup.hRestrictedToken;
        return true;
    }

    inline int AbortBeforeLaunch(bool isAppContainer,
                                 const ExecutionIdentity& identity,
                                 const std::wstring& containerName,
                                 SandboxGuard& guard,
                                 int exitCode,
                                 const wchar_t* reason,
                                 const wchar_t* containerContext = L"ABORT_BEFORE_LAUNCH")
    {
        if (isAppContainer && identity.deleteContainerOnExit && !containerName.empty())
            TeardownTransientContainerForCurrentRun(containerName, containerContext);

        guard.RunAll();
        FinalizeCleanupTaskForCurrentRun();
        g_logger.Log(reason);
        g_logger.Stop();
        return exitCode;
    }

    inline bool ApplyRunOwnedGrantPhase(PSID pSid,
                                        const SandboxConfig& config,
                                        const ExecutionIdentity& identity,
                                        bool isRestricted,
                                        const std::wstring& containerName,
                                        SandboxGuard& guard)
    {
        if (identity.grantsPreexisting) {
            g_logger.Log(L"GRANTS: skipped (persistent profile ownership)");
            return true;
        }

        // Reset first: a failure while the ledger is created must stay visible
        // to the GrantTrackingHealthy() check below.
        ResetGrantTrackingHealth();
        // Only AppContainer runs own a container; a restricted run records none.
        InitializeRunLedger(isRestricted ? L"" : containerName);
        // P2: Create cleanup task AFTER the ledger exists so concurrent
        // DeleteStaleCleanupTasks won't discard our freshly created task.
        CreateCleanupTask(g_instanceId);
        ULONGLONG tGrantStart = GetTickCount64();
        guard.Add([]() { RevokeAllGrants(); });

        bool grantFailed = false;
        if (!ApplyAccessPipeline(pSid, config))
            grantFailed = true;

        if (isRestricted && !GrantRegistryAccess(pSid, config))
            grantFailed = true;

        if (!GrantTrackingHealthy()) {
            g_logger.Log(L"WARNING: grant tracking persistence failed (cleanup inventory incomplete)");
            grantFailed = true;
        }

        if (grantFailed) {
            g_logger.Log(L"ERROR: grant setup incomplete — aborting before launch");
            return false;
        }

        g_logger.LogFmt(L"TIMING: grants applied in %llums", GetTickCount64() - tGrantStart);
        return true;
    }

    inline bool EnsureRestrictedDesktopAccess(PSID pSid,
                                              const SandboxConfig& config,
                                              const ExecutionIdentity& identity,
                                              SandboxGuard& guard)
    {
        if (!config.allowDesktop) {
            g_logger.Log(L"DESKTOP: isolated (desktop = false, enforced by job UI limits)");
            return true;
        }

        if (identity.persistentProfile) {
            g_logger.Log(L"DESKTOP: using profile-owned ACEs (no per-run grant)");
            return true;
        }

        // Record the SID before the ACEs exist, so stale recovery can remove
        // them after a kill.
        std::wstring sidStr = SidToStringOrEmpty(pSid);
        if (sidStr.empty() || !PersistDesktopGrantIntent(sidStr)) {
            g_logger.Log(L"DESKTOP: cannot record the desktop grant for recovery — not granting");
            return false;
        }

        if (!GrantDesktopAccess(pSid)) {
            RevokeDesktopAccess();  // one of the two objects can already hold the ACE
            return false;
        }

        g_logger.Log(L"DESKTOP: granted WinSta0 + Default access");
        guard.Add([]() { RevokeDesktopAccess(); });
        return true;
    }

    inline bool EnsureAppContainerLoopback(const SandboxConfig& config,
                                           const ExecutionIdentity& identity,
                                           const std::wstring& containerName,
                                           SandboxGuard& guard)
    {
        if (config.lanMode != LanMode::WithLocalhost)
            return true;

        if (identity.persistentProfile) {
            g_logger.Log(L"LOOPBACK: using profile-owned exemption (no per-run check)");
            return true;
        }

        bool ok = EnableRunLoopback(containerName);
        g_logger.Log(ok ? L"LOOPBACK: enabled" : L"LOOPBACK: FAILED");
        if (ok)
            guard.Add([]() { DisableLoopback(); });
        return ok;
    }

    // Extract and arm the pipe-hook DLL for an AppContainer/LPAC run that
    // configured [pipes].  The DLL is written into the container's own profile
    // folder, which the container can traverse and load from (under plain
    // AppContainer and under LPAC alike) by virtue of the ACLs
    // CreateAppContainerProfile set — so no extra grant is needed.  On success
    // the child's environment carries the pipe map and `state` knows the DLL
    // to inject before resume.
    inline bool PreparePipeHook(const SandboxConfig& config,
                                PSID pSid,
                                LaunchPreparationState& state,
                                std::wstring& extraEnv)
    {
        std::wstring sidStr = SidToStringOrEmpty(pSid);
        state.hookDllPath = sidStr.empty() ? std::wstring() : PipeHookPath(sidStr, g_instanceId);
        if (state.hookDllPath.empty()) {
            g_logger.Log(L"PIPEHOOK: cannot resolve the container profile folder — aborting");
            state.failedStep = L"pipe hook folder failure";
            return false;
        }

        if (!PersistPipeHookPath(state.hookDllPath)) {
            state.failedStep = L"pipe hook cleanup record failure";
            return false;
        }
        if (!ExtractEmbeddedHookDll(state.hookDllPath)) {
            state.failedStep = L"pipe hook extraction failure";
            return false;
        }
        state.pipeHookActive = true;
        extraEnv = std::wstring(SANDY_PIPEHOOK_ENV) + L"=" + SerializePipeMap(config.pipeMap);
        g_logger.LogFmt(L"PIPEHOOK: armed for %zu pipe mapping(s)", config.pipeMap.size());
        for (const auto& entry : config.pipeMap)
            g_logger.LogFmt(L"PIPEHOOK: map %s -> %s", entry.original.c_str(), entry.local.c_str());
        return true;
    }

    inline bool PrepareLaunchState(const SandboxConfig& config,
                                   const std::wstring& exePath,
                                   const std::wstring& exeArgs,
                                   bool isRestricted,
                                   bool isAppContainer,
                                   PSID pSid,
                                   SandboxGuard& guard,
                                   LaunchPreparationState& state)
    {
        if (isAppContainer) {
            state.caps = BuildCapabilities(config);
            if (state.caps.failed) {
                g_logger.Log(L"ERROR: capability SID allocation failed — aborting before launch");
                FreeCapabilities(state.caps);
                state.failedStep = L"capability failure";
                return false;
            }
            state.sc.AppContainerSid = pSid;
            state.sc.Capabilities = state.caps.capCount > 0 ? state.caps.caps : nullptr;
            state.sc.CapabilityCount = state.caps.capCount;
            guard.Add([&state]() { FreeCapabilities(state.caps); });
        }

        // The child inherits its three standard handles and nothing else.
        LogStdinMode(config.stdinMode);
        if (!SetupStdinHandle(config.stdinMode, state.hStdin, state.hStdinFile)) {
            state.failedStep = L"stdin setup failure";
            return false;
        }

        state.attrs = BuildAttributeList(config, isAppContainer ? &state.sc : nullptr, isRestricted,
                                         { state.hStdin,
                                           GetStdHandle(STD_OUTPUT_HANDLE),
                                           GetStdHandle(STD_ERROR_HANDLE) });
        if (!state.attrs.valid) {
            state.failedStep = L"attribute list failure";
            return false;
        }
        guard.Add([&state]() { FreeAttributeList(state.attrs); });

        std::wstring extraEnv;
        if (isAppContainer && !config.pipeMap.empty()) {
            if (!PreparePipeHook(config, pSid, state, extraEnv))
                return false;
        }

        state.envBlock = BuildEnvironmentBlock(config, extraEnv);
        LogEnvironmentState(config);
        if (!g_logger.IsActive())
            PrintConfigSummary(config, exePath, exeArgs);

        return true;
    }

    inline bool ValidateRestrictedTokenIntegrity(const SandboxConfig& config,
                                                 HANDLE hRestrictedToken)
    {
        if (!hRestrictedToken)
            return true;

        DWORD ilSize = 0;
        GetTokenInformation(hRestrictedToken, TokenIntegrityLevel, nullptr, 0, &ilSize);
        if (ilSize == 0)
            return true;

        std::vector<BYTE> ilBuf(ilSize);
        auto* pTIL = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(ilBuf.data());
        if (!GetTokenInformation(hRestrictedToken, TokenIntegrityLevel, pTIL, ilSize, &ilSize))
            return true;

        DWORD actualIL = *GetSidSubAuthority(pTIL->Label.Sid,
                         *GetSidSubAuthorityCount(pTIL->Label.Sid) - 1);
        DWORD expectedIL = (config.integrity == IntegrityLevel::Low)
                           ? SECURITY_MANDATORY_LOW_RID
                           : SECURITY_MANDATORY_MEDIUM_RID;
        if (actualIL != expectedIL) {
            g_logger.LogFmt(L"TOKEN_VALIDATE: FAILED — expected IL 0x%04X, got 0x%04X. Aborting launch.",
                            expectedIL, actualIL);
            return false;
        }

        g_logger.LogFmt(L"TOKEN_VALIDATE: OK (IL=0x%04X)", actualIL);
        return true;
    }

    inline int HandleLaunchFailure(DWORD launchErr,
                                   bool isAppContainer,
                                   const ExecutionIdentity& identity,
                                   const std::wstring& containerName,
                                   SandboxGuard& guard)
    {
        g_logger.Log(L"LAUNCH: FAILED (see LAUNCH_FAILED above)");
        g_logger.LogSummary(launchErr, false, 0);

        bool notFound = (launchErr == ERROR_FILE_NOT_FOUND ||
                         launchErr == ERROR_PATH_NOT_FOUND);
        return AbortBeforeLaunch(isAppContainer, identity, containerName, guard,
                                 notFound ? SandyExit::NotFound : SandyExit::CannotExec,
                                 L"CLEANUP: complete (launch failure)",
                                 L"LAUNCH_FAILURE");
    }

    inline int AbortAfterChildLaunch(bool isAppContainer,
                                     const ExecutionIdentity& identity,
                                     const std::wstring& containerName,
                                     SandboxGuard& guard,
                                     PROCESS_INFORMATION& pi,
                                     HANDLE hJob,
                                     DWORD terminateCode,
                                     const wchar_t* cleanupReason,
                                     const wchar_t* containerContext,
                                     int sandyExit = SandyExit::SetupError)
    {
        // Withdraw the handles before AbortLaunchedChild closes them: the
        // console-ctrl handler must not use a closed handle.
        PublishChildHandles(nullptr, nullptr);
        AbortLaunchedChild(pi, hJob, terminateCode);
        if (isAppContainer && identity.deleteContainerOnExit)
            TeardownTransientContainerForCurrentRun(containerName, containerContext);
        guard.RunAll();
        FinalizeCleanupTaskForCurrentRun();
        g_logger.Log(cleanupReason);
        g_logger.Stop();
        return sandyExit;
    }

    inline void CloseLaunchStdinHandle(LaunchPreparationState& prep)
    {
        if (prep.hStdinFile) {
            CloseHandle(prep.hStdinFile);
            prep.hStdinFile = nullptr;
        }
    }

    // Fills `child` in place: the watchdog thread keeps a pointer into it.
    inline void StartManagedChild(const SandboxConfig& config,
                                  const std::wstring& exeFolder,
                                  const std::wstring& exePath,
                                  const std::wstring& exeArgs,
                                  bool isRestricted,
                                  HANDLE hRestrictedToken,
                                  LaunchPreparationState& prep,
                                  ManagedChildState& child)
    {
        bool launched = LaunchChildProcess(
            isRestricted,
            isRestricted ? hRestrictedToken : nullptr,
            prep.attrs.pAttrList, prep.attrs.inheritedHandles,
            prep.envBlock, exeFolder, exePath, exeArgs,
            prep.hStdin, child.pi);
        DWORD launchError = launched ? ERROR_SUCCESS : GetLastError();
        CloseLaunchStdinHandle(prep);

        if (!launched) {
            child.status = ChildStartStatus::LaunchFailed;
            child.launchError = launchError;
            return;
        }

        child.hJob = AssignJobObject(config, child.pi.hProcess);
        if (NeedJobTracking(config) && !child.hJob) {
            child.status = ChildStartStatus::JobAssignmentFailed;
            return;
        }

        // Publish, then look at the flag.  The handler sets the flag, then
        // looks at the handles.  At least one side sees the other, so a
        // signal at this moment cannot leave the child running unwatched.
        PublishChildHandles(child.pi.hProcess, child.hJob);
        if (ShutdownRequested()) {
            child.status = ChildStartStatus::Interrupted;
            return;
        }

        // Keep the primary thread suspended until the pipe hooks are installed.
        // Initial DLL/TLS initialization can run during remote loader startup.
        if (prep.pipeHookActive &&
            !InjectHookDll(child.pi.hProcess, child.pi.dwProcessId, prep.hookDllPath)) {
            child.status = ChildStartStatus::InjectionFailed;
            return;
        }

        ResumeThread(child.pi.hThread);
        g_logger.Log(L"CHILD: resumed");
        CloseHandleIfValid(child.pi.hThread);

        child.timeoutCtx.hProcess = child.pi.hProcess;
        child.timeoutCtx.hJob = child.hJob;
        child.timeoutCtx.seconds = config.timeoutSeconds;
        child.hTimeoutThread = StartTimeoutWatchdog(child.timeoutCtx);
        if (config.timeoutSeconds > 0 && !child.hTimeoutThread) {
            child.status = ChildStartStatus::WatchdogFailed;
            return;
        }

        child.status = ChildStartStatus::Ready;
    }

    inline DWORD WaitForManagedChild(const SandboxConfig& config, ManagedChildState& child)
    {
        return WaitForChildExit(child.pi.hProcess,
                                child.hJob,
                                child.hTimeoutThread, child.timeoutCtx,
                                config.timeoutSeconds,
                                config.allowChildProcesses);
    }

    inline void LogChildExitClassification(DWORD exitCode,
                                           bool timedOut,
                                           DWORD timeoutSeconds)
    {
        g_logger.LogSummary(exitCode, timedOut, timeoutSeconds);
        if (timedOut)
            g_logger.Log(L"EXIT_CLASS: TIMEOUT");
        else if (IsCrashExitCode(exitCode))
            g_logger.LogFmt(L"EXIT_CLASS: CRASH (0x%08X)", exitCode);
        else if (exitCode != 0)
            g_logger.LogFmt(L"EXIT_CLASS: ERROR (code=%ld)", (long)exitCode);
        else
            g_logger.Log(L"EXIT_CLASS: CLEAN");
    }

    inline int MapChildExitToSandyExit(DWORD exitCode, bool timedOut)
    {
        if (timedOut)
            return SandyExit::Timeout;
        if (IsCrashExitCode(exitCode))
            return SandyExit::ChildCrash;
        return static_cast<int>(exitCode);
    }

    inline int FinalizeCompletedRun(bool isAppContainer,
                                    const ExecutionIdentity& identity,
                                    const std::wstring& containerName,
                                    SandboxGuard& guard,
                                    PROCESS_INFORMATION& pi,
                                    HANDLE hJob,
                                    DWORD exitCode,
                                    const TimeoutContext& timeoutCtx,
                                    DWORD timeoutSeconds)
    {
        LogChildExitClassification(exitCode, timeoutCtx.timedOut, timeoutSeconds);

        PublishChildHandles(nullptr, nullptr);  // withdraw before close — no thread may use a stale handle
        ReleaseLaunchedChildHandles(pi, hJob);

        if (identity.persistentProfile)
            g_logger.Log(L"CLEANUP: starting (persistent profile ownership)");
        else
            g_logger.Log(L"CLEANUP: starting");
        DWORD cleanupStart = GetTickCount();

        if (isAppContainer && identity.deleteContainerOnExit)
            TeardownTransientContainerForCurrentRun(containerName, L"NORMAL_CLEANUP");

        // Run all guard cleanups explicitly (RevokeAllGrants, RevokeDesktopAccess,
        // DisableLoopback, FreeCapabilities, FreeAttributeList, FreeSid, CloseHandle)
        // This must finish BEFORE DeleteCleanupTask so our own grants subkey is gone.
        guard.RunAll();

        FinalizeCleanupTaskForCurrentRun();
        g_logger.LogFmt(L"CLEANUP: complete (%lums)", GetTickCount() - cleanupStart);
        g_logger.Stop();
        return MapChildExitToSandyExit(exitCode, timeoutCtx.timedOut);
    }

    // =====================================================================
    // RunPipeline — single unified sandbox pipeline
    //
    // Phases:
    //   1. SETUP    — create token/SID, log mode
    //   2. GRANT    — apply ALLOW ACEs, DENY ACEs, registry, desktop
    //   3. PREPARE  — capabilities, environment, stdin, launch attributes
    //   4. LAUNCH   — create process, job, resume, relay output
    //   5. CLEANUP  — revoke grants, delete profile, free resources
    //
    // Mode-specific steps are marked with [AC] or [RT] comments.
    // Ownership-specific behavior comes from ExecutionIdentity rather than
    // from a bolted-on "profile mode" switch.
    // =====================================================================
    inline int RunPipeline(const SandboxConfig& config,
                            const std::wstring& exePath,
                            const std::wstring& exeArgs,
                            const std::wstring& exeFolder,
                            const ExecutionIdentity& identity)
    {
        bool isRestricted = (config.tokenMode == TokenMode::Restricted);
        bool isAppContainer = !isRestricted;

        SandboxGuard guard;  // RAII — all cleanup goes through guard

        // =================================================================
        // PHASE 1: SETUP — create token/SID, log mode
        // =================================================================

        ResolvedRunIdentity resolved;
        if (!ResolveRunIdentity(config, identity, guard, resolved))
            return SandyExit::SetupError;

        ConfigureEmergencyCleanupState(resolved.containerName, identity.deleteContainerOnExit,
                                       identity.persistentProfile);

        g_logger.LogFmt(L"WORKDIR: %s", exeFolder.c_str());

        // =================================================================
        // PHASE 2: GRANT — apply ACLs (ALLOW, then DENY)
        // =================================================================

        if (!ApplyRunOwnedGrantPhase(resolved.pSid, config, identity, isRestricted,
                                     resolved.containerName, guard)) {
            return AbortBeforeLaunch(isAppContainer, identity, resolved.containerName, guard,
                                     SandyExit::SetupError,
                                     L"CLEANUP: complete (grant setup failure)");
        }

        // Desktop and loopback — profile-owned grants are set at creation,
        // transient grants are managed per-run.

        // [RT] Desktop access
        if (isRestricted) {
            if (!EnsureRestrictedDesktopAccess(resolved.pSid, config, identity, guard)) {
                return AbortBeforeLaunch(isAppContainer, identity, resolved.containerName, guard,
                                         SandyExit::SetupError,
                                         L"CLEANUP: complete (desktop grant failure)");
            }
        }

        // [AC] Loopback
        if (isAppContainer) {
            if (!EnsureAppContainerLoopback(config, identity, resolved.containerName, guard)) {
                return AbortBeforeLaunch(isAppContainer, identity, resolved.containerName, guard,
                                         SandyExit::SetupError,
                                         L"CLEANUP: complete (loopback setup failure)");
            }
        }

        // =================================================================
        // PHASE 3: PREPARE — capabilities, env, pipes
        // =================================================================

        LaunchPreparationState prep;
        if (!PrepareLaunchState(config, exePath, exeArgs, isRestricted, isAppContainer,
                                resolved.pSid, guard, prep)) {
            std::wstring reason = L"CLEANUP: complete (";
            reason += prep.failedStep ? prep.failedStep : L"launch preparation failure";
            reason += L")";
            CloseLaunchStdinHandle(prep);
            return AbortBeforeLaunch(isAppContainer, identity, resolved.containerName, guard,
                                     SandyExit::SetupError, reason.c_str());
        }

        // A signal during setup: nothing runs yet, so undo the setup and stop.
        if (ShutdownRequested()) {
            CloseLaunchStdinHandle(prep);
            return AbortBeforeLaunch(isAppContainer, identity, resolved.containerName, guard,
                                     SandyExit::SetupError,
                                     L"CLEANUP: complete (interrupted before launch)");
        }

        // =================================================================
        // PHASE 4: LAUNCH & RUN
        // =================================================================

        // Log config before launch so it's always in the log even for instant failures
        g_logger.LogConfig(config, exePath, exeArgs);

        // Step 3f: [RT] Pre-launch token integrity validation (defense-in-depth)
        // Verify the restricted token's integrity level matches the configured
        // value before handing it to CreateProcessAsUser.  Catches any subtle
        // mutation that could have occurred during Phases 2-3.
        if (isRestricted && !ValidateRestrictedTokenIntegrity(config, resolved.hRestrictedToken)) {
            CloseLaunchStdinHandle(prep);
            return AbortBeforeLaunch(isAppContainer, identity, resolved.containerName, guard,
                                     SandyExit::SetupError,
                                     L"CLEANUP: complete (token validation failure)");
        }

        ManagedChildState child;
        StartManagedChild(config, exeFolder, exePath, exeArgs,
                          isRestricted, resolved.hRestrictedToken, prep, child);
        if (child.status == ChildStartStatus::LaunchFailed) {
            return HandleLaunchFailure(child.launchError, isAppContainer, identity,
                                       resolved.containerName, guard);
        }
        if (child.status == ChildStartStatus::Interrupted) {
            g_logger.Log(L"LAUNCH: interrupted — child terminated before it ran");
            return AbortAfterChildLaunch(isAppContainer, identity, resolved.containerName, guard,
                                         child.pi, child.hJob, SandyExit::SetupError,
                                         L"CLEANUP: complete (interrupted at launch)",
                                         L"INTERRUPTED");
        }
        if (child.status == ChildStartStatus::JobAssignmentFailed) {
            g_logger.Log(L"ERROR: job object assignment failed — aborting (limits NOT enforced)");
            return AbortAfterChildLaunch(isAppContainer, identity, resolved.containerName, guard,
                                         child.pi, child.hJob, SandyExit::SetupError,
                                         L"CLEANUP: complete (job assignment failure)",
                                         L"JOB_ASSIGN_FAILURE");
        }
        if (child.status == ChildStartStatus::InjectionFailed) {
            g_logger.Log(L"ERROR: pipe-hook injection failed — aborting before app entry");
            return AbortAfterChildLaunch(isAppContainer, identity, resolved.containerName, guard,
                                         child.pi, child.hJob, SandyExit::SetupError,
                                         L"CLEANUP: complete (pipe-hook injection failure)",
                                         L"INJECTION_FAILURE");
        }

        // F4/R8: Fail closed — if timeout is configured but watchdog couldn't
        // start, abort launch.  The child is already resumed but we terminate
        // it immediately to prevent running without time limits.
        if (child.status == ChildStartStatus::WatchdogFailed) {
            g_logger.Log(L"ERROR: timeout configured but watchdog thread failed — aborting");
            return AbortAfterChildLaunch(isAppContainer, identity, resolved.containerName, guard,
                                         child.pi, child.hJob, SandyExit::SetupError,
                                         L"CLEANUP: complete (watchdog failure)",
                                         L"WATCHDOG_FAILURE");
        }

        // Step 4e: Wait for child exit (console passthrough — no pipe relay)
        DWORD exitCode = WaitForManagedChild(config, child);
        return FinalizeCompletedRun(isAppContainer, identity, resolved.containerName, guard,
                                    child.pi, child.hJob, exitCode, child.timeoutCtx,
                                    config.timeoutSeconds);
    }

    // Forward declaration — defined in SandboxSavedProfile.h
    inline void CleanStagingProfiles();

    inline void BeginRunSession(const std::wstring& exePath,
                                const std::wstring& configSource,
                                const std::wstring& profileName = L"")
    {
        // From here on stdout belongs to the child (see RecoveryPrintf).
        g_recoveryConsoleOutput = false;
        ResetGrantMetadataPreservation();
        ResetDeferredCleanupRequest();
        CleanupStaleStartupState(exePath);
        CleanStagingProfiles();
        RestoreStaleGrants();
        DeleteStaleCleanupTasks();
        WarnStaleRegistryEntries();
        // P2: CreateCleanupTask moved to after ledger is established
        // (InitializeRunLedger for transient, PersistLiveState for profile)
        LogSandyIdentity();
        g_logger.Log((L"INSTANCE: " + g_instanceId).c_str());
        if (!profileName.empty())
            g_logger.Log((L"PROFILE: " + profileName).c_str());
        if (!configSource.empty())
            g_logger.Log((L"CONFIG_SOURCE: " + configSource).c_str());
    }

    // =====================================================================
    // RunSandboxed — common entry point.
    //
    // Ephemeral compatibility path. Creates a transient execution identity,
    // then runs through the same ownership-driven pipeline as saved profiles.
    // =====================================================================
    inline int RunSandboxed(const SandboxConfig& config,
                            const std::wstring& exePath,
                            const std::wstring& exeArgs)
    {
        ResetEmergencyCleanupState();
        g_instanceId = GenerateInstanceId();
        if (g_instanceId.empty()) {
            fprintf(stderr, "Error: failed to generate instance ID (CoCreateGuid failed).\n");
            return SandyExit::SetupError;
        }

        std::wstring exeFolder = config.workdir.empty() ? GetInheritedWorkdir() : config.workdir;
        if (exeFolder.empty())
            return SandyExit::SetupError;

        BeginRunSession(exePath, config.configSource);

        ExecutionIdentity identity;
        identity.containerName = ContainerNameFromId(g_instanceId);
        identity.persistentProfile = false;
        identity.grantsPreexisting = false;
        identity.deleteContainerOnExit = (config.tokenMode != TokenMode::Restricted);

        int result = RunPipeline(config, exePath, exeArgs, exeFolder, identity);
        ResetEmergencyCleanupState();
        return result;
    }

    // -----------------------------------------------------------------------
    // CleanupSandbox — emergency cleanup for the SEH crash path.
    //
    // Runs on the main thread, after its normal teardown was cut short by a
    // fatal exception.  Console signals do not come here: they set the
    // shutdown request and the main thread runs its normal teardown.
    //
    // MUST terminate the child process before dismantling sandbox state.
    // If the child cannot be confirmed dead, skip in-place teardown and
    // let stale-state recovery handle it on next run.
    // -----------------------------------------------------------------------
    inline void CleanupSandbox()
    {
        g_logger.Log(L"EMERGENCY_CLEANUP: starting");
        EmergencyCleanupState cleanupState = SnapshotEmergencyCleanupState();

        // Step 0: terminate the owned process tree before revoking sandbox state.
        // The job object is the authoritative run lifetime when child processes
        // are allowed. Falling back to the root process alone is only for paths
        // that never created a job.
        HANDLE hChild = g_childProcess;
        HANDLE hJob = g_childJob;
        if (hJob) {
            g_logger.Log(L"EMERGENCY_CLEANUP: terminating sandbox job");
            TerminateJobObject(hJob, 1);
            if (!WaitForJobTreeExit(hJob, 5000)) {
                g_logger.Log(L"EMERGENCY_CLEANUP: job did not quiesce within 5s, deferring cleanup to next run");
                g_logger.Stop();
                return;
            }
            g_logger.Log(L"EMERGENCY_CLEANUP: sandbox job terminated");
        } else if (hChild) {
            g_logger.Log(L"EMERGENCY_CLEANUP: terminating child process");
            TerminateProcess(hChild, 1);
            DWORD waitResult = WaitForSingleObject(hChild, 5000);
            if (waitResult != WAIT_OBJECT_0) {
                // Child could not be confirmed dead — skip in-place teardown.
                // Stale-state recovery on next run will clean up.
                g_logger.Log(L"EMERGENCY_CLEANUP: child did not terminate within 5s, deferring cleanup to next run");
                g_logger.Stop();
                return;
            }
            g_logger.Log(L"EMERGENCY_CLEANUP: child terminated");
        }

        // Profile-owned state (desktop, grants, loopback) is not revoked here —
        // it belongs to the profile lifecycle (create/delete), not the run.
        if (!cleanupState.persistentProfile) {
            RevokeDesktopAccess();
            RevokeAllGrants();
            DisableLoopback();
        } else {
            g_logger.Log(L"EMERGENCY_CLEANUP: skipping grant/desktop/loopback (profile-owned)");
            // Clear this run's live-state ledger so the next run's stale sweep
            // sees a dead-instance record to reap rather than an apparently-live
            // entry pointing at our soon-to-exit PID.
            ClearLiveState();
        }
        if (cleanupState.deleteContainerOnExit && !cleanupState.containerName.empty())
            TeardownTransientContainerForCurrentRun(cleanupState.containerName, L"EMERGENCY_CLEANUP");
        // Cleanup-task retention is ledger-driven: if any retry metadata
        // survived emergency cleanup, FinalizeCleanupTaskForCurrentRun keeps it.
        if (!g_instanceId.empty())
            FinalizeCleanupTaskForCurrentRun();
        ResetEmergencyCleanupState();
        g_logger.Log(L"EMERGENCY_CLEANUP: complete");
        g_logger.Stop();
    }

} // namespace Sandbox
