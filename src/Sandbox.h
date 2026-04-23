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


namespace Sandbox {

    struct ExecutionIdentity;

    // Global launch ownership handles for emergency cleanup coordination.
    // The process handle tracks the root process; the job handle tracks the
    // whole sandbox-owned process tree when descendants are allowed.
    inline HANDLE g_childProcess = nullptr;
    inline HANDLE g_childJob = nullptr;

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
    inline void RecordGrantCallback(const std::wstring& path,
                                     SE_OBJECT_TYPE objType,
                                     const std::wstring& sidString,
                                     const std::wstring& trappedSids,
                                     bool isDeny,
                                     bool isPeek)
    {
        RecordGrant(path, objType, sidString, trappedSids, isDeny, isPeek);
    }

    // -----------------------------------------------------------------------
    // ApplyAccessPipeline — depth-sorted grant/deny execution.
    //
    // Merges all allow + deny entries into a single pipeline sorted by path
    // depth (shallowest first).  When an allow path is under a previously
    // applied deny, strips the deny ACEs from the allow subtree first, then
    // grants.  Peek strips are non-recursive (directory only).
    //
    // This ensures the most specific (deepest) path always wins.
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

    // Check if `child` is at or under `parent` (case-insensitive, backslash boundary)
    static bool IsPathUnder(const std::wstring& child, const std::wstring& parent) {
        std::wstring normalizedChild = NormalizeFsPath(child);
        std::wstring normalizedParent = NormalizeFsPath(parent);
        if (normalizedChild.size() < normalizedParent.size()) return false;
        if (_wcsnicmp(normalizedChild.c_str(), normalizedParent.c_str(), normalizedParent.size()) != 0) return false;
        // Exact match
        if (normalizedChild.size() == normalizedParent.size()) return true;
        // Parent ends with backslash (drive root like "C:\") — every prefix
        // match is already a proper child because the separator is built in.
        if (!normalizedParent.empty() && normalizedParent.back() == L'\\') return true;
        // Normal case: child continues with a backslash boundary
        return normalizedChild[normalizedParent.size()] == L'\\';
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

    inline bool IsPathUnderAny(const std::wstring& candidate,
                               const std::vector<std::wstring>& parents)
    {
        for (const auto& parent : parents) {
            if (IsPathUnder(candidate, parent))
                return true;
        }
        return false;
    }

    inline std::vector<std::wstring> CollectDenyPaths(const AccessPipeline& pipeline)
    {
        std::vector<std::wstring> denyPaths;
        for (const auto& entry : pipeline) {
            if (entry.isDeny)
                denyPaths.push_back(entry.path);
        }
        return denyPaths;
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
        std::vector<std::wstring> preDenyPaths = CollectDenyPaths(pipeline);
        for (const auto& e : pipeline) {
            bool underDeny = !e.isDeny && IsPathUnderAny(e.path, preDenyPaths);
            if (e.isDeny) {
                g_logger.LogFmt(L"    DENY  [%-7s] %s",
                    AccessTag(e.access), e.path.c_str());
            } else if (underDeny && e.scope == GrantScope::This) {
                g_logger.LogFmt(L"    ALLOW [%-7s] %s  <- strip deny (dir only)",
                    AccessTag(e.access), e.path.c_str());
            } else if (underDeny) {
                g_logger.LogFmt(L"    ALLOW [%-7s] %s  <- strip deny (subtree)",
                    AccessTag(e.access), e.path.c_str());
            } else {
                g_logger.LogFmt(L"    ALLOW [%-7s] %s",
                    AccessTag(e.access), e.path.c_str());
            }
        }
    }

    inline bool ApplyDenyPipelineEntry(PSID pSid,
                                       const PipelineEntry& entry,
                                       std::vector<std::wstring>& activeDenyPaths)
    {
        DWORD rc = DenyObjectAccess(pSid, entry.path, entry.access, RecordGrantCallback,
                                    SE_FILE_OBJECT, entry.scope);
        if (rc != ERROR_SUCCESS) {
            g_logger.LogFmt(L"DENY: [%s] %s -> FAILED (0x%08X: %s)",
                            AccessTag(entry.access), entry.path.c_str(),
                            rc, GetSystemErrorMessage(rc).c_str());
            return false;
        }

        g_logger.LogFmt(L"DENY: [%s] %s -> OK (mask=0x%08X)",
                        AccessTag(entry.access), entry.path.c_str(),
                        AccessMask(entry.access));
        activeDenyPaths.push_back(entry.path);
        return true;
    }

    inline bool ApplyAllowPipelineEntry(PSID pSid,
                                        const PipelineEntry& entry,
                                        const std::wstring& sidStr,
                                        const std::vector<std::wstring>& activeDenyPaths)
    {
        bool underDeny = IsPathUnderAny(entry.path, activeDenyPaths);
        if (underDeny) {
            bool isThis = (entry.scope == GrantScope::This);
            if (!sidStr.empty()) {
                g_logger.LogFmt(L"STRIP_DENY: %s (%s)",
                                entry.path.c_str(), isThis ? L"dir only" : L"subtree");
                RemoveSidFromDacl(entry.path, sidStr, SE_FILE_OBJECT,
                                  DaclProtectionIntent::ForceProtected,
                                  isThis, AceRemovalMode::DenyOnly);
            } else {
                g_logger.LogFmt(L"STRIP_DENY: skipped for %s (SID conversion failed)",
                                entry.path.c_str());
            }
        }

        DWORD rc = GrantObjectAccess(pSid, entry.path, entry.access, RecordGrantCallback,
                                     SE_FILE_OBJECT, entry.scope);
        if (rc != ERROR_SUCCESS) {
            g_logger.LogFmt(L"GRANT: [%s] %s -> FAILED (0x%08X: %s)",
                            AccessTag(entry.access), entry.path.c_str(),
                            rc, GetSystemErrorMessage(rc).c_str());
            return false;
        }

        g_logger.LogFmt(L"GRANT: [%s] %s -> OK (mask=0x%08X)",
                        AccessTag(entry.access), entry.path.c_str(),
                        AccessMask(entry.access));
        return true;
    }

    inline bool ExecuteAccessPipeline(PSID pSid, const AccessPipeline& pipeline)
    {
        bool allOk = true;
        std::vector<std::wstring> activeDenyPaths;
        std::wstring sidStr = SidToStringOrEmpty(pSid);

        for (const auto& entry : pipeline) {
            bool ok = entry.isDeny
                ? ApplyDenyPipelineEntry(pSid, entry, activeDenyPaths)
                : ApplyAllowPipelineEntry(pSid, entry, sidStr, activeDenyPaths);
            if (!ok)
                allOk = false;
        }
        return allOk;
    }

    inline bool ApplyAccessPipeline(PSID pSid, const SandboxConfig& config)
    {
        AccessPipeline pipeline = BuildAccessPipeline(config);
        LogAccessPipelinePlan(pipeline);
        return ExecuteAccessPipeline(pSid, pipeline);
    }

    // -----------------------------------------------------------------------
    // GrantRegistryAccess — apply configured registry key grants.
    // -----------------------------------------------------------------------
    inline bool GrantRegistryAccess(PSID pSid, const SandboxConfig& config)
    {
        bool allOk = true;
        struct RegGrant { const std::vector<std::wstring>& keys; AccessLevel level; const wchar_t* tag; };
        for (auto& rg : { RegGrant{config.registryRead, AccessLevel::Read, L"R"},
                          RegGrant{config.registryWrite, AccessLevel::Write, L"W"} }) {
            for (const auto& key : rg.keys) {
                std::wstring win32Path = RegistryToWin32Path(key);
                DWORD rc = GrantObjectAccess(pSid, win32Path, rg.level, RecordGrantCallback, SE_REGISTRY_KEY);
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
        guard.Add([&r]() { if (r.hRestrictedToken) CloseHandle(r.hRestrictedToken); });

        LPWSTR sidStr = nullptr;
        if (ConvertSidToStringSidW(pGrantSid, &sidStr)) {
            g_logger.LogFmt(L"RT_SID: %s", sidStr);
            LocalFree(sidStr);
        }
        g_logger.Log(config.integrity == IntegrityLevel::Low
                     ? L"MODE: restricted token (Low integrity)"
                     : L"MODE: restricted token (Medium integrity)");
        g_logger.Log(config.allowNamedPipes ? L"Named Pipes: allowed (Everyone in restricting SIDs)"
                                           : L"Named Pipes: blocked (Everyone excluded)");
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
    };

    enum class ChildStartStatus {
        Ready,
        LaunchFailed,
        JobAssignmentFailed,
        WatchdogFailed
    };

    struct ManagedChildState {
        ChildStartStatus     status = ChildStartStatus::LaunchFailed;
        DWORD                launchError = 0;
        PROCESS_INFORMATION  pi{};
        HANDLE               hJob = nullptr;
        TimeoutContext       timeoutCtx{};
        HANDLE               hTimeoutThread = nullptr;
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

        InitializeRunLedger(containerName);
        // P2: Create cleanup task AFTER the ledger exists so concurrent
        // DeleteStaleCleanupTasks won't discard our freshly created task.
        CreateCleanupTask(g_instanceId);
        ULONGLONG tGrantStart = GetTickCount64();
        ResetGrantTrackingHealth();
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
            g_logger.Log(L"DESKTOP: disabled (desktop = false)");
            return true;
        }

        if (identity.persistentProfile) {
            g_logger.Log(L"DESKTOP: using profile-owned ACEs (no per-run grant)");
            return true;
        }

        if (!GrantDesktopAccess(pSid))
            return false;

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
                return false;
            }
            state.sc.AppContainerSid = pSid;
            state.sc.Capabilities = state.caps.capCount > 0 ? state.caps.caps : nullptr;
            state.sc.CapabilityCount = state.caps.capCount;
            guard.Add([&state]() { FreeCapabilities(state.caps); });
        }

        state.attrs = BuildAttributeList(config, isAppContainer ? &state.sc : nullptr, isRestricted);
        if (!state.attrs.valid)
            return false;
        guard.Add([&state]() { FreeAttributeList(state.attrs); });

        LogStdinMode(config.stdinMode);
        state.envBlock = BuildEnvironmentBlock(config);
        LogEnvironmentState(config);
        if (!g_logger.IsActive())
            PrintConfigSummary(config, exePath, exeArgs);

        return SetupStdinHandle(config.stdinMode, state.hStdin, state.hStdinFile);
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
        // Terminate BEFORE clearing the emergency globals.  If a CTRL_C fires
        // between the clear and the terminate, the handler would see nullptrs
        // and skip killing the child that is still alive.
        AbortLaunchedChild(pi, hJob, terminateCode);
        g_childProcess = nullptr;
        g_childJob = nullptr;
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

    inline ManagedChildState StartManagedChild(const SandboxConfig& config,
                                               const std::wstring& exeFolder,
                                               const std::wstring& exePath,
                                               const std::wstring& exeArgs,
                                               bool isRestricted,
                                               HANDLE hRestrictedToken,
                                               LaunchPreparationState& prep)
    {
        ManagedChildState child;

        bool launched = LaunchChildProcess(
            isRestricted,
            isRestricted ? hRestrictedToken : nullptr,
            prep.attrs.pAttrList, prep.envBlock, exeFolder, exePath, exeArgs,
            prep.hStdin, child.pi);
        DWORD launchError = launched ? ERROR_SUCCESS : GetLastError();
        CloseLaunchStdinHandle(prep);

        if (!launched) {
            child.status = ChildStartStatus::LaunchFailed;
            child.launchError = launchError;
            return child;
        }

        child.hJob = AssignJobObject(config, child.pi.hProcess);
        if (NeedJobTracking(config) && !child.hJob) {
            child.status = ChildStartStatus::JobAssignmentFailed;
            return child;
        }

        g_childProcess = child.pi.hProcess;
        g_childJob = child.hJob;

        ResumeThread(child.pi.hThread);
        g_logger.Log(L"CHILD: resumed");
        CloseHandleIfValid(child.pi.hThread);

        child.timeoutCtx = { child.pi.hProcess, child.hJob, config.timeoutSeconds, false };
        child.hTimeoutThread = StartTimeoutWatchdog(child.timeoutCtx);
        if (config.timeoutSeconds > 0 && !child.hTimeoutThread) {
            child.status = ChildStartStatus::WatchdogFailed;
            return child;
        }

        child.status = ChildStartStatus::Ready;
        return child;
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

        g_childProcess = nullptr;  // clear before close — emergency path must not use stale handle
        g_childJob = nullptr;
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
            const wchar_t* reason = (isAppContainer && prep.caps.failed)
                ? L"CLEANUP: complete (capability failure)"
                : (!prep.attrs.valid)
                    ? L"CLEANUP: complete (attribute list failure)"
                    : L"CLEANUP: complete (stdin setup failure)";
            return AbortBeforeLaunch(isAppContainer, identity, resolved.containerName, guard,
                                     SandyExit::SetupError, reason);
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

        ManagedChildState child = StartManagedChild(config, exeFolder, exePath, exeArgs,
                                                    isRestricted, resolved.hRestrictedToken, prep);
        if (child.status == ChildStartStatus::LaunchFailed) {
            return HandleLaunchFailure(child.launchError, isAppContainer, identity,
                                       resolved.containerName, guard);
        }
        if (child.status == ChildStartStatus::JobAssignmentFailed) {
            g_logger.Log(L"ERROR: job object assignment failed — aborting (limits NOT enforced)");
            return AbortAfterChildLaunch(isAppContainer, identity, resolved.containerName, guard,
                                         child.pi, child.hJob, SandyExit::SetupError,
                                         L"CLEANUP: complete (job assignment failure)",
                                         L"JOB_ASSIGN_FAILURE");
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
    // CleanupSandbox — emergency cleanup for Ctrl+C / SEH crash paths.
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
