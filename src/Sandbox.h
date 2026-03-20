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
#include "SandboxDynamic.h"

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

    inline bool ApplyAccessPipeline(PSID pSid, const SandboxConfig& config, bool isAppContainer)
    {
        // 1. Build pipeline
        std::vector<PipelineEntry> pipeline;
        for (const auto& e : config.folders) {
            if (e.path.empty()) continue;
            pipeline.push_back({ e.path, e.access, false, PathDepth(e.path), e.scope });
        }
        for (const auto& e : config.denyFolders) {
            if (e.path.empty()) continue;
            pipeline.push_back({ e.path, e.access, true, PathDepth(e.path), e.scope });
        }

        // 2. Stable sort: by depth ascending, deny before allow at same depth
        std::stable_sort(pipeline.begin(), pipeline.end(),
            [](const PipelineEntry& a, const PipelineEntry& b) {
                if (a.depth != b.depth) return a.depth < b.depth;
                // deny before allow at same depth
                if (a.isDeny != b.isDeny) return a.isDeny;
                return false;
            });

        // 3. Log the sorted plan
        g_logger.LogFmt(L"PIPELINE: sorted %zu entries by path depth:", pipeline.size());
        // Pre-scan: collect deny paths for annotation
        std::vector<std::wstring> preDenyPaths;
        for (const auto& e : pipeline) {
            if (e.isDeny) {
                preDenyPaths.push_back(e.path);
            }
        }
        for (const auto& e : pipeline) {
            bool underDeny = false;
            if (!e.isDeny) {
                for (const auto& dp : preDenyPaths) {
                    if (IsPathUnder(e.path, dp)) { underDeny = true; break; }
                }
            }
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

        // 4. Execute pipeline
        bool allOk = true;
        std::vector<std::wstring> activeDenyPaths;
        // Convert SID to string once (for RemoveSidFromDacl calls)
        std::wstring sidStr;
        {
            LPWSTR s = nullptr;
            if (ConvertSidToStringSidW(pSid, &s)) {
                sidStr = s;
                LocalFree(s);
            }
        }

        for (const auto& e : pipeline) {
            if (e.isDeny) {
                // Apply deny
                DWORD rc = DenyObjectAccess(pSid, e.path, e.access, RecordGrantCallback,
                                            SE_FILE_OBJECT, e.scope);
                bool ok = (rc == ERROR_SUCCESS);
                if (!ok) allOk = false;
                if (ok) {
                    g_logger.LogFmt(L"DENY: [%s] %s -> OK (mask=0x%08X)",
                        AccessTag(e.access), e.path.c_str(), AccessMask(e.access));
                    activeDenyPaths.push_back(e.path);
                } else {
                    g_logger.LogFmt(L"DENY: [%s] %s -> FAILED (0x%08X: %s)",
                        AccessTag(e.access), e.path.c_str(),
                        rc, GetSystemErrorMessage(rc).c_str());
                }
            } else {
                // Check if this allow is under an active deny
                bool underDeny = false;
                for (const auto& dp : activeDenyPaths) {
                    if (IsPathUnder(e.path, dp)) { underDeny = true; break; }
                }

                // Strip deny ACEs if needed
                if (underDeny && !sidStr.empty()) {
                    bool isThis = (e.scope == GrantScope::This);
                    g_logger.LogFmt(L"STRIP_DENY: %s (%s)",
                        e.path.c_str(), isThis ? L"dir only" : L"subtree");
                    RemoveSidFromDacl(e.path, sidStr, SE_FILE_OBJECT,
                                     DaclProtectionIntent::ForceProtected, isThis, AceRemovalMode::DenyOnly);
                }

                // Apply allow
                DWORD rc = GrantObjectAccess(pSid, e.path, e.access, RecordGrantCallback,
                                             SE_FILE_OBJECT, e.scope);
                bool ok = (rc == ERROR_SUCCESS);
                if (!ok) allOk = false;
                if (ok) {
                    g_logger.LogFmt(L"GRANT: [%s] %s -> OK (mask=0x%08X)",
                        AccessTag(e.access), e.path.c_str(), AccessMask(e.access));
                } else {
                    g_logger.LogFmt(L"GRANT: [%s] %s -> FAILED (0x%08X: %s)",
                        AccessTag(e.access), e.path.c_str(),
                        rc, GetSystemErrorMessage(rc).c_str());
                }
            }
        }
        return allOk;
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

    // -----------------------------------------------------------------------
    // DynamicWatcherThread — polls config file, applies only grant deltas.
    //
    // Computes the set difference between old and new grant entries.
    // Only grants added entries and revokes removed entries.
    // A small config change (e.g. adding one peek path) results in
    // exactly one grant operation — no regranting of existing entries.
    //
    // Lives in Sandbox.h because it calls GrantObjectAccess, DenyObjectAccess,
    // RemoveSidFromDacl, and GrantRegistryAccess defined above.
    // -----------------------------------------------------------------------
    static DWORD WINAPI DynamicWatcherThread(LPVOID param)
    {
        auto* ctx = static_cast<DynamicContext*>(param);
        ULONGLONG lastWriteTime = GetFileLastWriteTime(ctx->configPath);
        int reloadCount = 0;

        // Build initial grant key sets
        std::set<GrantKey> currentKeys = BuildGrantKeySet(ctx->currentConfig);
        std::set<RegGrantKey> currentRegKeys = BuildRegKeySet(ctx->currentConfig);

        g_logger.LogFmt(L"DYNAMIC: watcher started (polling every 2s, %zu file + %zu reg entries tracked)",
                        currentKeys.size(), currentRegKeys.size());

        while (true) {
            // Wait 2s or until stop event is signaled (child exited)
            DWORD waitResult = WaitForSingleObject(ctx->hStopEvent, 2000);
            if (waitResult == WAIT_OBJECT_0)
                break;

            // Check if child process is still alive
            if (WaitForSingleObject(ctx->hProcess, 0) != WAIT_TIMEOUT)
                break;

            // Check file modification time
            ULONGLONG newWriteTime = GetFileLastWriteTime(ctx->configPath);
            if (newWriteTime == 0 || newWriteTime == lastWriteTime)
                continue;

            // Do NOT advance lastWriteTime yet — only commit after success
            // so failed reloads are retried on the next poll cycle.
            g_logger.Log(L"DYNAMIC: config file changed, reloading...");

            // Load and parse new config
            SandboxConfig newConfig = LoadConfig(ctx->configPath);
            if (newConfig.parseError) {
                g_logger.Log(L"DYNAMIC: config reload FAILED (parse error), keeping current grants");
                continue;
            }

            // Warn about immutable setting changes
            WarnImmutableChanges(ctx->currentConfig, newConfig);

            // P1: Sanitize reloaded config — force immutable fields back to
            // the original values.  Without this, changing token from
            // 'appcontainer' to 'restricted' in the config file would cause
            // BuildGrantKeySet to include deny entries, which DenyObjectAccess
            // then stamps onto the DACL with D:PAI — a real host-state
            // regression even though the kernel ignores the DENY ACEs.
            newConfig.tokenMode  = ctx->currentConfig.tokenMode;
            newConfig.integrity  = ctx->currentConfig.integrity;
            newConfig.strict     = ctx->currentConfig.strict;
            if (ctx->isAppContainer) {
                // AC mode: deny and registry are invalid — strip them
                newConfig.denyFolders.clear();
                newConfig.registryRead.clear();
                newConfig.registryWrite.clear();
            }

            // ---- File/folder grant delta ----
            std::set<GrantKey> newKeys = BuildGrantKeySet(newConfig);

            // Compute delta: removed = in current but not in new
            std::vector<GrantKey> removed;
            std::set_difference(currentKeys.begin(), currentKeys.end(),
                                newKeys.begin(), newKeys.end(),
                                std::back_inserter(removed));

            // Compute delta: added = in new but not in current
            std::vector<GrantKey> added;
            std::set_difference(newKeys.begin(), newKeys.end(),
                                currentKeys.begin(), currentKeys.end(),
                                std::back_inserter(added));

            // ---- Registry grant delta (RT mode only) ----
            std::set<RegGrantKey> newRegKeys = BuildRegKeySet(newConfig);
            std::vector<RegGrantKey> regRemoved, regAdded;

            if (!ctx->isAppContainer) {
                std::set_difference(currentRegKeys.begin(), currentRegKeys.end(),
                                    newRegKeys.begin(), newRegKeys.end(),
                                    std::back_inserter(regRemoved));
                std::set_difference(newRegKeys.begin(), newRegKeys.end(),
                                    currentRegKeys.begin(), currentRegKeys.end(),
                                    std::back_inserter(regAdded));
            }

            // Skip if no grant changes
            if (removed.empty() && added.empty() && regRemoved.empty() && regAdded.empty()) {
                g_logger.Log(L"DYNAMIC: config reloaded, no grant changes");
                continue;
            }

            ULONGLONG tStart = GetTickCount64();
            int revokeCount = 0, grantCount = 0, failCount = 0;
            ResetGrantTrackingHealth();

            auto ReapplySamePathFileEntries = [&](const std::wstring& path) -> bool {
                std::vector<GrantKey> survivors;
                for (const auto& k : newKeys) {
                    if (_wcsicmp(k.path.c_str(), path.c_str()) == 0)
                        survivors.push_back(k);
                }
                if (survivors.empty())
                    return true;

                std::stable_sort(survivors.begin(), survivors.end(),
                    [](const GrantKey& a, const GrantKey& b) {
                        if (a.isDeny != b.isDeny) return a.isDeny;
                        return false;
                    });

                bool hasDeny = false;
                for (const auto& entry : survivors) {
                    if (entry.isDeny) {
                        hasDeny = true;
                        break;
                    }
                }

                bool ok = true;
                for (const auto& entry : survivors) {
                    if (entry.isDeny) {
                        DWORD rc = DenyObjectAccess(ctx->pSid, entry.path, entry.access,
                                                    RecordGrantCallback,
                                                    SE_FILE_OBJECT, entry.scope);
                        if (rc == ERROR_SUCCESS) {
                            g_logger.LogFmt(L"DYNAMIC_REAPPLY: [deny] %s -> OK",
                                            entry.path.c_str());
                            grantCount++;
                        } else {
                            g_logger.LogFmt(L"DYNAMIC_REAPPLY: [deny] %s -> FAILED (0x%08X)",
                                            entry.path.c_str(), rc);
                            failCount++;
                            ok = false;
                        }
                        continue;
                    }

                    if (hasDeny && !ctx->sidString.empty()) {
                        bool isThis = (entry.scope == GrantScope::This);
                        g_logger.LogFmt(L"DYNAMIC_REAPPLY: strip deny [%s] %s",
                                        AccessTag(entry.access), entry.path.c_str());
                        RemoveSidFromDacl(entry.path, ctx->sidString, SE_FILE_OBJECT,
                                          DaclProtectionIntent::ForceProtected, isThis, AceRemovalMode::DenyOnly);
                    }

                    DWORD rc = GrantObjectAccess(ctx->pSid, entry.path, entry.access,
                                                 RecordGrantCallback,
                                                 SE_FILE_OBJECT, entry.scope);
                    if (rc == ERROR_SUCCESS) {
                        g_logger.LogFmt(L"DYNAMIC_REAPPLY: [%s] %s -> OK",
                                        AccessTag(entry.access), entry.path.c_str());
                        grantCount++;
                    } else {
                        g_logger.LogFmt(L"DYNAMIC_REAPPLY: [%s] %s -> FAILED (0x%08X)",
                                        AccessTag(entry.access), entry.path.c_str(), rc);
                        failCount++;
                        ok = false;
                    }
                }
                return ok;
            };

            auto ReapplySamePathRegistryEntries = [&](const std::wstring& path) -> bool {
                bool ok = true;
                for (const auto& entry : newRegKeys) {
                    if (_wcsicmp(entry.path.c_str(), path.c_str()) != 0)
                        continue;

                    std::wstring win32Path = RegistryToWin32Path(entry.path);
                    DWORD rc = GrantObjectAccess(ctx->pSid, win32Path, entry.access,
                                                 RecordGrantCallback, SE_REGISTRY_KEY);
                    if (rc == ERROR_SUCCESS) {
                        g_logger.LogFmt(L"DYNAMIC_REAPPLY_REG: [%s] %s -> OK",
                                        entry.access == AccessLevel::Read ? L"R" : L"W",
                                        entry.path.c_str());
                        grantCount++;
                    } else {
                        g_logger.LogFmt(L"DYNAMIC_REAPPLY_REG: [%s] %s -> FAILED (0x%08X)",
                                        entry.access == AccessLevel::Read ? L"R" : L"W",
                                        entry.path.c_str(), rc);
                        failCount++;
                        ok = false;
                    }
                }
                return ok;
            };

            // ---- Phase 1: Revoke removed entries ----
            std::set<std::wstring> removedFilePaths;
            for (const auto& r : removed)
                removedFilePaths.insert(ToLower(r.path));

            for (const auto& pathLower : removedFilePaths) {
                std::wstring path;
                bool hadDeny = false;
                bool peekOnly = true;

                for (const auto& current : currentKeys) {
                    if (current.pathLower != pathLower)
                        continue;
                    if (path.empty())
                        path = current.path;
                    if (current.isDeny)
                        hadDeny = true;
                    if (current.scope != GrantScope::This)
                        peekOnly = false;
                }

                if (path.empty())
                    continue;

                if (RevokePathEntries(path, ctx->sidString, SE_FILE_OBJECT, hadDeny, peekOnly))
                    revokeCount++;
                else
                    failCount++;

                ReapplySamePathFileEntries(path);
            }

            // ---- Phase 2: Apply added entries (context-aware) ----
            //
            // Correctness requires replicating the pipeline's deny interaction:
            //   a) New allow under existing deny → strip deny ACEs first
            //   b) New deny over existing allows → re-grant affected allows
            //
            // Collect ALL deny paths from the full NEW config for context.
            std::vector<std::wstring> allNewDenyPaths;
            for (const auto& k : newKeys) {
                if (k.isDeny) allNewDenyPaths.push_back(k.path);
            }

            // Phase 2a: Apply denies first, then allows (depth-order within delta)
            //           This mirrors the pipeline's deny-before-allow rule.
            std::vector<GrantKey> addedDenies, addedAllows;
            for (const auto& a : added) {
                if (removedFilePaths.count(a.pathLower))
                    continue;
                if (a.isDeny) addedDenies.push_back(a);
                else          addedAllows.push_back(a);
            }

            // Apply new deny entries
            for (const auto& d : addedDenies) {
                DWORD rc = DenyObjectAccess(ctx->pSid, d.path, d.access,
                                            RecordGrantCallback,
                                            SE_FILE_OBJECT, d.scope);
                if (rc == ERROR_SUCCESS) {
                    g_logger.LogFmt(L"DYNAMIC_GRANT: [deny] %s -> OK", d.path.c_str());
                    grantCount++;
                } else {
                    g_logger.LogFmt(L"DYNAMIC_GRANT: [deny] %s -> FAILED (0x%08X)",
                                    d.path.c_str(), rc);
                    failCount++;
                    continue;
                }

                // Phase 2b: New deny may block existing allows underneath.
                // Find EXISTING (unchanged) allows that are children of this
                // new deny and re-grant them: strip deny ACEs → re-apply allow.
                for (const auto& existing : newKeys) {
                    if (existing.isDeny) continue;
                    if (!IsPathUnder(existing.path, d.path)) continue;
                    // Skip if this allow was also just added (handled below)
                    bool isNewlyAdded = false;
                    for (const auto& aa : addedAllows) {
                        if (aa == existing) { isNewlyAdded = true; break; }
                    }
                    if (isNewlyAdded) continue;

                    // Strip deny ACEs from this existing allow path, then re-grant
                    bool isThis = (existing.scope == GrantScope::This);
                    g_logger.LogFmt(L"DYNAMIC_FIXUP: strip deny + re-grant [%s] %s",
                                    AccessTag(existing.access), existing.path.c_str());
                    RemoveSidFromDacl(existing.path, ctx->sidString, SE_FILE_OBJECT,
                                     DaclProtectionIntent::ForceProtected, isThis, AceRemovalMode::DenyOnly);
                    DWORD rc = GrantObjectAccess(ctx->pSid, existing.path, existing.access,
                                                 RecordGrantCallback,
                                                 SE_FILE_OBJECT, existing.scope);
                    if (rc == ERROR_SUCCESS) {
                        grantCount++;
                    } else {
                        g_logger.LogFmt(L"DYNAMIC_FIXUP: re-grant [%s] %s FAILED (0x%08X)",
                                        AccessTag(existing.access), existing.path.c_str(), rc);
                        failCount++;
                    }
                }
            }

            // Apply new allow entries (with deny-context awareness)
            for (const auto& a : addedAllows) {
                // Check if this allow is under any deny path in the full config
                bool underDeny = false;
                for (const auto& dp : allNewDenyPaths) {
                    if (IsPathUnder(a.path, dp)) { underDeny = true; break; }
                }

                // Strip deny ACEs first if under a deny (pipeline semantics)
                if (underDeny && !ctx->sidString.empty()) {
                    bool isThis = (a.scope == GrantScope::This);
                    g_logger.LogFmt(L"DYNAMIC_STRIP: %s (%s)",
                                    a.path.c_str(), isThis ? L"dir only" : L"subtree");
                    RemoveSidFromDacl(a.path, ctx->sidString, SE_FILE_OBJECT,
                                     DaclProtectionIntent::ForceProtected, isThis, AceRemovalMode::DenyOnly);
                }

                DWORD rc = GrantObjectAccess(ctx->pSid, a.path, a.access, RecordGrantCallback,
                                             SE_FILE_OBJECT, a.scope);
                if (rc == ERROR_SUCCESS) {
                    g_logger.LogFmt(L"DYNAMIC_GRANT: [%s] %s -> OK",
                                    AccessTag(a.access), a.path.c_str());
                    grantCount++;
                } else {
                    g_logger.LogFmt(L"DYNAMIC_GRANT: [%s] %s -> FAILED (0x%08X)",
                                    AccessTag(a.access), a.path.c_str(), rc);
                    failCount++;
                }
            }

            // ---- Phase 3: Registry delta (RT mode) ----
            std::set<std::wstring> removedRegistryPaths;
            for (const auto& r : regRemoved)
                removedRegistryPaths.insert(ToLower(r.path));

            for (const auto& pathLower : removedRegistryPaths) {
                std::wstring path;
                for (const auto& current : currentRegKeys) {
                    if (current.pathLower == pathLower) {
                        path = current.path;
                        break;
                    }
                }
                if (path.empty())
                    continue;

                std::wstring win32Path = RegistryToWin32Path(path);
                if (RevokePathEntries(win32Path, ctx->sidString, SE_REGISTRY_KEY))
                    revokeCount++;
                else
                    failCount++;

                ReapplySamePathRegistryEntries(path);
            }
            for (const auto& a : regAdded) {
                if (removedRegistryPaths.count(a.pathLower))
                    continue;
                std::wstring win32Path = RegistryToWin32Path(a.path);
                DWORD rc = GrantObjectAccess(ctx->pSid, win32Path, a.access,
                                              RecordGrantCallback, SE_REGISTRY_KEY);
                if (rc == ERROR_SUCCESS) {
                    g_logger.LogFmt(L"DYNAMIC_GRANT_REG: [%s] %s -> OK",
                                    a.access == AccessLevel::Read ? L"R" : L"W",
                                    a.path.c_str());
                    grantCount++;
                } else {
                    g_logger.LogFmt(L"DYNAMIC_GRANT_REG: [%s] %s -> FAILED (0x%08X)",
                                    a.access == AccessLevel::Read ? L"R" : L"W",
                                    a.path.c_str(), rc);
                    failCount++;
                }
            }
            if (!GrantTrackingHealthy()) {
                g_logger.Log(L"DYNAMIC: grant tracking persistence FAILED during reload");
                failCount++;
            }

            // F4/R9: Only update tracked state when all changes succeeded.
            // If any failed, keep the old baseline so failed changes are
            // retried on the next poll cycle.
            if (failCount == 0) {
                lastWriteTime = newWriteTime;
                currentKeys = newKeys;
                currentRegKeys = newRegKeys;
                ctx->currentConfig.folders = newConfig.folders;
                ctx->currentConfig.denyFolders = newConfig.denyFolders;
                ctx->currentConfig.registryRead = newConfig.registryRead;
                ctx->currentConfig.registryWrite = newConfig.registryWrite;
            } else {
                g_logger.LogFmt(L"DYNAMIC: %d failure(s) — keeping previous baseline for retry", failCount);
            }

            reloadCount++;
            g_logger.LogFmt(L"DYNAMIC: reload #%d — %d granted, %d revoked, %d failed (%llums)",
                reloadCount, grantCount, revokeCount, failCount,
                GetTickCount64() - tStart);
        }

        g_logger.LogFmt(L"DYNAMIC: watcher stopped (%d reloads performed)", reloadCount);
        return 0;
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
                            const ExecutionIdentity& identity,
                            bool dynamic = false,
                            const std::wstring& configPath = L"")
    {
        bool isRestricted = (config.tokenMode == TokenMode::Restricted);
        bool isAppContainer = !isRestricted;

        SandboxGuard guard;  // RAII — all cleanup goes through guard

        // =================================================================
        // PHASE 1: SETUP — create token/SID, log mode
        // =================================================================

        PSID pSid = nullptr;
        HANDLE hRestrictedToken = nullptr;
        std::wstring containerName = identity.containerName;

        if (identity.pSid) {
            pSid = identity.pSid;
            hRestrictedToken = identity.hToken;
        } else {
            auto setup = isAppContainer
                ? SetupAppContainer(containerName, guard)
                : SetupRestrictedToken(config, guard);
            if (!setup.ok) return SandyExit::SetupError;
            pSid = setup.pSid;
            hRestrictedToken = setup.hRestrictedToken;
        }

        ConfigureEmergencyCleanupState(containerName, identity.deleteContainerOnExit,
                                       identity.persistentProfile);

        g_logger.LogFmt(L"WORKDIR: %s", exeFolder.c_str());

        auto AbortBeforeLaunch = [&](int exitCode, const wchar_t* reason) -> int {
            if (isAppContainer && identity.deleteContainerOnExit && !containerName.empty()) {
                TeardownTransientContainerForCurrentRun(containerName, L"ABORT_BEFORE_LAUNCH");
            }
            guard.RunAll();
            FinalizeCleanupTaskForCurrentRun();
            g_logger.Log(reason);
            g_logger.Stop();
            return exitCode;
        };

        // =================================================================
        // PHASE 2: GRANT — apply ACLs (ALLOW, then DENY)
        // =================================================================

        if (identity.grantsPreexisting) {
            g_logger.Log(L"GRANTS: skipped (persistent profile ownership)");
        } else {
            InitializeRunLedger(containerName);
            // P2: Create cleanup task AFTER the ledger exists so concurrent
            // DeleteStaleCleanupTasks won't discard our freshly created task.
            CreateCleanupTask(g_instanceId);
            ULONGLONG tGrantStart = GetTickCount64();
            ResetGrantTrackingHealth();
            guard.Add([]() { RevokeAllGrants(); });

            // Apply depth-sorted access pipeline (allow + deny, most specific wins)
            // TOML is the sole grant source — no implicit auto-grants.
            bool grantFailed = false;
            if (!ApplyAccessPipeline(pSid, config, isAppContainer))
                grantFailed = true;

            // Step 2c: [RT] Grant registry access
            if (isRestricted) {
                if (!GrantRegistryAccess(pSid, config))
                    grantFailed = true;
            }
            if (!GrantTrackingHealthy()) {
                g_logger.Log(L"WARNING: grant tracking persistence failed (cleanup inventory incomplete)");
                grantFailed = true;
            }

            if (grantFailed) {
                g_logger.Log(L"ERROR: grant setup incomplete — aborting before launch");
                return AbortBeforeLaunch(SandyExit::SetupError, L"CLEANUP: complete (grant setup failure)");
            }

            g_logger.LogFmt(L"TIMING: grants applied in %llums", GetTickCount64() - tGrantStart);
        }

        // Desktop and loopback — profile-owned grants are set at creation,
        // transient grants are managed per-run.

        // [RT] Desktop access
        if (isRestricted && config.allowDesktop) {
            if (identity.persistentProfile) {
                g_logger.Log(L"DESKTOP: using profile-owned ACEs (no per-run grant)");
            } else {
                if (!GrantDesktopAccess(pSid))
                    return AbortBeforeLaunch(SandyExit::SetupError, L"CLEANUP: complete (desktop grant failure)");
                g_logger.Log(L"DESKTOP: granted WinSta0 + Default access");
                guard.Add([]() { RevokeDesktopAccess(); });
            }
        } else if (isRestricted) {
            g_logger.Log(L"DESKTOP: disabled (desktop = false)");
        }

        // [AC] Loopback
        if (isAppContainer && config.lanMode == LanMode::WithLocalhost) {
            if (identity.persistentProfile) {
                g_logger.Log(L"LOOPBACK: using profile-owned exemption (no per-run check)");
            } else {
                bool ok = EnableRunLoopback(containerName);
                g_logger.Log(ok ? L"LOOPBACK: enabled" : L"LOOPBACK: FAILED (need Administrator)");
                if (!ok)
                    return AbortBeforeLaunch(SandyExit::SetupError, L"CLEANUP: complete (loopback setup failure)");
                guard.Add([]() { DisableLoopback(); });
            }
        }

        // =================================================================
        // PHASE 3: PREPARE — capabilities, env, pipes
        // =================================================================

        // Step 3a: [AC] Build capabilities (network SIDs)
        CapabilityState caps = {};
        SECURITY_CAPABILITIES sc{};
        if (isAppContainer) {
            caps = BuildCapabilities(config);
            // P3: Abort if any requested capability SID failed to allocate.
            if (caps.failed) {
                g_logger.Log(L"ERROR: capability SID allocation failed — aborting before launch");
                FreeCapabilities(caps);
                return AbortBeforeLaunch(SandyExit::SetupError, L"CLEANUP: complete (capability failure)");
            }
            sc.AppContainerSid = pSid;
            sc.Capabilities = caps.capCount > 0 ? caps.caps : nullptr;
            sc.CapabilityCount = caps.capCount;
            guard.Add([&caps]() { FreeCapabilities(caps); });
        }

        // Step 3b: Build attribute list
        AttributeListState attrs = BuildAttributeList(config,
            isAppContainer ? &sc : nullptr, isRestricted);
        if (!attrs.valid)
            return AbortBeforeLaunch(SandyExit::SetupError, L"CLEANUP: complete (attribute list failure)");
        guard.Add([&attrs]() { FreeAttributeList(attrs); });

        // Step 3c: Log stdin, build environment, print config summary
        LogStdinMode(config.stdinMode);
        std::vector<wchar_t> envBlock = BuildEnvironmentBlock(config);
        LogEnvironmentState(config);
        if (!g_logger.IsActive())
            PrintConfigSummary(config, exePath, exeArgs, isRestricted);

        // Step 3d: Setup stdin handle
        HANDLE hStdin = nullptr, hStdinFile = nullptr;
        if (!SetupStdinHandle(config.stdinMode, hStdin, hStdinFile))
            return AbortBeforeLaunch(SandyExit::SetupError, L"CLEANUP: complete (stdin setup failure)");

        // =================================================================
        // PHASE 4: LAUNCH & RUN
        // =================================================================

        // Log config before launch so it's always in the log even for instant failures
        g_logger.LogConfig(config, exePath, exeArgs);

        // Step 3f: [RT] Pre-launch token integrity validation (defense-in-depth)
        // Verify the restricted token's integrity level matches the configured
        // value before handing it to CreateProcessAsUser.  Catches any subtle
        // mutation that could have occurred during Phases 2-3.
        if (isRestricted && hRestrictedToken) {
            DWORD ilSize = 0;
            GetTokenInformation(hRestrictedToken, TokenIntegrityLevel, nullptr, 0, &ilSize);
            if (ilSize > 0) {
                std::vector<BYTE> ilBuf(ilSize);
                auto* pTIL = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(ilBuf.data());
                if (GetTokenInformation(hRestrictedToken, TokenIntegrityLevel, pTIL, ilSize, &ilSize)) {
                    DWORD actualIL = *GetSidSubAuthority(pTIL->Label.Sid,
                                     *GetSidSubAuthorityCount(pTIL->Label.Sid) - 1);
                    DWORD expectedIL = (config.integrity == IntegrityLevel::Low)
                                       ? SECURITY_MANDATORY_LOW_RID
                                       : SECURITY_MANDATORY_MEDIUM_RID;
                    if (actualIL != expectedIL) {
                        g_logger.LogFmt(L"TOKEN_VALIDATE: FAILED — expected IL 0x%04X, got 0x%04X. Aborting launch.",
                                        expectedIL, actualIL);
                        if (hStdinFile) CloseHandle(hStdinFile);
                        return AbortBeforeLaunch(SandyExit::SetupError, L"CLEANUP: complete (token validation failure)");
                    }
                    g_logger.LogFmt(L"TOKEN_VALIDATE: OK (IL=0x%04X)", actualIL);
                }
            }
        }

        // Step 4a: Launch the child process (suspended, console passthrough)
        HANDLE hJob = nullptr;
        PROCESS_INFORMATION pi{};
        bool launched = LaunchChildProcess(
            isRestricted,
            isRestricted ? hRestrictedToken : nullptr,
            attrs.pAttrList, envBlock, exeFolder, exePath, exeArgs,
            hStdin, pi);

        // Close stdin file handle (parent doesn't need it)
        if (hStdinFile) CloseHandle(hStdinFile);

        if (!launched) {
            DWORD launchErr = GetLastError();
            g_logger.Log(L"LAUNCH: FAILED (see LAUNCH_FAILED above)");
            g_logger.LogSummary(launchErr, false, 0);
            if (isAppContainer && identity.deleteContainerOnExit)
                TeardownTransientContainerForCurrentRun(containerName, L"LAUNCH_FAILURE");
            guard.RunAll();
            FinalizeCleanupTaskForCurrentRun();
            g_logger.Log(L"CLEANUP: complete (launch failure)");
            g_logger.Stop();
            // POSIX convention: 127 = not found, 126 = cannot execute
            bool notFound = (launchErr == ERROR_FILE_NOT_FOUND ||
                             launchErr == ERROR_PATH_NOT_FOUND);
            return notFound ? SandyExit::NotFound : SandyExit::CannotExec;
        }

        auto AbortAfterChildLaunch = [&](DWORD terminateCode,
                                         const wchar_t* cleanupReason,
                                         const wchar_t* containerContext,
                                         int sandyExit = SandyExit::SetupError) -> int {
            g_childProcess = nullptr;
            g_childJob = nullptr;
            AbortLaunchedChild(pi, hJob, terminateCode);
            if (isAppContainer && identity.deleteContainerOnExit)
                TeardownTransientContainerForCurrentRun(containerName, containerContext);
            guard.RunAll();
            FinalizeCleanupTaskForCurrentRun();
            g_logger.Log(cleanupReason);
            g_logger.Stop();
            return sandyExit;
        };

        // Step 4b: Assign job object for resource limits
        hJob = AssignJobObject(config, pi.hProcess);
        bool jobNeeded = NeedJobTracking(config);
        if (jobNeeded && !hJob) {
            g_logger.Log(L"ERROR: job object assignment failed — aborting (limits NOT enforced)");
            return AbortAfterChildLaunch(SandyExit::SetupError,
                                         L"CLEANUP: complete (job assignment failure)",
                                         L"JOB_ASSIGN_FAILURE");
        }

        // Expose child handle for emergency cleanup (Ctrl+C / SEH)
        g_childProcess = pi.hProcess;
        g_childJob = hJob;

        // Step 4c: Resume child and start timeout watchdog
        ResumeThread(pi.hThread);
        g_logger.Log(L"CHILD: resumed");
        CloseHandleIfValid(pi.hThread);

        TimeoutContext timeoutCtx = { pi.hProcess, hJob, config.timeoutSeconds, false };
        HANDLE hTimeoutThread = StartTimeoutWatchdog(timeoutCtx);

        // F4/R8: Fail closed — if timeout is configured but watchdog couldn't
        // start, abort launch.  The child is already resumed but we terminate
        // it immediately to prevent running without time limits.
        if (config.timeoutSeconds > 0 && !hTimeoutThread) {
            g_logger.Log(L"ERROR: timeout configured but watchdog thread failed — aborting");
            return AbortAfterChildLaunch(SandyExit::SetupError,
                                         L"CLEANUP: complete (watchdog failure)",
                                         L"WATCHDOG_FAILURE");
        }

        // Step 4d: [DYNAMIC] Start config watcher if enabled
        HANDLE hDynamicThread = nullptr;
        HANDLE hStopEvent = nullptr;
        DynamicContext dynCtx{};
        if (dynamic && !configPath.empty() && !identity.grantsPreexisting) {
            hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            // F5/R10: Fail-closed — abort if event creation fails
            if (!hStopEvent) {
                fprintf(stderr, "Error: dynamic config reload requested but event creation failed.\n");
                g_logger.LogFmt(L"DYNAMIC: CreateEventW failed (error %lu)", GetLastError());
                return AbortAfterChildLaunch(1,
                                             L"CLEANUP: complete (dynamic event failure)",
                                             L"DYNAMIC_EVENT_FAILURE");
            }
            dynCtx.pSid = pSid;
            // Convert SID to string for RevokeGrant calls
            {
                LPWSTR s = nullptr;
                if (ConvertSidToStringSidW(pSid, &s)) {
                    dynCtx.sidString = s;
                    LocalFree(s);
                }
            }
            dynCtx.configPath = configPath;
            dynCtx.hProcess = pi.hProcess;
            dynCtx.isAppContainer = isAppContainer;
            dynCtx.currentConfig = config;
            dynCtx.hStopEvent = hStopEvent;
            hDynamicThread = CreateThread(nullptr, 0, DynamicWatcherThread,
                                          &dynCtx, 0, nullptr);
            // F5/R10: Fail-closed — abort if watcher thread cannot start
            if (!hDynamicThread) {
                fprintf(stderr, "Error: dynamic config reload requested but watcher thread failed to start.\n");
                g_logger.LogFmt(L"DYNAMIC: CreateThread failed (error %lu)", GetLastError());
                CloseHandle(hStopEvent);
                return AbortAfterChildLaunch(1,
                                             L"CLEANUP: complete (dynamic watcher failure)",
                                             L"DYNAMIC_WATCHER_FAILURE");
            }
        }

        // Step 4e: Wait for child exit (console passthrough — no pipe relay)
        DWORD exitCode = WaitForChildExit(pi.hProcess,
                                           hJob,
                                           hTimeoutThread, timeoutCtx,
                                           config.timeoutSeconds,
                                           config.allowChildProcesses);

        // Stop dynamic watcher
        if (hDynamicThread) {
            SetEvent(hStopEvent);
            WaitForSingleObject(hDynamicThread, INFINITE);
            CloseHandle(hDynamicThread);
            CloseHandle(hStopEvent);
        }


        // =================================================================
        // PHASE 5: CLEANUP (guard handles grants, SID, token, caps, attrs)
        // =================================================================

        // Step 5a: Log summary and classify the exit
        g_logger.LogSummary(exitCode, timeoutCtx.timedOut, config.timeoutSeconds);
        if (timeoutCtx.timedOut)
            g_logger.Log(L"EXIT_CLASS: TIMEOUT");
        else if (IsCrashExitCode(exitCode))
            g_logger.LogFmt(L"EXIT_CLASS: CRASH (0x%08X)", exitCode);
        else if (exitCode != 0)
            g_logger.LogFmt(L"EXIT_CLASS: ERROR (code=%ld)", (long)exitCode);
        else
            g_logger.Log(L"EXIT_CLASS: CLEAN");

        // Step 5b: Close process and job handles
        g_childProcess = nullptr;  // clear before close — emergency path must not use stale handle
        g_childJob = nullptr;
        ReleaseLaunchedChildHandles(pi, hJob);

        // Step 5c: Mode-specific cleanup
        if (identity.persistentProfile)
            g_logger.Log(L"CLEANUP: starting (persistent profile ownership)");
        else
            g_logger.Log(L"CLEANUP: starting");
        DWORD cleanupStart = GetTickCount();

        if (isAppContainer && identity.deleteContainerOnExit) {
            TeardownTransientContainerForCurrentRun(containerName, L"NORMAL_CLEANUP");
        }

        // Run all guard cleanups explicitly (RevokeAllGrants, RevokeDesktopAccess,
        // DisableLoopback, FreeCapabilities, FreeAttributeList, FreeSid, CloseHandle)
        // This must finish BEFORE DeleteCleanupTask so our own grants subkey is gone.
        guard.RunAll();

        FinalizeCleanupTaskForCurrentRun();
        g_logger.LogFmt(L"CLEANUP: complete (%lums)", GetTickCount() - cleanupStart);
        g_logger.Stop();

        // Map child exit code to Sandy exit code:
        //   timeout  → SandyExit::Timeout (7)
        //   crash    → SandyExit::ChildCrash (9)
        //   normal   → child's exit code as-is
        int sandyExit;
        if (timeoutCtx.timedOut)
            sandyExit = SandyExit::Timeout;
        else if (IsCrashExitCode(exitCode))
            sandyExit = SandyExit::ChildCrash;
        else
            sandyExit = static_cast<int>(exitCode);

        return sandyExit;
    }

    // Forward declaration — defined in SandboxSavedProfile.h
    inline void CleanStagingProfiles();

    inline void BeginRunSession(const std::wstring& exePath,
                                const std::wstring& configSource,
                                const std::wstring& profileName = L"",
                                bool dynamic = false)
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
        if (dynamic)
            g_logger.Log(L"DYNAMIC: enabled (live config reload)");
    }

    // =====================================================================
    // RunSandboxed — common entry point.
    //
    // Ephemeral compatibility path. Creates a transient execution identity,
    // then runs through the same ownership-driven pipeline as saved profiles.
    // =====================================================================
    inline int RunSandboxed(const SandboxConfig& config,
                            const std::wstring& exePath,
                            const std::wstring& exeArgs,
                            bool dynamic = false,
                            const std::wstring& configPath = L"")
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

        BeginRunSession(exePath, config.configSource, L"", dynamic);

        ExecutionIdentity identity;
        identity.containerName = ContainerNameFromId(g_instanceId);
        identity.persistentProfile = false;
        identity.grantsPreexisting = false;
        identity.deleteContainerOnExit = (config.tokenMode != TokenMode::Restricted);

        int result = RunPipeline(config, exePath, exeArgs, exeFolder,
                                 identity, dynamic, configPath);
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
