// =========================================================================
// SandboxCleanup.h — Loopback, scheduled task, and stale state recovery
//
// Self-contained utilities for managing sandbox lifecycle: loopback
// exemptions, crash-resilience tasks, stale state detection and cleanup.
// Each function is an independently testable semantic unit.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include "SandboxGrants.h"
#include "SandboxProcess.h"
#include <sstream>

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Loopback exemption — flag tracks runtime state
    // -----------------------------------------------------------------------
    inline bool g_loopbackGranted = false;
    inline std::wstring g_loopbackContainerName;  // the container name used for loopback

    // -----------------------------------------------------------------------
    // HasOtherLiveContainerUsers — true when another live Sandy instance is
    // still using the same AppContainer name.
    //
    // This is important for persistent saved profiles: loopback exemption is
    // host-global per container name, so one profile run must not remove it
    // while another run of the same profile is still alive.
    // -----------------------------------------------------------------------
    inline bool HasOtherLiveContainerUsers(const std::wstring& containerName,
                                           const std::wstring& excludeInstanceId)
    {
        if (containerName.empty()) return false;

        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return false;

        bool foundOther = false;
        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD idx = 0; idx < subKeyCount && !foundOther; idx++) {
            wchar_t name[128];
            DWORD nameLen = 128;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;

            if (!excludeInstanceId.empty() && excludeInstanceId == name)
                continue;

            std::wstring fullKey = GetRecoveryLedgerKey(RecoveryLedgerKind::Grants, name);
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            DWORD pid = 0; ULONGLONG ctime = 0;
            ReadPidAndCtime(hKey, pid, ctime);
            if (IsProcessAlive(pid, ctime)) {
                std::wstring liveContainer = ReadRegSz(hKey, L"_container");
                if (_wcsicmp(liveContainer.c_str(), containerName.c_str()) == 0)
                    foundOther = true;
            }
            RegCloseKey(hKey);
        }

        RegCloseKey(hParent);
        return foundOther;
    }

    // -----------------------------------------------------------------------
    // Per-instance scheduled task naming.
    // Deleted on clean exit; stale tasks cleaned by --cleanup.
    // -----------------------------------------------------------------------
    constexpr const wchar_t* kCleanupTaskPrefix = L"SandyCleanup_";

    inline std::wstring CleanupTaskName(const std::wstring& instanceId)
    {
        return kCleanupTaskPrefix + instanceId;
    }

    // -----------------------------------------------------------------------
    // CreateCleanupTask — register a per-instance scheduled task.
    //
    // Inputs:  instanceId — this instance's UUID
    // Effect:  creates SandyCleanup_<uuid> logon task
    // -----------------------------------------------------------------------
    inline void CreateCleanupTask(const std::wstring& instanceId)
    {
        wchar_t exePath[MAX_PATH];
        if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return;

        std::wstring taskName = CleanupTaskName(instanceId);
        std::wstring args = L"/Create /TN \"";
        args += taskName;
        args += L"\" /TR \"\\\"";
        args += exePath;
        args += L"\\\" --cleanup\" /SC ONLOGON /F /RL HIGHEST";

        if (RunSchtasks(args) == 0) {
            g_logger.Log((L"SCHTASK: created " + taskName).c_str());
        }
    }

    // -----------------------------------------------------------------------
    // DeleteCleanupTask — remove this instance's scheduled task.
    //
    // Inputs:  instanceId — this instance's UUID
    // Effect:  deletes SandyCleanup_<uuid> unconditionally
    // -----------------------------------------------------------------------
    inline void DeleteCleanupTask(const std::wstring& instanceId)
    {
        std::wstring taskName = CleanupTaskName(instanceId);
        std::wstring args = L"/Delete /TN \"";
        args += taskName;
        args += L"\" /F";

        if (RunSchtasks(args) == 0) {
            g_logger.Log((L"SCHTASK: deleted " + taskName).c_str());
        }
    }

    inline void FinalizeCleanupTaskForCurrentRun()
    {
        if (g_instanceId.empty()) return;
        if (ShouldRetainCleanupTask(g_instanceId, DeferredCleanupRequested())) {
            g_logger.LogFmt(L"SCHTASK: retained %s (cleanup retry still pending)",
                            CleanupTaskName(g_instanceId).c_str());
            return;
        }
        DeleteCleanupTask(g_instanceId);
    }

    inline std::vector<std::wstring> ListCleanupTasks()
    {
        std::vector<std::wstring> tasks;
        HiddenProcessResult query = RunSchtasksCapture(L"/Query /FO CSV /NH");
        if (query.status != HiddenProcessStatus::Completed)
            return tasks;

        std::istringstream stream(query.output);
        std::string line;
        while (std::getline(stream, line)) {
            std::wstring wline(line.begin(), line.end());
            if (wline.find(kCleanupTaskPrefix) == std::wstring::npos) continue;
            auto q1 = wline.find(L'"');
            auto q2 = (q1 == std::wstring::npos) ? std::wstring::npos : wline.find(L'"', q1 + 1);
            if (q1 == std::wstring::npos || q2 == std::wstring::npos) continue;

            auto taskPath = wline.substr(q1 + 1, q2 - q1 - 1);
            auto bs = taskPath.find_last_of(L'\\');
            tasks.push_back(bs != std::wstring::npos ? taskPath.substr(bs + 1) : taskPath);
        }
        return tasks;
    }

    // -----------------------------------------------------------------------
    // DeleteStaleCleanupTasks — remove tasks whose recovery ledgers are gone.
    //
    // Lists all SandyCleanup_* tasks via schtasks, extracts instance IDs,
    // and deletes tasks only after the run no longer has any recovery ledger.
    // Called by startup recovery, --cleanup, and emergency cleanup.
    // -----------------------------------------------------------------------
    inline void DeleteStaleCleanupTasks()
    {
        for (const auto& taskName : ListCleanupTasks()) {
            std::wstring instanceId = taskName.substr(wcslen(kCleanupTaskPrefix));
            if (instanceId.empty()) continue;
            if (!QueryRecoveryLedgerPresence(instanceId).Any()) {
                std::wstring delArgs = L"/Delete /TN \"" + taskName + L"\" /F";
                if (RunSchtasks(delArgs) == 0) {
                    g_logger.Log((L"SCHTASK_STALE: deleted " + taskName).c_str());
                    printf("  [TASK] %ls -> deleted\n", taskName.c_str());
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // AddLoopbackExemption — add localhost exemption for an AppContainer.
    //
    // Inputs:  containerName — AppContainer moniker
    //          trackRunState — true when this exemption is owned by the current
    //                          transient run and should be removed on run exit
    // Returns: true if exemption was added
    // -----------------------------------------------------------------------
    inline bool AddLoopbackExemption(const std::wstring& containerName,
                                     bool trackRunState)
    {
        std::wstring cniExe = GetSystemDirectoryPath() + L"CheckNetIsolation.exe";
        std::wstring cmd = L"\"" + cniExe + L"\" LoopbackExempt -a -n=" + containerName;
        DWORD exitCode = RunHiddenProcess(cmd, 5000, cniExe);
        bool ok = (exitCode == 0);
        if (ok && trackRunState) {
            g_loopbackGranted = true;
            g_loopbackContainerName = containerName;
        }
        return ok;
    }

    // -----------------------------------------------------------------------
    // EnableRunLoopback — add localhost exemption owned by the current run.
    // -----------------------------------------------------------------------
    inline bool EnableRunLoopback(const std::wstring& containerName)
    {
        return AddLoopbackExemption(containerName, true);
    }

    // -----------------------------------------------------------------------
    // EnsureProfileLoopback — ensure localhost exemption exists for a durable
    // saved-profile AppContainer.  This is profile-owned state, not run-owned
    // state, so the caller does not register transient cleanup.
    // -----------------------------------------------------------------------
    inline bool EnsureProfileLoopback(const std::wstring& containerName)
    {
        return AddLoopbackExemption(containerName, false);
    }

    // -----------------------------------------------------------------------
    // RemoveLoopbackExemption — unconditionally remove a localhost exemption.
    // Returns true when CheckNetIsolation reports success.
    // -----------------------------------------------------------------------
    inline bool RemoveLoopbackExemption(const std::wstring& containerName)
    {
        if (containerName.empty()) return true;
        std::wstring cniExe = GetSystemDirectoryPath() + L"CheckNetIsolation.exe";
        std::wstring cmd = L"\"" + cniExe + L"\" LoopbackExempt -d -n=" + containerName;
        return RunHiddenProcess(cmd, 5000, cniExe) == 0;
    }

    // -----------------------------------------------------------------------
    // DisableLoopback — remove localhost exemption (only if we granted it).
    //
    // Inputs:  (none — checks g_loopbackGranted flag)
    // Effect:  removes the per-instance exemption from loopback list
    // Verifiable: exemption no longer appears in CheckNetIsolation -s
    // -----------------------------------------------------------------------
    inline void DisableLoopback() {
        if (!g_loopbackGranted || g_loopbackContainerName.empty()) return;
        if (HasOtherLiveContainerUsers(g_loopbackContainerName, g_instanceId)) {
            g_logger.Log((L"LOOPBACK: preserving (" + g_loopbackContainerName +
                         L", other live users remain)").c_str());
            g_loopbackGranted = false;
            g_loopbackContainerName.clear();
            return;
        }
        g_logger.Log((L"LOOPBACK: disabling (" + g_loopbackContainerName + L")").c_str());
        RemoveLoopbackExemption(g_loopbackContainerName);
        g_loopbackGranted = false;
        g_loopbackContainerName.clear();
    }

    // -----------------------------------------------------------------------
    // ForceDisableLoopback — unconditional exemption removal for startup.
    //
    // Inputs:  containerName — the container name to remove (or empty to
    //          remove the legacy "SandySandbox" moniker for compat)
    // Effect:  removes the specified container from loopback exemption list
    // Verifiable: exemption is absent after call
    // -----------------------------------------------------------------------
    inline void ForceDisableLoopback(const std::wstring& containerName = L"")
    {
        std::wstring cniExe = GetSystemDirectoryPath() + L"CheckNetIsolation.exe";
        // Remove legacy hardcoded moniker (from pre-fix builds)
        RunHiddenProcess(L"\"" + cniExe + L"\" LoopbackExempt -d -n=SandySandbox", 5000, cniExe);
        // Remove per-instance moniker if provided
        if (!containerName.empty()) {
            std::wstring cmd = L"\"" + cniExe + L"\" LoopbackExempt -d -n=" + containerName;
            RunHiddenProcess(cmd, 5000, cniExe);
        }
        g_logger.Log(L"LOOPBACK: force-disabled (stale cleanup)");
    }

    // -----------------------------------------------------------------------
    // ForceDisableLoopback (vector) — remove loopback exemptions for all
    // provided container names.  Used by --cleanup to sweep stale
    // per-instance exemptions discovered via EnumSandyProfiles().
    // -----------------------------------------------------------------------
    inline void ForceDisableLoopback(const std::vector<std::wstring>& containerNames)
    {
        std::wstring cniExe = GetSystemDirectoryPath() + L"CheckNetIsolation.exe";
        RunHiddenProcess(L"\"" + cniExe + L"\" LoopbackExempt -d -n=SandySandbox", 5000, cniExe);
        for (const auto& name : containerNames) {
            std::wstring cmd = L"\"" + cniExe + L"\" LoopbackExempt -d -n=" + name;
            RunHiddenProcess(cmd, 5000, cniExe);
            printf("  [LOOP] %ls -> loopback exemption removed\n", name.c_str());
        }
        if (!containerNames.empty())
            g_logger.LogFmt(L"LOOPBACK: force-disabled %zu stale exemption(s)", containerNames.size());
        else
            g_logger.Log(L"LOOPBACK: force-disabled (legacy only)");
    }

    // -----------------------------------------------------------------------
    // EnumSandyProfiles — enumerate Sandy AppContainer profiles.
    //
    // Scans the Windows AppContainer Mappings registry for monikers
    // starting with "Sandy_".  Used by both startup cleanup and
    // --cleanup to discover stale per-instance profiles/exemptions.
    // -----------------------------------------------------------------------
    inline std::vector<std::wstring> EnumSandyProfiles()
    {
        std::vector<std::wstring> profiles;
        HKEY hMap = nullptr;
        const wchar_t* mapKey = L"Software\\Classes\\Local Settings\\Software\\"
            L"Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings";
        if (RegOpenKeyExW(HKEY_CURRENT_USER, mapKey, 0,
                KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hMap) != ERROR_SUCCESS)
            return profiles;

        DWORD subCount = 0;
        RegQueryInfoKeyW(hMap, nullptr, nullptr, nullptr, &subCount,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        for (DWORD i = 0; i < subCount; i++) {
            wchar_t sid[256];
            DWORD sidLen = 256;
            if (RegEnumKeyExW(hMap, i, sid, &sidLen,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;
            HKEY hSub = nullptr;
            if (RegOpenKeyExW(hMap, sid, 0, KEY_READ, &hSub) != ERROR_SUCCESS)
                continue;
            wchar_t moniker[256] = {};
            DWORD mSize = sizeof(moniker);
            if (RegQueryValueExW(hSub, L"Moniker", nullptr, nullptr,
                    reinterpret_cast<BYTE*>(moniker), &mSize) == ERROR_SUCCESS) {
                if (_wcsnicmp(moniker, L"Sandy_", 6) == 0)
                    profiles.push_back(moniker);
            }
            RegCloseKey(hSub);
        }
        RegCloseKey(hMap);
        return profiles;
    }

    // -----------------------------------------------------------------------
    // CleanupStaleStartupState — clear stale state from previous crashed runs.
    //
    // Startup cleanup owns transient host-side artifacts only. It removes
    // stale loopback exemptions for dead transient containers while preserving
    // live runs and durable saved-profile containers.
    // -----------------------------------------------------------------------
    inline void CleanupStaleStartupState(const std::wstring& exePath)
    {
        (void)exePath;
        // Filter profiles through liveness check — only clean stale ones
        // Also exclude saved-profile containers (permanent, never cleaned)
        auto allProfiles = EnumSandyProfiles();
        auto liveContainers = GetLiveContainerNames();
        auto savedContainers = GetSavedProfileContainerNames();
        std::vector<std::wstring> staleProfiles;
        for (const auto& p : allProfiles) {
            std::wstring lookup = NormalizeLookupKey(p);
            if (!liveContainers.count(lookup) && !savedContainers.count(lookup))
                staleProfiles.push_back(p);
        }
        ForceDisableLoopback(staleProfiles);

        g_logger.Log(L"STARTUP_CLEANUP: cleared stale AppContainer/loopback state");
    }

    // -----------------------------------------------------------------------
    // WarnStaleRegistryEntries — detect and warn about stale registry state.
    //
    // Inputs:  (none — reads HKCU\Software\Sandy\Grants)
    // Effect:  prints warning to stderr and logs if stale entries found
    // Verifiable: warning printed iff stale keys exist in registry
    // -----------------------------------------------------------------------
    inline void WarnStaleRegistryEntries()
    {
        bool staleGrants = false;
        bool staleTransientContainers = false;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD subKeyCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &subKeyCount,
                             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
            RegCloseKey(hKey);
            if (subKeyCount > 0) staleGrants = true;
        }
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kTransientContainersParentKey, 0,
                          KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD subKeyCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &subKeyCount,
                             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
            RegCloseKey(hKey);
            if (subKeyCount > 0) staleTransientContainers = true;
        }
        if (staleGrants || staleTransientContainers) {
            if (!g_logger.IsActive())
                fprintf(stderr,
                    "[Sandy] WARNING: Stale recovery metadata detected from a previous crashed run.\n"
                    "        Grants: HKCU\\%ls\n"
                    "        Containers: HKCU\\%ls\n"
                    "        Run 'sandy.exe --cleanup' to restore original state.\n"
                    "        If another sandy instance is running, its entries are expected.\n",
                    kGrantsParentKey, kTransientContainersParentKey);
            g_logger.Log(L"STARTUP_WARNING: stale recovery metadata found (use --cleanup)");
        }
    }

    // -----------------------------------------------------------------------
    // LogSandyIdentity — log the current process PID and integrity level.
    //
    // Inputs:  (none — queries current process token)
    // Effect:  logs PID and integrity level for forensic analysis
    // Verifiable: log contains correct PID and integrity level
    // -----------------------------------------------------------------------
    inline void LogSandyIdentity()
    {
        g_logger.LogFmt(L"SANDY: PID %lu", GetCurrentProcessId());

        HANDLE hToken = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            DWORD ilSize = 0;
            GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &ilSize);
            if (ilSize > 0) {
                std::vector<BYTE> ilBuf(ilSize);
                auto* pTIL = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(ilBuf.data());
                if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, ilSize, &ilSize)) {
                    DWORD il = *GetSidSubAuthority(pTIL->Label.Sid,
                                *GetSidSubAuthorityCount(pTIL->Label.Sid) - 1);
                    const wchar_t* ilName = il >= SECURITY_MANDATORY_HIGH_RID ? L"High (elevated)" :
                                            il >= SECURITY_MANDATORY_MEDIUM_RID ? L"Medium" : L"Low";
                    g_logger.LogFmt(L"SANDY: integrity=%s (0x%04X)", ilName, il);
                }
            }
            CloseHandle(hToken);
        }
    }

} // namespace Sandbox
