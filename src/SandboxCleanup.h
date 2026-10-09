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
#include <objbase.h>
#include <oleauto.h>
#include <taskschd.h>

#pragma comment(lib, "taskschd.lib")

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Loopback exemption — flag tracks runtime state
    //
    // Lock-guarded: normal pipeline cleanup (main thread) and emergency
    // cleanup (console-ctrl handler thread) can both reach DisableLoopback
    // after a Ctrl+C terminates the child and unblocks the main wait.
    // -----------------------------------------------------------------------
    inline bool g_loopbackGranted = false;
    inline std::wstring g_loopbackContainerName;  // the container name used for loopback
    inline SRWLOCK g_loopbackStateLock = SRWLOCK_INIT;

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

        for (const auto& e : SnapshotGrantLedgers()) {
            if (!excludeInstanceId.empty() && excludeInstanceId == e.instanceId)
                continue;
            if (e.liveness == RecoveryLedgerLiveness::Stale)
                continue;
            if (!e.container.empty() &&
                _wcsicmp(e.container.c_str(), containerName.c_str()) == 0) {
                if (e.liveness == RecoveryLedgerLiveness::Incomplete)
                    g_logger.LogFmt(L"LOOPBACK_LIVENESS: treating incomplete ledger %s as live (fail closed)",
                                    e.instanceId.c_str());
                return true;
            }
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Per-instance scheduled task naming.
    // Deleted on clean exit; stale tasks cleaned by --cleanup.
    //
    // The tasks are managed through the Task Scheduler API, not schtasks.exe:
    //   - a task with a logon trigger for the current user can be registered
    //     without elevation (schtasks /SC ONLOGON needs an administrator);
    //   - no helper process is started, and only the root folder is listed.
    // -----------------------------------------------------------------------
    constexpr const wchar_t* kCleanupTaskPrefix = L"SandyCleanup_";

    enum class CleanupTaskState {
        Retained,
        Orphaned,
    };

    struct CleanupTaskInventoryEntry {
        std::wstring taskName;
        std::wstring instanceId;
        RecoveryLedgerPresence ledgers;
        CleanupTaskState state = CleanupTaskState::Orphaned;
    };

    inline std::wstring CleanupTaskName(const std::wstring& instanceId)
    {
        return kCleanupTaskPrefix + instanceId;
    }

    inline const char* CleanupTaskStateJsonName(CleanupTaskState state)
    {
        return state == CleanupTaskState::Retained ? "retained" : "orphaned";
    }

    inline const char* CleanupTaskStateTextLabel(CleanupTaskState state)
    {
        return state == CleanupTaskState::Retained ? "retained" : "orphaned";
    }

    // Owning COM interface pointer / owning BSTR for the calls below.
    template <class T>
    struct ComRef {
        T* p = nullptr;
        ComRef() = default;
        ~ComRef() { if (p) p->Release(); }
        ComRef(const ComRef&) = delete;
        ComRef& operator=(const ComRef&) = delete;
        T** operator&() { return &p; }
        T* operator->() const { return p; }
    };

    struct ComString {
        BSTR b;
        explicit ComString(const std::wstring& s)
            : b(SysAllocStringLen(s.data(), static_cast<UINT>(s.size()))) {}
        ~ComString() { SysFreeString(b); }
        ComString(const ComString&) = delete;
        ComString& operator=(const ComString&) = delete;
        operator BSTR() const { return b; }
    };

    // -----------------------------------------------------------------------
    // TaskRootFolder — a connection to the root folder of the Task Scheduler.
    // ok() is false when the service cannot be reached.
    // -----------------------------------------------------------------------
    struct TaskRootFolder {
        ComRef<ITaskService> service;
        ComRef<ITaskFolder>  folder;
        bool                 comInitialized = false;

        TaskRootFolder()
        {
            HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            comInitialized = SUCCEEDED(hr);
            if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
                return;
            if (FAILED(CoCreateInstance(__uuidof(TaskScheduler), nullptr, CLSCTX_INPROC_SERVER,
                                        __uuidof(ITaskService), reinterpret_cast<void**>(&service))))
                return;
            VARIANT none;
            VariantInit(&none);
            if (FAILED(service->Connect(none, none, none, none)))
                return;
            service->GetFolder(ComString(L"\\"), &folder);
        }

        ~TaskRootFolder()
        {
            // Release the interfaces before COM goes away.
            if (folder.p)  { folder.p->Release();  folder.p = nullptr; }
            if (service.p) { service.p->Release(); service.p = nullptr; }
            if (comInitialized)
                CoUninitialize();
        }

        TaskRootFolder(const TaskRootFolder&) = delete;
        TaskRootFolder& operator=(const TaskRootFolder&) = delete;

        bool ok() const { return folder.p != nullptr; }
    };

    // "DOMAIN\user" of the current process; empty on failure.
    inline std::wstring CurrentUserAccountName()
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return {};
        std::wstring account;
        DWORD size = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);
        std::vector<BYTE> buf(size);
        if (size && GetTokenInformation(hToken, TokenUser, buf.data(), size, &size)) {
            wchar_t name[256], domain[256];
            DWORD nameLen = 256, domainLen = 256;
            SID_NAME_USE use;
            if (LookupAccountSidW(nullptr, reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid,
                                  name, &nameLen, domain, &domainLen, &use))
                account = std::wstring(domain) + L"\\" + name;
        }
        CloseHandle(hToken);
        return account;
    }

    inline bool CurrentProcessIsElevated()
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;
        TOKEN_ELEVATION elevation{};
        DWORD size = sizeof(elevation);
        bool elevated = GetTokenInformation(hToken, TokenElevation, &elevation, size, &size) &&
                        elevation.TokenIsElevated;
        CloseHandle(hToken);
        return elevated;
    }

    // -----------------------------------------------------------------------
    // RegisterLogonTask — register `taskName` to run `exePath arguments` at
    // the next logon of the current user.  Runs with the highest run level
    // only when Sandy itself is elevated.
    // Returns S_OK, or the HRESULT of the step that failed.
    // -----------------------------------------------------------------------
    inline HRESULT RegisterLogonTask(const std::wstring& taskName,
                                     const std::wstring& exePath,
                                     const std::wstring& arguments)
    {
        TaskRootFolder root;
        if (!root.ok())
            return E_FAIL;
        std::wstring user = CurrentUserAccountName();
        if (user.empty())
            return E_FAIL;

        ComRef<ITaskDefinition> definition;
        HRESULT hr = root.service->NewTask(0, &definition);
        if (FAILED(hr)) return hr;

        ComRef<IPrincipal> principal;
        hr = definition->get_Principal(&principal);
        if (FAILED(hr)) return hr;
        principal->put_UserId(ComString(user));
        principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
        principal->put_RunLevel(CurrentProcessIsElevated() ? TASK_RUNLEVEL_HIGHEST
                                                           : TASK_RUNLEVEL_LUA);

        ComRef<ITriggerCollection> triggers;
        ComRef<ITrigger> trigger;
        ComRef<ILogonTrigger> logonTrigger;
        hr = definition->get_Triggers(&triggers);
        if (SUCCEEDED(hr)) hr = triggers->Create(TASK_TRIGGER_LOGON, &trigger);
        if (SUCCEEDED(hr)) hr = trigger->QueryInterface(__uuidof(ILogonTrigger),
                                                        reinterpret_cast<void**>(&logonTrigger));
        if (SUCCEEDED(hr)) hr = logonTrigger->put_UserId(ComString(user));
        if (FAILED(hr)) return hr;

        ComRef<IActionCollection> actions;
        ComRef<IAction> action;
        ComRef<IExecAction> execAction;
        hr = definition->get_Actions(&actions);
        if (SUCCEEDED(hr)) hr = actions->Create(TASK_ACTION_EXEC, &action);
        if (SUCCEEDED(hr)) hr = action->QueryInterface(__uuidof(IExecAction),
                                                       reinterpret_cast<void**>(&execAction));
        if (SUCCEEDED(hr)) hr = execAction->put_Path(ComString(exePath));
        if (SUCCEEDED(hr)) hr = execAction->put_Arguments(ComString(arguments));
        if (FAILED(hr)) return hr;

        // A recovery task must also run on battery power.
        ComRef<ITaskSettings> settings;
        if (SUCCEEDED(definition->get_Settings(&settings))) {
            settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
            settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
        }

        VARIANT userId, none;
        VariantInit(&userId);
        VariantInit(&none);
        userId.vt = VT_BSTR;
        userId.bstrVal = SysAllocString(user.c_str());
        ComRef<IRegisteredTask> registered;
        hr = root.folder->RegisterTaskDefinition(ComString(taskName), definition.p,
                                                 TASK_CREATE_OR_UPDATE, userId, none,
                                                 TASK_LOGON_INTERACTIVE_TOKEN, none, &registered);
        VariantClear(&userId);
        return hr;
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
        HRESULT hr = RegisterLogonTask(taskName, exePath, L"--cleanup");
        if (SUCCEEDED(hr))
            g_logger.Log((L"SCHTASK: created " + taskName).c_str());
        else
            g_logger.LogFmt(L"SCHTASK: create %s FAILED (0x%08X) — after a kill, cleanup waits for the next Sandy run",
                            taskName.c_str(), hr);
    }

    // Delete one task in the root folder.  True when the task is gone.
    inline bool DeleteRootTask(const std::wstring& taskName)
    {
        TaskRootFolder root;
        if (!root.ok())
            return false;
        HRESULT hr = root.folder->DeleteTask(ComString(taskName), 0);
        return SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
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
        if (DeleteRootTask(taskName))
            g_logger.Log((L"SCHTASK: deleted " + taskName).c_str());
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

    // Names of all SandyCleanup_* tasks in the root folder.
    inline std::vector<std::wstring> EnumCleanupTaskNames()
    {
        std::vector<std::wstring> names;
        TaskRootFolder root;
        if (!root.ok())
            return names;

        ComRef<IRegisteredTaskCollection> tasks;
        if (FAILED(root.folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)))
            return names;
        LONG count = 0;
        tasks->get_Count(&count);
        for (LONG i = 1; i <= count; i++) {
            VARIANT index;
            VariantInit(&index);
            index.vt = VT_I4;
            index.lVal = i;
            ComRef<IRegisteredTask> task;
            BSTR name = nullptr;
            if (FAILED(tasks->get_Item(index, &task)) || FAILED(task->get_Name(&name)) || !name)
                continue;
            std::wstring taskName(name, SysStringLen(name));
            SysFreeString(name);
            if (taskName.rfind(kCleanupTaskPrefix, 0) == 0)
                names.push_back(std::move(taskName));
        }
        return names;
    }

    inline std::vector<CleanupTaskInventoryEntry> BuildCleanupTaskInventory()
    {
        std::vector<CleanupTaskInventoryEntry> tasks;
        for (auto& taskName : EnumCleanupTaskNames()) {
            CleanupTaskInventoryEntry task;
            task.instanceId = taskName.substr(wcslen(kCleanupTaskPrefix));
            task.taskName = std::move(taskName);
            if (task.instanceId.empty())
                continue;

            task.ledgers = QueryRecoveryLedgerPresence(task.instanceId);
            task.state = task.ledgers.Any()
                ? CleanupTaskState::Retained
                : CleanupTaskState::Orphaned;
            tasks.push_back(std::move(task));
        }
        return tasks;
    }

    // -----------------------------------------------------------------------
    // DeleteStaleCleanupTasks — remove tasks whose recovery ledgers are gone.
    //
    // Lists all SandyCleanup_* tasks, extracts instance IDs, and deletes
    // tasks only after the run no longer has any recovery ledger.
    // Called by startup recovery, --cleanup, and emergency cleanup.
    // -----------------------------------------------------------------------
    inline void DeleteStaleCleanupTasks()
    {
        for (const auto& task : BuildCleanupTaskInventory()) {
            if (task.state == CleanupTaskState::Orphaned) {
                if (DeleteRootTask(task.taskName)) {
                    g_logger.LogFmt(L"SCHTASK_STALE: deleted %ls (orphaned)", task.taskName.c_str());
                    RecoveryPrintf("  [TASK] %ls -> deleted\n", task.taskName.c_str());
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
        std::wstring cmd = L"\"" + cniExe + L"\" LoopbackExempt -a -n=\"" + containerName + L"\"";
        DWORD exitCode = RunHiddenProcess(cmd, 5000, cniExe);
        bool ok = (exitCode == 0);
        if (ok && trackRunState) {
            AcquireSRWLockExclusive(&g_loopbackStateLock);
            g_loopbackGranted = true;
            g_loopbackContainerName = containerName;
            ReleaseSRWLockExclusive(&g_loopbackStateLock);
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
        std::wstring cmd = L"\"" + cniExe + L"\" LoopbackExempt -d -n=\"" + containerName + L"\"";
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
        // Snapshot-and-clear under the lock: whichever thread (normal or
        // emergency cleanup) gets here first owns the removal; the other
        // sees cleared state and returns.
        std::wstring containerName;
        AcquireSRWLockExclusive(&g_loopbackStateLock);
        if (g_loopbackGranted) {
            containerName = std::move(g_loopbackContainerName);
            g_loopbackGranted = false;
            g_loopbackContainerName.clear();
        }
        ReleaseSRWLockExclusive(&g_loopbackStateLock);
        if (containerName.empty()) return;

        if (HasOtherLiveContainerUsers(containerName, g_instanceId)) {
            g_logger.Log((L"LOOPBACK: preserving (" + containerName +
                         L", other live users remain)").c_str());
            return;
        }
        g_logger.Log((L"LOOPBACK: disabling (" + containerName + L")").c_str());
        RemoveLoopbackExemption(containerName);
    }

    // -----------------------------------------------------------------------
    // DisableLoopbackForContainer — remove loopback exemption for a specific
    // container name.  Used by profile deletion to revoke profile-owned
    // loopback state without relying on the in-memory g_loopbackGranted flag.
    // -----------------------------------------------------------------------
    inline void DisableLoopbackForContainer(const std::wstring& containerName)
    {
        if (containerName.empty()) return;
        if (RemoveLoopbackExemption(containerName))
            g_logger.LogFmt(L"LOOPBACK_PROFILE: %ls -> removed", containerName.c_str());
        else
            g_logger.LogFmt(L"LOOPBACK_PROFILE: %ls -> removal failed", containerName.c_str());
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
        RunHiddenProcess(L"\"" + cniExe + L"\" LoopbackExempt -d -n=\"SandySandbox\"", 5000, cniExe);
        // Remove per-instance moniker if provided
        if (!containerName.empty()) {
            std::wstring cmd = L"\"" + cniExe + L"\" LoopbackExempt -d -n=\"" + containerName + L"\"";
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
        RunHiddenProcess(L"\"" + cniExe + L"\" LoopbackExempt -d -n=\"SandySandbox\"", 5000, cniExe);
        for (const auto& name : containerNames) {
            std::wstring cmd = L"\"" + cniExe + L"\" LoopbackExempt -d -n=\"" + name + L"\"";
            RunHiddenProcess(cmd, 5000, cniExe);
            RecoveryPrintf("  [LOOP] %ls -> loopback exemption removed\n", name.c_str());
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

        // P1: Snapshot subkey names first to avoid index-shift races.
        DWORD subCount = 0;
        RegQueryInfoKeyW(hMap, nullptr, nullptr, nullptr, &subCount,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        std::vector<std::wstring> sidKeys;
        for (DWORD i = 0; i < subCount; i++) {
            wchar_t sid[256];
            DWORD sidLen = 256;
            if (RegEnumKeyExW(hMap, i, sid, &sidLen,
                    nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                sidKeys.push_back(sid);
        }
        RegCloseKey(hMap);

        for (const auto& sidKey : sidKeys) {
            HKEY hSub = nullptr;
            std::wstring fullSidKey = std::wstring(mapKey) + L"\\" + sidKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullSidKey.c_str(), 0,
                              KEY_READ, &hSub) != ERROR_SUCCESS)
                continue;
            // Use a buffer with room for an extra NUL so that values stored
            // without a terminating NUL can still be read as a wstring.
            wchar_t moniker[257] = {};
            DWORD mSize = sizeof(moniker) - sizeof(wchar_t);  // leave last cell as guaranteed NUL
            DWORD type = 0;
            if (RegQueryValueExW(hSub, L"Moniker", nullptr, &type,
                    reinterpret_cast<BYTE*>(moniker), &mSize) == ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ)) {
                // mSize is in bytes, including NUL if present. Bound wstring
                // construction explicitly so we never read past what the
                // registry actually returned.
                size_t wcharCount = mSize / sizeof(wchar_t);
                std::wstring value(moniker, wcharCount);
                while (!value.empty() && value.back() == L'\0') value.pop_back();
                if (_wcsnicmp(value.c_str(), L"Sandy_", 6) == 0)
                    profiles.push_back(std::move(value));
            }
            RegCloseKey(hSub);
        }
        return profiles;
    }

    enum class SandyContainerKind { StaleTransient, LiveTransient, SavedProfile };

    struct SandyContainerInventoryEntry {
        std::wstring name;
        SandyContainerKind kind = SandyContainerKind::StaleTransient;
    };

    // -----------------------------------------------------------------------
    // BuildSandyContainerInventory — classify Windows AppContainer mappings
    // by durable ownership.
    //
    // Saved profile containers are durable profile-owned identities and must
    // not be treated as generic transient mappings even if a live run is
    // currently using them.  Transient containers split into live vs stale.
    // -----------------------------------------------------------------------
    inline std::vector<SandyContainerInventoryEntry> BuildSandyContainerInventory()
    {
        std::vector<SandyContainerInventoryEntry> inventory;
        std::set<std::wstring> liveContainers = GetLiveContainerNames();
        std::set<std::wstring> savedContainers = GetSavedProfileContainerNames();

        for (const auto& profile : EnumSandyProfiles()) {
            SandyContainerInventoryEntry entry;
            entry.name = profile;

            std::wstring lookup = NormalizeLookupKey(profile);
            if (savedContainers.count(lookup))
                entry.kind = SandyContainerKind::SavedProfile;
            else if (liveContainers.count(lookup))
                entry.kind = SandyContainerKind::LiveTransient;
            else
                entry.kind = SandyContainerKind::StaleTransient;

            inventory.push_back(std::move(entry));
        }
        return inventory;
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
        std::vector<std::wstring> staleProfiles;
        for (const auto& entry : BuildSandyContainerInventory()) {
            if (entry.kind == SandyContainerKind::StaleTransient)
                staleProfiles.push_back(entry.name);
        }
        ForceDisableLoopback(staleProfiles);

        g_logger.Log(L"STARTUP_CLEANUP: cleared stale AppContainer/loopback state");
    }

    // -----------------------------------------------------------------------
    // WarnStaleRegistryEntries — detect and warn about stale or incomplete
    // recovery metadata.
    //
    // Inputs:  (none — reads HKCU\Software\Sandy\Grants)
    // Effect:  prints warning to stderr and logs if stale/incomplete entries found
    // Verifiable: warning printed iff stale/incomplete keys exist in registry
    // -----------------------------------------------------------------------
    inline void WarnStaleRegistryEntries()
    {
        auto grantSnapshot = SnapshotGrantLedgers();
        int grantActive = 0, grantStale = 0, grantIncomplete = 0;
        for (const auto& e : grantSnapshot) {
            if (e.liveness == RecoveryLedgerLiveness::Active) grantActive++;
            else if (e.liveness == RecoveryLedgerLiveness::Incomplete) grantIncomplete++;
            else grantStale++;
        }

        auto tcSnapshot = SnapshotTransientContainerLedgers();
        int containerActive = 0, containerStale = 0, containerIncomplete = 0;
        for (const auto& e : tcSnapshot) {
            if (e.liveness == RecoveryLedgerLiveness::Active) containerActive++;
            else if (e.liveness == RecoveryLedgerLiveness::Incomplete) containerIncomplete++;
            else containerStale++;
        }

        if (grantStale > 0 || grantIncomplete > 0 ||
            containerStale > 0 || containerIncomplete > 0) {
            if (!g_logger.IsActive())
                fprintf(stderr,
                    "[Sandy] WARNING: Stale or incomplete recovery metadata detected.\n"
                    "        Grants: %d stale, %d incomplete (%d active) under HKCU\\%ls\n"
                    "        Containers: %d stale, %d incomplete (%d active) under HKCU\\%ls\n"
                    "        Run 'sandy.exe --cleanup' to restore original state.\n",
                    grantStale, grantIncomplete, grantActive, kGrantsParentKey,
                    containerStale, containerIncomplete, containerActive, kTransientContainersParentKey);
            g_logger.LogFmt(L"STARTUP_WARNING: recovery metadata — grants: %d stale/%d incomplete/%d active, containers: %d stale/%d incomplete/%d active",
                            grantStale, grantIncomplete, grantActive,
                            containerStale, containerIncomplete, containerActive);
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
