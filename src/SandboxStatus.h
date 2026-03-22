// =========================================================================
// SandboxStatus.h — Status, cleanup, and explain command handlers
//
// Implements --status, --cleanup, and --explain CLI commands.
// Extracted from sandy.cpp for readability.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include "SandboxGrants.h"
#include "SandboxCleanup.h"
#include "SandboxSavedProfile.h"

namespace Sandbox {

// EnumSandyProfiles() is defined in SandboxCleanup.h (included above)

struct StatusInstanceEntry {
    std::wstring uuid;
    DWORD pid = 0;
    RecoveryLedgerLiveness liveness = RecoveryLedgerLiveness::Incomplete;
};

struct StatusRetryContainerEntry {
    std::wstring instanceId;
    std::wstring container;
    RecoveryLedgerLiveness liveness = RecoveryLedgerLiveness::Incomplete;
};

struct StatusCleanupTaskEntry {
    std::wstring taskName;
    std::wstring instanceId;
    CleanupTaskState state = CleanupTaskState::Orphaned;
    RecoveryLedgerPresence ledgers;
};

struct StatusSnapshot {
    std::vector<StatusInstanceEntry> instances;
    std::vector<StatusRetryContainerEntry> retryContainers;
    std::vector<StatusCleanupTaskEntry> tasks;
    std::vector<std::wstring> profiles;  // transient/orphaned container mappings only
    std::vector<ProfileSummary> savedProfiles;
    int staleInstances = 0;
    int incompleteInstances = 0;
    int staleRetryContainers = 0;
    int incompleteRetryContainers = 0;
    int retainedTasks = 0;
    int orphanedTasks = 0;
};

inline bool HasVisibleStatusState(const StatusSnapshot& snapshot)
{
    return !snapshot.instances.empty() ||
           !snapshot.retryContainers.empty() ||
           !snapshot.tasks.empty() ||
           !snapshot.profiles.empty() ||
           !snapshot.savedProfiles.empty();
}

inline std::string EscapeStatusJson(const std::wstring& s)
{
    std::string result;
    for (wchar_t c : s) {
        if (c == L'"') result += "\\\"";
        else if (c == L'\\') result += "\\\\";
        else if (c < 128) result += static_cast<char>(c);
        else {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\u%04X", static_cast<unsigned>(c));
            result += buf;
        }
    }
    return result;
}

inline const char* CleanupTaskLedgerSourceLabel(const RecoveryLedgerPresence& ledgers)
{
    if (ledgers.grants && ledgers.transientContainerRetry)
        return "grants + transient retry";
    if (ledgers.grants)
        return "grants";
    if (ledgers.transientContainerRetry)
        return "transient retry";
    return "none";
}

inline StatusSnapshot BuildStatusSnapshot()
{
    StatusSnapshot snapshot;

    auto grantSnapshot = SnapshotGrantLedgers();
    for (const auto& entry : grantSnapshot) {
        if (entry.liveness == RecoveryLedgerLiveness::Stale)
            snapshot.staleInstances++;
        else if (entry.liveness == RecoveryLedgerLiveness::Incomplete)
            snapshot.incompleteInstances++;
        snapshot.instances.push_back({ entry.instanceId, entry.pid, entry.liveness });
    }

    auto retrySnapshot = SnapshotTransientContainerLedgers();
    for (const auto& entry : retrySnapshot) {
        if (entry.liveness == RecoveryLedgerLiveness::Stale)
            snapshot.staleRetryContainers++;
        else if (entry.liveness == RecoveryLedgerLiveness::Incomplete)
            snapshot.incompleteRetryContainers++;
        snapshot.retryContainers.push_back({ entry.instanceId, entry.container, entry.liveness });
    }

    for (const auto& task : BuildCleanupTaskInventory()) {
        if (task.state == CleanupTaskState::Retained)
            snapshot.retainedTasks++;
        else
            snapshot.orphanedTasks++;
        snapshot.tasks.push_back({ task.taskName, task.instanceId, task.state, task.ledgers });
    }

    for (const auto& entry : BuildSandyContainerInventory()) {
        if (entry.kind != SandyContainerKind::SavedProfile)
            snapshot.profiles.push_back(entry.name);
    }

    snapshot.savedProfiles = EnumSavedProfiles();
    return snapshot;
}

inline void PrintStatusJson(const StatusSnapshot& snapshot)
{
    printf("{\"instances\":[");
    for (size_t i = 0; i < snapshot.instances.size(); i++)
        printf("%s{\"uuid\":\"%s\",\"pid\":%lu,\"status\":\"%s\"}",
               i ? "," : "", EscapeStatusJson(snapshot.instances[i].uuid).c_str(),
               snapshot.instances[i].pid,
               RecoveryLedgerLivenessJsonName(snapshot.instances[i].liveness));
    printf("],\"retry_containers\":[");
    for (size_t i = 0; i < snapshot.retryContainers.size(); i++)
        printf("%s{\"instance\":\"%s\",\"container\":\"%s\",\"status\":\"%s\"}",
               i ? "," : "",
               EscapeStatusJson(snapshot.retryContainers[i].instanceId).c_str(),
               EscapeStatusJson(snapshot.retryContainers[i].container).c_str(),
               RecoveryLedgerLivenessJsonName(snapshot.retryContainers[i].liveness));
    printf("],\"tasks\":[");
    for (size_t i = 0; i < snapshot.tasks.size(); i++)
        printf("%s{\"name\":\"%s\",\"instance\":\"%s\",\"status\":\"%s\",\"grants_ledger\":%s,\"transient_container_retry_ledger\":%s}",
               i ? "," : "",
               EscapeStatusJson(snapshot.tasks[i].taskName).c_str(),
               EscapeStatusJson(snapshot.tasks[i].instanceId).c_str(),
               CleanupTaskStateJsonName(snapshot.tasks[i].state),
               snapshot.tasks[i].ledgers.grants ? "true" : "false",
               snapshot.tasks[i].ledgers.transientContainerRetry ? "true" : "false");
    printf("],\"profiles\":[");
    for (size_t i = 0; i < snapshot.profiles.size(); i++)
        printf("%s\"%s\"", i ? "," : "", EscapeStatusJson(snapshot.profiles[i]).c_str());
    printf("],\"saved_profiles\":[");
    for (size_t i = 0; i < snapshot.savedProfiles.size(); i++)
        printf("%s{\"name\":\"%s\",\"type\":\"%s\",\"created\":\"%s\",\"status\":\"%s\"}",
               i ? "," : "", EscapeStatusJson(snapshot.savedProfiles[i].name).c_str(),
               EscapeStatusJson(snapshot.savedProfiles[i].type).c_str(),
               EscapeStatusJson(snapshot.savedProfiles[i].created).c_str(),
               snapshot.savedProfiles[i].invalid ? "invalid" : "ok");
    printf("],\"summary\":{\"instances\":%zu,\"stale_instances\":%d,\"incomplete_instances\":%d,\"retry_containers\":%zu,\"stale_retry_containers\":%d,\"incomplete_retry_containers\":%d,\"tasks\":%zu,\"retained_tasks\":%d,\"orphaned_tasks\":%d,\"profiles\":%zu,\"saved_profiles\":%zu}}\n",
           snapshot.instances.size(), snapshot.staleInstances, snapshot.incompleteInstances,
           snapshot.retryContainers.size(), snapshot.staleRetryContainers, snapshot.incompleteRetryContainers,
           snapshot.tasks.size(), snapshot.retainedTasks, snapshot.orphanedTasks,
           snapshot.profiles.size(), snapshot.savedProfiles.size());
}

inline void PrintStatusText(const StatusSnapshot& snapshot)
{
    for (const auto& instance : snapshot.instances) {
        const char* label = RecoveryLedgerLivenessTextLabel(instance.liveness);
        const char* suffix = "";
        if (instance.liveness == RecoveryLedgerLiveness::Stale)
            suffix = " (dead process)";
        else if (instance.liveness == RecoveryLedgerLiveness::Incomplete)
            suffix = " (writer initializing or metadata incomplete)";
        printf("  [%s]  PID %-6lu  %ls%s\n",
               label, instance.pid, instance.uuid.c_str(), suffix);
    }
    for (const auto& retry : snapshot.retryContainers) {
        const wchar_t* container = retry.container.empty()
            ? L"<missing>"
            : retry.container.c_str();
        printf("  [RETRY_CONTAINER] %ls  (%s, instance: %ls)\n",
               container,
               RecoveryLedgerLivenessJsonName(retry.liveness),
               retry.instanceId.c_str());
    }
    for (const auto& task : snapshot.tasks) {
        printf("  [TASK]    %ls  (%s, instance: %ls, ledgers: %s)\n",
               task.taskName.c_str(),
               CleanupTaskStateTextLabel(task.state),
               task.instanceId.c_str(),
               CleanupTaskLedgerSourceLabel(task.ledgers));
    }
    for (const auto& profile : snapshot.profiles)
        printf("  [PROFILE] %ls\n", profile.c_str());
    for (const auto& savedProfile : snapshot.savedProfiles) {
        const wchar_t* created = savedProfile.created.empty()
            ? L"unknown"
            : savedProfile.created.c_str();
        if (savedProfile.invalid) {
            printf("  [SAVED_PROFILE] %ls  (corrupted or incomplete, created: %ls)\n",
                   savedProfile.name.c_str(), created);
        } else {
            printf("  [SAVED_PROFILE] %ls  (%ls, created: %ls)\n",
                   savedProfile.name.c_str(), savedProfile.type.c_str(),
                   created);
        }
    }

    if (!HasVisibleStatusState(snapshot)) {
        printf("Sandy - no active instances or recovery state.\n");
    } else {
        printf("Summary: %zu instance(s), %d stale instance(s), %d incomplete instance(s), %zu retry container(s), %zu task(s) (%d retained, %d orphaned), %zu profile(s), %zu saved profile(s).\n",
               snapshot.instances.size(), snapshot.staleInstances, snapshot.incompleteInstances,
               snapshot.retryContainers.size(), snapshot.tasks.size(),
               snapshot.retainedTasks, snapshot.orphanedTasks,
               snapshot.profiles.size(), snapshot.savedProfiles.size());
    }
}

// -----------------------------------------------------------------------
// Show active, stale, or incomplete instances and other Sandy state
// (--status [--json])
// -----------------------------------------------------------------------
inline int HandleStatus(bool json = false)
{
    StatusSnapshot snapshot = BuildStatusSnapshot();
    if (json) PrintStatusJson(snapshot);
    else      PrintStatusText(snapshot);
    return 0;
}

// -----------------------------------------------------------------------
// Restore stale state from crashed runs (--cleanup)
// -----------------------------------------------------------------------
inline int HandleCleanup()
{
    std::vector<std::wstring> staleProfiles;
    for (const auto& entry : BuildSandyContainerInventory()) {
        if (entry.kind == SandyContainerKind::LiveTransient) {
            printf("  [PROFILE] %ls -> SKIPPED (live instance)\n", entry.name.c_str());
        } else if (entry.kind == SandyContainerKind::SavedProfile) {
            printf("  [PROFILE] %ls -> SKIPPED (saved profile)\n", entry.name.c_str());
        } else {
            staleProfiles.push_back(entry.name);
        }
    }

    // Remove loopback exemptions for STALE profiles only
    Sandbox::ForceDisableLoopback(staleProfiles);

    Sandbox::RestoreStaleGrants();   // restores DACLs + deletes stale container profiles
    Sandbox::CleanStagingProfiles(); // roll back incomplete --create-profile operations
    Sandbox::DeleteStaleCleanupTasks();

    // Clean orphaned Sandy AppContainer profiles from Windows Mappings
    if (!staleProfiles.empty())
        printf("  Cleaning %zu orphaned AppContainer profile(s)...\n",
                staleProfiles.size());
    for (const auto& m : staleProfiles) {
        if (DeleteTransientContainerNow(m, L"MANUAL_CLEANUP")) {
            ClearTransientContainerCleanupByContainerName(m);
            printf("  [PROFILE] %ls -> deleted\n", m.c_str());
        } else if (PersistTransientContainerCleanupForOrphanedContainer(m)) {
            fprintf(stderr, "  [PROFILE] %ls -> deferred for retry\n", m.c_str());
        } else {
            fprintf(stderr, "  [PROFILE] %ls -> FAILED\n", m.c_str());
        }
    }

    // Remove test registry tree (tests use Software\Sandy\Test\ instead of
    // production keys so they never interfere with real sandbox state)
    if (DeleteRegTreeIfExists(HKEY_CURRENT_USER, L"Software\\Sandy\\Test"))
        printf("  [TEST]    Software\\Sandy\\Test -> cleaned\n");

    printf("Sandy - cleanup complete.\n");
    return 0;
}

// -----------------------------------------------------------------------
// Explain an exit code (--explain <code>)
// -----------------------------------------------------------------------
inline int HandleExplain(const wchar_t* codeStr)
{
    // Parse code (decimal, hex, or negative)
    wchar_t* end = nullptr;
    long long code = wcstoll(codeStr, &end, 0);
    if (end == codeStr || *end != L'\0') {
        fprintf(stderr, "Error: '%ls' is not a valid number.\n", codeStr);
        return SandyExit::InternalError;
    }
    DWORD dw = static_cast<DWORD>(code);

    printf("Code: %lld (0x%08X)\n\n", code, dw);

    // Sandy exit codes
    struct { int code; const char* name; const char* desc; } sandyCodes[] = {
        { 0,   "Success",       "Child exited cleanly, or info command succeeded" },
        { 125, "InternalError", "Sandy internal / general error" },
        { 126, "CannotExec",    "CreateProcess failed (permission denied, bad format)" },
        { 127, "NotFound",      "Executable not found on disk" },
        { 128, "ConfigError",   "Configuration error (invalid TOML, wrong-mode keys)" },
        { 129, "SetupError",    "Sandbox setup failed (token, SID, ACL, pipes)" },
        { 130, "Timeout",       "Child killed by Sandy's timeout watchdog" },
        { 131, "ChildCrash",    "Child crashed (NTSTATUS crash code detected)" },
    };
    for (auto& s : sandyCodes) {
        if (s.code == static_cast<int>(code)) {
            printf("Sandy exit code: %s\n  %s\n", s.name, s.desc);
            return 0;
        }
    }

    // Known NTSTATUS crash codes
    struct { DWORD code; const char* name; } crashCodes[] = {
        { 0xC0000005, "STATUS_ACCESS_VIOLATION (SIGSEGV equivalent)" },
        { 0xC00000FD, "STATUS_STACK_OVERFLOW" },
        { 0xC0000409, "STATUS_STACK_BUFFER_OVERRUN (/GS security check failure)" },
        { 0x80000003, "STATUS_BREAKPOINT (INT 3 / debugger break)" },
        { 0xC0000374, "STATUS_HEAP_CORRUPTION" },
        { 0xC0000096, "STATUS_PRIVILEGED_INSTRUCTION" },
        { 0xC000001D, "STATUS_ILLEGAL_INSTRUCTION" },
        { 0xC0000094, "STATUS_INTEGER_DIVIDE_BY_ZERO" },
        { 0xC000008C, "STATUS_ARRAY_BOUNDS_EXCEEDED" },
        { 0xC0000135, "STATUS_DLL_NOT_FOUND" },
        { 0xC0000142, "STATUS_DLL_INIT_FAILED" },
        { 0x40010004, "STATUS_DEBUGGER_INACTIVE" },
        { 0xE0434352, "CLR unhandled exception (.NET)" },
        { 0xE06D7363, "MSVC C++ unhandled exception (throw without catch)" },
    };
    for (auto& c : crashCodes) {
        if (c.code == dw) {
            printf("NTSTATUS: %s\n", c.name);
            return 0;
        }
    }

    // Try FormatMessage for Win32 or NTSTATUS
    wchar_t* msgBuf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageW(flags, nullptr, dw, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                               reinterpret_cast<LPWSTR>(&msgBuf), 0, nullptr);
    if (len > 0 && msgBuf) {
        // Strip trailing newline
        while (len > 0 && (msgBuf[len-1] == L'\n' || msgBuf[len-1] == L'\r')) msgBuf[--len] = 0;
        printf("System message: %ls\n", msgBuf);
        LocalFree(msgBuf);
    } else {
        // Try NTSTATUS via ntdll
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            len = FormatMessageW(flags | FORMAT_MESSAGE_FROM_HMODULE, hNtdll, dw,
                                 MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                                 reinterpret_cast<LPWSTR>(&msgBuf), 0, nullptr);
            if (len > 0 && msgBuf) {
                while (len > 0 && (msgBuf[len-1] == L'\n' || msgBuf[len-1] == L'\r')) msgBuf[--len] = 0;
                printf("NTSTATUS message: %ls\n", msgBuf);
                LocalFree(msgBuf);
            } else {
                printf("Unknown code.\n");
            }
        } else {
            printf("Unknown code.\n");
        }
    }

    // Additional context for NTSTATUS range
    if (dw >= 0x80000000)
        printf("  (NTSTATUS range: 0x8* = warning, 0xC* = error/crash, 0xE* = software exception)\n");
    else if (code >= 1 && code <= 124)
        printf("  (In Sandy: this would be the child process's own exit code)\n");

    return 0;
}

} // namespace Sandbox
