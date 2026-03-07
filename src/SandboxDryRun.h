// =========================================================================
// SandboxDryRun.h — Dry-run and print-config command handlers
//
// Implements --dry-run and --print-config CLI commands.
// Extracted from sandy.cpp for readability.
//
// All output uses printf with %ls for wide strings — plain ASCII/UTF-8
// on stdout, compatible with cmd redirect, findstr, and piping.
// =========================================================================
#pragma once

#include "SandboxTypes.h"

namespace Sandbox {

// -----------------------------------------------------------------------
// Human-readable access level name (wide string for %ls output)
// -----------------------------------------------------------------------
inline const wchar_t* AccessLevelNameW(AccessLevel a)
{
    switch (a) {
        case AccessLevel::Read:    return L"read";
        case AccessLevel::Write:   return L"write";
        case AccessLevel::Execute: return L"execute";
        case AccessLevel::Append:  return L"append";
        case AccessLevel::Delete:  return L"delete";
        case AccessLevel::All:     return L"all";
    }
    return L"?";
}

// -----------------------------------------------------------------------
// Print folder entries grouped by access level (for dry-run display)
// -----------------------------------------------------------------------
inline void PrintFolderEntries(const wchar_t* section,
                               const std::vector<FolderEntry>& entries)
{
    printf("[%ls]\n", section);
    if (entries.empty()) { printf("  (none)\n"); return; }
    for (int a = 0; a <= 5; a++) {
        auto lvl = static_cast<AccessLevel>(a);
        bool first = true;
        for (auto& e : entries) {
            if (e.access != lvl) continue;
            if (first) { printf("  %ls:\n", AccessLevelNameW(lvl)); first = false; }
            printf("    %ls\n", e.path.c_str());
        }
    }
}

// -----------------------------------------------------------------------
// Print folder entries as TOML (for --print-config)
// -----------------------------------------------------------------------
inline void PrintFolderToml(const wchar_t* section,
                            const std::vector<FolderEntry>& entries)
{
    printf("[%ls]\n", section);
    for (int a = 0; a <= 5; a++) {
        auto lvl = static_cast<AccessLevel>(a);
        bool first = true;
        for (auto& e : entries) {
            if (e.access != lvl) continue;
            if (first) {
                printf("%ls = [", AccessLevelNameW(lvl));
                first = false;
            } else {
                printf(", ");
            }
            printf("'%ls'", e.path.c_str());
        }
        if (!first) printf("]\n");
    }
}

// -----------------------------------------------------------------------
// Dry-run mode (--dry-run / --check) — validate config + show plan
// -----------------------------------------------------------------------
inline int HandleDryRun(const SandboxConfig& config,
                        const std::wstring& exePath,
                        const std::wstring& exeArgs)
{
    bool isRestricted = (config.tokenMode == TokenMode::Restricted);
    printf("=== Sandy Dry Run ===\n\n");

    printf("Mode: %ls\n", isRestricted ? L"restricted" : L"appcontainer");
    if (isRestricted)
        printf("Integrity: %ls\n",
               config.integrity == IntegrityLevel::Low ? L"low" : L"medium");
    if (!exePath.empty()) printf("Executable: %ls\n", exePath.c_str());
    if (!exeArgs.empty()) printf("Arguments: %ls\n", exeArgs.c_str());
    if (config.workdir.empty())
        printf("Working dir: (sandy.exe folder)\n\n");
    else
        printf("Working dir: %ls\n\n", config.workdir.c_str());

    PrintFolderEntries(L"allow", config.folders);
    printf("\n");
    PrintFolderEntries(L"deny", config.denyFolders);

    printf("\n[privileges]\n");
    if (!isRestricted) {
        printf("  system_dirs:     %ls\n", config.allowSystemDirs ? L"true" : L"false");
        printf("  network:         %ls\n", config.allowNetwork ? L"true" : L"false");
        printf("  localhost:       %ls\n", config.allowLocalhost ? L"true" : L"false");
        printf("  lan:             %ls\n", config.allowLan ? L"true" : L"false");
    } else {
        printf("  named_pipes:     %ls\n", config.allowNamedPipes ? L"true" : L"false");
    }
    printf("  stdin:           %ls\n", config.stdinMode.c_str());
    printf("  clipboard_read:  %ls\n", config.allowClipboardRead ? L"true" : L"false");
    printf("  clipboard_write: %ls\n", config.allowClipboardWrite ? L"true" : L"false");
    printf("  child_processes: %ls\n", config.allowChildProcesses ? L"true" : L"false");

    if (isRestricted) {
        printf("\n[registry]\n");
        if (!config.registryRead.empty()) {
            printf("  read:\n");
            for (auto& k : config.registryRead) printf("    %ls\n", k.c_str());
        }
        if (!config.registryWrite.empty()) {
            printf("  write:\n");
            for (auto& k : config.registryWrite) printf("    %ls\n", k.c_str());
        }
        if (config.registryRead.empty() && config.registryWrite.empty())
            printf("  (none)\n");
    }

    printf("\n[limit]\n");
    printf("  timeout:   %lu%ls\n", config.timeoutSeconds,
           config.timeoutSeconds == 0 ? L" (unlimited)" : L"s");
    printf("  memory:    %zuMB%ls\n", config.memoryLimitMB,
           config.memoryLimitMB == 0 ? L" (unlimited)" : L"");
    printf("  processes: %lu%ls\n", config.maxProcesses,
           config.maxProcesses == 0 ? L" (unlimited)" : L"");

    printf("\n[environment]\n");
    printf("  inherit: %ls\n", config.envInherit ? L"true" : L"false");
    if (!config.envPass.empty()) {
        printf("  pass:");
        for (auto& v : config.envPass) printf(" %ls", v.c_str());
        printf("\n");
    }

    printf("\n=== Config valid. No system state modified. ===\n");
    return 0;
}

// -----------------------------------------------------------------------
// Print resolved config (--print-config)
// -----------------------------------------------------------------------
inline int HandlePrintConfig(const SandboxConfig& config)
{
    bool isRT = (config.tokenMode == TokenMode::Restricted);

    printf("[sandbox]\n");
    printf("token = '%ls'\n", isRT ? L"restricted" : L"appcontainer");
    if (isRT)
        printf("integrity = '%ls'\n",
               config.integrity == IntegrityLevel::Low ? L"low" : L"medium");
    printf("workdir = '%ls'\n\n",
           config.workdir.empty() ? L"inherit" : config.workdir.c_str());

    PrintFolderToml(L"allow", config.folders);
    printf("\n");
    PrintFolderToml(L"deny", config.denyFolders);

    printf("\n[privileges]\n");
    if (!isRT) {
        printf("system_dirs     = %ls\n", config.allowSystemDirs ? L"true" : L"false");
        printf("network         = %ls\n", config.allowNetwork ? L"true" : L"false");
        printf("localhost       = %ls\n", config.allowLocalhost ? L"true" : L"false");
        printf("lan             = %ls\n", config.allowLan ? L"true" : L"false");
    } else {
        printf("named_pipes     = %ls\n", config.allowNamedPipes ? L"true" : L"false");
    }
    printf("stdin           = %ls\n", config.stdinMode.c_str());
    printf("clipboard_read  = %ls\n", config.allowClipboardRead ? L"true" : L"false");
    printf("clipboard_write = %ls\n", config.allowClipboardWrite ? L"true" : L"false");
    printf("child_processes = %ls\n", config.allowChildProcesses ? L"true" : L"false");

    if (isRT) {
        printf("\n[registry]\n");
        auto printKeys = [](const wchar_t* k, const std::vector<std::wstring>& v) {
            printf("%ls = [", k);
            for (size_t i = 0; i < v.size(); i++) {
                if (i) printf(", ");
                printf("'%ls'", v[i].c_str());
            }
            printf("]\n");
        };
        printKeys(L"read",  config.registryRead);
        printKeys(L"write", config.registryWrite);
    }

    printf("\n[environment]\n");
    printf("inherit = %ls\n", config.envInherit ? L"true" : L"false");
    printf("pass = [");
    for (size_t i = 0; i < config.envPass.size(); i++) {
        if (i) printf(", ");
        printf("'%ls'", config.envPass[i].c_str());
    }
    printf("]\n");

    printf("\n[limit]\n");
    printf("timeout   = %lu\n", config.timeoutSeconds);
    printf("memory    = %zu\n", config.memoryLimitMB);
    printf("processes = %lu\n", config.maxProcesses);

    return 0;
}

} // namespace Sandbox
