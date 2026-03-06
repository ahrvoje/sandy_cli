// =========================================================================
// SandboxDryRun.h — Dry-run and print-config command handlers
//
// Implements --dry-run and --print-config CLI commands.
// Extracted from sandy.cpp for readability.
// =========================================================================
#pragma once

#include "SandboxTypes.h"

namespace Sandbox {

// -----------------------------------------------------------------------
// Human-readable access level name (narrow string for printf output)
// -----------------------------------------------------------------------
inline const char* AccessLevelName(AccessLevel a)
{
    switch (a) {
        case AccessLevel::Read:    return "read";
        case AccessLevel::Write:   return "write";
        case AccessLevel::Execute: return "execute";
        case AccessLevel::Append:  return "append";
        case AccessLevel::Delete:  return "delete";
        case AccessLevel::All:     return "all";
    }
    return "?";
}

// -----------------------------------------------------------------------
// Print folder entries grouped by access level (for dry-run display)
// -----------------------------------------------------------------------
inline void PrintFolderEntries(const char* section,
                               const std::vector<FolderEntry>& entries)
{
    printf("[%s]\n", section);
    if (entries.empty()) { printf("  (none)\n"); return; }
    for (int a = 0; a <= 5; a++) {
        auto lvl = static_cast<AccessLevel>(a);
        bool first = true;
        for (auto& e : entries) {
            if (e.access != lvl) continue;
            if (first) { printf("  %s:\n", AccessLevelName(lvl)); first = false; }
            printf("    %ls\n", e.path.c_str());
        }
    }
}

// -----------------------------------------------------------------------
// Print folder entries as TOML (for --print-config)
// -----------------------------------------------------------------------
inline void PrintFolderToml(const char* section,
                            const std::vector<FolderEntry>& entries)
{
    printf("[%s]\n", section);
    for (int a = 0; a <= 5; a++) {
        auto lvl = static_cast<AccessLevel>(a);
        std::string paths;
        for (auto& e : entries) {
            if (e.access != lvl) continue;
            if (!paths.empty()) paths += ", ";
            // Convert wstring path to narrow for printf
            paths += "'";
            for (wchar_t c : e.path) paths += (c < 128) ? (char)c : '?';
            paths += "'";
        }
        if (!paths.empty())
            printf("%s = [%s]\n", AccessLevelName(lvl), paths.c_str());
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

    printf("Mode: %s\n", isRestricted ? "restricted" : "appcontainer");
    if (isRestricted)
        printf("Integrity: %s\n",
               config.integrity == IntegrityLevel::Low ? "low" : "medium");
    if (!exePath.empty()) printf("Executable: %ls\n", exePath.c_str());
    if (!exeArgs.empty()) printf("Arguments: %ls\n", exeArgs.c_str());
    printf("Working dir: %s\n\n",
           config.workdir.empty() ? "(sandy.exe folder)" : "custom");

    PrintFolderEntries("allow", config.folders);
    printf("\n");
    PrintFolderEntries("deny", config.denyFolders);

    printf("\n[privileges]\n");
    if (!isRestricted) {
        printf("  system_dirs:     %s\n", config.allowSystemDirs ? "true" : "false");
        printf("  network:         %s\n", config.allowNetwork ? "true" : "false");
        printf("  localhost:       %s\n", config.allowLocalhost ? "true" : "false");
        printf("  lan:             %s\n", config.allowLan ? "true" : "false");
    } else {
        printf("  named_pipes:     %s\n", config.allowNamedPipes ? "true" : "false");
    }
    printf("  stdin:           %ls\n", config.stdinMode.c_str());
    printf("  clipboard_read:  %s\n", config.allowClipboardRead ? "true" : "false");
    printf("  clipboard_write: %s\n", config.allowClipboardWrite ? "true" : "false");
    printf("  child_processes: %s\n", config.allowChildProcesses ? "true" : "false");

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
    printf("  timeout:   %lu%s\n", config.timeoutSeconds,
           config.timeoutSeconds == 0 ? " (unlimited)" : "s");
    printf("  memory:    %zuMB%s\n", config.memoryLimitMB,
           config.memoryLimitMB == 0 ? " (unlimited)" : "");
    printf("  processes: %lu%s\n", config.maxProcesses,
           config.maxProcesses == 0 ? " (unlimited)" : "");

    printf("\n[environment]\n");
    printf("  inherit: %s\n", config.envInherit ? "true" : "false");
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
    printf("token = '%s'\n", isRT ? "restricted" : "appcontainer");
    if (isRT)
        printf("integrity = '%s'\n",
               config.integrity == IntegrityLevel::Low ? "low" : "medium");
    printf("workdir = '%ls'\n\n",
           config.workdir.empty() ? L"inherit" : config.workdir.c_str());

    PrintFolderToml("allow", config.folders);
    printf("\n");
    PrintFolderToml("deny", config.denyFolders);

    printf("\n[privileges]\n");
    if (!isRT) {
        printf("system_dirs     = %s\n", config.allowSystemDirs ? "true" : "false");
        printf("network         = %s\n", config.allowNetwork ? "true" : "false");
        printf("localhost       = %s\n", config.allowLocalhost ? "true" : "false");
        printf("lan             = %s\n", config.allowLan ? "true" : "false");
    } else {
        printf("named_pipes     = %s\n", config.allowNamedPipes ? "true" : "false");
    }
    printf("stdin           = %ls\n", config.stdinMode.c_str());
    printf("clipboard_read  = %s\n", config.allowClipboardRead ? "true" : "false");
    printf("clipboard_write = %s\n", config.allowClipboardWrite ? "true" : "false");
    printf("child_processes = %s\n", config.allowChildProcesses ? "true" : "false");

    if (isRT) {
        printf("\n[registry]\n");
        auto printKeys = [](const char* k, const std::vector<std::wstring>& v) {
            printf("%s = [", k);
            for (size_t i = 0; i < v.size(); i++) {
                if (i) printf(", ");
                printf("'%ls'", v[i].c_str());
            }
            printf("]\n");
        };
        printKeys("read",  config.registryRead);
        printKeys("write", config.registryWrite);
    }

    printf("\n[environment]\n");
    printf("inherit = %s\n", config.envInherit ? "true" : "false");
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
