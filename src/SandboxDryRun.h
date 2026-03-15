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
#include "SandboxSavedProfile.h"

namespace Sandbox {

// -----------------------------------------------------------------------
// Print folder entries grouped by access level (for dry-run display)
// -----------------------------------------------------------------------
inline void PrintFolderEntries(const wchar_t* section,
                               const std::vector<FolderEntry>& entries,
                               GrantScope scope)
{
    printf("[%ls]\n", section);
    bool anyMatch = false;
    for (int a = 0; a <= static_cast<int>(AccessLevel::Create); a++) {
        auto lvl = static_cast<AccessLevel>(a);
        bool first = true;
        for (auto& e : entries) {
            if (e.access != lvl || e.scope != scope) continue;
            anyMatch = true;
            if (first) { printf("  %ls:\n", AccessLevelName(lvl)); first = false; }
            printf("    %ls\n", e.path.c_str());
        }
    }
    if (!anyMatch) printf("  (none)\n");
}

// -----------------------------------------------------------------------
// Print folder entries as TOML (for --print-config)
// -----------------------------------------------------------------------
inline void PrintFolderToml(const wchar_t* section,
                            const std::vector<FolderEntry>& entries,
                            GrantScope scope)
{
    printf("[%ls]\n", section);
    for (int a = 0; a <= static_cast<int>(AccessLevel::Create); a++) {
        auto lvl = static_cast<AccessLevel>(a);
        bool first = true;
        for (auto& e : entries) {
            if (e.access != lvl || e.scope != scope) continue;
            if (first) {
                printf("%ls = [", AccessLevelName(lvl));
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
        printf("Working dir: (inherited from Sandy current working directory)\n\n");
    else
        printf("Working dir: %ls\n\n", config.workdir.c_str());

    PrintFolderEntries(L"allow.deep", config.folders, GrantScope::Deep);
    printf("\n");
    PrintFolderEntries(L"allow.this", config.folders, GrantScope::This);
    printf("\n");
    PrintFolderEntries(L"deny.deep", config.denyFolders, GrantScope::Deep);
    printf("\n");
    PrintFolderEntries(L"deny.this", config.denyFolders, GrantScope::This);

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
// Dry-run mode for --create-profile — validate only, no system changes
// -----------------------------------------------------------------------
inline int HandleDryRunCreateProfile(const std::wstring& name,
                                     const std::wstring& configPath)
{
    printf("=== Sandy Dry Run: create-profile '%ls' ===\n\n", name.c_str());

    // --- Validate name ---
    if (name.empty()) {
        fprintf(stderr, "Error: profile name cannot be empty.\n");
        return SandyExit::ConfigError;
    }
    for (wchar_t c : name) {
        if (c == L'\\' || c == L'/' || c == L'|' || c == L'"' || c < 32) {
            fprintf(stderr, "Error: profile name contains invalid characters.\n");
            return SandyExit::ConfigError;
        }
    }

    // --- Duplicate check ---
    if (ProfileExists(name)) {
        fprintf(stderr, "Error: profile '%ls' already exists. Use --delete-profile first.\n",
                name.c_str());
        return SandyExit::ConfigError;
    }

    // --- Read and parse TOML ---
    std::wstring tomlText = ReadTomlFileText(configPath);
    if (tomlText.empty()) {
        fprintf(stderr, "Error: cannot read config file: %ls\n", configPath.c_str());
        return SandyExit::ConfigError;
    }
    SandboxConfig config = ParseConfig(tomlText);
    if (config.parseError) {
        fprintf(stderr, "Error: config contains unknown sections or keys.\n");
        return SandyExit::ConfigError;
    }

    bool isAC = (config.tokenMode == TokenMode::AppContainer);
    const wchar_t* typeStr      = isAC ? L"appcontainer" : L"restricted";
    const wchar_t* integrityStr = (config.integrity == IntegrityLevel::Low) ? L"low" : L"medium";

    // --- Print what would happen ---
    printf("Profile name: %ls\n", name.c_str());
    printf("Type:         %ls\n", typeStr);
    if (!isAC)
        printf("Integrity:    %ls\n", integrityStr);
    if (isAC)
        printf("Container:    Sandy_%ls  (would be created via CreateAppContainerProfile)\n",
               name.c_str());
    printf("SID:          (would be generated at creation time)\n");
    printf("Registry key: HKCU\\Software\\Sandy\\Profiles\\%ls\n\n", name.c_str());

    printf("[allow] — %zu path(s) would be granted\n", config.folders.size());
    for (auto& f : config.folders)
        printf("  [%-7ls] %ls\n", AccessTag(f.access), f.path.c_str());

    if (!config.denyFolders.empty()) {
        printf("[deny.*] \u2014 %zu path(s)\n", config.denyFolders.size());
        for (auto& f : config.denyFolders)
            printf("  [%-7ls] %ls\n", AccessTag(f.access), f.path.c_str());
    }

    if (!isAC && (!config.registryRead.empty() || !config.registryWrite.empty())) {
        printf("[registry]\n");
        for (auto& k : config.registryRead)  printf("  read:  %ls\n", k.c_str());
        for (auto& k : config.registryWrite) printf("  write: %ls\n", k.c_str());
    }

    printf("\n=== Dry run complete. No system state modified. ===\n");
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

    PrintFolderToml(L"allow.deep", config.folders, GrantScope::Deep);
    PrintFolderToml(L"allow.this", config.folders, GrantScope::This);
    printf("\n");
    PrintFolderToml(L"deny.deep", config.denyFolders, GrantScope::Deep);
    PrintFolderToml(L"deny.this", config.denyFolders, GrantScope::This);

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
