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

#include "SandboxConfigRender.h"
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
// Dry-run mode (--dry-run / --check) — validate config + show plan
// -----------------------------------------------------------------------
inline int HandleDryRun(const SandboxConfig& config,
                        const std::wstring& exePath,
                        const std::wstring& exeArgs)
{
    bool isRestricted = IsRestrictedTokenMode(config.tokenMode);
    printf("=== Sandy Dry Run ===\n\n");

    printf("Mode: %ls\n", TokenModeName(config.tokenMode));
    if (isRestricted)
        printf("Integrity: %ls\n",
               config.integrity == IntegrityLevel::Low ? L"low" : L"medium");
    if (isRestricted && config.strict)
        printf("Strict: yes (user SID excluded from restricting list)\n");
    if (!exePath.empty()) printf("Executable: %ls\n", exePath.c_str());
    if (!exeArgs.empty()) printf("Arguments: %ls\n", exeArgs.c_str());
    if (config.workdir.empty())
        printf("Working dir: (inherited from Sandy's current working directory)\n\n");
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
        printf("  network:         %ls\n", config.allowNetwork ? L"true" : L"false");
        printf("  lan:             %ls\n", LanModeTomlDisplayValue(config.lanMode));
    } else {
        printf("  named_pipes:     %ls\n", config.allowNamedPipes ? L"true" : L"false");
        printf("  desktop:         %ls\n", config.allowDesktop ? L"true" : L"false");
    }
    // P3: Map internal stdinMode to user-visible representation
    // (NUL = false, empty = true/inherited, other = file path)
    if (config.stdinMode == L"NUL")
        printf("  stdin:           false\n");
    else if (config.stdinMode.empty())
        printf("  stdin:           true\n");
    else
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

    // --- Validate name (same rules as HandleCreateProfile) ---
    if (!ValidateProfileCreateName(name))
        return SandyExit::ConfigError;

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
    SandboxConfig config = ParseConfigFileText(tomlText);
    if (config.parseError) {
        fprintf(stderr, "Error: config contains unknown sections or keys.\n");
        return SandyExit::ConfigError;
    }

    bool isRestricted = IsRestrictedTokenMode(config.tokenMode);
    bool isAppContainerFamily = IsAppContainerFamilyTokenMode(config.tokenMode);
    const wchar_t* integrityStr = (config.integrity == IntegrityLevel::Low) ? L"low" : L"medium";

    // --- Print what would happen ---
    printf("Profile name: %ls\n", name.c_str());
    printf("Type:         %ls\n", TokenModeName(config.tokenMode));
    if (isRestricted)
        printf("Integrity:    %ls\n", integrityStr);
    if (isAppContainerFamily)
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

    if (isRestricted && (!config.registryRead.empty() || !config.registryWrite.empty())) {
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
    PrintResolvedConfig(config);
    return 0;
}

} // namespace Sandbox
