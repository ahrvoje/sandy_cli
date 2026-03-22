// =========================================================================
// SandboxEnvironment.h — Environment block, config summary, and logging
//
// Self-contained utilities for building filtered environment blocks,
// printing human-readable config summaries, and logging environment state.
// Each function is an independently testable semantic unit.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include <algorithm>

namespace Sandbox {

    using EnvironmentVariable = std::pair<std::wstring, std::wstring>;

    struct EnvironmentSnapshot {
        std::vector<std::wstring> hiddenVars;
        std::vector<EnvironmentVariable> vars;
    };

    inline bool IsEssentialEnvironmentVar(const std::wstring& name)
    {
        static const wchar_t* essential[] = {
            L"SYSTEMROOT", L"SYSTEMDRIVE", L"WINDIR",
            L"TEMP", L"TMP",
            L"COMSPEC", L"PATHEXT",
            L"LOCALAPPDATA", L"APPDATA",
            L"USERPROFILE", L"HOMEDRIVE", L"HOMEPATH",
            L"PROCESSOR_ARCHITECTURE", L"NUMBER_OF_PROCESSORS",
            L"OS",
        };
        for (auto* entry : essential) {
            if (_wcsicmp(name.c_str(), entry) == 0)
                return true;
        }
        return false;
    }

    inline bool IsExplicitlyPassedEnvironmentVar(const std::wstring& name,
                                                 const SandboxConfig& config)
    {
        for (const auto& allowed : config.envPass) {
            if (_wcsicmp(name.c_str(), allowed.c_str()) == 0)
                return true;
        }
        return false;
    }

    inline bool ShouldKeepEnvironmentVar(const std::wstring& name,
                                         const SandboxConfig& config)
    {
        return IsEssentialEnvironmentVar(name) ||
               IsExplicitlyPassedEnvironmentVar(name, config);
    }

    inline EnvironmentSnapshot CollectCurrentEnvironmentSnapshot()
    {
        EnvironmentSnapshot snapshot;

        LPWCH envStrings = GetEnvironmentStringsW();
        if (!envStrings)
            return snapshot;

        for (LPCWSTR p = envStrings; *p; p += wcslen(p) + 1) {
            std::wstring entry(p);
            if (entry.empty())
                continue;

            if (entry[0] == L'=') {
                snapshot.hiddenVars.push_back(std::move(entry));
                continue;
            }

            size_t eq = entry.find(L'=');
            if (eq != std::wstring::npos && eq > 0) {
                snapshot.vars.push_back({
                    entry.substr(0, eq),
                    entry.substr(eq + 1)
                });
            }
        }

        FreeEnvironmentStringsW(envStrings);
        return snapshot;
    }

    inline std::vector<EnvironmentVariable> FilterEnvironmentVars(
        const std::vector<EnvironmentVariable>& vars,
        const SandboxConfig& config)
    {
        std::vector<EnvironmentVariable> filtered;
        for (const auto& var : vars) {
            if (ShouldKeepEnvironmentVar(var.first, config))
                filtered.push_back(var);
        }
        return filtered;
    }

    inline void SortEnvironmentVarsForWindows(std::vector<EnvironmentVariable>& vars)
    {
        std::sort(vars.begin(), vars.end(),
            [](const EnvironmentVariable& a, const EnvironmentVariable& b) {
                return _wcsicmp(a.first.c_str(), b.first.c_str()) < 0;
            });
    }

    inline void AppendSerializedEnvironmentEntry(const std::wstring& entry,
                                                 std::vector<wchar_t>& block)
    {
        block.insert(block.end(), entry.begin(), entry.end());
        block.push_back(L'\0');
    }

    inline std::vector<wchar_t> SerializeEnvironmentBlock(
        const std::vector<std::wstring>& hiddenVars,
        const std::vector<EnvironmentVariable>& vars)
    {
        std::vector<wchar_t> block;
        if (hiddenVars.empty() && vars.empty()) {
            block.push_back(L'\0');
            block.push_back(L'\0');
            return block;
        }

        for (const auto& hidden : hiddenVars)
            AppendSerializedEnvironmentEntry(hidden, block);

        for (const auto& var : vars)
            AppendSerializedEnvironmentEntry(var.first + L"=" + var.second, block);

        block.push_back(L'\0');
        return block;
    }

    // -----------------------------------------------------------------------
    // BuildEnvironmentBlock — create a filtered environment for the child.
    //
    // Inputs:  config — sandbox config with envInherit flag and envPass list
    // Returns: serialized wchar_t environment block (empty = inherit all)
    // Verifiable: block contains exactly essential + passed vars, sorted;
    //             empty block when envInherit=true
    // -----------------------------------------------------------------------
    inline std::vector<wchar_t> BuildEnvironmentBlock(const SandboxConfig& config)
    {
        if (config.envInherit)
            return {};  // empty = pass nullptr to CreateProcessW (inherit all)

        EnvironmentSnapshot snapshot = CollectCurrentEnvironmentSnapshot();
        std::vector<EnvironmentVariable> filteredVars =
            FilterEnvironmentVars(snapshot.vars, config);
        SortEnvironmentVarsForWindows(filteredVars);
        return SerializeEnvironmentBlock(snapshot.hiddenVars, filteredVars);
    }

    // -----------------------------------------------------------------------
    // LogEnvironmentState — log environment block details for forensics.
    //
    // Inputs:  config — sandbox config (envInherit, envPass)
    // Effect:  logs essential vars, pass list, and env mode to session log
    // Verifiable: log entries match expected environment configuration
    // -----------------------------------------------------------------------
    inline void LogEnvironmentState(const SandboxConfig& config)
    {
        wchar_t msg[256];
        if (config.envInherit)
            swprintf(msg, 256, L"ENV: inherit all");
        else
            swprintf(msg, 256, L"ENV: filtered (pass=%zu vars)", config.envPass.size());
        g_logger.Log(msg);

        if (!config.envInherit) {
            g_logger.Log(L"ENV_ESSENTIAL: SYSTEMROOT SYSTEMDRIVE WINDIR TEMP TMP COMSPEC PATHEXT LOCALAPPDATA APPDATA USERPROFILE HOMEDRIVE HOMEPATH PROCESSOR_ARCHITECTURE NUMBER_OF_PROCESSORS OS");
            if (!config.envPass.empty()) {
                std::wstring passVars = L"ENV_PASS:";
                for (const auto& v : config.envPass) passVars += L" " + v;
                g_logger.Log(passVars.c_str());
            }
        }
    }

    // -----------------------------------------------------------------------
    // LogStdinMode — log stdin configuration for forensics.
    //
    // Inputs:  stdinMode — "" (inherit), "NUL", or file path
    // Effect:  logs stdin source to session log
    // Verifiable: log entry matches configured stdin mode
    // -----------------------------------------------------------------------
    inline void LogStdinMode(const std::wstring& stdinMode)
    {
        if (!stdinMode.empty()) {
            if (_wcsicmp(stdinMode.c_str(), L"NUL") == 0)
                g_logger.Log(L"STDIN: disabled (NUL)");
            else {
                wchar_t msg[512];
                swprintf(msg, 512, L"STDIN: file %s", stdinMode.c_str());
                g_logger.Log(msg);
            }
        } else {
            g_logger.Log(L"STDIN: inherited");
        }
    }

    inline const char* NetworkSummaryLabel(const SandboxConfig& config)
    {
        if (IsRestrictedTokenMode(config.tokenMode))
            return "unrestricted (no capability model)";
        if (config.allowNetwork)
            return "INTERNET";
        if (config.lanMode == LanMode::WithLocalhost)
            return "LAN + LOCALHOST";
        if (config.lanMode == LanMode::WithoutLocalhost)
            return "LAN";
        return "BLOCKED";
    }

    inline const char* StdinSummaryLabel(const std::wstring& stdinMode)
    {
        if (stdinMode.empty())
            return nullptr;
        return _wcsicmp(stdinMode.c_str(), L"NUL") == 0 ? "DISABLED" : "FILE";
    }

    inline void PrintSummaryHeader(const SandboxConfig& config,
                                   const std::wstring& exePath,
                                   const std::wstring& exeArgs)
    {
        fprintf(stderr, "Sandy - %s\n", TokenModeSummaryLabel(config.tokenMode));
        fprintf(stderr, "Executable: %ls\n", exePath.c_str());
        if (!exeArgs.empty())
            fprintf(stderr, "Arguments:  %ls\n", exeArgs.c_str());
    }

    inline void PrintSummaryFolders(const SandboxConfig& config)
    {
        fprintf(stderr, "Folders:    %zu configured\n",
                config.folders.size() + config.denyFolders.size());
        for (const auto& entry : config.folders)
            fprintf(stderr, "  [%ls] %ls\n", AccessTag(entry.access), entry.path.c_str());
        for (const auto& entry : config.denyFolders)
            fprintf(stderr, "  [DENY %ls] %ls\n", AccessTag(entry.access), entry.path.c_str());
    }

    inline void PrintSummaryRegistry(const SandboxConfig& config)
    {
        if (!IsRestrictedTokenMode(config.tokenMode))
            return;
        if (config.registryRead.empty() && config.registryWrite.empty())
            return;

        fprintf(stderr, "Registry:   %zu keys\n",
                config.registryRead.size() + config.registryWrite.size());
        for (const auto& key : config.registryRead)
            fprintf(stderr, "  [R]  %ls\n", key.c_str());
        for (const auto& key : config.registryWrite)
            fprintf(stderr, "  [W]  %ls\n", key.c_str());
    }

    inline void PrintSummaryPrivileges(const SandboxConfig& config)
    {
        if (IsRestrictedTokenMode(config.tokenMode) && config.strict)
            fprintf(stderr, "Strict:     YES (user SID excluded from restricting list)\n");
        if (IsRestrictedTokenMode(config.tokenMode))
            fprintf(stderr, "Named Pipes: %s\n", config.allowNamedPipes ? "ALLOWED" : "BLOCKED");

        fprintf(stderr, "Network:    %s\n", NetworkSummaryLabel(config));

        if (const char* stdinLabel = StdinSummaryLabel(config.stdinMode))
            fprintf(stderr, "Stdin:      %s\n", stdinLabel);
        if (!config.allowClipboardRead || !config.allowClipboardWrite)
            fprintf(stderr, "Clipboard:  read=%s write=%s\n",
                    config.allowClipboardRead ? "ALLOWED" : "BLOCKED",
                    config.allowClipboardWrite ? "ALLOWED" : "BLOCKED");
        if (!config.allowChildProcesses)
            fprintf(stderr, "Children:   BLOCKED\n");
        if (!config.envInherit)
            fprintf(stderr, "Env:        filtered (%zu pass vars)\n", config.envPass.size());
    }

    inline void PrintSummaryLimits(const SandboxConfig& config)
    {
        if (config.timeoutSeconds > 0)
            fprintf(stderr, "Timeout:    %lu seconds\n", config.timeoutSeconds);
        if (config.memoryLimitMB > 0)
            fprintf(stderr, "Memory:     %zu MB\n", config.memoryLimitMB);
        if (config.maxProcesses > 0)
            fprintf(stderr, "Processes:  %lu max\n", config.maxProcesses);
    }

    // -----------------------------------------------------------------------
    // PrintConfigSummary — print human-readable config to stderr.
    //
    // Prints the sandbox mode, executable, folders, registry keys, network
    // settings, limits, and other configuration for user visibility.
    //
    // Inputs:  config     — sandbox configuration
    //          exePath    — target executable path
    //          exeArgs    — command-line arguments
    // Effect:  prints formatted summary to stderr
    // Verifiable: output matches config fields exactly
    // -----------------------------------------------------------------------
    inline void PrintConfigSummary(const SandboxConfig& config,
                                   const std::wstring& exePath,
                                   const std::wstring& exeArgs)
    {
        if (config.quiet)
            return;

        PrintSummaryHeader(config, exePath, exeArgs);
        PrintSummaryFolders(config);
        PrintSummaryRegistry(config);
        fprintf(stderr, "---\n");
        PrintSummaryPrivileges(config);
        PrintSummaryLimits(config);
    }

} // namespace Sandbox
