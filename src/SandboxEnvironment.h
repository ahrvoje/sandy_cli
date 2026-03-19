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
        std::vector<wchar_t> block;

        if (config.envInherit)
            return block;  // empty = pass nullptr to CreateProcessW (inherit all)

        // Collect environment variables
        // Hidden vars (starting with '=', e.g. =C:=C:\path) are drive-letter
        // assignments required by the Windows loader — always include them.
        std::vector<std::wstring> hiddenVars;
        std::vector<std::pair<std::wstring, std::wstring>> env;

        LPWCH envStrings = GetEnvironmentStringsW();
        if (envStrings) {
            for (LPCWSTR p = envStrings; *p; p += wcslen(p) + 1) {
                std::wstring entry(p);
                if (entry[0] == L'=') {
                    hiddenVars.push_back(entry);
                    continue;
                }
                auto eq = entry.find(L'=');
                if (eq != std::wstring::npos && eq > 0)
                    env.push_back({ entry.substr(0, eq), entry.substr(eq + 1) });
            }
            FreeEnvironmentStringsW(envStrings);
        }

        // Keep only essential vars + explicitly passed vars
        std::vector<std::pair<std::wstring, std::wstring>> filtered;
        auto isAllowed = [&](const std::wstring& name) {
            // Always pass essential Windows vars needed by the loader
            static const wchar_t* essential[] = {
                L"SYSTEMROOT", L"SYSTEMDRIVE", L"WINDIR",
                L"TEMP", L"TMP",
                L"COMSPEC", L"PATHEXT",
                L"LOCALAPPDATA", L"APPDATA",
                L"USERPROFILE", L"HOMEDRIVE", L"HOMEPATH",
                L"PROCESSOR_ARCHITECTURE", L"NUMBER_OF_PROCESSORS",
                L"OS",
            };
            for (auto* e : essential) {
                if (_wcsicmp(name.c_str(), e) == 0) return true;
            }
            for (const auto& allowed : config.envPass) {
                if (_wcsicmp(name.c_str(), allowed.c_str()) == 0) return true;
            }
            return false;
        };
        for (auto& p : env) {
            if (isAllowed(p.first)) filtered.push_back(p);
        }
        env = std::move(filtered);

        // Sort regular vars alphabetically by name (required by Windows)
        std::sort(env.begin(), env.end(),
            [](const std::pair<std::wstring, std::wstring>& a,
               const std::pair<std::wstring, std::wstring>& b) {
                return _wcsicmp(a.first.c_str(), b.first.c_str()) < 0;
            });

        // Serialize: hidden vars first, then KEY=VALUE\0...\0
        if (hiddenVars.empty() && env.empty()) {
            // Empty block must still be double-NUL terminated for CreateProcess
            block.push_back(L'\0');
            block.push_back(L'\0');
            return block;
        }
        for (const auto& h : hiddenVars) {
            block.insert(block.end(), h.begin(), h.end());
            block.push_back(L'\0');
        }
        for (const auto& p : env) {
            std::wstring line = p.first + L"=" + p.second;
            block.insert(block.end(), line.begin(), line.end());
            block.push_back(L'\0');
        }
        block.push_back(L'\0');
        return block;
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

    // -----------------------------------------------------------------------
    // PrintConfigSummary — print human-readable config to stderr.
    //
    // Prints the sandbox mode, executable, folders, registry keys, network
    // settings, limits, and other configuration for user visibility.
    //
    // Inputs:  config     — sandbox configuration
    //          exePath    — target executable path
    //          exeArgs    — command-line arguments
    //          isRestricted — true for restricted-token mode
    // Effect:  prints formatted summary to stderr
    // Verifiable: output matches config fields exactly
    // -----------------------------------------------------------------------
    inline void PrintConfigSummary(const SandboxConfig& config,
                                    const std::wstring& exePath,
                                    const std::wstring& exeArgs,
                                    bool isRestricted)
    {
        if (config.quiet) return;

        const char* modeLabel = isRestricted ? "Restricted Token"
                             : (config.tokenMode == TokenMode::LPAC) ? "LPAC Sandbox"
                             : "AppContainer";
        fprintf(stderr, "Sandy - %s\n", modeLabel);
        fprintf(stderr, "Executable: %ls\n", exePath.c_str());
        if (!exeArgs.empty())
            fprintf(stderr, "Arguments:  %ls\n", exeArgs.c_str());
        fprintf(stderr, "Folders:    %zu configured\n", config.folders.size() + config.denyFolders.size());
        for (const auto& e : config.folders) {
            fprintf(stderr, "  [%ls] %ls\n", AccessTag(e.access), e.path.c_str());
        }
        if (!config.denyFolders.empty()) {
            for (const auto& e : config.denyFolders) {
                fprintf(stderr, "  [DENY %ls] %ls\n", AccessTag(e.access), e.path.c_str());
            }
        }
        if (isRestricted && (!config.registryRead.empty() || !config.registryWrite.empty())) {
            fprintf(stderr, "Registry:   %zu keys\n", config.registryRead.size() + config.registryWrite.size());
            for (const auto& k : config.registryRead)  fprintf(stderr, "  [R]  %ls\n", k.c_str());
            for (const auto& k : config.registryWrite) fprintf(stderr, "  [W]  %ls\n", k.c_str());
        }
        fprintf(stderr, "---\n");
        if (isRestricted && config.strict)
            fprintf(stderr, "Strict:     YES (user SID excluded from restricting list)\n");
        if (isRestricted)
            fprintf(stderr, "Named Pipes: %s\n", config.allowNamedPipes ? "ALLOWED" : "BLOCKED");

        fprintf(stderr, "Network:    %s\n", isRestricted ? "unrestricted (no capability model)" :
                                            config.allowNetwork ? "INTERNET" :
                                            config.allowLan     ? "LAN ONLY" : "BLOCKED");
        if (config.allowLocalhost && !isRestricted)
            fprintf(stderr, "Localhost:  ALLOWED\n");
        if (!config.stdinMode.empty())
            fprintf(stderr, "Stdin:      %s\n",
                    _wcsicmp(config.stdinMode.c_str(), L"NUL") == 0 ? "DISABLED" : "FILE");
        if (!config.allowClipboardRead || !config.allowClipboardWrite)
            fprintf(stderr, "Clipboard:  read=%s write=%s\n",
                    config.allowClipboardRead ? "ALLOWED" : "BLOCKED",
                    config.allowClipboardWrite ? "ALLOWED" : "BLOCKED");
        if (!config.allowChildProcesses)
            fprintf(stderr, "Children:   BLOCKED\n");
        if (!config.envInherit)
            fprintf(stderr, "Env:        filtered (%zu pass vars)\n", config.envPass.size());
        if (config.timeoutSeconds > 0)
            fprintf(stderr, "Timeout:    %lu seconds\n", config.timeoutSeconds);
        if (config.memoryLimitMB > 0)
            fprintf(stderr, "Memory:     %zu MB\n", config.memoryLimitMB);
        if (config.maxProcesses > 0)
            fprintf(stderr, "Processes:  %lu max\n", config.maxProcesses);
    }

} // namespace Sandbox
