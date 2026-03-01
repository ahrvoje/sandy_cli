// =========================================================================
// SandboxConfig.h — Configuration loading and validation
//
// Maps TOML documents to SandboxConfig, loads config from files/strings.
// Also provides utility functions: IsRunningInAppContainer, GetExeFolder.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include "TomlParser.h"

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Check if the current process is already running inside an AppContainer
    // -----------------------------------------------------------------------
    inline bool IsRunningInAppContainer()
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;

        DWORD isAppContainer = 0;
        DWORD size = sizeof(isAppContainer);
        BOOL ok = GetTokenInformation(hToken, TokenIsAppContainer, &isAppContainer, size, &size);
        CloseHandle(hToken);

        return ok && isAppContainer != 0;
    }

    // -----------------------------------------------------------------------
    // Get the folder that contains the running exe
    // -----------------------------------------------------------------------
    inline std::wstring GetExeFolder()
    {
        wchar_t buf[MAX_PATH]{};
        DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) {
            fprintf(stderr, "[Error] Could not determine exe path.\n");
            return {};
        }
        std::wstring folder(buf, len);
        auto pos = folder.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            folder.resize(pos);
        return folder;
    }

    // -----------------------------------------------------------------------
    // Map a parsed TOML document to SandboxConfig (semantic layer).
    // All TOML syntax parsing is handled by TomlParser.h.
    // -----------------------------------------------------------------------
    inline SandboxConfig MapConfig(const Toml::ParseResult& parsed)
    {
        SandboxConfig config;
        const auto& doc = parsed.doc;

        // Forward parse-level errors
        if (!parsed.ok()) {
            for (auto& e : parsed.errors)
                fprintf(stderr, "Error: %ls\n", e.c_str());
            config.parseError = true;
        }

        // Track which sections exist
        bool sandboxSeen = doc.count(L"sandbox") > 0;
        bool registrySeen = doc.count(L"registry") > 0;

        // Reject unknown sections
        for (auto dit = doc.begin(); dit != doc.end(); ++dit) {
            const std::wstring& name = dit->first;
            if (!name.empty() &&
                name != L"sandbox" && name != L"access" && name != L"allow" &&
                name != L"registry" && name != L"environment" && name != L"limit")
            {
                fprintf(stderr, "Error: Unknown config section: [%ls]\n", name.c_str());
                config.parseError = true;
            }
        }

        // --- [sandbox] ---
        if (sandboxSeen) {
            const Toml::TomlSection& sec = doc.find(L"sandbox")->second;
            for (auto it = sec.begin(); it != sec.end(); ++it) {
                const std::wstring& key = it->first;
                const Toml::TomlValue& val = it->second;
                if (key == L"token") {
                    if (val.str == L"restricted") config.tokenMode = TokenMode::Restricted;
                    else if (val.str == L"appcontainer") config.tokenMode = TokenMode::AppContainer;
                    else {
                        fprintf(stderr, "Error: Unknown token mode: %ls\n", val.str.c_str());
                        config.parseError = true;
                    }
                } else if (key == L"integrity") {
                    if (val.str == L"low") config.integrity = IntegrityLevel::Low;
                    else if (val.str == L"medium") config.integrity = IntegrityLevel::Medium;
                    else {
                        fprintf(stderr, "Error: Unknown integrity level: %ls (expected 'low' or 'medium')\n", val.str.c_str());
                        config.parseError = true;
                    }
                } else {
                    fprintf(stderr, "Error: Unknown key in [sandbox]: %ls\n", key.c_str());
                    config.parseError = true;
                }
            }
        }

        // --- [access] ---
        {
            auto sit = doc.find(L"access");
            if (sit != doc.end()) {
                static const std::map<std::wstring, AccessLevel> accessKeys = {
                    {L"read", AccessLevel::Read}, {L"write", AccessLevel::Write},
                    {L"execute", AccessLevel::Execute}, {L"append", AccessLevel::Append},
                    {L"delete", AccessLevel::Delete}, {L"all", AccessLevel::All}
                };
                for (auto ait = sit->second.begin(); ait != sit->second.end(); ++ait) {
                    const std::wstring& key = ait->first;
                    const Toml::TomlValue& val = ait->second;
                    auto it = accessKeys.find(key);
                    if (it == accessKeys.end()) {
                        fprintf(stderr, "Error: Unknown key in [access]: %ls\n", key.c_str());
                        config.parseError = true;
                        continue;
                    }
                    if (val.isArray) {
                        for (size_t i = 0; i < val.arr.size(); i++)
                            config.folders.push_back({ val.arr[i], it->second });
                    }
                }
            }
        }

        // --- [registry] ---
        {
            auto sit = doc.find(L"registry");
            if (sit != doc.end()) {
                for (auto rit = sit->second.begin(); rit != sit->second.end(); ++rit) {
                    const std::wstring& key = rit->first;
                    const Toml::TomlValue& val = rit->second;
                    if (key == L"read" && val.isArray) {
                        for (size_t i = 0; i < val.arr.size(); i++) config.registryRead.push_back(val.arr[i]);
                    } else if (key == L"write" && val.isArray) {
                        for (size_t i = 0; i < val.arr.size(); i++) config.registryWrite.push_back(val.arr[i]);
                    } else {
                        fprintf(stderr, "Error: Unknown key in [registry]: %ls\n", key.c_str());
                        config.parseError = true;
                    }
                }
            }
        }

        // --- [allow] ---
        {
            auto sit = doc.find(L"allow");
            if (sit != doc.end()) {
                for (auto ait = sit->second.begin(); ait != sit->second.end(); ++ait) {
                    const std::wstring& key = ait->first;
                    bool enabled = (ait->second.str == L"true");
                    if (key == L"network")           config.allowNetwork = enabled;
                    else if (key == L"localhost")     config.allowLocalhost = enabled;
                    else if (key == L"lan")           config.allowLan = enabled;
                    else if (key == L"system_dirs")   config.allowSystemDirs = enabled;
                    else if (key == L"named_pipes")   config.allowNamedPipes = enabled;
                    else if (key == L"stdin")         config.allowStdin = enabled;
                    else if (key == L"clipboard_read")  config.allowClipboardRead = enabled;
                    else if (key == L"clipboard_write") config.allowClipboardWrite = enabled;
                    else if (key == L"child_processes")  config.allowChildProcesses = enabled;
                    else {
                        fprintf(stderr, "Error: Unknown key in [allow]: %ls\n", key.c_str());
                        config.parseError = true;
                    }
                }
            }
        }

        // --- [environment] ---
        {
            auto sit = doc.find(L"environment");
            if (sit != doc.end()) {
                for (auto eit = sit->second.begin(); eit != sit->second.end(); ++eit) {
                    const std::wstring& key = eit->first;
                    const Toml::TomlValue& val = eit->second;
                    if (key == L"inherit") {
                        config.envInherit = (val.str == L"true");
                    } else if (key == L"pass") {
                        if (val.isArray) config.envPass = val.arr;
                    } else {
                        fprintf(stderr, "Error: Unknown key in [environment]: %ls\n", key.c_str());
                        config.parseError = true;
                    }
                }
            }
        }

        // --- [limit] ---
        {
            auto sit = doc.find(L"limit");
            if (sit != doc.end()) {
                for (auto lit = sit->second.begin(); lit != sit->second.end(); ++lit) {
                    const std::wstring& key = lit->first;
                    const Toml::TomlValue& val = lit->second;
                    int v = _wtoi(val.str.c_str());
                    if (v <= 0 && val.str != L"0") {
                        fprintf(stderr, "[Warning] Invalid limit value: %ls = %ls\n",
                                key.c_str(), val.str.c_str());
                    } else {
                        if (key == L"timeout")        config.timeoutSeconds = static_cast<DWORD>(v);
                        else if (key == L"memory")    config.memoryLimitMB = static_cast<SIZE_T>(v);
                        else if (key == L"processes") config.maxProcesses = static_cast<DWORD>(v);
                        else {
                            fprintf(stderr, "Error: Unknown key in [limit]: %ls\n", key.c_str());
                            config.parseError = true;
                        }
                    }
                }
            }
        }

        // --- Mandatory [sandbox] check ---
        if (!sandboxSeen) {
            fprintf(stderr, "Error: [sandbox] section is required. Add [sandbox] with token = \"appcontainer\" or \"restricted\".\n");
            config.parseError = true;
        }

        // --- Mode-specific validation ---
        if (!config.parseError) {
            bool isAC = (config.tokenMode == TokenMode::AppContainer);
            bool isRT = (config.tokenMode == TokenMode::Restricted);

            if (isRT) {
                if (config.allowNetwork)   { fprintf(stderr, "Error: 'network' is not available in restricted mode (network is always unrestricted).\n");   config.parseError = true; }
                if (config.allowLocalhost) { fprintf(stderr, "Error: 'localhost' is not available in restricted mode (network is always unrestricted).\n"); config.parseError = true; }
                if (config.allowLan)       { fprintf(stderr, "Error: 'lan' is not available in restricted mode (network is always unrestricted).\n");       config.parseError = true; }
                if (config.allowSystemDirs){ fprintf(stderr, "Error: 'system_dirs' is not available in restricted mode (system dirs are always readable).\n"); config.parseError = true; }
            }

            if (isAC) {
                if (config.allowNamedPipes)          { fprintf(stderr, "Error: 'named_pipes' is not available in appcontainer mode (named pipes are always blocked).\n"); config.parseError = true; }
                if (config.integrity != IntegrityLevel::Low) { fprintf(stderr, "Error: 'integrity' is not available in appcontainer mode (always Low).\n"); config.parseError = true; }
                if (registrySeen)                   { fprintf(stderr, "Error: [registry] section is not available in appcontainer mode.\n"); config.parseError = true; }
            }
        }

        return config;
    }

    // -----------------------------------------------------------------------
    // Parse TOML string -> SandboxConfig (convenience wrapper)
    // -----------------------------------------------------------------------
    inline SandboxConfig ParseConfig(const std::wstring& content)
    {
        return MapConfig(Toml::Parse(content));
    }

    // -----------------------------------------------------------------------
    // Load config from a TOML file (reads file, then delegates to ParseConfig)
    // -----------------------------------------------------------------------
    inline SandboxConfig LoadConfig(const std::wstring& configPath)
    {
        HANDLE hFile = CreateFileW(configPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return SandboxConfig{};

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
            CloseHandle(hFile);
            return SandboxConfig{};
        }

        std::string buf(fileSize, '\0');
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, &buf[0], fileSize, &bytesRead, nullptr) || bytesRead == 0) {
            CloseHandle(hFile);
            return SandboxConfig{};
        }
        CloseHandle(hFile);

        int wideLen = MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), static_cast<int>(bytesRead), nullptr, 0);
        std::wstring content(wideLen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), static_cast<int>(bytesRead), &content[0], wideLen);

        return ParseConfig(content);
    }

} // namespace Sandbox
