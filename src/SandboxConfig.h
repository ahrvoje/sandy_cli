// =========================================================================
// SandboxConfig.h — Configuration loading and validation
//
// Maps TOML documents to SandboxConfig, loads config from files/strings.
// Also provides utility functions: IsRunningInAppContainer, GetExeFolder.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include "TomlParser.h"
#include <set>

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
        for (const auto& [name, section] : doc) {
            if (!name.empty() &&
                name != L"sandbox" && name != L"access" && name != L"allow" &&
                name != L"registry" && name != L"environment" && name != L"limit")
            {
                fprintf(stderr, "Error: Unknown config section: [%ls]\n", name.c_str());
                config.parseError = true;
            }
        }

        // --- [sandbox] ---
        bool integritySeen = false;
        bool workdirSeen = false;
        if (sandboxSeen) {
            const Toml::TomlSection& sec = doc.find(L"sandbox")->second;
            for (const auto& [key, val] : sec) {
                if (key == L"token") {
                    if (val.str == L"restricted") config.tokenMode = TokenMode::Restricted;
                    else if (val.str == L"appcontainer") config.tokenMode = TokenMode::AppContainer;
                    else {
                        fprintf(stderr, "Error: Unknown token mode: %ls\n", val.str.c_str());
                        config.parseError = true;
                    }
                } else if (key == L"integrity") {
                    integritySeen = true;
                    if (val.str == L"low") config.integrity = IntegrityLevel::Low;
                    else if (val.str == L"medium") config.integrity = IntegrityLevel::Medium;
                    else {
                        fprintf(stderr, "Error: Unknown integrity level: %ls (expected 'low' or 'medium')\n", val.str.c_str());
                        config.parseError = true;
                    }
                } else if (key == L"workdir") {
                    workdirSeen = true;
                    if (val.str == L"inherit")
                        config.workdir.clear();  // inherit = use exe folder
                    else
                        config.workdir = val.str;
                } else {
                    fprintf(stderr, "Error: Unknown key in [sandbox]: %ls\n", key.c_str());
                    config.parseError = true;
                }
            }
        }

        // --- [access] ---
        std::set<std::wstring> accessSeen;
        {
            auto sit = doc.find(L"access");
            if (sit != doc.end()) {
                static const std::map<std::wstring, AccessLevel> accessKeys = {
                    {L"read", AccessLevel::Read}, {L"write", AccessLevel::Write},
                    {L"execute", AccessLevel::Execute}, {L"append", AccessLevel::Append},
                    {L"delete", AccessLevel::Delete}, {L"all", AccessLevel::All}
                };
                for (const auto& [key, val] : sit->second) {
                    auto it = accessKeys.find(key);
                    if (it == accessKeys.end()) {
                        fprintf(stderr, "Error: Unknown key in [access]: %ls\n", key.c_str());
                        config.parseError = true;
                        continue;
                    }
                    if (val.isArray) {
                        accessSeen.insert(key);
                        for (size_t i = 0; i < val.arr.size(); i++)
                            config.folders.push_back({ val.arr[i], it->second });
                    } else {
                        fprintf(stderr, "Error: '%ls' in [access] must be an array, e.g. ['C:\\path']. Got scalar value.\n", key.c_str());
                        config.parseError = true;
                    }
                }
            }
        }

        // --- [registry] ---
        bool registryReadSeen = false;
        bool registryWriteSeen = false;
        {
            auto sit = doc.find(L"registry");
            if (sit != doc.end()) {
                for (const auto& [key, val] : sit->second) {
                    if (key == L"read") {
                        registryReadSeen = true;
                        if (!val.isArray) { fprintf(stderr, "Error: 'read' in [registry] must be an array, e.g. ['HKCU\\...'].\n"); config.parseError = true; }
                        else { for (size_t i = 0; i < val.arr.size(); i++) config.registryRead.push_back(val.arr[i]); }
                    } else if (key == L"write") {
                        registryWriteSeen = true;
                        if (!val.isArray) { fprintf(stderr, "Error: 'write' in [registry] must be an array, e.g. ['HKCU\\...'].\n"); config.parseError = true; }
                        else { for (size_t i = 0; i < val.arr.size(); i++) config.registryWrite.push_back(val.arr[i]); }
                    } else {
                        fprintf(stderr, "Error: Unknown key in [registry]: %ls\n", key.c_str());
                        config.parseError = true;
                    }
                }
            }
        }

        // --- [allow] ---
        std::set<std::wstring> allowSeen;
        {
            auto sit = doc.find(L"allow");
            if (sit != doc.end()) {
                // Helper: validate boolean value is exactly 'true' or 'false'
                auto requireBool = [&](const std::wstring& key, const std::wstring& val) -> bool {
                    if (val != L"true" && val != L"false") {
                        fprintf(stderr, "Error: '%ls' in [allow] must be 'true' or 'false', got '%ls'.\n", key.c_str(), val.c_str());
                        config.parseError = true;
                        return false;
                    }
                    return true;
                };
                for (const auto& [key, valObj] : sit->second) {
                    const std::wstring& valStr = valObj.str;
                    allowSeen.insert(key);
                    if (key == L"stdin") {
                        // true = inherit, false = NUL, anything else = file path
                        if (valStr == L"true")
                            config.stdinMode.clear();  // inherit
                        else if (valStr == L"false")
                            config.stdinMode = L"NUL";
                        else
                            config.stdinMode = valStr;  // file path
                    }
                    else if (key == L"network" || key == L"localhost" || key == L"lan" ||
                             key == L"system_dirs" || key == L"named_pipes" ||
                             key == L"clipboard_read" || key == L"clipboard_write" ||
                             key == L"child_processes") {
                        if (requireBool(key, valStr)) {
                            bool enabled = (valStr == L"true");
                            if (key == L"network")           config.allowNetwork = enabled;
                            else if (key == L"localhost")     config.allowLocalhost = enabled;
                            else if (key == L"lan")           config.allowLan = enabled;
                            else if (key == L"system_dirs")   config.allowSystemDirs = enabled;
                            else if (key == L"named_pipes")   config.allowNamedPipes = enabled;
                            else if (key == L"clipboard_read")  config.allowClipboardRead = enabled;
                            else if (key == L"clipboard_write") config.allowClipboardWrite = enabled;
                            else if (key == L"child_processes")  config.allowChildProcesses = enabled;
                        }
                    }
                    else {
                        fprintf(stderr, "Error: Unknown key in [allow]: %ls\n", key.c_str());
                        config.parseError = true;
                    }
                }
            }
        }

        // --- [environment] ---
        bool inheritSeen = false;
        bool passSeen = false;
        {
            auto sit = doc.find(L"environment");
            if (sit != doc.end()) {
                for (const auto& [key, val] : sit->second) {
                    if (key == L"inherit") {
                        if (val.str != L"true" && val.str != L"false") {
                            fprintf(stderr, "Error: 'inherit' in [environment] must be 'true' or 'false', got '%ls'.\n", val.str.c_str());
                            config.parseError = true;
                        }
                        config.envInherit = (val.str == L"true");
                        inheritSeen = true;
                    } else if (key == L"pass") {
                        passSeen = true;
                        if (val.isArray) {
                            config.envPass = val.arr;
                        } else {
                            fprintf(stderr, "Error: 'pass' in [environment] must be an array, e.g. pass = ['PATH']. Got scalar value.\n");
                            config.parseError = true;
                        }
                    } else {
                        fprintf(stderr, "Error: Unknown key in [environment]: %ls\n", key.c_str());
                        config.parseError = true;
                    }
                }
            }
        }

        // --- [limit] ---
        std::set<std::wstring> limitSeen;
        {
            auto sit = doc.find(L"limit");
            if (sit != doc.end()) {
                for (const auto& [key, val] : sit->second) {
                    int v = _wtoi(val.str.c_str());
                    // _wtoi returns 0 for non-numeric input — validate digits
                    bool isNumeric = !val.str.empty();
                    for (size_t ci = 0; ci < val.str.size() && isNumeric; ci++)
                        isNumeric = iswdigit(val.str[ci]);
                    if (key != L"timeout" && key != L"memory" && key != L"processes") {
                        fprintf(stderr, "Error: Unknown key in [limit]: %ls\n", key.c_str());
                        config.parseError = true;
                    } else if (!isNumeric) {
                        fprintf(stderr, "Error: '%ls' in [limit] must be a non-negative integer, got '%ls'.\n", key.c_str(), val.str.c_str());
                        config.parseError = true;
                    } else {
                        limitSeen.insert(key);
                        if (key == L"timeout")        config.timeoutSeconds = static_cast<DWORD>(v);
                        else if (key == L"memory")    config.memoryLimitMB = static_cast<SIZE_T>(v);
                        else if (key == L"processes") config.maxProcesses = static_cast<DWORD>(v);
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
                // Reject wrong-mode keys by presence, not value
                if (allowSeen.count(L"network"))     { fprintf(stderr, "Error: 'network' is not available in restricted mode (network is always unrestricted).\n");   config.parseError = true; }
                if (allowSeen.count(L"localhost"))   { fprintf(stderr, "Error: 'localhost' is not available in restricted mode (network is always unrestricted).\n"); config.parseError = true; }
                if (allowSeen.count(L"lan"))         { fprintf(stderr, "Error: 'lan' is not available in restricted mode (network is always unrestricted).\n");       config.parseError = true; }
                if (allowSeen.count(L"system_dirs")) { fprintf(stderr, "Error: 'system_dirs' is not available in restricted mode (system dirs are always readable).\n"); config.parseError = true; }
                if (!integritySeen)                  { fprintf(stderr, "Error: 'integrity' is required in [sandbox] for restricted mode ('low' or 'medium').\n"); config.parseError = true; }
            }

            if (isAC) {
                // Reject wrong-mode keys by presence, not value
                if (allowSeen.count(L"named_pipes")) { fprintf(stderr, "Error: 'named_pipes' is not available in appcontainer mode (named pipes are always blocked).\n"); config.parseError = true; }
                if (integritySeen)                   { fprintf(stderr, "Error: 'integrity' is not available in appcontainer mode (always Low).\n"); config.parseError = true; }
                if (registrySeen)                    { fprintf(stderr, "Error: [registry] section is not available in appcontainer mode.\n"); config.parseError = true; }
            }

            // --- Mandatory keys (no optional settings) ---
            auto requireKey = [&](const wchar_t* key, const wchar_t* section) {
                if (allowSeen.find(key) == allowSeen.end()) {
                    fprintf(stderr, "Error: '%ls' is required in [%ls]. All settings must be explicit.\n", key, section);
                    config.parseError = true;
                }
            };

            // Mode-specific mandatory [allow] keys
            if (isAC) {
                requireKey(L"system_dirs", L"allow");
                requireKey(L"network", L"allow");
                requireKey(L"localhost", L"allow");
                requireKey(L"lan", L"allow");
            }
            if (isRT) {
                requireKey(L"named_pipes", L"allow");
            }

            // Common mandatory [allow] keys
            requireKey(L"stdin", L"allow");
            requireKey(L"clipboard_read", L"allow");
            requireKey(L"clipboard_write", L"allow");
            requireKey(L"child_processes", L"allow");

            // [environment] inherit + pass are mandatory
            if (!inheritSeen) {
                fprintf(stderr, "Error: 'inherit' is required in [environment]. All settings must be explicit.\n");
                config.parseError = true;
            }
            if (!passSeen) {
                fprintf(stderr, "Error: 'pass' is required in [environment]. Use pass = [] for no extra variables.\n");
                config.parseError = true;
            }

            // [sandbox] workdir is mandatory
            if (!workdirSeen) {
                fprintf(stderr, "Error: 'workdir' is required in [sandbox]. Use workdir = 'inherit' for exe folder.\n");
                config.parseError = true;
            }

            // [access] section + all 6 keys mandatory
            if (doc.find(L"access") == doc.end()) {
                fprintf(stderr, "Error: [access] section is required. Use empty arrays [] for no grants.\n");
                config.parseError = true;
            } else {
                static const wchar_t* accessKeys[] = { L"read", L"write", L"execute", L"append", L"delete", L"all" };
                for (auto ak : accessKeys) {
                    if (accessSeen.find(ak) == accessSeen.end()) {
                        fprintf(stderr, "Error: '%ls' is required in [access]. Use %ls = [] for no grants.\n", ak, ak);
                        config.parseError = true;
                    }
                }
            }

            // [registry] section + both keys mandatory (restricted only)
            if (isRT) {
                if (!registrySeen) {
                    fprintf(stderr, "Error: [registry] section is required in restricted mode. Use empty arrays [] for no grants.\n");
                    config.parseError = true;
                } else {
                    if (!registryReadSeen) {
                        fprintf(stderr, "Error: 'read' is required in [registry]. Use read = [] for no grants.\n");
                        config.parseError = true;
                    }
                    if (!registryWriteSeen) {
                        fprintf(stderr, "Error: 'write' is required in [registry]. Use write = [] for no grants.\n");
                        config.parseError = true;
                    }
                }
            }

            // [limit] section + all 3 keys mandatory
            if (doc.find(L"limit") == doc.end()) {
                fprintf(stderr, "Error: [limit] section is required. Use 0 for unlimited.\n");
                config.parseError = true;
            } else {
                if (limitSeen.find(L"timeout") == limitSeen.end()) {
                    fprintf(stderr, "Error: 'timeout' is required in [limit]. Use timeout = 0 for no timeout.\n");
                    config.parseError = true;
                }
                if (limitSeen.find(L"memory") == limitSeen.end()) {
                    fprintf(stderr, "Error: 'memory' is required in [limit]. Use memory = 0 for no limit.\n");
                    config.parseError = true;
                }
                if (limitSeen.find(L"processes") == limitSeen.end()) {
                    fprintf(stderr, "Error: 'processes' is required in [limit]. Use processes = 0 for no limit.\n");
                    config.parseError = true;
                }
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
        if (hFile == INVALID_HANDLE_VALUE) {
            SandboxConfig cfg; cfg.parseError = true; return cfg;
        }

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
            CloseHandle(hFile);
            SandboxConfig cfg; cfg.parseError = true; return cfg;
        }

        std::string buf(fileSize, '\0');
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, &buf[0], fileSize, &bytesRead, nullptr) || bytesRead == 0) {
            CloseHandle(hFile);
            SandboxConfig cfg; cfg.parseError = true; return cfg;
        }
        CloseHandle(hFile);

        int wideLen = MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), static_cast<int>(bytesRead), nullptr, 0);
        std::wstring content(wideLen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), static_cast<int>(bytesRead), &content[0], wideLen);

        return ParseConfig(content);
    }

} // namespace Sandbox
