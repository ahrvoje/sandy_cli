// =========================================================================
// SandboxConfig.h — Configuration loading and validation
//
// Maps TOML documents to SandboxConfig, loads config from files/strings.
// Also provides utility function: GetInheritedWorkdir.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include "TomlParser.h"
#include <set>

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Get the inherited working directory for the child process.
    //
    // Sandy's contract is simple: workdir is either set explicitly in config
    // or inherited from Sandy's own current working directory.
    // -----------------------------------------------------------------------
    inline std::wstring GetInheritedWorkdir()
    {
        DWORD len = GetCurrentDirectoryW(0, nullptr);
        if (len == 0) {
            fprintf(stderr, "[Error] Could not determine current working directory.\n");
            return {};
        }
        std::wstring workdir(len, L'\0');
        DWORD copied = GetCurrentDirectoryW(len, &workdir[0]);
        if (copied == 0 || copied >= len) {
            fprintf(stderr, "[Error] Could not determine current working directory.\n");
            return {};
        }
        workdir.resize(copied);
        return workdir;
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
                name != L"sandbox" &&
                name != L"allow.deep" && name != L"allow.this" &&
                name != L"deny.deep" && name != L"deny.this" &&
                name != L"privileges" &&
                name != L"registry" && name != L"environment" && name != L"limit")
            {
                fprintf(stderr, "Error: Unknown config section: [%ls]\n", name.c_str());
                config.parseError = true;
            }
        }

        // --- [sandbox] ---
        bool integritySeen = false;
        bool workdirSeen = false;
        bool tokenSeen = false;
        if (sandboxSeen) {
            const Toml::TomlSection& sec = doc.find(L"sandbox")->second;
            for (const auto& [key, val] : sec) {
                if (key == L"token") {
                    tokenSeen = true;
                    if (val.str == L"restricted") config.tokenMode = TokenMode::Restricted;
                    else if (val.str == L"appcontainer") config.tokenMode = TokenMode::AppContainer;
                    else if (val.str == L"lpac") config.tokenMode = TokenMode::LPAC;
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
                        config.workdir.clear();  // inherit = use Sandy's current working directory
                    else
                        config.workdir = val.str;
                } else {
                    fprintf(stderr, "Error: Unknown key in [sandbox]: %ls\n", key.c_str());
                    config.parseError = true;
                }
            }
        }

        // token is always mandatory
        if (sandboxSeen && !tokenSeen) {
            fprintf(stderr, "Error: 'token' is required in [sandbox]. Use token = 'appcontainer' or 'restricted'.\n");
            config.parseError = true;
        }
        // --- [allow.deep] / [allow.this] — file/folder ALLOW ACEs ---
        std::set<std::wstring> allowSeen;
        {
            static const std::map<std::wstring, AccessLevel> allowKeys = {
                {L"read", AccessLevel::Read}, {L"write", AccessLevel::Write},
                {L"execute", AccessLevel::Execute}, {L"append", AccessLevel::Append},
                {L"delete", AccessLevel::Delete}, {L"all", AccessLevel::All},
                {L"run", AccessLevel::Run}, {L"stat", AccessLevel::Stat},
                {L"touch", AccessLevel::Touch}, {L"create", AccessLevel::Create}
            };
            auto parseAllow = [&](const wchar_t* sectionName, GrantScope scope) {
                auto sit = doc.find(sectionName);
                if (sit == doc.end()) return;
                for (const auto& [key, val] : sit->second) {
                    auto it = allowKeys.find(key);
                    if (it == allowKeys.end()) {
                        fprintf(stderr, "Error: Unknown key in [%ls]: %ls\n", sectionName, key.c_str());
                        config.parseError = true;
                        continue;
                    }
                    if (val.isArray) {
                        allowSeen.insert(key);
                        for (size_t i = 0; i < val.arr.size(); i++)
                            config.folders.push_back({ val.arr[i], it->second, scope });
                    } else {
                        fprintf(stderr, "Error: '%ls' in [%ls] must be an array, e.g. ['C:\\path']. Got scalar value.\n", key.c_str(), sectionName);
                        config.parseError = true;
                    }
                }
            };
            parseAllow(L"allow.deep", GrantScope::Deep);
            parseAllow(L"allow.this", GrantScope::This);
            // Reject bare [allow] — must use [allow.deep] or [allow.this]
            if (doc.find(L"allow") != doc.end()) {
                fprintf(stderr, "Error: [allow] is no longer supported. Use [allow.deep] or [allow.this].\n");
                config.parseError = true;
            }
        }

        // --- [deny.deep] / [deny.this] — file/folder DENY ACEs ---
        std::set<std::wstring> denySeen;
        {
            static const std::map<std::wstring, AccessLevel> denyKeys = {
                {L"read", AccessLevel::Read}, {L"write", AccessLevel::Write},
                {L"execute", AccessLevel::Execute}, {L"append", AccessLevel::Append},
                {L"delete", AccessLevel::Delete}, {L"all", AccessLevel::All},
                {L"run", AccessLevel::Run}, {L"stat", AccessLevel::Stat},
                {L"touch", AccessLevel::Touch}, {L"create", AccessLevel::Create}
            };
            auto parseDeny = [&](const wchar_t* sectionName, GrantScope scope) {
                auto sit = doc.find(sectionName);
                if (sit == doc.end()) return;
                for (const auto& [key, val] : sit->second) {
                    auto it = denyKeys.find(key);
                    if (it == denyKeys.end()) {
                        fprintf(stderr, "Error: Unknown key in [%ls]: %ls\n", sectionName, key.c_str());
                        config.parseError = true;
                        continue;
                    }
                    if (val.isArray) {
                        denySeen.insert(key);
                        for (size_t i = 0; i < val.arr.size(); i++)
                            config.denyFolders.push_back({ val.arr[i], it->second, scope });
                    } else {
                        fprintf(stderr, "Error: '%ls' in [%ls] must be an array, e.g. ['C:\\path']. Got scalar value.\n", key.c_str(), sectionName);
                        config.parseError = true;
                    }
                }
            };
            parseDeny(L"deny.deep", GrantScope::Deep);
            parseDeny(L"deny.this", GrantScope::This);
            // Reject bare [deny]
            if (doc.find(L"deny") != doc.end()) {
                fprintf(stderr, "Error: [deny] is no longer supported. Use [deny.deep] or [deny.this].\n");
                config.parseError = true;
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

        // --- [privileges] — sandbox capabilities ---
        std::set<std::wstring> privSeen;
        {
            auto sit = doc.find(L"privileges");
            if (sit != doc.end()) {
                // Helper: validate boolean value is exactly 'true' or 'false'
                auto requireBool = [&](const std::wstring& key, const std::wstring& val) -> bool {
                    if (val != L"true" && val != L"false") {
                        fprintf(stderr, "Error: '%ls' in [privileges] must be 'true' or 'false', got '%ls'.\n", key.c_str(), val.c_str());
                        config.parseError = true;
                        return false;
                    }
                    return true;
                };
                for (const auto& [key, valObj] : sit->second) {
                    const std::wstring& valStr = valObj.str;
                    privSeen.insert(key);
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
                             key == L"named_pipes" || key == L"desktop" ||
                             key == L"clipboard_read" || key == L"clipboard_write" ||
                             key == L"child_processes") {
                        if (requireBool(key, valStr)) {
                            bool enabled = (valStr == L"true");
                            if (key == L"network")           config.allowNetwork = enabled;
                            else if (key == L"localhost")     config.allowLocalhost = enabled;
                            else if (key == L"lan")           config.allowLan = enabled;
                            else if (key == L"named_pipes")   config.allowNamedPipes = enabled;
                            else if (key == L"desktop")       config.allowDesktop = enabled;
                            else if (key == L"clipboard_read")  config.allowClipboardRead = enabled;
                            else if (key == L"clipboard_write") config.allowClipboardWrite = enabled;
                            else if (key == L"child_processes")  config.allowChildProcesses = enabled;
                        }
                    }
                    else {
                        fprintf(stderr, "Error: Unknown key in [privileges]: %ls\n", key.c_str());
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
            bool isAC = (config.tokenMode != TokenMode::Restricted);  // AC and LPAC share validation
            bool isRT = (config.tokenMode == TokenMode::Restricted);

            if (isRT) {
                // Reject wrong-mode keys by presence, not value
                if (privSeen.count(L"network"))     { fprintf(stderr, "Error: 'network' is not available in restricted mode (network is always unrestricted).\n");   config.parseError = true; }
                if (privSeen.count(L"localhost"))   { fprintf(stderr, "Error: 'localhost' is not available in restricted mode (network is always unrestricted).\n"); config.parseError = true; }
                if (privSeen.count(L"lan"))         { fprintf(stderr, "Error: 'lan' is not available in restricted mode (network is always unrestricted).\n");       config.parseError = true; }
                if (!integritySeen)                  { fprintf(stderr, "Error: 'integrity' is required in [sandbox] for restricted mode ('low' or 'medium').\n"); config.parseError = true; }
            }

            if (isAC) {
                // Reject wrong-mode keys by presence, not value
                if (privSeen.count(L"named_pipes")) { fprintf(stderr, "Error: 'named_pipes' is not available in appcontainer/lpac mode (named pipes are always blocked).\n"); config.parseError = true; }
                if (privSeen.count(L"desktop"))     { fprintf(stderr, "Error: 'desktop' is not available in appcontainer/lpac mode (desktop access is inherited from creator token).\n"); config.parseError = true; }
                if (integritySeen)                   { fprintf(stderr, "Error: 'integrity' is not available in appcontainer/lpac mode (always Low).\n"); config.parseError = true; }
                if (registrySeen)                    { fprintf(stderr, "Error: [registry] section is not available in appcontainer/lpac mode.\n"); config.parseError = true; }
                if (!config.denyFolders.empty()) {
                    fprintf(stderr, "Error: [deny.*] is not available in appcontainer mode.\n");
                    fprintf(stderr, "  The Windows kernel ignores DENY ACEs for AppContainer SIDs.\n");
                    fprintf(stderr, "  Use token = 'restricted' for deny rules, or remove the deny sections.\n");
                    config.parseError = true;
                }
            }
        }

        // Normalize filesystem paths once at config-ingest time so the rest of
        // the sandbox can reason about one canonical separator style.
        config.workdir = NormalizeFsPath(config.workdir);
        if (!config.stdinMode.empty() && _wcsicmp(config.stdinMode.c_str(), L"NUL") != 0)
            config.stdinMode = NormalizeFsPath(config.stdinMode);
        for (auto& e : config.folders)
            e.path = NormalizeFsPath(e.path);
        for (auto& e : config.denyFolders)
            e.path = NormalizeFsPath(e.path);

        // --- Path validation (absolute paths, existence, deduplication) ---
        if (!config.parseError) {
            auto validatePaths = [&](const std::vector<FolderEntry>& entries, const wchar_t* section) {
                std::set<std::wstring> seen;
                for (const auto& e : entries) {
                    if (e.path.empty()) continue;
                    // Check absolute path (drive letter or UNC)
                    bool isAbsolute = (e.path.size() >= 3 && e.path[1] == L':' && e.path[2] == L'\\');
                    bool isUNC = (e.path.size() >= 2 && e.path[0] == L'\\' && e.path[1] == L'\\');
                    if (!isAbsolute && !isUNC) {
                        fprintf(stderr, "Error: '%ls' in [%ls] is not an absolute path. Use 'C:\\...' format.\n",
                                e.path.c_str(), section);
                        config.parseError = true;
                    }
                    // Non-existent paths are a config error (R9: fail-safe)
                    if (GetFileAttributesW(e.path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                        fprintf(stderr, "Error: Path does not exist: %ls (in [%ls])\n",
                                e.path.c_str(), section);
                        config.parseError = true;
                    }
                    // Detect duplicates within same section
                    if (!seen.insert(e.path).second) {
                        if (g_logger.IsActive())
                            g_logger.LogFmt(L"CONFIG_WARN: Duplicate path in [%s]: %s", section, e.path.c_str());
                        else
                            fprintf(stderr, "Warning: Duplicate path in [%ls]: %ls\n", section, e.path.c_str());
                    }
                }
            };
            validatePaths(config.folders, L"allow.*");
            validatePaths(config.denyFolders, L"deny.*");

            // Validate registry paths have proper prefix
            for (const auto& key : config.registryRead) {
                if (_wcsnicmp(key.c_str(), L"HKCU\\", 5) != 0 &&
                    _wcsnicmp(key.c_str(), L"HKLM\\", 5) != 0) {
                    fprintf(stderr, "Error: Registry path must start with 'HKCU\\' or 'HKLM\\': %ls\n", key.c_str());
                    config.parseError = true;
                }
            }
            for (const auto& key : config.registryWrite) {
                if (_wcsnicmp(key.c_str(), L"HKCU\\", 5) != 0 &&
                    _wcsnicmp(key.c_str(), L"HKLM\\", 5) != 0) {
                    fprintf(stderr, "Error: Registry path must start with 'HKCU\\' or 'HKLM\\': %ls\n", key.c_str());
                    config.parseError = true;
                }
            }

            // --- Sanity limits (defense-in-depth against crafted configs) ---
            constexpr size_t kMaxPathLength = 32768;   // Win32 MAX_PATH extended limit
            constexpr size_t kMaxRulesPerSection = 256; // reasonable upper bound

            auto checkPathLengths = [&](const std::vector<FolderEntry>& entries, const wchar_t* section) {
                for (const auto& e : entries) {
                    if (e.path.size() > kMaxPathLength) {
                        fprintf(stderr, "Error: Path in [%ls] exceeds %zu character limit (%zu chars).\n",
                                section, kMaxPathLength, e.path.size());
                        config.parseError = true;
                    }
                }
            };
            checkPathLengths(config.folders, L"allow.*");
            checkPathLengths(config.denyFolders, L"deny.*");

            if (config.folders.size() > kMaxRulesPerSection) {
                fprintf(stderr, "Error: allow sections have %zu rules (max %zu). Reduce configuration complexity.\n",
                        config.folders.size(), kMaxRulesPerSection);
                config.parseError = true;
            }
            if (config.denyFolders.size() > kMaxRulesPerSection) {
                fprintf(stderr, "Error: deny sections have %zu rules (max %zu). Reduce configuration complexity.\n",
                        config.denyFolders.size(), kMaxRulesPerSection);
                config.parseError = true;
            }
            if (config.registryRead.size() + config.registryWrite.size() > kMaxRulesPerSection) {
                fprintf(stderr, "Error: [registry] has %zu keys (max %zu). Reduce configuration complexity.\n",
                        config.registryRead.size() + config.registryWrite.size(), kMaxRulesPerSection);
                config.parseError = true;
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
        // Defense-in-depth: reject unreasonably large config files (>1 MB)
        constexpr DWORD kMaxConfigFileSize = 1024 * 1024;
        if (fileSize > kMaxConfigFileSize) {
            CloseHandle(hFile);
            fprintf(stderr, "Error: Config file exceeds 1 MB size limit (%lu bytes).\n", fileSize);
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
