// =========================================================================
// SandboxConfig.h — Configuration loading and validation
//
// Maps TOML documents to SandboxConfig, loads config from files/strings.
// TOML parsing is handled by toml11 via TomlAdapter.h.
// Also provides utility function: GetInheritedWorkdir.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include "TomlAdapter.h"
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
    // ReadTomlFileUtf8 — load a TOML config file as validated UTF-8 bytes.
    //
    // File-backed config must keep raw file semantics. In particular, this
    // path must NOT apply the inline `-s` literal-newline translation used by
    // Toml::Parse(wstring).
    // -----------------------------------------------------------------------
    inline std::string ReadTomlFileUtf8(const std::wstring& configPath)
    {
        HANDLE hFile = CreateFileW(configPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return {};

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
            CloseHandle(hFile);
            return {};
        }

        constexpr DWORD kMaxConfigFileSize = 1024 * 1024;
        if (fileSize > kMaxConfigFileSize) {
            CloseHandle(hFile);
            fprintf(stderr, "Error: Config file exceeds 1 MB size limit (%lu bytes).\n", fileSize);
            return {};
        }

        std::string buf(fileSize, '\0');
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, &buf[0], fileSize, &bytesRead, nullptr) || bytesRead == 0) {
            CloseHandle(hFile);
            return {};
        }
        CloseHandle(hFile);
        buf.resize(bytesRead);

        // UTF-8 BOM (EF BB BF) passes through to toml11 as U+FEFF,
        // invisibly corrupting the first token and causing cryptic parse errors.
        if (bytesRead >= 3 &&
            static_cast<unsigned char>(buf[0]) == 0xEF &&
            static_cast<unsigned char>(buf[1]) == 0xBB &&
            static_cast<unsigned char>(buf[2]) == 0xBF) {
            fprintf(stderr, "Error: Config file starts with a UTF-8 BOM (byte order mark).\n");
            fprintf(stderr, "  Sandy requires clean UTF-8 without a BOM. Re-save the file as 'UTF-8' (not 'UTF-8 with BOM').\n");
            return {};
        }

        if (bytesRead >= 2 &&
            ((static_cast<unsigned char>(buf[0]) == 0xFF && static_cast<unsigned char>(buf[1]) == 0xFE) ||
             (static_cast<unsigned char>(buf[0]) == 0xFE && static_cast<unsigned char>(buf[1]) == 0xFF))) {
            fprintf(stderr, "Error: Config file appears to be UTF-16 encoded.\n");
            fprintf(stderr, "  Sandy requires plain UTF-8. Re-save the file as 'UTF-8' (not 'Unicode' or 'UTF-16').\n");
            return {};
        }

        int wideLen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                          buf.c_str(), static_cast<int>(bytesRead),
                                          nullptr, 0);
        if (wideLen == 0) {
            fprintf(stderr, "Error: Config file contains invalid UTF-8 byte sequences.\n");
            return {};
        }

        return buf;
    }

    // -----------------------------------------------------------------------
    // ReadTomlFileText — load a TOML config file as raw wide text.
    //
    // Uses the same UTF-8 validation as ReadTomlFileUtf8 so dry-run/profile
    // flows can store or print the original TOML without reparsing from disk.
    // -----------------------------------------------------------------------
    inline std::wstring ReadTomlFileText(const std::wstring& configPath)
    {
        std::string utf8 = ReadTomlFileUtf8(configPath);
        if (utf8.empty())
            return {};
        return Toml::Utf8ToWide(utf8);
    }

    inline const std::map<std::wstring, AccessLevel>& FolderAccessKeyMap()
    {
        static const std::map<std::wstring, AccessLevel> kFolderAccessKeys = {
            {L"read", AccessLevel::Read}, {L"write", AccessLevel::Write},
            {L"execute", AccessLevel::Execute}, {L"append", AccessLevel::Append},
            {L"delete", AccessLevel::Delete}, {L"all", AccessLevel::All},
            {L"run", AccessLevel::Run}, {L"stat", AccessLevel::Stat},
            {L"touch", AccessLevel::Touch}, {L"create", AccessLevel::Create}
        };
        return kFolderAccessKeys;
    }

    inline void ParseFolderRuleSection(const Toml::TomlDocument& doc,
                                       const wchar_t* sectionName,
                                       GrantScope scope,
                                       std::vector<FolderEntry>& destination,
                                       bool& parseError)
    {
        auto sit = doc.find(sectionName);
        if (sit == doc.end())
            return;

        const auto& accessKeys = FolderAccessKeyMap();
        for (const auto& [key, val] : sit->second) {
            auto it = accessKeys.find(key);
            if (it == accessKeys.end()) {
                fprintf(stderr, "Error: Unknown key in [%ls]: %ls\n", sectionName, key.c_str());
                parseError = true;
                continue;
            }
            if (!val.isArray) {
                fprintf(stderr, "Error: '%ls' in [%ls] must be an array, e.g. ['C:\\path']. Got scalar value.\n",
                        key.c_str(), sectionName);
                parseError = true;
                continue;
            }

            for (size_t i = 0; i < val.arr.size(); i++) {
                if (val.arr[i].empty()) {
                    fprintf(stderr, "Error: Empty path in [%ls] '%ls' array (element %zu).\n",
                            sectionName, key.c_str(), i);
                    parseError = true;
                    continue;
                }
                destination.push_back({ val.arr[i], it->second, scope });
            }
        }
    }

    inline bool RequireScalarValue(const Toml::TomlValue& val,
                                   const wchar_t* sectionName,
                                   const std::wstring& key,
                                   bool& parseError)
    {
        if (!val.isArray)
            return true;

        fprintf(stderr, "Error: '%ls' in [%ls] must be a scalar value, got array.\n",
                key.c_str(), sectionName);
        parseError = true;
        return false;
    }

    inline bool TryParseBoolValue(const Toml::TomlValue& val,
                                  const wchar_t* sectionName,
                                  const std::wstring& key,
                                  bool& out,
                                  bool& parseError)
    {
        if (!RequireScalarValue(val, sectionName, key, parseError))
            return false;

        if (val.str == L"true") {
            out = true;
            return true;
        }
        if (val.str == L"false") {
            out = false;
            return true;
        }

        fprintf(stderr, "Error: '%ls' in [%ls] must be 'true' or 'false', got '%ls'.\n",
                key.c_str(), sectionName, val.str.c_str());
        parseError = true;
        return false;
    }

    inline bool AppendStringArrayValues(const Toml::TomlValue& val,
                                        const wchar_t* sectionName,
                                        const std::wstring& key,
                                        std::vector<std::wstring>& destination,
                                        bool& parseError,
                                        const wchar_t* example,
                                        const wchar_t* emptyElementLabel)
    {
        if (!val.isArray) {
            fprintf(stderr,
                    "Error: '%ls' in [%ls] must be an array, e.g. %ls. Got scalar value.\n",
                    key.c_str(), sectionName, example);
            parseError = true;
            return false;
        }

        bool ok = true;
        for (size_t i = 0; i < val.arr.size(); i++) {
            if (val.arr[i].empty()) {
                fprintf(stderr, "Error: Empty %ls in [%ls] '%ls' array (element %zu).\n",
                        emptyElementLabel, sectionName, key.c_str(), i);
                parseError = true;
                ok = false;
                continue;
            }
            destination.push_back(val.arr[i]);
        }
        return ok;
    }

    inline bool TryParseBoundedNonNegativeInteger(const Toml::TomlValue& val,
                                                  const wchar_t* sectionName,
                                                  const std::wstring& key,
                                                  long long maxValue,
                                                  long long& out,
                                                  bool& parseError)
    {
        if (!RequireScalarValue(val, sectionName, key, parseError))
            return false;

        if (val.str.empty()) {
            fprintf(stderr, "Error: '%ls' in [%ls] must be a non-negative integer, got '%ls'.\n",
                    key.c_str(), sectionName, val.str.c_str());
            parseError = true;
            return false;
        }

        unsigned long long parsed = 0;
        const unsigned long long limit = static_cast<unsigned long long>(maxValue);
        for (size_t i = 0; i < val.str.size(); i++) {
            wchar_t ch = val.str[i];
            if (!iswdigit(ch)) {
                fprintf(stderr, "Error: '%ls' in [%ls] must be a non-negative integer, got '%ls'.\n",
                        key.c_str(), sectionName, val.str.c_str());
                parseError = true;
                return false;
            }

            unsigned long long digit = static_cast<unsigned long long>(ch - L'0');
            if (parsed > limit / 10 ||
                (parsed == limit / 10 && digit > (limit % 10))) {
                fprintf(stderr, "Error: '%ls' in [%ls] is %ls, maximum is %lld.\n",
                        key.c_str(), sectionName, val.str.c_str(), maxValue);
                parseError = true;
                return false;
            }
            parsed = parsed * 10 + digit;
        }

        out = static_cast<long long>(parsed);
        return true;
    }

    inline const std::map<std::wstring, bool SandboxConfig::*>& PrivilegeBoolKeyMap()
    {
        static const std::map<std::wstring, bool SandboxConfig::*> kPrivilegeBoolKeys = {
            {L"network", &SandboxConfig::allowNetwork},
            {L"named_pipes", &SandboxConfig::allowNamedPipes},
            {L"desktop", &SandboxConfig::allowDesktop},
            {L"clipboard_read", &SandboxConfig::allowClipboardRead},
            {L"clipboard_write", &SandboxConfig::allowClipboardWrite},
            {L"child_processes", &SandboxConfig::allowChildProcesses}
        };
        return kPrivilegeBoolKeys;
    }

    inline const std::map<std::wstring, std::vector<std::wstring> SandboxConfig::*>& RegistryArrayKeyMap()
    {
        static const std::map<std::wstring, std::vector<std::wstring> SandboxConfig::*> kRegistryArrayKeys = {
            {L"read", &SandboxConfig::registryRead},
            {L"write", &SandboxConfig::registryWrite}
        };
        return kRegistryArrayKeys;
    }

    enum class LimitKeyKind { Timeout, Memory, Processes };

    struct LimitKeyBinding {
        LimitKeyKind kind;
        long long maxValue;
    };

    inline const std::map<std::wstring, LimitKeyBinding>& LimitKeyMap()
    {
        static const std::map<std::wstring, LimitKeyBinding> kLimitKeys = {
            {L"timeout", { LimitKeyKind::Timeout, 86400 }},
            {L"memory", { LimitKeyKind::Memory, 65536 }},
            {L"processes", { LimitKeyKind::Processes, 1024 }}
        };
        return kLimitKeys;
    }

    constexpr size_t kMaxConfigPathLength = 32768;
    constexpr size_t kMaxRulesPerSection = 256;

    enum class ConfigPathKind { Any, File, Directory };
    enum class ConfigPathValidationError { None, NotAbsolute, Missing, ExpectedFile, ExpectedDirectory };

    inline bool IsAbsoluteFilesystemPath(const std::wstring& path)
    {
        return (path.size() >= 3 && iswalpha(path[0]) && path[1] == L':' && path[2] == L'\\') ||
               (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\');
    }

    inline ConfigPathValidationError GetConfiguredPathValidationError(const std::wstring& path,
                                                                     ConfigPathKind expectedKind)
    {
        if (path.empty())
            return ConfigPathValidationError::None;
        if (!IsAbsoluteFilesystemPath(path))
            return ConfigPathValidationError::NotAbsolute;

        DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES)
            return ConfigPathValidationError::Missing;

        bool isDirectory = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (expectedKind == ConfigPathKind::Directory && !isDirectory)
            return ConfigPathValidationError::ExpectedDirectory;
        if (expectedKind == ConfigPathKind::File && isDirectory)
            return ConfigPathValidationError::ExpectedFile;
        return ConfigPathValidationError::None;
    }

    inline void ReportConfiguredPathValidationError(const std::wstring& path,
                                                    const wchar_t* sectionName,
                                                    const std::wstring& key,
                                                    ConfigPathValidationError error,
                                                    bool& parseError)
    {
        switch (error) {
        case ConfigPathValidationError::NotAbsolute:
            fprintf(stderr, "Error: '%ls' in [%ls] is not an absolute path. Use 'C:\\...' format.\n",
                    key.c_str(), sectionName);
            break;
        case ConfigPathValidationError::Missing:
            fprintf(stderr, "Error: Path does not exist: %ls (in [%ls] '%ls')\n",
                    path.c_str(), sectionName, key.c_str());
            break;
        case ConfigPathValidationError::ExpectedFile:
            fprintf(stderr, "Error: '%ls' in [%ls] must reference a file, got directory: %ls\n",
                    key.c_str(), sectionName, path.c_str());
            break;
        case ConfigPathValidationError::ExpectedDirectory:
            fprintf(stderr, "Error: '%ls' in [%ls] must reference a directory, got file: %ls\n",
                    key.c_str(), sectionName, path.c_str());
            break;
        default:
            return;
        }
        parseError = true;
    }

    inline bool ValidateConfiguredPath(const std::wstring& path,
                                       const wchar_t* sectionName,
                                       const std::wstring& key,
                                       ConfigPathKind expectedKind,
                                       bool& parseError)
    {
        ConfigPathValidationError error = GetConfiguredPathValidationError(path, expectedKind);
        if (error == ConfigPathValidationError::None)
            return true;

        ReportConfiguredPathValidationError(path, sectionName, key, error, parseError);
        return false;
    }

    inline void NormalizeConfigFilesystemPaths(SandboxConfig& config)
    {
        config.workdir = NormalizeFsPath(config.workdir);
        if (!config.stdinMode.empty() && _wcsicmp(config.stdinMode.c_str(), L"NUL") != 0)
            config.stdinMode = NormalizeFsPath(config.stdinMode);
        for (auto& e : config.folders)
            e.path = NormalizeFsPath(e.path);
        for (auto& e : config.denyFolders)
            e.path = NormalizeFsPath(e.path);
    }

    inline void ValidateModeSpecificConfig(const SandboxConfig& config,
                                           bool integritySeen,
                                           bool registrySeen,
                                           const std::set<std::wstring>& privSeen,
                                           bool& parseError)
    {
        bool isAC = IsAppContainerFamilyTokenMode(config.tokenMode);
        bool isRT = IsRestrictedTokenMode(config.tokenMode);

        if (isRT) {
            if (privSeen.count(L"network")) {
                fprintf(stderr, "Error: 'network' is not available in restricted mode (network is always unrestricted).\n");
                parseError = true;
            }
            if (privSeen.count(L"lan")) {
                fprintf(stderr, "Error: 'lan' is not available in restricted mode (network is always unrestricted).\n");
                parseError = true;
            }
            if (!integritySeen) {
                fprintf(stderr, "Error: 'integrity' is required in [sandbox] for restricted mode ('low' or 'medium').\n");
                parseError = true;
            }
        }

        if (isAC) {
            if (privSeen.count(L"named_pipes")) {
                fprintf(stderr, "Error: 'named_pipes' is not available in appcontainer/lpac mode (named pipes are always blocked).\n");
                parseError = true;
            }
            if (privSeen.count(L"desktop")) {
                fprintf(stderr, "Error: 'desktop' is not available in appcontainer/lpac mode (desktop access is inherited from creator token).\n");
                parseError = true;
            }
            if (integritySeen) {
                fprintf(stderr, "Error: 'integrity' is not available in appcontainer/lpac mode (always Low).\n");
                parseError = true;
            }
            if (config.strict) {
                fprintf(stderr, "Error: 'strict' is not available in appcontainer/lpac mode (use token = 'restricted' for strict mode).\n");
                parseError = true;
            }
            if (registrySeen) {
                fprintf(stderr, "Error: [registry] section is not available in appcontainer/lpac mode.\n");
                parseError = true;
            }
            if (!config.denyFolders.empty()) {
                fprintf(stderr, "Error: [deny.*] is not available in appcontainer mode.\n");
                fprintf(stderr, "  The Windows kernel ignores DENY ACEs for AppContainer SIDs.\n");
                fprintf(stderr, "  Use token = 'restricted' for deny rules, or remove the deny sections.\n");
                parseError = true;
            }
        }
    }

    inline void ValidateFolderEntryPaths(const std::vector<FolderEntry>& entries,
                                         const wchar_t* section,
                                         bool& parseError)
    {
        std::set<std::wstring> seen;
        for (const auto& e : entries) {
            if (e.path.empty())
                continue;

            if (!IsAbsoluteFilesystemPath(e.path)) {
                fprintf(stderr, "Error: '%ls' in [%ls] is not an absolute path. Use 'C:\\...' format.\n",
                        e.path.c_str(), section);
                parseError = true;
            }
            if (GetFileAttributesW(e.path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                fprintf(stderr, "Error: Path does not exist: %ls (in [%ls])\n",
                        e.path.c_str(), section);
                parseError = true;
            }

            std::wstring lowerPath = NormalizeLookupKey(e.path);
            if (!seen.insert(lowerPath).second) {
                if (g_logger.IsActive())
                    g_logger.LogFmt(L"CONFIG_WARN: Duplicate path in [%s]: %s", section, e.path.c_str());
                else
                    fprintf(stderr, "Warning: Duplicate path in [%ls]: %ls\n", section, e.path.c_str());
            }
        }
    }

    inline void ValidateRegistryPathPrefixes(const std::vector<std::wstring>& keys,
                                             bool& parseError)
    {
        for (const auto& key : keys) {
            if (_wcsnicmp(key.c_str(), L"HKCU\\", 5) != 0 &&
                _wcsnicmp(key.c_str(), L"HKLM\\", 5) != 0) {
                fprintf(stderr, "Error: Registry path must start with 'HKCU\\' or 'HKLM\\': %ls\n",
                        key.c_str());
                parseError = true;
            }
        }
    }

    inline void ValidateScalarPathLength(const std::wstring& path,
                                         const wchar_t* sectionName,
                                         const std::wstring& key,
                                         bool& parseError)
    {
        if (path.size() > kMaxConfigPathLength) {
            fprintf(stderr, "Error: '%ls' in [%ls] exceeds %zu character limit (%zu chars).\n",
                    key.c_str(), sectionName, kMaxConfigPathLength, path.size());
            parseError = true;
        }
    }

    inline void ValidateFolderEntryPathLengths(const std::vector<FolderEntry>& entries,
                                               const wchar_t* section,
                                               bool& parseError)
    {
        for (const auto& e : entries) {
            if (e.path.size() > kMaxConfigPathLength) {
                fprintf(stderr, "Error: Path in [%ls] exceeds %zu character limit (%zu chars).\n",
                        section, kMaxConfigPathLength, e.path.size());
                parseError = true;
            }
        }
    }

    inline void ValidateConfigSanityLimits(const SandboxConfig& config,
                                           bool& parseError)
    {
        ValidateScalarPathLength(config.workdir, L"sandbox", L"workdir", parseError);
        if (!config.stdinMode.empty() && _wcsicmp(config.stdinMode.c_str(), L"NUL") != 0)
            ValidateScalarPathLength(config.stdinMode, L"privileges", L"stdin", parseError);

        ValidateFolderEntryPathLengths(config.folders, L"allow.*", parseError);
        ValidateFolderEntryPathLengths(config.denyFolders, L"deny.*", parseError);

        if (config.folders.size() > kMaxRulesPerSection) {
            fprintf(stderr, "Error: allow sections have %zu rules (max %zu). Reduce configuration complexity.\n",
                    config.folders.size(), kMaxRulesPerSection);
            parseError = true;
        }
        if (config.denyFolders.size() > kMaxRulesPerSection) {
            fprintf(stderr, "Error: deny sections have %zu rules (max %zu). Reduce configuration complexity.\n",
                    config.denyFolders.size(), kMaxRulesPerSection);
            parseError = true;
        }
        if (config.registryRead.size() + config.registryWrite.size() > kMaxRulesPerSection) {
            fprintf(stderr, "Error: [registry] has %zu keys (max %zu). Reduce configuration complexity.\n",
                    config.registryRead.size() + config.registryWrite.size(), kMaxRulesPerSection);
            parseError = true;
        }
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
        bool tokenSeen = false;
        if (sandboxSeen) {
            const Toml::TomlSection& sec = doc.find(L"sandbox")->second;
            for (const auto& [key, val] : sec) {
                if (key == L"token") {
                    tokenSeen = true;
                    if (!RequireScalarValue(val, L"sandbox", key, config.parseError))
                        continue;
                    if (!TryParseTokenMode(val.str, config.tokenMode)) {
                        fprintf(stderr, "Error: Unknown token mode: %ls\n", val.str.c_str());
                        config.parseError = true;
                    }
                } else if (key == L"integrity") {
                    integritySeen = true;
                    if (!RequireScalarValue(val, L"sandbox", key, config.parseError))
                        continue;
                    if (val.str == L"low") config.integrity = IntegrityLevel::Low;
                    else if (val.str == L"medium") config.integrity = IntegrityLevel::Medium;
                    else {
                        fprintf(stderr, "Error: Unknown integrity level: %ls (expected 'low' or 'medium')\n", val.str.c_str());
                        config.parseError = true;
                    }
                } else if (key == L"strict") {
                    TryParseBoolValue(val, L"sandbox", key, config.strict, config.parseError);
                } else if (key == L"workdir") {
                    if (!RequireScalarValue(val, L"sandbox", key, config.parseError))
                        continue;
                    if (val.str == L"inherit")
                        config.workdir.clear();  // inherit = use Sandy's current working directory
                    else if (val.str.empty()) {
                        fprintf(stderr, "Error: 'workdir' in [sandbox] must be 'inherit' or a path, got empty string.\n");
                        config.parseError = true;
                    } else {
                        config.workdir = val.str;
                    }
                } else {
                    fprintf(stderr, "Error: Unknown key in [sandbox]: %ls\n", key.c_str());
                    config.parseError = true;
                }
            }
        }

        // token is always mandatory
        if (sandboxSeen && !tokenSeen) {
            fprintf(stderr, "Error: 'token' is required in [sandbox]. Use token = 'appcontainer', 'lpac', or 'restricted'.\n");
            config.parseError = true;
        }
        ParseFolderRuleSection(doc, L"allow.deep", GrantScope::Deep, config.folders, config.parseError);
        ParseFolderRuleSection(doc, L"allow.this", GrantScope::This, config.folders, config.parseError);
        if (doc.find(L"allow") != doc.end()) {
            fprintf(stderr, "Error: [allow] is no longer supported. Use [allow.deep] or [allow.this].\n");
            config.parseError = true;
        }

        ParseFolderRuleSection(doc, L"deny.deep", GrantScope::Deep, config.denyFolders, config.parseError);
        ParseFolderRuleSection(doc, L"deny.this", GrantScope::This, config.denyFolders, config.parseError);
        if (doc.find(L"deny") != doc.end()) {
            fprintf(stderr, "Error: [deny] is no longer supported. Use [deny.deep] or [deny.this].\n");
            config.parseError = true;
        }

        // --- [registry] ---
        {
            auto sit = doc.find(L"registry");
            if (sit != doc.end()) {
                const auto& registryArrayKeys = RegistryArrayKeyMap();
                for (const auto& [key, val] : sit->second) {
                    auto it = registryArrayKeys.find(key);
                    if (it == registryArrayKeys.end()) {
                        fprintf(stderr, "Error: Unknown key in [registry]: %ls\n", key.c_str());
                        config.parseError = true;
                        continue;
                    }
                    AppendStringArrayValues(val, L"registry", key, config.*(it->second),
                                            config.parseError, L"['HKCU\\\\...']", L"registry path");
                }
            }
        }

        // --- [privileges] — sandbox capabilities ---
        std::set<std::wstring> privSeen;
        {
            auto sit = doc.find(L"privileges");
            if (sit != doc.end()) {
                const auto& privilegeBoolKeys = PrivilegeBoolKeyMap();
                for (const auto& [key, valObj] : sit->second) {
                    privSeen.insert(key);
                    if (key == L"stdin") {
                        if (!RequireScalarValue(valObj, L"privileges", key, config.parseError))
                            continue;
                        const std::wstring& valStr = valObj.str;
                        // true = inherit, false = NUL, anything else = file path
                        if (valStr == L"true")
                            config.stdinMode.clear();  // inherit
                        else if (valStr == L"false")
                            config.stdinMode = L"NUL";
                        else if (valStr.empty()) {
                            fprintf(stderr, "Error: 'stdin' in [privileges] must be true, false, or a path, got empty string.\n");
                            config.parseError = true;
                        } else {
                            config.stdinMode = valStr;  // file path
                        }
                    }
                    else if (key == L"lan") {
                        if (!RequireScalarValue(valObj, L"privileges", key, config.parseError))
                            continue;
                        if (!TryParseLanModeConfigValue(valObj.str, config.lanMode)) {
                            fprintf(stderr, "Error: Invalid value for 'lan': '%ls'. "
                                    "Expected false, 'with localhost', or 'without localhost'.\n",
                                    valObj.str.c_str());
                            config.parseError = true;
                        }
                    }
                    else if (key == L"localhost") {
                        fprintf(stderr, "Error: Key 'localhost' has been removed. "
                                "Use lan = 'with localhost' instead.\n");
                        config.parseError = true;
                    }
                    else if (auto it = privilegeBoolKeys.find(key); it != privilegeBoolKeys.end()) {
                        bool enabled = false;
                        if (TryParseBoolValue(valObj, L"privileges", key, enabled, config.parseError))
                            config.*(it->second) = enabled;
                    }
                    else {
                        fprintf(stderr, "Error: Unknown key in [privileges]: %ls\n", key.c_str());
                        config.parseError = true;
                    }
                }
            }
        }

        // --- [environment] ---
        {
            auto sit = doc.find(L"environment");
            if (sit != doc.end()) {
                for (const auto& [key, val] : sit->second) {
                    if (key == L"inherit") {
                        TryParseBoolValue(val, L"environment", key, config.envInherit, config.parseError);
                    } else if (key == L"pass") {
                        AppendStringArrayValues(val, L"environment", key, config.envPass,
                                                config.parseError, L"['PATH']", L"variable name");
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
                const auto& limitKeys = LimitKeyMap();
                for (const auto& [key, val] : sit->second) {
                    auto it = limitKeys.find(key);
                    if (it == limitKeys.end()) {
                        fprintf(stderr, "Error: Unknown key in [limit]: %ls\n", key.c_str());
                        config.parseError = true;
                        continue;
                    }

                    long long parsed = 0;
                    if (!TryParseBoundedNonNegativeInteger(val, L"limit", key,
                                                           it->second.maxValue,
                                                           parsed,
                                                           config.parseError)) {
                        continue;
                    }

                    switch (it->second.kind) {
                    case LimitKeyKind::Timeout:
                        config.timeoutSeconds = static_cast<DWORD>(parsed);
                        break;
                    case LimitKeyKind::Memory:
                        config.memoryLimitMB = static_cast<SIZE_T>(parsed);
                        break;
                    case LimitKeyKind::Processes:
                        config.maxProcesses = static_cast<DWORD>(parsed);
                        break;
                    }
                }
            }
        }

        // --- Mandatory [sandbox] check ---
        if (!sandboxSeen) {
            fprintf(stderr, "Error: [sandbox] section is required. Add [sandbox] with token = \"appcontainer\", \"lpac\", or \"restricted\".\n");
            config.parseError = true;
        }

        // --- Mode-specific validation ---
        if (!config.parseError) {
            ValidateModeSpecificConfig(config, integritySeen, registrySeen, privSeen, config.parseError);
        }

        // Normalize filesystem paths once at config-ingest time so the rest of
        // the sandbox can reason about one canonical separator style.
        NormalizeConfigFilesystemPaths(config);

        // --- Path validation (absolute paths, existence, deduplication) ---
        if (!config.parseError) {
            ValidateConfiguredPath(config.workdir, L"sandbox", L"workdir",
                                   ConfigPathKind::Directory, config.parseError);
            if (!config.stdinMode.empty() && _wcsicmp(config.stdinMode.c_str(), L"NUL") != 0) {
                ValidateConfiguredPath(config.stdinMode, L"privileges", L"stdin",
                                       ConfigPathKind::File, config.parseError);
            }
            ValidateFolderEntryPaths(config.folders, L"allow.*", config.parseError);
            ValidateFolderEntryPaths(config.denyFolders, L"deny.*", config.parseError);
            ValidateRegistryPathPrefixes(config.registryRead, config.parseError);
            ValidateRegistryPathPrefixes(config.registryWrite, config.parseError);
            ValidateConfigSanityLimits(config, config.parseError);
        }

        return config;
    }

    // -----------------------------------------------------------------------
    // Parse inline TOML string -> SandboxConfig (convenience wrapper)
    //
    // This is the `-s/--string` path and intentionally preserves the legacy
    // ConvertLiteralNewlines() behavior for command-line convenience.
    // -----------------------------------------------------------------------
    inline SandboxConfig ParseConfig(const std::wstring& content)
    {
        return MapConfig(Toml::Parse(content));
    }

    // -----------------------------------------------------------------------
    // Parse file-backed TOML text -> SandboxConfig.
    //
    // Unlike ParseConfig(), this keeps exact file semantics and must not apply
    // inline literal-newline conversion.
    // -----------------------------------------------------------------------
    inline SandboxConfig ParseConfigFileText(const std::wstring& content)
    {
        return MapConfig(Toml::ParseUtf8(Toml::WideToUtf8(content)));
    }

    // -----------------------------------------------------------------------
    // Load config from a TOML file (reads file, then delegates to ParseConfig)
    // -----------------------------------------------------------------------
    inline SandboxConfig LoadConfig(const std::wstring& configPath)
    {
        std::string utf8 = ReadTomlFileUtf8(configPath);
        if (utf8.empty()) {
            SandboxConfig cfg; cfg.parseError = true; return cfg;
        }
        return MapConfig(Toml::ParseUtf8(utf8));
    }

} // namespace Sandbox
