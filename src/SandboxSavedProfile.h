// =========================================================================
// SandboxSavedProfile.h — Persistent named sandbox profiles
//
// Creates, loads, deletes, and enumerates named profiles that persist
// SID + ACL grants + TOML config between Sandy runs.  Composes existing
// primitives: ApplyAccessPipeline, SetupAppContainer/SetupRestrictedToken,
// RecordGrant format, RemoveSidFromDacl.
// =========================================================================
#pragma once

#include "Sandbox.h"

namespace Sandbox {

    // Registry parent key for saved profiles
    static const wchar_t* kProfilesParentKey = L"Software\\Sandy\\Profiles";

    // -----------------------------------------------------------------------
    // SavedProfile — in-memory representation of a persisted profile
    // -----------------------------------------------------------------------
    struct SavedProfile {
        std::wstring name;
        std::wstring type;         // "appcontainer", "lpac", or "restricted"
        std::wstring integrity;    // "low" or "medium" (restricted only)
        std::wstring sidString;
        std::wstring containerName; // AC only: "Sandy_<name>"
        std::wstring created;       // ISO 8601
        std::wstring tomlText;      // raw TOML config
        SandboxConfig config;       // parsed config
    };

    // Durable profile teardown must be treated as a transaction: only forget
    // profile ownership metadata after both loopback and container state are
    // confirmed gone (or already absent).
    inline bool TeardownPersistentProfileContainer(const std::wstring& containerName,
                                                   const wchar_t* contextTag)
    {
        if (containerName.empty()) return true;

        bool loopbackOk = RemoveLoopbackExemption(containerName);
        HRESULT hr = DeleteAppContainerProfile(containerName.c_str());
        bool containerOk = SUCCEEDED(hr) || AppContainerMissing(hr);

        g_logger.LogFmt(L"%ls: loopback=%s container=%s (%s)",
                        contextTag,
                        loopbackOk ? L"OK" : L"FAILED",
                        containerName.c_str(),
                        containerOk ? L"deleted-or-absent" : L"FAILED");
        printf("  [CONTAINER] %ls -> %s\n", containerName.c_str(),
               containerOk ? "deleted/already absent" : "FAILED");

        return loopbackOk && containerOk;
    }

    inline bool DeleteProfileRegistryState(const std::wstring& profileName,
                                           const wchar_t* contextTag)
    {
        std::wstring regKey = std::wstring(kProfilesParentKey) + L"\\" + profileName;
        LSTATUS st = DeleteRegTreeBestEffort(HKEY_CURRENT_USER, regKey);
        if (st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND || st == ERROR_PATH_NOT_FOUND) {
            g_logger.LogFmt(L"%ls: registry metadata deleted for profile '%s'",
                            contextTag, profileName.c_str());
            return true;
        }

        g_logger.LogFmt(L"%ls: registry metadata delete FAILED for profile '%s' (error %lu)",
                        contextTag, profileName.c_str(), st);
        return false;
    }

    // -----------------------------------------------------------------------
    // ReadStagingPidAndCtime — atomic read of staging creator identity.
    //
    // Mirrors ReadPidAndCtime() from SandboxGrants.h but reads the staging-
    // specific value names (_staging_pid, _staging_ctime).  Returns false
    // if either value is missing — the caller must treat this as "writer
    // still in progress" and skip the entry, not falsely declare it dead.
    // -----------------------------------------------------------------------
    inline bool ReadStagingPidAndCtime(HKEY hKey, DWORD& pid, ULONGLONG& ctime)
    {
        DWORD tempPid = 0;
        DWORD size = sizeof(DWORD);
        LSTATUS pidStatus = RegQueryValueExW(hKey, L"_staging_pid", nullptr, nullptr,
                         reinterpret_cast<BYTE*>(&tempPid), &size);
        if (pidStatus != ERROR_SUCCESS) {
            pid = 0; ctime = 0;
            return false;
        }
        ULONGLONG tempCtime = 0;
        size = sizeof(ULONGLONG);
        LSTATUS ctimeStatus = RegQueryValueExW(hKey, L"_staging_ctime", nullptr, nullptr,
                         reinterpret_cast<BYTE*>(&tempCtime), &size);
        if (ctimeStatus != ERROR_SUCCESS) {
            pid = 0; ctime = 0;
            return false;
        }
        pid = tempPid;
        ctime = tempCtime;
        return pid != 0 && ctime != 0;
    }

    // -----------------------------------------------------------------------
    // ReadTomlFileText — read a TOML file as raw wide string for storage.
    // -----------------------------------------------------------------------
    inline std::wstring ReadTomlFileText(const std::wstring& configPath)
    {
        HANDLE hFile = CreateFileW(configPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return {};

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == 0 || fileSize == INVALID_FILE_SIZE || fileSize > 1024 * 1024) {
            CloseHandle(hFile);
            return {};
        }

        std::string buf(fileSize, '\0');
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, &buf[0], fileSize, &bytesRead, nullptr) || bytesRead == 0) {
            CloseHandle(hFile);
            return {};
        }
        CloseHandle(hFile);

        // Reject files with a BOM — Sandy requires clean UTF-8 (no BOM).
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

        int wideLen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, buf.c_str(), (int)bytesRead, nullptr, 0);
        if (wideLen == 0) {
            fprintf(stderr, "Error: Config file contains invalid UTF-8 byte sequences.\n");
            return {};
        }
        std::wstring content(wideLen, L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, buf.c_str(), (int)bytesRead, &content[0], wideLen);
        return content;
    }

    // -----------------------------------------------------------------------
    // ProfileExists — check if a named profile exists in the registry.
    // -----------------------------------------------------------------------
    inline bool ProfileExists(const std::wstring& name)
    {
        std::wstring key = std::wstring(kProfilesParentKey) + L"\\" + name;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // WriteConfigToRegistry — persist every SandboxConfig field as discrete
    // registry values under an open HKEY.  Each value maps 1:1 to a config
    // field so the profile is fully inspectable in regedit and does not
    // depend on the TOML parser at load time.
    //
    // Layout:
    //   _token_mode         REG_SZ   "appcontainer" | "lpac" | "restricted"
    //   _cfg_integrity      REG_SZ   "low" | "medium"
    //   _workdir            REG_SZ   path (may be empty)
    //   _allow_network      REG_DWORD  0 | 1
    //   _lan_mode           REG_SZ     "off" | "with_localhost" | "without_localhost"

    //   _allow_named_pipes   REG_DWORD  0 | 1
    //   _allow_desktop       REG_DWORD  0 | 1
    //   _strict              REG_DWORD  0 | 1
    //   _allow_clipboard_r   REG_DWORD  0 | 1
    //   _allow_clipboard_w   REG_DWORD  0 | 1
    //   _allow_child_procs   REG_DWORD  0 | 1
    //   _stdin_mode          REG_SZ   "NUL" | "" | path
    //   _env_inherit         REG_DWORD  0 | 1
    //   _timeout             REG_DWORD  seconds (0 = none)
    //   _memory_limit_mb     REG_DWORD  MB (0 = none)
    //   _max_processes       REG_DWORD  count (0 = none)
    //   _allow_count         REG_DWORD  number of allow entries
    //   _allow_0 .. _allow_N REG_SZ   "access.deep|path" or "access.this|path"
    //   _deny_count          REG_DWORD  number of deny entries
    //   _deny_0  .. _deny_N  REG_SZ   "access.deep|path" or "access.this|path"
    //   _reg_read_count      REG_DWORD  count
    //   _reg_read_0 ..       REG_SZ   registry path
    //   _reg_write_count     REG_DWORD  count
    //   _reg_write_0 ..      REG_SZ   registry path
    //   _env_pass_count      REG_DWORD  count
    //   _env_pass_0 ..       REG_SZ   variable name
    // -----------------------------------------------------------------------
    inline bool WriteConfigToRegistry(HKEY hKey, const SandboxConfig& cfg)
    {
        bool ok = true;

        // --- Enums ---
        ok &= TryWriteRegSz(hKey, L"_token_mode",
            (cfg.tokenMode == TokenMode::Restricted) ? L"restricted"
            : (cfg.tokenMode == TokenMode::LPAC) ? L"lpac"
            : L"appcontainer");
        ok &= TryWriteRegSz(hKey, L"_cfg_integrity",
            (cfg.integrity == IntegrityLevel::Low) ? L"low" : L"medium");

        // --- Strings ---
        ok &= TryWriteRegSz(hKey, L"_workdir", cfg.workdir);
        ok &= TryWriteRegSz(hKey, L"_stdin_mode", cfg.stdinMode.empty() ? L"INHERIT" : cfg.stdinMode);

        // --- Booleans (REG_DWORD 0/1) ---
        ok &= TryWriteRegDword(hKey, L"_allow_network",      cfg.allowNetwork     ? 1 : 0);
        ok &= TryWriteRegSz(hKey, L"_lan_mode",
            cfg.lanMode == LanMode::WithLocalhost ? L"with_localhost" :
            cfg.lanMode == LanMode::WithoutLocalhost ? L"without_localhost" : L"off");

        ok &= TryWriteRegDword(hKey, L"_allow_named_pipes",   cfg.allowNamedPipes  ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_allow_desktop",       cfg.allowDesktop     ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_strict",              cfg.strict           ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_allow_clipboard_r",   cfg.allowClipboardRead  ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_allow_clipboard_w",   cfg.allowClipboardWrite ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_allow_child_procs",   cfg.allowChildProcesses ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_env_inherit",         cfg.envInherit       ? 1 : 0);

        // --- Integers ---
        ok &= TryWriteRegDword(hKey, L"_timeout",         cfg.timeoutSeconds);
        ok &= TryWriteRegDword(hKey, L"_memory_limit_mb", static_cast<DWORD>(cfg.memoryLimitMB));
        ok &= TryWriteRegDword(hKey, L"_max_processes",   cfg.maxProcesses);

        // --- Allow folders: _allow_count + _allow_0, _allow_1, ... ---
        // Format: "access.deep|path" or "access.this|path"
        ok &= TryWriteRegDword(hKey, L"_allow_count", static_cast<DWORD>(cfg.folders.size()));
        for (DWORD i = 0; i < cfg.folders.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_allow_%lu", i);
            std::wstring tag = std::wstring(AccessLevelName(cfg.folders[i].access))
                + ((cfg.folders[i].scope == GrantScope::This) ? L".this" : L".deep");
            ok &= TryWriteRegSz(hKey, name, tag + L"|" + cfg.folders[i].path);
        }

        // --- Deny folders: _deny_count + _deny_0, _deny_1, ... ---
        ok &= TryWriteRegDword(hKey, L"_deny_count", static_cast<DWORD>(cfg.denyFolders.size()));
        for (DWORD i = 0; i < cfg.denyFolders.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_deny_%lu", i);
            std::wstring tag = std::wstring(AccessLevelName(cfg.denyFolders[i].access))
                + ((cfg.denyFolders[i].scope == GrantScope::This) ? L".this" : L".deep");
            ok &= TryWriteRegSz(hKey, name, tag + L"|" + cfg.denyFolders[i].path);
        }

        // --- Registry read keys ---
        ok &= TryWriteRegDword(hKey, L"_reg_read_count", static_cast<DWORD>(cfg.registryRead.size()));
        for (DWORD i = 0; i < cfg.registryRead.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_reg_read_%lu", i);
            ok &= TryWriteRegSz(hKey, name, cfg.registryRead[i]);
        }

        // --- Registry write keys ---
        ok &= TryWriteRegDword(hKey, L"_reg_write_count", static_cast<DWORD>(cfg.registryWrite.size()));
        for (DWORD i = 0; i < cfg.registryWrite.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_reg_write_%lu", i);
            ok &= TryWriteRegSz(hKey, name, cfg.registryWrite[i]);
        }

        // --- Environment pass-through vars ---
        ok &= TryWriteRegDword(hKey, L"_env_pass_count", static_cast<DWORD>(cfg.envPass.size()));
        for (DWORD i = 0; i < cfg.envPass.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_env_pass_%lu", i);
            ok &= TryWriteRegSz(hKey, name, cfg.envPass[i]);
        }

        return ok;
    }

    // -----------------------------------------------------------------------
    // ReadConfigFromRegistry — reconstruct SandboxConfig from discrete
    // registry values.  No TOML parsing involved.
    // -----------------------------------------------------------------------
    inline SandboxConfig ReadConfigFromRegistry(HKEY hKey)
    {
        SandboxConfig cfg;

        // --- Enums ---
        // P2: Reject missing/unrecognized _token_mode instead of silently
        // defaulting to AppContainer — incomplete metadata is a data integrity error.
        std::wstring mode = ReadRegSz(hKey, L"_token_mode");
        if (mode == L"restricted") cfg.tokenMode = TokenMode::Restricted;
        else if (mode == L"lpac") cfg.tokenMode = TokenMode::LPAC;
        else if (mode == L"appcontainer") cfg.tokenMode = TokenMode::AppContainer;
        else {
            g_logger.LogFmt(L"PROFILE_LOAD: _token_mode missing or unrecognized ('%s') — rejecting profile",
                            mode.c_str());
            cfg.parseError = true;
        }

        // P1a: Fail closed on missing/unrecognized integrity for restricted mode.
        std::wstring integ = ReadRegSz(hKey, L"_cfg_integrity");
        if (integ == L"medium") cfg.integrity = IntegrityLevel::Medium;
        else if (integ == L"low") cfg.integrity = IntegrityLevel::Low;
        else if (cfg.tokenMode == TokenMode::Restricted) {
            g_logger.LogFmt(L"PROFILE_LOAD: _cfg_integrity missing or unrecognized ('%s') for restricted mode — rejecting profile",
                            integ.c_str());
            cfg.parseError = true;
        }

        // --- Strings ---
        cfg.workdir   = NormalizeFsPath(ReadRegSz(hKey, L"_workdir"));
        cfg.stdinMode = ReadRegSz(hKey, L"_stdin_mode");
        if (cfg.stdinMode == L"INHERIT")
            cfg.stdinMode.clear();  // inherit stdin
        else if (cfg.stdinMode.empty())
            cfg.stdinMode = L"NUL";  // default (unspecified)
        else
            cfg.stdinMode = NormalizeFsPath(cfg.stdinMode);

        // --- Booleans ---
        // P1a: _allow_desktop and _allow_child_procs must exist in the registry.
        // Missing values previously defaulted to 1 (enabled), silently granting
        // permissions the user never configured.  Now fail closed.
        cfg.allowNetwork        = ReadRegDword(hKey, L"_allow_network")    != 0;
        std::wstring lanModeStr = ReadRegSz(hKey, L"_lan_mode");
        if (lanModeStr == L"with_localhost")
            cfg.lanMode = LanMode::WithLocalhost;
        else if (lanModeStr == L"without_localhost")
            cfg.lanMode = LanMode::WithoutLocalhost;
        else
            cfg.lanMode = LanMode::Off;

        cfg.allowNamedPipes     = ReadRegDword(hKey, L"_allow_named_pipes") != 0;
        {
            DWORD desktopVal = 0, desktopSz = sizeof(desktopVal), desktopType = 0;
            if (RegQueryValueExW(hKey, L"_allow_desktop", nullptr, &desktopType,
                                 reinterpret_cast<BYTE*>(&desktopVal), &desktopSz) != ERROR_SUCCESS
                || desktopType != REG_DWORD) {
                g_logger.Log(L"PROFILE_LOAD: _allow_desktop missing — rejecting profile");
                cfg.parseError = true;
            } else {
                cfg.allowDesktop = desktopVal != 0;
            }
        }
        cfg.strict              = ReadRegDword(hKey, L"_strict") != 0;
        cfg.allowClipboardRead  = ReadRegDword(hKey, L"_allow_clipboard_r") != 0;
        cfg.allowClipboardWrite = ReadRegDword(hKey, L"_allow_clipboard_w") != 0;
        {
            DWORD childVal = 0, childSz = sizeof(childVal), childType = 0;
            if (RegQueryValueExW(hKey, L"_allow_child_procs", nullptr, &childType,
                                 reinterpret_cast<BYTE*>(&childVal), &childSz) != ERROR_SUCCESS
                || childType != REG_DWORD) {
                g_logger.Log(L"PROFILE_LOAD: _allow_child_procs missing — rejecting profile");
                cfg.parseError = true;
            } else {
                cfg.allowChildProcesses = childVal != 0;
            }
        }
        cfg.envInherit          = ReadRegDword(hKey, L"_env_inherit")       != 0;

        // --- Integers ---
        cfg.timeoutSeconds = ReadRegDword(hKey, L"_timeout");
        cfg.memoryLimitMB  = ReadRegDword(hKey, L"_memory_limit_mb");
        cfg.maxProcesses   = ReadRegDword(hKey, L"_max_processes");

        // --- Allow folders ---
        // Format: "access.deep|path" or "access.this|path"
        DWORD allowCount = ReadRegDword(hKey, L"_allow_count");
        for (DWORD i = 0; i < allowCount; i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_allow_%lu", i);
            std::wstring val = ReadRegSz(hKey, name);
            size_t sep = val.find(L'|');
            if (sep != std::wstring::npos) {
                FolderEntry entry;
                std::wstring tag = val.substr(0, sep);
                if (tag.size() > 5 && tag.substr(tag.size() - 5) == L".this") {
                    entry.scope = GrantScope::This;
                    tag = tag.substr(0, tag.size() - 5);
                } else if (tag.size() > 5 && tag.substr(tag.size() - 5) == L".deep") {
                    entry.scope = GrantScope::Deep;
                    tag = tag.substr(0, tag.size() - 5);
                }
                if (!ParseAccessTag(tag, entry.access)) {
                    g_logger.LogFmt(L"PROFILE_LOAD: skipping allow entry with unknown tag '%s'", tag.c_str());
                    continue;
                }
                entry.path = NormalizeFsPath(val.substr(sep + 1));
                cfg.folders.push_back(std::move(entry));
            }
        }

        // --- Deny folders ---
        DWORD denyCount = ReadRegDword(hKey, L"_deny_count");
        for (DWORD i = 0; i < denyCount; i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_deny_%lu", i);
            std::wstring val = ReadRegSz(hKey, name);
            size_t sep = val.find(L'|');
            if (sep != std::wstring::npos) {
                FolderEntry entry;
                std::wstring tag = val.substr(0, sep);
                if (tag.size() > 5 && tag.substr(tag.size() - 5) == L".this") {
                    entry.scope = GrantScope::This;
                    tag = tag.substr(0, tag.size() - 5);
                } else if (tag.size() > 5 && tag.substr(tag.size() - 5) == L".deep") {
                    entry.scope = GrantScope::Deep;
                    tag = tag.substr(0, tag.size() - 5);
                }
                if (!ParseAccessTag(tag, entry.access)) {
                    g_logger.LogFmt(L"PROFILE_LOAD: skipping deny entry with unknown tag '%s'", tag.c_str());
                    continue;
                }
                entry.path = NormalizeFsPath(val.substr(sep + 1));
                cfg.denyFolders.push_back(std::move(entry));
            }
        }

        // --- Registry read keys ---
        DWORD regReadCount = ReadRegDword(hKey, L"_reg_read_count");
        for (DWORD i = 0; i < regReadCount; i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_reg_read_%lu", i);
            std::wstring val = ReadRegSz(hKey, name);
            if (!val.empty()) cfg.registryRead.push_back(std::move(val));
        }

        // --- Registry write keys ---
        DWORD regWriteCount = ReadRegDword(hKey, L"_reg_write_count");
        for (DWORD i = 0; i < regWriteCount; i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_reg_write_%lu", i);
            std::wstring val = ReadRegSz(hKey, name);
            if (!val.empty()) cfg.registryWrite.push_back(std::move(val));
        }

        // --- Environment pass-through ---
        DWORD envPassCount = ReadRegDword(hKey, L"_env_pass_count");
        for (DWORD i = 0; i < envPassCount; i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_env_pass_%lu", i);
            std::wstring val = ReadRegSz(hKey, name);
            if (!val.empty()) cfg.envPass.push_back(std::move(val));
        }

        return cfg;
    }

    // -----------------------------------------------------------------------
    // CreateSavedProfile — create a named profile with persistent SID + ACLs.
    //
    // Steps:
    //   1. Parse TOML config
    //   2. Generate SID (AC: CreateAppContainerProfile, RT: AllocateAndInitializeSid)
    //   3. Apply grants via ApplyAccessPipeline (ACLs stay on disk)
    //   4. Persist metadata + config + grant records to registry
    // -----------------------------------------------------------------------
    inline int HandleCreateProfile(const std::wstring& name, const std::wstring& configPath)
    {
        // Validate name
        if (name.empty()) {
            fprintf(stderr, "Error: profile name cannot be empty.\n");
            return SandyExit::ConfigError;
        }
        // Reject names with backslashes or special chars
        for (wchar_t c : name) {
            if (c == L'\\' || c == L'/' || c == L'|' || c == L'"' || c < 32) {
                fprintf(stderr, "Error: profile name contains invalid characters.\n");
                return SandyExit::ConfigError;
            }
        }
        // Read TOML file as raw text (for storage) and parse config
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

        bool isAppContainer = (config.tokenMode != TokenMode::Restricted);
        std::wstring sidString;
        std::wstring containerName;
        std::wstring typeStr = isAppContainer
            ? ((config.tokenMode == TokenMode::LPAC) ? L"lpac" : L"appcontainer")
            : L"restricted";
        std::wstring integrityStr = (config.integrity == IntegrityLevel::Low) ? L"low" : L"medium";

        // --- Stage 1: Create profile registry key FIRST ---
        // Verify exclusive creation via REG_CREATED_NEW_KEY
        std::wstring regKey = std::wstring(kProfilesParentKey) + L"\\" + name;
        HKEY hKey = nullptr;
        DWORD disposition = 0;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr,
                0, KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC, nullptr, &hKey, &disposition) != ERROR_SUCCESS) {
            fprintf(stderr, "Error: cannot create registry key for profile.\n");
            return SandyExit::InternalError;
        }

        if (disposition == REG_OPENED_EXISTING_KEY) {
            RegCloseKey(hKey);
            fprintf(stderr, "Error: profile '%ls' already exists or is being created. Use --delete-profile first.\n",
                    name.c_str());
            return SandyExit::ConfigError;
        }

        // Harden the new key immediately so that a sandboxed child cannot manipulate its own metadata
        HardenRegistryKeyAgainstRestricted(hKey);

        // Mark profile as staging — if Sandy crashes between here and
        // the final commit, cleanup will detect this and roll back.
        DWORD stagingFlag = 1;
        bool stageOk = true;
        stageOk &= TryWriteRegDword(hKey, L"_staging", stagingFlag);

        // F1/R8: Persist creator identity so CleanStagingProfiles can
        // distinguish a crashed create from an in-progress one.
        DWORD creatorPid = GetCurrentProcessId();
        stageOk &= TryWriteRegDword(hKey, L"_staging_pid", creatorPid);
        ULONGLONG creatorCtime = GetCurrentProcessCreationTime();
        stageOk &= TryWriteRegQword(hKey, L"_staging_ctime", creatorCtime);

        if (!stageOk) {
            fprintf(stderr, "Error: cannot persist staging metadata for profile creation.\n");
            RegCloseKey(hKey);
            DeleteProfileRegistryState(name, L"CREATE_PROFILE_STAGE");
            return SandyExit::InternalError;
        }

        // --- Generate SID ---
        PSID pSid = nullptr;
        if (isAppContainer) {
            // Use deterministic container name based on profile name
            containerName = std::wstring(kContainerPrefix) + name;
            PSID pContainerSid = nullptr;
            HRESULT hr = CreateAppContainerProfile(
                containerName.c_str(), L"Sandy Sandbox Profile",
                L"Persistent sandbox profile",
                nullptr, 0, &pContainerSid);
            if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
                // Profile exists in Windows but not in our registry — derive SID
                hr = DeriveAppContainerSidFromAppContainerName(
                    containerName.c_str(), &pContainerSid);
            }
            if (FAILED(hr) || !pContainerSid) {
                fprintf(stderr, "Error: AppContainer profile creation failed (0x%08lX).\n",
                        (unsigned long)hr);
                RegCloseKey(hKey);
                DeleteProfileRegistryState(name, L"CREATE_PROFILE_STAGE");
                return SandyExit::SetupError;
            }
            pSid = pContainerSid;
        } else {
            // Restricted Token: generate unique SID from GUID
            pSid = AllocateInstanceSid();
            if (!pSid) {
                fprintf(stderr, "Error: SID allocation failed (error %lu).\n", GetLastError());
                RegCloseKey(hKey);
                DeleteProfileRegistryState(name, L"CREATE_PROFILE_STAGE");
                return SandyExit::SetupError;
            }
        }

        // Convert SID to string
        LPWSTR pSidStr = nullptr;
        if (ConvertSidToStringSidW(pSid, &pSidStr)) {
            sidString = pSidStr;
            LocalFree(pSidStr);
        } else {
            fprintf(stderr, "Error: SID conversion failed.\n");
            FreeSid(pSid);
            RegCloseKey(hKey);
            if (isAppContainer) DeleteAppContainerProfile(containerName.c_str());
            DeleteProfileRegistryState(name, L"CREATE_PROFILE_STAGE");
            return SandyExit::SetupError;
        }

        // Persist SID now so cleanup can find it if we crash during grant application
        stageOk = true;
        stageOk &= TryWriteRegSz(hKey, L"_sid", sidString);
        if (!containerName.empty())
            stageOk &= TryWriteRegSz(hKey, L"_container", containerName);

        if (!stageOk) {
            fprintf(stderr, "Error: cannot persist staging metadata for profile creation.\n");
            RegCloseKey(hKey);
            DeleteProfileRegistryState(name, L"CREATE_PROFILE_STAGE");
            if (isAppContainer && !containerName.empty())
                DeleteAppContainerProfile(containerName.c_str());
            FreeSid(pSid);
            return SandyExit::InternalError;
        }

        // --- Stage 2: Apply grants (persistent — remain on filesystem) ---
        //
        // Suppress RecordGrant's normal registry writes — grant records are
        // written incrementally to the staging profile key instead (crash-safe).
        // This also resets the metadata-health flag so we fail closed if ACLs
        // are applied but their cleanup inventory cannot be persisted.
        BeginStagingGrantCapture(hKey);

        printf("Applying grants for profile '%ls'...\n", name.c_str());
        bool grantOk = ApplyAccessPipeline(pSid, config, isAppContainer);
        // F1/R9: Restricted profiles must also apply registry grants
        if (!isAppContainer) {
            if (!GrantRegistryAccess(pSid, config))
                grantOk = false;
        }
        // AppContainer localhost is durable profile-owned state and must be
        // established with the profile rather than treated as a transient run
        // side effect.
        if (isAppContainer && config.lanMode == LanMode::WithLocalhost) {
            if (!EnsureProfileLoopback(containerName)) {
                g_logger.Log(L"CREATE_PROFILE: profile-owned loopback enable FAILED");
                grantOk = false;
            }
        }
        // RT desktop is durable profile-owned state — grant at creation,
        // revoke at deletion.  The ACE uses the profile's persistent SID so
        // it naturally survives across runs.
        if (!isAppContainer && config.allowDesktop) {
            if (!GrantDesktopAccess(pSid)) {
                g_logger.Log(L"CREATE_PROFILE: profile-owned desktop grant FAILED");
                grantOk = false;
            }
        }
        if (!GrantTrackingHealthy()) {
            g_logger.Log(L"CREATE_PROFILE: grant tracking persistence FAILED — aborting");
            grantOk = false;
        }
        if (!grantOk) {
            // F2/R10: Immediate self-rollback — undo already-applied grants now
            // instead of deferring to future CleanStagingProfiles().
            fprintf(stderr, "Error: grant application failed (may need Administrator). "
                    "Profile not committed.\n");
            AbortStagingGrantCapture();
            // Revoke profile-owned desktop ACEs (RT only, best-effort during rollback)
            if (!isAppContainer && config.allowDesktop && !sidString.empty())
                RevokeDesktopAccessForSid(sidString);
            // Roll back ACLs — SIDs are unique, so rollback is always complete
            bool grantsRestored = RestoreGrantsFromKey(hKey);
            bool containerRollbackOk = true;
            if (isAppContainer && !containerName.empty()) {
                containerRollbackOk = TeardownPersistentProfileContainer(
                    containerName, L"CREATE_PROFILE_ROLLBACK");
            }
            AcquireSRWLockExclusive(&g_aclGrantsLock);
            g_aclGrants.clear();
            ReleaseSRWLockExclusive(&g_aclGrantsLock);
            RegCloseKey(hKey);
            if (grantsRestored && containerRollbackOk) {
                // Rollback complete — safe to delete staging key
                if (!DeleteProfileRegistryState(name, L"CREATE_PROFILE_ROLLBACK")) {
                    g_logger.LogFmt(L"CREATE_PROFILE_ROLLBACK: metadata delete failed, preserving staging key");
                    fprintf(stderr, "  Profile metadata preserved for --cleanup retry.\n");
                }
            } else {
                // Preserve staging metadata until both ACL and container rollback are complete.
                g_logger.LogFmt(L"CREATE_PROFILE_ROLLBACK: rollback incomplete (acl=%s container=%s), preserving staging key for retry",
                                grantsRestored ? L"OK" : L"FAILED",
                                containerRollbackOk ? L"OK" : L"FAILED");
                fprintf(stderr, "  Staging key preserved for --cleanup retry.\n");
            }
            FreeSid(pSid);
            return SandyExit::SetupError;
        }

        DWORD grantIdx = EndStagingGrantCapture();

        // --- Stage 3: Persist metadata + grant records to open key ---
        // (_sid and _container were written before Stage 2 for crash recovery)
        bool commitOk = true;
        commitOk &= TryWriteRegSz(hKey, L"_type", typeStr);
        commitOk &= TryWriteRegSz(hKey, L"_integrity", integrityStr);
        commitOk &= TryWriteRegSz(hKey, L"_created", SandyLogger::Timestamp());
        commitOk &= TryWriteRegSz(hKey, L"_toml", tomlText);  // reference only
        commitOk &= WriteConfigToRegistry(hKey, config);

        // Grant records are already in the profile key (written incrementally
        // during Stage 2 via g_stagingProfileKey).

        // Remove staging marker — profile is now fully committed
        if (commitOk)
            commitOk &= (RegDeleteValueW(hKey, L"_staging") == ERROR_SUCCESS);

        if (!commitOk) {
            fprintf(stderr, "Error: profile metadata commit failed. Rolling back.\n");
            // Revoke profile-owned desktop ACEs (RT only, best-effort during rollback)
            if (!isAppContainer && config.allowDesktop && !sidString.empty())
                RevokeDesktopAccessForSid(sidString);
            bool grantsRestored = RestoreGrantsFromKey(hKey);
            bool containerRollbackOk = true;
            if (isAppContainer && !containerName.empty()) {
                containerRollbackOk = TeardownPersistentProfileContainer(
                    containerName, L"CREATE_PROFILE_COMMIT_ROLLBACK");
            }
            AcquireSRWLockExclusive(&g_aclGrantsLock);
            g_aclGrants.clear();
            ReleaseSRWLockExclusive(&g_aclGrantsLock);
            RegCloseKey(hKey);
            if (grantsRestored && containerRollbackOk) {
                if (!DeleteProfileRegistryState(name, L"CREATE_PROFILE_COMMIT_ROLLBACK")) {
                    g_logger.Log(L"CREATE_PROFILE_COMMIT: metadata delete failed, preserving staging key for retry");
                    fprintf(stderr, "  Profile metadata preserved for --cleanup retry.\n");
                }
            } else {
                g_logger.LogFmt(L"CREATE_PROFILE_COMMIT: rollback incomplete (acl=%s container=%s), preserving staging key for retry",
                                grantsRestored ? L"OK" : L"FAILED",
                                containerRollbackOk ? L"OK" : L"FAILED");
                fprintf(stderr, "  Staging key preserved for --cleanup retry.\n");
            }
            FreeSid(pSid);
            return SandyExit::InternalError;
        }

        RegCloseKey(hKey);
        FreeSid(pSid);

        // Clear in-memory grant list (ACLs stay on disk, records are in Profiles)
        AcquireSRWLockExclusive(&g_aclGrantsLock);
        g_aclGrants.clear();
        ReleaseSRWLockExclusive(&g_aclGrantsLock);

        printf("Profile '%ls' created successfully.\n", name.c_str());
        printf("  Type:      %ls\n", typeStr.c_str());
        if (!isAppContainer)
            printf("  Integrity: %ls\n", integrityStr.c_str());
        printf("  SID:       %ls\n", sidString.c_str());
        if (!containerName.empty())
            printf("  Container: %ls\n", containerName.c_str());
        printf("  Grants:    %lu path(s)\n", (unsigned long)grantIdx);
        return 0;
    }

    // -----------------------------------------------------------------------
    // CleanStagingProfiles — remove profiles left in staging state.
    //
    // Scans Profiles\* for keys with _staging=1 (crash mid-create-profile).
    // For each, revokes ACLs from grant records, deletes the AC profile
    // if present, and removes the incomplete registry key.
    // -----------------------------------------------------------------------
    inline void CleanStagingProfiles()
    {
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kProfilesParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return;

        // P1: Snapshot subkey names first to avoid index-shift races.
        DWORD numKeys = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &numKeys,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        std::vector<std::wstring> allNames;
        for (DWORD i = 0; i < numKeys; i++) {
            wchar_t nm[256]; DWORD nl = 256;
            if (RegEnumKeyExW(hParent, i, nm, &nl, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                allNames.push_back(nm);
        }
        RegCloseKey(hParent);

        std::vector<std::wstring> stagingNames;
        for (const auto& nm : allNames) {
            HKEY hSub = nullptr;
            std::wstring subKey = std::wstring(kProfilesParentKey) + L"\\" + nm;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0,
                              KEY_READ, &hSub) != ERROR_SUCCESS)
                continue;

            DWORD staging = 0, sz = sizeof(staging);
            if (RegQueryValueExW(hSub, L"_staging", nullptr, nullptr,
                                 reinterpret_cast<BYTE*>(&staging), &sz) == ERROR_SUCCESS
                && staging == 1) {
                // F1/R8: Atomic read of staging creator identity.
                // If either value is missing, treat as "writer still in progress".
                DWORD creatorPid = 0; ULONGLONG creatorCtime = 0;
                if (!ReadStagingPidAndCtime(hSub, creatorPid, creatorCtime)) {
                    g_logger.LogFmt(L"STAGING_SKIP: profile '%s' staging identity incomplete (writer in progress)",
                                    nm.c_str());
                } else if (IsProcessAlive(creatorPid, creatorCtime)) {
                    g_logger.LogFmt(L"STAGING_SKIP: profile '%s' creator PID %lu still alive",
                                    nm.c_str(), creatorPid);
                } else {
                    stagingNames.push_back(nm);
                }
            }
            RegCloseKey(hSub);
        }

        for (const auto& name : stagingNames) {
            g_logger.LogFmt(L"STAGING_CLEANUP: profile '%s' left in staging — rolling back", name.c_str());
            printf("  [STAGING] Rolling back incomplete profile '%ls'...\n", name.c_str());

            std::wstring regKey = std::wstring(kProfilesParentKey) + L"\\" + name;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0,
                              KEY_READ, &hKey) == ERROR_SUCCESS) {
                // Revoke ACLs recorded in the profile key
                bool grantsRestored = RestoreGrantsFromKey(hKey);
                bool containerCleanOk = true;
                bool desktopCleanOk = true;

                // Revoke desktop ACEs for restricted profiles with desktop = true
                std::wstring profileType = ReadRegSz(hKey, L"_type");
                std::wstring profileSid = ReadRegSz(hKey, L"_sid");
                bool hadDesktop = (ReadRegDword(hKey, L"_allow_desktop") != 0);
                if (profileType == L"restricted" && hadDesktop && !profileSid.empty()) {
                    desktopCleanOk = RevokeDesktopAccessForSid(profileSid);
                    if (!desktopCleanOk)
                        g_logger.LogFmt(L"STAGING_CLEANUP: desktop revocation FAILED for profile '%s'",
                                        name.c_str());
                }

                // Delete AppContainer profile if present
                std::wstring containerName = ReadRegSz(hKey, L"_container");
                if (!containerName.empty()) {
                    containerCleanOk = TeardownPersistentProfileContainer(
                        containerName, L"STAGING_CLEANUP");
                }
                RegCloseKey(hKey);

                // Preserve metadata for retry until durable host state
                // has been fully reverted.
                if (!grantsRestored || !containerCleanOk || !desktopCleanOk) {
                    g_logger.LogFmt(L"STAGING_CLEANUP: profile '%s' rollback incomplete (acl=%s container=%s desktop=%s), preserving metadata",
                                    name.c_str(),
                                    grantsRestored ? L"OK" : L"FAILED",
                                    containerCleanOk ? L"OK" : L"FAILED",
                                    desktopCleanOk ? L"OK" : L"FAILED");
                    printf("  [STAGING] Profile '%ls' rollback incomplete — metadata preserved for retry.\n",
                           name.c_str());
                    continue;
                }
            }

            // Delete the incomplete profile registry key
            if (!DeleteProfileRegistryState(name, L"STAGING_CLEANUP")) {
                g_logger.LogFmt(L"STAGING_CLEANUP: profile '%s' metadata delete failed, preserving metadata",
                                name.c_str());
                printf("  [STAGING] Profile '%ls' metadata delete failed — preserved for retry.\n",
                       name.c_str());
                continue;
            }
            g_logger.LogFmt(L"STAGING_CLEANUP: profile '%s' rolled back", name.c_str());
            printf("  [STAGING] Profile '%ls' rolled back.\n", name.c_str());
        }
    }

    // -----------------------------------------------------------------------
    // LoadSavedProfile — read a named profile from registry.
    // Returns false if not found.
    // -----------------------------------------------------------------------
    inline bool LoadSavedProfile(const std::wstring& name, SavedProfile& out)
    {
        std::wstring regKey = std::wstring(kProfilesParentKey) + L"\\" + name;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0,
                          KEY_READ, &hKey) != ERROR_SUCCESS)
            return false;

        // P1c: Reject profiles still in staging state — they were never
        // fully committed and may contain incomplete/corrupt config.
        DWORD staging = 0, stagingSz = sizeof(staging);
        if (RegQueryValueExW(hKey, L"_staging", nullptr, nullptr,
                             reinterpret_cast<BYTE*>(&staging), &stagingSz) == ERROR_SUCCESS
            && staging == 1) {
            g_logger.LogFmt(L"PROFILE_LOAD: profile '%s' is still in staging — rejecting",
                            name.c_str());
            RegCloseKey(hKey);
            return false;
        }

        out.name = name;
        out.type = ReadRegSz(hKey, L"_type");
        out.integrity = ReadRegSz(hKey, L"_integrity");
        out.sidString = ReadRegSz(hKey, L"_sid");
        out.containerName = ReadRegSz(hKey, L"_container");
        out.created = ReadRegSz(hKey, L"_created");
        out.tomlText = ReadRegSz(hKey, L"_toml");

        // Read config from discrete registry values (no TOML parsing)
        out.config = ReadConfigFromRegistry(hKey);
        RegCloseKey(hKey);
        // Reject profiles with missing mandatory fields or corrupt config
        if (out.sidString.empty() || out.type.empty() || out.config.parseError)
            return false;
        return true;
    }

    // -----------------------------------------------------------------------
    // DeleteSavedProfile — remove a profile: revoke ACLs, delete container,
    // delete registry key.
    // -----------------------------------------------------------------------
    inline int HandleDeleteProfile(const std::wstring& name)
    {
        std::wstring regKey = std::wstring(kProfilesParentKey) + L"\\" + name;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0,
                          KEY_READ, &hKey) != ERROR_SUCCESS) {
            fprintf(stderr, "Error: profile '%ls' not found.\n", name.c_str());
            return SandyExit::ConfigError;
        }

        // Read container name for AppContainer cleanup
        std::wstring containerName = ReadRegSz(hKey, L"_container");

        // F2/R8: Type-agnostic liveness guard — refuse deletion when any
        // live instance is using this profile (covers both AC and RT modes)
        auto liveProfiles = GetLiveProfileNames();
        if (liveProfiles.count(NormalizeLookupKey(name))) {
            RegCloseKey(hKey);
            fprintf(stderr, "Error: profile '%ls' is currently in use by a live sandbox.\n"
                    "Wait for the sandbox to exit, or terminate it first.\n", name.c_str());
            return SandyExit::InternalError;
        }
        // Legacy AC container check (for instances that predate _profile_name)
        if (!containerName.empty()) {
                auto liveContainers = GetLiveContainerNames();
                if (liveContainers.count(NormalizeLookupKey(containerName))) {
                RegCloseKey(hKey);
                fprintf(stderr, "Error: profile '%ls' is currently in use by a live sandbox.\n"
                        "Wait for the sandbox to exit, or terminate it first.\n", name.c_str());
                return SandyExit::InternalError;
            }
        }

        // Refuse deletion while another process is still staging this profile
        {
            DWORD staging = 0, stagingSz = sizeof(staging);
            if (RegQueryValueExW(hKey, L"_staging", nullptr, nullptr,
                                 reinterpret_cast<BYTE*>(&staging), &stagingSz) == ERROR_SUCCESS
                && staging == 1) {
                // Atomic read — if either value missing, treat as writer in progress
                DWORD creatorPid = 0; ULONGLONG creatorCtime = 0;
                if (!ReadStagingPidAndCtime(hKey, creatorPid, creatorCtime)) {
                    RegCloseKey(hKey);
                    fprintf(stderr, "Error: profile '%ls' is currently being created by another process.\n"
                            "Wait for creation to finish, or use --cleanup if the creator crashed.\n",
                            name.c_str());
                    return SandyExit::InternalError;
                }
                if (IsProcessAlive(creatorPid, creatorCtime)) {
                    RegCloseKey(hKey);
                    fprintf(stderr, "Error: profile '%ls' is currently being created by another process.\n"
                            "Wait for creation to finish, or use --cleanup if the creator crashed.\n",
                            name.c_str());
                    return SandyExit::InternalError;
                }
                // Creator is dead — staging remnant; let delete proceed
                // (cleanup will roll back the partial state)
                g_logger.LogFmt(L"DELETE_PROFILE: profile '%s' has dead staging — proceeding with delete",
                                name.c_str());
            }
        }

        // Read profile metadata needed for profile-owned teardown
        std::wstring profileType = ReadRegSz(hKey, L"_type");
        std::wstring profileSid = ReadRegSz(hKey, L"_sid");
        bool hadDesktop = (ReadRegDword(hKey, L"_allow_desktop") != 0);
        std::wstring lanModeStr = ReadRegSz(hKey, L"_lan_mode");
        bool hadLoopback = (lanModeStr == L"with_localhost");

        // Revoke profile-owned desktop ACEs (RT profiles with desktop = true)
        // Done before filesystem ACL rollback — desktop/loopback cleanup is
        // independent and must always be attempted to prevent permanent leaks.
        bool desktopOk = true;
        if (profileType == L"restricted" && hadDesktop && !profileSid.empty()) {
            desktopOk = RevokeDesktopAccessForSid(profileSid);
            if (!desktopOk) {
                g_logger.LogFmt(L"DELETE_PROFILE: desktop revocation FAILED for profile '%s'",
                                name.c_str());
            }
        }

        // Revoke profile-owned loopback exemption (AC profiles with loopback)
        if (!containerName.empty() && hadLoopback) {
            DisableLoopbackForContainer(containerName);
        }

        // Revoke all grant ACLs
        printf("Revoking grants for profile '%ls'...\n", name.c_str());
        bool grantsRestored = RestoreGrantsFromKey(hKey);
        RegCloseKey(hKey);
        if (!grantsRestored || !desktopOk) {
            fprintf(stderr, "Warning: %s rollback failed for profile '%ls'.\n"
                    "Profile metadata preserved so --delete-profile can be retried safely.\n",
                    !grantsRestored ? "ACL" : "desktop ACE",
                    name.c_str());
            return SandyExit::InternalError;
        }

        // Delete AppContainer profile from Windows
        bool containerDeleted = true;
        if (!containerName.empty()) {
            containerDeleted = TeardownPersistentProfileContainer(
                containerName, L"DELETE_PROFILE");
            if (!containerDeleted) {
                fprintf(stderr, "Warning: durable container teardown failed for profile '%ls'.\n"
                        "Profile metadata preserved so --delete-profile can be retried safely.\n",
                        name.c_str());
                return SandyExit::InternalError;
            }
        }

        // Delete registry key
        if (!DeleteProfileRegistryState(name, L"DELETE_PROFILE")) {
            fprintf(stderr, "Warning: registry key deletion failed for profile '%ls'.\n"
                    "Profile metadata preserved so --delete-profile can be retried safely.\n",
                    name.c_str());
            return SandyExit::InternalError;
        }

        printf("Profile '%ls' deleted.\n", name.c_str());
        return 0;
    }

    // -----------------------------------------------------------------------
    // EnumSavedProfiles — list all saved profile names + creation dates.
    // -----------------------------------------------------------------------
    struct ProfileSummary {
        std::wstring name;
        std::wstring created;
        std::wstring type;
    };

    inline std::vector<ProfileSummary> EnumSavedProfiles()
    {
        std::vector<ProfileSummary> result;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kProfilesParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return result;

        // P1: Snapshot subkey names first to avoid index-shift races.
        DWORD numKeys = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &numKeys,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        std::vector<std::wstring> allNames;
        for (DWORD i = 0; i < numKeys; i++) {
            wchar_t nm[256]; DWORD nl = 256;
            if (RegEnumKeyExW(hParent, i, nm, &nl, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                allNames.push_back(nm);
        }
        RegCloseKey(hParent);

        for (const auto& nm : allNames) {
            ProfileSummary ps;
            ps.name = nm;

            // Read creation date and type from subkey
            std::wstring subKey = std::wstring(kProfilesParentKey) + L"\\" + nm;
            HKEY hSub = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0,
                              KEY_READ, &hSub) == ERROR_SUCCESS) {
                // P3: Skip staging profiles — incomplete create-profile
                DWORD staging = 0, ssz = sizeof(staging);
                RegQueryValueExW(hSub, L"_staging", nullptr, nullptr,
                                 reinterpret_cast<BYTE*>(&staging), &ssz);
                if (staging == 1) {
                    RegCloseKey(hSub);
                    continue;
                }
                ps.created = ReadRegSz(hSub, L"_created");
                ps.type = ReadRegSz(hSub, L"_type");
                RegCloseKey(hSub);
                // P2a: Skip entries with missing _type — ghost profiles from a
                // crash between RegCreateKeyExW and _type write in Stage 3.
                if (ps.type.empty())
                    continue;
            }
            result.push_back(std::move(ps));
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // HandleProfileInfo — print detailed info about a saved profile.
    // -----------------------------------------------------------------------
    inline int HandleProfileInfo(const std::wstring& name)
    {
        SavedProfile prof;
        if (!LoadSavedProfile(name, prof)) {
            fprintf(stderr, "Error: profile '%ls' not found.\n", name.c_str());
            return SandyExit::ConfigError;
        }

        printf("=== Profile: %ls ===\n", prof.name.c_str());
        printf("Created:     %ls\n", prof.created.c_str());
        printf("Type:        %ls\n", prof.type.c_str());
        if (prof.type == L"restricted")
            printf("Integrity:   %ls\n", prof.integrity.c_str());
        printf("SID:         %ls\n", prof.sidString.c_str());
        if (!prof.containerName.empty())
            printf("Container:   %ls\n", prof.containerName.c_str());

        // Config summary
        if (!prof.config.parseError) {
            printf("\nConfiguration:\n");
            int allowCount = (int)prof.config.folders.size();
            int denyCount = (int)prof.config.denyFolders.size();
            printf("  Allow paths:  %d\n", allowCount);
            for (const auto& f : prof.config.folders)
                printf("    [%-7ls] %ls\n", AccessTag(f.access), f.path.c_str());
            if (denyCount > 0) {
                printf("  Deny paths:   %d\n", denyCount);
                for (const auto& f : prof.config.denyFolders)
                    printf("    [%-7ls] %ls\n", AccessTag(f.access), f.path.c_str());
            }

            // Privileges
            printf("  Privileges:\n");
            if (prof.type == L"appcontainer" || prof.type == L"lpac") {
                printf("    network         = %s\n", prof.config.allowNetwork ? "true" : "false");
                printf("    lan             = %s\n",
                    prof.config.lanMode == LanMode::WithLocalhost ? "'with localhost'" :
                    prof.config.lanMode == LanMode::WithoutLocalhost ? "'without localhost'" : "false");
            } else {
                printf("    named_pipes     = %s\n", prof.config.allowNamedPipes ? "true" : "false");
            }
            printf("    stdin           = %s\n",
                   prof.config.stdinMode == L"NUL" ? "false" : "true");
            printf("    clipboard_read  = %s\n", prof.config.allowClipboardRead ? "true" : "false");
            printf("    clipboard_write = %s\n", prof.config.allowClipboardWrite ? "true" : "false");
            printf("    child_processes = %s\n", prof.config.allowChildProcesses ? "true" : "false");

            // Limits
            if (prof.config.timeoutSeconds || prof.config.memoryLimitMB || prof.config.maxProcesses) {
                printf("  Limits:\n");
                if (prof.config.timeoutSeconds)
                    printf("    timeout         = %lu sec\n", prof.config.timeoutSeconds);
                if (prof.config.memoryLimitMB)
                    printf("    memory          = %zu MB\n", prof.config.memoryLimitMB);
                if (prof.config.maxProcesses)
                    printf("    processes       = %lu max\n", prof.config.maxProcesses);
            }
        }

        return 0;
    }

    // -----------------------------------------------------------------------
    // RunWithProfile — run a process using a saved profile's SID + config.
    //
    // Reconstructs the profile's execution identity and delegates to the same
    // ownership-driven pipeline used by transient runs. Persistent profile
    // grants are treated as the primary ownership model rather than as a
    // special-case "normal run plus profile exceptions".
    // -----------------------------------------------------------------------
    inline int RunWithProfile(const SavedProfile& prof,
                               const std::wstring& exePath,
                               const std::wstring& exeArgs)
    {
        ResetEmergencyCleanupState();
        const SandboxConfig& config = prof.config;
        bool isRestricted = (config.tokenMode == TokenMode::Restricted);
        bool isAppContainer = !isRestricted;

        g_instanceId = GenerateInstanceId();
        if (g_instanceId.empty()) {
            fprintf(stderr, "Error: failed to generate instance ID (CoCreateGuid failed).\n");
            return SandyExit::SetupError;
        }

        std::wstring exeFolder = config.workdir.empty() ? GetInheritedWorkdir() : config.workdir;
        if (exeFolder.empty())
            return SandyExit::SetupError;

        BeginRunSession(exePath, L"profile:" + prof.name, prof.name, false);
        g_logger.Log((L"PROFILE_SID: " + prof.sidString).c_str());

        PSID pSid = nullptr;
        HANDLE hRestrictedToken = nullptr;

        if (isAppContainer) {
            PSID pContainerSid = nullptr;
            HRESULT hr = DeriveAppContainerSidFromAppContainerName(
                prof.containerName.c_str(), &pContainerSid);
            if (FAILED(hr) || !pContainerSid) {
                g_logger.LogFmt(L"ERROR: cannot derive SID from container '%s' (0x%08X)",
                                prof.containerName.c_str(), hr);
                fprintf(stderr, "Error: cannot derive SID for profile '%ls'. "
                        "Profile may be corrupted — recreate it.\n", prof.name.c_str());
                DeleteCleanupTask(g_instanceId);
                return SandyExit::SetupError;
            }
            pSid = pContainerSid;
            g_logger.Log(L"MODE: appcontainer (profile)");
        } else {
            PSID pGrantSid = nullptr;
            if (!ConvertStringSidToSidW(prof.sidString.c_str(), &pGrantSid)) {
                g_logger.LogFmt(L"ERROR: cannot convert SID '%s' (error %lu)",
                                prof.sidString.c_str(), GetLastError());
                fprintf(stderr, "Error: cannot reconstruct SID for profile '%ls'.\n",
                        prof.name.c_str());
                DeleteCleanupTask(g_instanceId);  // no-op if task not yet created
                return SandyExit::SetupError;
            }
            pSid = pGrantSid;

            hRestrictedToken = CreateRestrictedSandboxToken(config.integrity, pGrantSid, config.strict);
            if (!hRestrictedToken) {
                g_logger.LogFmt(L"ERROR: restricted token creation failed (error %lu)",
                                GetLastError());
                LocalFree(pGrantSid);
                DeleteCleanupTask(g_instanceId);  // no-op if task not yet created
                return SandyExit::SetupError;
            }
            g_logger.Log(config.integrity == IntegrityLevel::Low
                         ? L"MODE: restricted token (Low integrity, profile)"
                         : L"MODE: restricted token (Medium integrity, profile)");
        }

        ExecutionIdentity identity;
        identity.pSid = pSid;
        identity.hToken = hRestrictedToken;
        identity.containerName = prof.containerName;
        identity.profileName = prof.name;
        identity.persistentProfile = true;
        identity.grantsPreexisting = true;
        identity.deleteContainerOnExit = false;

        // Register live-state so both GetLiveContainerNames() and
        // GetLiveProfileNames() can detect this run (F2/R8)
        if (!PersistLiveState(identity.containerName, prof.name)) {
            if (hRestrictedToken) CloseHandle(hRestrictedToken);
            if (isAppContainer)
                FreeSid(pSid);
            else
                LocalFree(pSid);
            DeleteCleanupTask(g_instanceId);  // no-op if task not yet created
            ResetEmergencyCleanupState();
            fprintf(stderr, "Error: failed to persist live profile state for '%ls'.\n",
                    prof.name.c_str());
            return SandyExit::SetupError;
        }

        // P2: Create cleanup task AFTER PersistLiveState writes the ledger.
        // This ensures concurrent DeleteStaleCleanupTasks sees our ledger
        // and won't discard the task prematurely.
        CreateCleanupTask(g_instanceId);

        int result = RunPipeline(config, exePath, exeArgs, exeFolder,
                                 identity);

        // Cleanup SID and token (RunPipeline doesn't own these in profile mode)
        ClearLiveState();
        FinalizeCleanupTaskForCurrentRun();
        if (hRestrictedToken) CloseHandle(hRestrictedToken);
        if (isAppContainer)
            FreeSid(pSid);
        else
            LocalFree(pSid);
        ResetEmergencyCleanupState();

        return result;
    }

} // namespace Sandbox
