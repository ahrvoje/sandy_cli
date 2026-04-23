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
#include "SandboxConfigRender.h"
#include "SandboxProfileRegistry.h"

namespace Sandbox {

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

    enum class SavedProfileLoadStatus { Ok, NotFound, Invalid };

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
    // ProfileExists — check if a named profile exists in the registry.
    // -----------------------------------------------------------------------
    inline bool ProfileExists(const std::wstring& name)
    {
        HKEY hKey = nullptr;
        if (OpenSavedProfileRegistryKey(name, KEY_READ, hKey)) {
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }

    inline void BuildIndexedValueName(const wchar_t* prefix,
                                      DWORD index,
                                      wchar_t (&name)[32])
    {
        swprintf(name, 32, L"%ls%lu", prefix, index);
    }

    inline const wchar_t* GrantScopeSuffix(GrantScope scope)
    {
        return scope == GrantScope::This ? L".this" : L".deep";
    }

    inline std::wstring SerializeFolderEntry(const FolderEntry& entry)
    {
        return std::wstring(AccessLevelName(entry.access))
             + GrantScopeSuffix(entry.scope)
             + L"|"
             + entry.path;
    }

    inline bool TryDeserializeFolderEntry(const std::wstring& serialized,
                                          FolderEntry& entry,
                                          std::wstring& error)
    {
        size_t sep = serialized.find(L'|');
        if (sep == std::wstring::npos || sep == 0 || sep + 1 >= serialized.size()) {
            error = L"missing access/path separator";
            return false;
        }

        std::wstring tag = serialized.substr(0, sep);
        if (tag.size() > 5 && tag.substr(tag.size() - 5) == L".this") {
            entry.scope = GrantScope::This;
            tag.resize(tag.size() - 5);
        } else if (tag.size() > 5 && tag.substr(tag.size() - 5) == L".deep") {
            entry.scope = GrantScope::Deep;
            tag.resize(tag.size() - 5);
        } else {
            error = L"missing grant scope suffix";
            return false;
        }

        if (!ParseAccessTag(tag, entry.access)) {
            error = L"unknown access tag";
            return false;
        }

        entry.path = NormalizeFsPath(serialized.substr(sep + 1));
        if (entry.path.empty()) {
            error = L"empty path";
            return false;
        }
        return true;
    }

    inline bool WriteIndexedStringValues(HKEY hKey,
                                         const wchar_t* countName,
                                         const wchar_t* valuePrefix,
                                         const std::vector<std::wstring>& values)
    {
        bool ok = TryWriteRegDword(hKey, countName, static_cast<DWORD>(values.size()));
        for (DWORD i = 0; i < values.size(); i++) {
            wchar_t name[32];
            BuildIndexedValueName(valuePrefix, i, name);
            ok &= TryWriteRegSz(hKey, name, values[i]);
        }
        return ok;
    }

    inline bool WriteIndexedFolderEntries(HKEY hKey,
                                          const wchar_t* countName,
                                          const wchar_t* valuePrefix,
                                          const std::vector<FolderEntry>& entries)
    {
        bool ok = TryWriteRegDword(hKey, countName, static_cast<DWORD>(entries.size()));
        for (DWORD i = 0; i < entries.size(); i++) {
            wchar_t name[32];
            BuildIndexedValueName(valuePrefix, i, name);
            ok &= TryWriteRegSz(hKey, name, SerializeFolderEntry(entries[i]));
        }
        return ok;
    }

    inline bool ReadIndexedStringValues(HKEY hKey,
                                        const wchar_t* countName,
                                        const wchar_t* valuePrefix,
                                        const wchar_t* fieldTag,
                                        std::vector<std::wstring>& out)
    {
        DWORD count = ReadRegDword(hKey, countName);
        for (DWORD i = 0; i < count; i++) {
            wchar_t name[32];
            BuildIndexedValueName(valuePrefix, i, name);
            std::wstring value = ReadRegSz(hKey, name);
            if (value.empty()) {
                g_logger.LogFmt(L"PROFILE_LOAD: %s entry '%s' missing or empty — rejecting profile",
                                fieldTag, name);
                return false;
            }
            out.push_back(std::move(value));
        }
        return true;
    }

    inline bool ReadIndexedFolderEntries(HKEY hKey,
                                         const wchar_t* countName,
                                         const wchar_t* valuePrefix,
                                         const wchar_t* fieldTag,
                                         std::vector<FolderEntry>& out)
    {
        DWORD count = ReadRegDword(hKey, countName);
        for (DWORD i = 0; i < count; i++) {
            wchar_t name[32];
            BuildIndexedValueName(valuePrefix, i, name);
            std::wstring value = ReadRegSz(hKey, name);
            FolderEntry entry;
            std::wstring error;
            if (!TryDeserializeFolderEntry(value, entry, error)) {
                g_logger.LogFmt(L"PROFILE_LOAD: malformed %s entry '%s' (%s) — rejecting profile",
                                fieldTag, name, error.c_str());
                return false;
            }
            out.push_back(std::move(entry));
        }
        return true;
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
        ok &= TryWriteRegSz(hKey, L"_token_mode", TokenModeName(cfg.tokenMode));
        ok &= TryWriteRegSz(hKey, L"_cfg_integrity",
            (cfg.integrity == IntegrityLevel::Low) ? L"low" : L"medium");

        // --- Strings ---
        ok &= TryWriteRegSz(hKey, L"_workdir", cfg.workdir);
        ok &= TryWriteRegSz(hKey, L"_stdin_mode", cfg.stdinMode.empty() ? L"INHERIT" : cfg.stdinMode);

        // --- Booleans (REG_DWORD 0/1) ---
        ok &= TryWriteRegDword(hKey, L"_allow_network",      cfg.allowNetwork     ? 1 : 0);
        ok &= TryWriteRegSz(hKey, L"_lan_mode", LanModeRegistryName(cfg.lanMode));

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

        ok &= WriteIndexedFolderEntries(hKey, L"_allow_count", L"_allow_", cfg.folders);
        ok &= WriteIndexedFolderEntries(hKey, L"_deny_count", L"_deny_", cfg.denyFolders);
        ok &= WriteIndexedStringValues(hKey, L"_reg_read_count", L"_reg_read_", cfg.registryRead);
        ok &= WriteIndexedStringValues(hKey, L"_reg_write_count", L"_reg_write_", cfg.registryWrite);
        ok &= WriteIndexedStringValues(hKey, L"_env_pass_count", L"_env_pass_", cfg.envPass);

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
        if (!TryParseTokenMode(mode, cfg.tokenMode)) {
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

        auto rejectPathValue = [&](const wchar_t* sectionName,
                                   const wchar_t* keyName,
                                   const std::wstring& value,
                                   ConfigPathValidationError error) {
            switch (error) {
            case ConfigPathValidationError::NotAbsolute:
                g_logger.LogFmt(L"PROFILE_LOAD: '%s' in [%s] is not an absolute path — rejecting profile",
                                keyName, sectionName);
                break;
            case ConfigPathValidationError::Missing:
                g_logger.LogFmt(L"PROFILE_LOAD: path does not exist for '%s' in [%s]: %s — rejecting profile",
                                keyName, sectionName, value.c_str());
                break;
            case ConfigPathValidationError::ExpectedFile:
                g_logger.LogFmt(L"PROFILE_LOAD: '%s' in [%s] must reference a file, got directory: %s — rejecting profile",
                                keyName, sectionName, value.c_str());
                break;
            case ConfigPathValidationError::ExpectedDirectory:
                g_logger.LogFmt(L"PROFILE_LOAD: '%s' in [%s] must reference a directory, got file: %s — rejecting profile",
                                keyName, sectionName, value.c_str());
                break;
            default:
                return;
            }
            cfg.parseError = true;
        };

        if (!cfg.workdir.empty()) {
            rejectPathValue(L"sandbox", L"workdir", cfg.workdir,
                            GetConfiguredPathValidationError(cfg.workdir, ConfigPathKind::Directory));
        }
        if (!cfg.stdinMode.empty() && _wcsicmp(cfg.stdinMode.c_str(), L"NUL") != 0) {
            rejectPathValue(L"privileges", L"stdin", cfg.stdinMode,
                            GetConfiguredPathValidationError(cfg.stdinMode, ConfigPathKind::File));
        }

        // --- Booleans ---
        // P1a: _allow_desktop and _allow_child_procs must exist in the registry.
        // Missing values previously defaulted to 1 (enabled), silently granting
        // permissions the user never configured.  Now fail closed.
        cfg.allowNetwork        = ReadRegDword(hKey, L"_allow_network")    != 0;
        std::wstring lanModeStr = ReadRegSz(hKey, L"_lan_mode");
        if (!TryParseLanModeRegistryValue(lanModeStr, cfg.lanMode))
            cfg.lanMode = LanMode::Off;

        cfg.allowNamedPipes     = ReadRegDword(hKey, L"_allow_named_pipes") != 0;
        {
            DWORD desktopVal = 0;
            if (!TryReadRegDword(hKey, L"_allow_desktop", desktopVal)) {
                g_logger.Log(L"PROFILE_LOAD: _allow_desktop missing — rejecting profile");
                cfg.parseError = true;
            } else {
                cfg.allowDesktop = desktopVal != 0;
            }
        }
        {
            DWORD strictVal = 0;
            if (!TryReadRegDword(hKey, L"_strict", strictVal)) {
                g_logger.Log(L"PROFILE_LOAD: _strict missing — rejecting profile");
                cfg.parseError = true;
            } else {
                cfg.strict = strictVal != 0;
            }
        }
        cfg.allowClipboardRead  = ReadRegDword(hKey, L"_allow_clipboard_r") != 0;
        cfg.allowClipboardWrite = ReadRegDword(hKey, L"_allow_clipboard_w") != 0;
        {
            DWORD childVal = 0;
            if (!TryReadRegDword(hKey, L"_allow_child_procs", childVal)) {
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

        if (!ReadIndexedFolderEntries(hKey, L"_allow_count", L"_allow_", L"allow", cfg.folders))
            cfg.parseError = true;
        if (!ReadIndexedFolderEntries(hKey, L"_deny_count", L"_deny_", L"deny", cfg.denyFolders))
            cfg.parseError = true;
        if (!ReadIndexedStringValues(hKey, L"_reg_read_count", L"_reg_read_", L"registry read", cfg.registryRead))
            cfg.parseError = true;
        if (!ReadIndexedStringValues(hKey, L"_reg_write_count", L"_reg_write_", L"registry write", cfg.registryWrite))
            cfg.parseError = true;
        if (!ReadIndexedStringValues(hKey, L"_env_pass_count", L"_env_pass_", L"environment pass", cfg.envPass))
            cfg.parseError = true;

        return cfg;
    }

    struct ProfileCreateConfig {
        SandboxConfig config;
        std::wstring tomlText;
        bool isAppContainer = false;
        std::wstring typeStr;
        std::wstring integrityStr;
    };

    struct ProfileCreateIdentity {
        PSID sid = nullptr;
        std::wstring sidString;
        std::wstring containerName;
    };

    struct ProfileCreateGrantPhaseResult {
        bool ok = false;
        DWORD grantCount = 0;
    };

    struct ProfileCreateRollbackStatus {
        bool grantsRestored = true;
        bool containerRollbackOk = true;
        bool desktopCleanOk = true;
    };

    enum class ProfileCreateTransactionStatus {
        Ok,
        AlreadyExists,
        InternalError
    };

    inline void FreeProfileCreateSid(ProfileCreateIdentity& identity)
    {
        if (!identity.sid)
            return;
        FreeSid(identity.sid);
        identity.sid = nullptr;
    }

    inline void ClearTrackedAclGrantInventory()
    {
        AcquireSRWLockExclusive(&g_aclGrantsLock);
        g_aclGrants.clear();
        ReleaseSRWLockExclusive(&g_aclGrantsLock);
    }

    // AppContainer profile names (moniker "Sandy_<name>") are limited by
    // CreateAppContainerProfile to ~64 chars with a conservative character
    // set.  Reject unsupported names at validation time so the failure path
    // is a clean error message rather than a raw HRESULT from Windows.
    //
    // Allowed: alphanumeric, '.', '_', '-'.  First char must be alphanumeric.
    // Length: 1..58 chars (leaving 6 chars for the "Sandy_" prefix).
    inline bool ValidateProfileCreateName(const std::wstring& name)
    {
        if (name.empty()) {
            fprintf(stderr, "Error: profile name cannot be empty.\n");
            return false;
        }

        constexpr size_t kMaxProfileNameChars = 58;
        if (name.size() > kMaxProfileNameChars) {
            fprintf(stderr,
                    "Error: profile name exceeds %zu-character limit (got %zu).\n",
                    kMaxProfileNameChars, name.size());
            return false;
        }

        if (!iswalnum(name.front())) {
            fprintf(stderr, "Error: profile name must start with an alphanumeric character.\n");
            return false;
        }

        for (wchar_t c : name) {
            bool ok = iswalnum(c) || c == L'.' || c == L'_' || c == L'-';
            if (!ok) {
                fprintf(stderr,
                        "Error: profile name contains invalid characters (first: '%lc'). "
                        "Allowed: letters, digits, '.', '_', '-'.\n", c);
                return false;
            }
        }

        return true;
    }

    inline bool LoadProfileCreateConfig(const std::wstring& configPath,
                                        ProfileCreateConfig& createConfig)
    {
        createConfig.tomlText = ReadTomlFileText(configPath);
        if (createConfig.tomlText.empty()) {
            fprintf(stderr, "Error: cannot read config file: %ls\n", configPath.c_str());
            return false;
        }

        createConfig.config = ParseConfigFileText(createConfig.tomlText);
        if (createConfig.config.parseError) {
            fprintf(stderr, "Error: config contains unknown sections or keys.\n");
            return false;
        }

        createConfig.isAppContainer =
            IsAppContainerFamilyTokenMode(createConfig.config.tokenMode);
        createConfig.typeStr = TokenModeName(createConfig.config.tokenMode);
        createConfig.integrityStr =
            (createConfig.config.integrity == IntegrityLevel::Low) ? L"low" : L"medium";
        return true;
    }

    inline ProfileCreateTransactionStatus BeginProfileCreationTransaction(const std::wstring& name,
                                                                         HKEY& hKey)
    {
        std::wstring regKey = std::wstring(kProfilesParentKey) + L"\\" + name;
        DWORD disposition = 0;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr,
                            0, KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC, nullptr,
                            &hKey, &disposition) != ERROR_SUCCESS) {
            fprintf(stderr, "Error: cannot create registry key for profile.\n");
            return ProfileCreateTransactionStatus::InternalError;
        }

        if (disposition == REG_OPENED_EXISTING_KEY) {
            RegCloseKey(hKey);
            hKey = nullptr;
            fprintf(stderr,
                    "Error: profile '%ls' already exists or is being created. Use --delete-profile first.\n",
                    name.c_str());
            return ProfileCreateTransactionStatus::AlreadyExists;
        }

        HardenRegistryKeyAgainstRestricted(hKey);

        DWORD stagingFlag = 1;
        bool stageOk = true;
        stageOk &= TryWriteRegDword(hKey, L"_staging", stagingFlag);
        stageOk &= TryWriteRegDword(hKey, L"_staging_pid", GetCurrentProcessId());
        stageOk &= TryWriteRegQword(hKey, L"_staging_ctime", GetCurrentProcessCreationTime());
        if (stageOk)
            return ProfileCreateTransactionStatus::Ok;

        fprintf(stderr, "Error: cannot persist staging metadata for profile creation.\n");
        RegCloseKey(hKey);
        hKey = nullptr;
        DeleteProfileRegistryState(name, L"CREATE_PROFILE_STAGE");
        return ProfileCreateTransactionStatus::InternalError;
    }

    inline bool CreateProfileIdentity(const std::wstring& name,
                                      const ProfileCreateConfig& createConfig,
                                      ProfileCreateIdentity& identity)
    {
        if (createConfig.isAppContainer) {
            identity.containerName = std::wstring(kContainerPrefix) + name;
            PSID containerSid = nullptr;
            HRESULT hr = CreateAppContainerProfile(
                identity.containerName.c_str(), L"Sandy Sandbox Profile",
                L"Persistent sandbox profile",
                nullptr, 0, &containerSid);
            if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
                hr = DeriveAppContainerSidFromAppContainerName(
                    identity.containerName.c_str(), &containerSid);
            }
            if (FAILED(hr) || !containerSid) {
                fprintf(stderr, "Error: AppContainer profile creation failed (0x%08lX).\n",
                        (unsigned long)hr);
                return false;
            }
            identity.sid = containerSid;
        } else {
            identity.sid = AllocateInstanceSid();
            if (!identity.sid) {
                fprintf(stderr, "Error: SID allocation failed (error %lu).\n", GetLastError());
                return false;
            }
        }

        LPWSTR sidText = nullptr;
        if (ConvertSidToStringSidW(identity.sid, &sidText)) {
            identity.sidString = sidText;
            LocalFree(sidText);
            return true;
        }

        fprintf(stderr, "Error: SID conversion failed.\n");
        FreeProfileCreateSid(identity);
        if (createConfig.isAppContainer && !identity.containerName.empty()) {
            DeleteAppContainerProfile(identity.containerName.c_str());
            identity.containerName.clear();
        }
        return false;
    }

    inline void AbortUncommittedProfileCreation(const std::wstring& name,
                                                ProfileCreateIdentity& identity,
                                                const wchar_t* contextTag)
    {
        if (!identity.containerName.empty())
            DeleteAppContainerProfile(identity.containerName.c_str());
        FreeProfileCreateSid(identity);
        DeleteProfileRegistryState(name, contextTag);
    }

    inline bool PersistProfileCreateIdentity(HKEY hKey, const ProfileCreateIdentity& identity)
    {
        bool ok = TryWriteRegSz(hKey, L"_sid", identity.sidString);
        if (!identity.containerName.empty())
            ok &= TryWriteRegSz(hKey, L"_container", identity.containerName);

        if (!ok)
            fprintf(stderr, "Error: cannot persist staging metadata for profile creation.\n");
        return ok;
    }

    inline ProfileCreateGrantPhaseResult ApplyProfileCreateGrantPhase(
        HKEY hKey,
        const std::wstring& profileName,
        const ProfileCreateConfig& createConfig,
        const ProfileCreateIdentity& identity)
    {
        ProfileCreateGrantPhaseResult result;
        BeginStagingGrantCapture(hKey);

        printf("Applying grants for profile '%ls'...\n", profileName.c_str());

        bool grantOk = ApplyAccessPipeline(identity.sid, createConfig.config);
        if (!createConfig.isAppContainer && !GrantRegistryAccess(identity.sid, createConfig.config))
            grantOk = false;
        if (createConfig.isAppContainer &&
            createConfig.config.lanMode == LanMode::WithLocalhost &&
            !EnsureProfileLoopback(identity.containerName)) {
            g_logger.Log(L"CREATE_PROFILE: profile-owned loopback enable FAILED");
            grantOk = false;
        }
        if (!createConfig.isAppContainer &&
            createConfig.config.allowDesktop &&
            !GrantDesktopAccess(identity.sid)) {
            g_logger.Log(L"CREATE_PROFILE: profile-owned desktop grant FAILED");
            grantOk = false;
        }
        if (!GrantTrackingHealthy()) {
            g_logger.Log(L"CREATE_PROFILE: grant tracking persistence FAILED - aborting");
            grantOk = false;
        }

        if (!grantOk) {
            AbortStagingGrantCapture();
            return result;
        }

        result.ok = true;
        result.grantCount = EndStagingGrantCapture();
        return result;
    }

    inline ProfileCreateRollbackStatus RollbackProfileCreateHostState(
        HKEY hKey,
        const ProfileCreateConfig& createConfig,
        const ProfileCreateIdentity& identity,
        const wchar_t* contextTag)
    {
        ProfileCreateRollbackStatus status;
        if (!createConfig.isAppContainer &&
            createConfig.config.allowDesktop &&
            !identity.sidString.empty()) {
            status.desktopCleanOk = RevokeDesktopAccessForSid(identity.sidString);
        }

        status.grantsRestored = RestoreGrantsFromKey(hKey);
        if (createConfig.isAppContainer && !identity.containerName.empty()) {
            status.containerRollbackOk = TeardownPersistentProfileContainer(
                identity.containerName, contextTag);
        }

        ClearTrackedAclGrantInventory();
        return status;
    }

    inline void FinalizeProfileCreateRollback(const std::wstring& name,
                                              const ProfileCreateRollbackStatus& status,
                                              const wchar_t* contextTag)
    {
        if (!status.grantsRestored || !status.containerRollbackOk || !status.desktopCleanOk) {
            g_logger.LogFmt(L"%ls: rollback incomplete (acl=%s container=%s desktop=%s), preserving staging key for retry",
                            contextTag,
                            status.grantsRestored ? L"OK" : L"FAILED",
                            status.containerRollbackOk ? L"OK" : L"FAILED",
                            status.desktopCleanOk ? L"OK" : L"FAILED");
            fprintf(stderr, "  Staging key preserved for --cleanup retry.\n");
            return;
        }

        if (!DeleteProfileRegistryState(name, contextTag)) {
            g_logger.LogFmt(L"%ls: metadata delete failed, preserving staging key for retry",
                            contextTag);
            fprintf(stderr, "  Profile metadata preserved for --cleanup retry.\n");
        }
    }

    inline bool CommitCreatedProfile(HKEY hKey, const ProfileCreateConfig& createConfig)
    {
        bool commitOk = true;
        commitOk &= TryWriteRegSz(hKey, L"_type", createConfig.typeStr);
        commitOk &= TryWriteRegSz(hKey, L"_integrity", createConfig.integrityStr);
        commitOk &= TryWriteRegSz(hKey, L"_created", SandyLogger::Timestamp());
        commitOk &= TryWriteRegSz(hKey, L"_toml", createConfig.tomlText);
        commitOk &= WriteConfigToRegistry(hKey, createConfig.config);
        if (commitOk)
            commitOk &= (RegDeleteValueW(hKey, L"_staging") == ERROR_SUCCESS);

        if (!commitOk)
            fprintf(stderr, "Error: profile metadata commit failed. Rolling back.\n");
        return commitOk;
    }

    inline void PrintCreatedProfileSummary(const std::wstring& name,
                                           const ProfileCreateConfig& createConfig,
                                           const ProfileCreateIdentity& identity,
                                           DWORD grantCount)
    {
        printf("Profile '%ls' created successfully.\n", name.c_str());
        printf("  Type:      %ls\n", createConfig.typeStr.c_str());
        if (!createConfig.isAppContainer)
            printf("  Integrity: %ls\n", createConfig.integrityStr.c_str());
        printf("  SID:       %ls\n", identity.sidString.c_str());
        if (!identity.containerName.empty())
            printf("  Container: %ls\n", identity.containerName.c_str());
        printf("  Grants:    %lu path(s)\n", (unsigned long)grantCount);
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
        if (!ValidateProfileCreateName(name))
            return SandyExit::ConfigError;

        ProfileCreateConfig createConfig;
        if (!LoadProfileCreateConfig(configPath, createConfig))
            return SandyExit::ConfigError;

        HKEY hKey = nullptr;
        ProfileCreateTransactionStatus transactionStatus =
            BeginProfileCreationTransaction(name, hKey);
        if (transactionStatus == ProfileCreateTransactionStatus::AlreadyExists)
            return SandyExit::ConfigError;
        if (transactionStatus == ProfileCreateTransactionStatus::InternalError)
            return SandyExit::InternalError;

        ProfileCreateIdentity identity;
        if (!CreateProfileIdentity(name, createConfig, identity)) {
            RegCloseKey(hKey);
            DeleteProfileRegistryState(name, L"CREATE_PROFILE_STAGE");
            return SandyExit::SetupError;
        }

        if (!PersistProfileCreateIdentity(hKey, identity)) {
            RegCloseKey(hKey);
            AbortUncommittedProfileCreation(name, identity, L"CREATE_PROFILE_STAGE");
            return SandyExit::InternalError;
        }

        ProfileCreateGrantPhaseResult grantPhase =
            ApplyProfileCreateGrantPhase(hKey, name, createConfig, identity);
        if (!grantPhase.ok) {
            fprintf(stderr, "Error: grant application failed (may need Administrator). "
                    "Profile not committed.\n");
            ProfileCreateRollbackStatus rollbackStatus = RollbackProfileCreateHostState(
                hKey, createConfig, identity, L"CREATE_PROFILE_ROLLBACK");
            RegCloseKey(hKey);
            FinalizeProfileCreateRollback(name, rollbackStatus, L"CREATE_PROFILE_ROLLBACK");
            FreeProfileCreateSid(identity);
            return SandyExit::SetupError;
        }

        if (!CommitCreatedProfile(hKey, createConfig)) {
            ProfileCreateRollbackStatus rollbackStatus = RollbackProfileCreateHostState(
                hKey, createConfig, identity, L"CREATE_PROFILE_COMMIT_ROLLBACK");
            RegCloseKey(hKey);
            FinalizeProfileCreateRollback(name, rollbackStatus,
                                          L"CREATE_PROFILE_COMMIT_ROLLBACK");
            FreeProfileCreateSid(identity);
            return SandyExit::InternalError;
        }

        RegCloseKey(hKey);
        FreeProfileCreateSid(identity);
        ClearTrackedAclGrantInventory();
        PrintCreatedProfileSummary(name, createConfig, identity, grantPhase.grantCount);
        return 0;
    }

    // -----------------------------------------------------------------------
    // CleanStagingProfiles — remove profiles left in staging state.
    //
    // Scans Profiles\* for keys with _staging=1 (crash mid-create-profile).
    // For each, revokes ACLs from grant records, deletes the AC profile
    // if present, and removes the incomplete registry key.
    // -----------------------------------------------------------------------
    struct StagingRollbackStatus {
        bool grantsRestored = true;
        bool containerCleanOk = true;
        bool desktopCleanOk = true;
    };

    inline bool ShouldRollbackStagingProfile(const SavedProfileRegistrySummary& summary)
    {
        HKEY hSub = nullptr;
        if (!OpenSavedProfileRegistryKey(summary.name, KEY_READ, hSub))
            return false;

        bool shouldRollback = false;
        DWORD creatorPid = 0;
        ULONGLONG creatorCtime = 0;
        if (!ReadStagingPidAndCtime(hSub, creatorPid, creatorCtime)) {
            g_logger.LogFmt(L"STAGING_SKIP: profile '%s' staging identity incomplete (writer in progress)",
                            summary.name.c_str());
        } else if (IsProcessAlive(creatorPid, creatorCtime)) {
            g_logger.LogFmt(L"STAGING_SKIP: profile '%s' creator PID %lu still alive",
                            summary.name.c_str(), creatorPid);
        } else {
            shouldRollback = true;
        }

        RegCloseKey(hSub);
        return shouldRollback;
    }

    inline std::vector<std::wstring> CollectRollbackEligibleStagingProfiles()
    {
        std::vector<std::wstring> stagingNames;
        for (const auto& summary : EnumSavedProfileRegistrySummaries()) {
            if (!summary.staging)
                continue;
            if (ShouldRollbackStagingProfile(summary))
                stagingNames.push_back(summary.name);
        }
        return stagingNames;
    }

    inline bool CleanupStagingProfileDesktop(HKEY hKey, const std::wstring& name)
    {
        std::wstring profileType = ReadRegSz(hKey, L"_type");
        std::wstring profileSid = ReadRegSz(hKey, L"_sid");
        bool hadDesktop = (ReadRegDword(hKey, L"_allow_desktop") != 0);
        if (profileType != L"restricted" || !hadDesktop || profileSid.empty())
            return true;

        bool ok = RevokeDesktopAccessForSid(profileSid);
        if (!ok) {
            g_logger.LogFmt(L"STAGING_CLEANUP: desktop revocation FAILED for profile '%s'",
                            name.c_str());
        }
        return ok;
    }

    inline bool CleanupStagingProfileContainer(HKEY hKey)
    {
        std::wstring containerName = ReadRegSz(hKey, L"_container");
        if (containerName.empty())
            return true;
        return TeardownPersistentProfileContainer(containerName, L"STAGING_CLEANUP");
    }

    inline bool RollbackStagingProfileHostState(HKEY hKey,
                                                const std::wstring& name,
                                                StagingRollbackStatus& status)
    {
        status.grantsRestored = RestoreGrantsFromKey(hKey);
        status.desktopCleanOk = CleanupStagingProfileDesktop(hKey, name);
        status.containerCleanOk = CleanupStagingProfileContainer(hKey);
        return status.grantsRestored && status.containerCleanOk && status.desktopCleanOk;
    }

    inline void LogIncompleteStagingRollback(const std::wstring& name,
                                             const StagingRollbackStatus& status)
    {
        g_logger.LogFmt(L"STAGING_CLEANUP: profile '%s' rollback incomplete (acl=%s container=%s desktop=%s), preserving metadata",
                        name.c_str(),
                        status.grantsRestored ? L"OK" : L"FAILED",
                        status.containerCleanOk ? L"OK" : L"FAILED",
                        status.desktopCleanOk ? L"OK" : L"FAILED");
        printf("  [STAGING] Profile '%ls' rollback incomplete — metadata preserved for retry.\n",
               name.c_str());
    }

    inline bool FinalizeStagingRollbackMetadata(const std::wstring& name)
    {
        if (!DeleteProfileRegistryState(name, L"STAGING_CLEANUP")) {
            g_logger.LogFmt(L"STAGING_CLEANUP: profile '%s' metadata delete failed, preserving metadata",
                            name.c_str());
            printf("  [STAGING] Profile '%ls' metadata delete failed — preserved for retry.\n",
                   name.c_str());
            return false;
        }

        g_logger.LogFmt(L"STAGING_CLEANUP: profile '%s' rolled back", name.c_str());
        printf("  [STAGING] Profile '%ls' rolled back.\n", name.c_str());
        return true;
    }

    inline void RollbackStagingProfile(const std::wstring& name)
    {
        g_logger.LogFmt(L"STAGING_CLEANUP: profile '%s' left in staging — rolling back", name.c_str());
        printf("  [STAGING] Rolling back incomplete profile '%ls'...\n", name.c_str());

        HKEY hKey = nullptr;
        if (OpenSavedProfileRegistryKey(name, KEY_READ, hKey)) {
            StagingRollbackStatus status;
            bool rollbackComplete = RollbackStagingProfileHostState(hKey, name, status);
            RegCloseKey(hKey);

            if (!rollbackComplete) {
                LogIncompleteStagingRollback(name, status);
                return;
            }
        }

        FinalizeStagingRollbackMetadata(name);
    }

    inline void CleanStagingProfiles()
    {
        for (const auto& name : CollectRollbackEligibleStagingProfiles())
            RollbackStagingProfile(name);
    }

    // -----------------------------------------------------------------------
    // LoadSavedProfile — read a named profile from registry.
    // Distinguishes missing profiles from present-but-invalid ones so callers
    // can report corruption honestly instead of collapsing both into "not found".
    // -----------------------------------------------------------------------
    inline SavedProfileLoadStatus LoadSavedProfile(const std::wstring& name, SavedProfile& out)
    {
        HKEY hKey = nullptr;
        if (!OpenSavedProfileRegistryKey(name, KEY_READ, hKey))
            return SavedProfileLoadStatus::NotFound;

        SavedProfileRegistrySummary summary;
        ReadSavedProfileRegistrySummary(hKey, name, summary);

        // P1c: Reject profiles still in staging state — they were never
        // fully committed and may contain incomplete/corrupt config.
        if (summary.staging) {
            g_logger.LogFmt(L"PROFILE_LOAD: profile '%s' is still in staging — rejecting",
                            name.c_str());
            RegCloseKey(hKey);
            return SavedProfileLoadStatus::Invalid;
        }

        out.name = name;
        out.type = summary.type;
        out.integrity = ReadRegSz(hKey, L"_integrity");
        out.sidString = summary.sidString;
        out.containerName = summary.containerName;
        out.created = summary.created;
        out.tomlText = ReadRegSz(hKey, L"_toml");

        // Read config from discrete registry values (no TOML parsing)
        out.config = ReadConfigFromRegistry(hKey);
        RegCloseKey(hKey);
        // Reject profiles with missing mandatory fields or corrupt config
        if (out.sidString.empty() || out.type.empty() || out.config.parseError)
            return SavedProfileLoadStatus::Invalid;
        if (_wcsicmp(out.type.c_str(), TokenModeName(out.config.tokenMode)) != 0) {
            g_logger.LogFmt(L"PROFILE_LOAD: _type ('%s') mismatches _token_mode ('%s') — rejecting profile",
                            out.type.c_str(), TokenModeName(out.config.tokenMode));
            return SavedProfileLoadStatus::Invalid;
        }
        return SavedProfileLoadStatus::Ok;
    }

    // -----------------------------------------------------------------------
    // DeleteSavedProfile — remove a profile: revoke ACLs, delete container,
    // delete registry key.
    // -----------------------------------------------------------------------
    inline int HandleDeleteProfile(const std::wstring& name)
    {
        HKEY hKey = nullptr;
        if (!OpenSavedProfileRegistryKey(name, KEY_READ, hKey)) {
            fprintf(stderr, "Error: profile '%ls' not found.\n", name.c_str());
            return SandyExit::ConfigError;
        }

        SavedProfileRegistrySummary summary;
        ReadSavedProfileRegistrySummary(hKey, name, summary);
        const std::wstring& containerName = summary.containerName;

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
        const std::wstring& profileType = summary.type;
        const std::wstring& profileSid = summary.sidString;
        bool hadDesktop = summary.allowDesktop;
        bool hadLoopback = (summary.lanMode == L"with_localhost");

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
        bool invalid = false;
    };

    inline std::vector<ProfileSummary> EnumSavedProfiles()
    {
        std::vector<ProfileSummary> result;
        for (const auto& summary : EnumSavedProfileRegistrySummaries()) {
            ProfileSummary ps;
            ps.name = summary.name;
            ps.created = summary.created;
            ps.type = summary.type.empty() ? L"unknown" : summary.type;

            // Skip live staging entries. Non-staging keys with missing
            // metadata are surfaced as invalid instead of disappearing.
            if (summary.staging)
                continue;

            SavedProfile prof;
            SavedProfileLoadStatus loadStatus = LoadSavedProfile(summary.name, prof);
            if (loadStatus == SavedProfileLoadStatus::NotFound)
                continue;
            if (loadStatus == SavedProfileLoadStatus::Ok)
                ps.type = TokenModeName(prof.config.tokenMode);
            else
                ps.invalid = true;

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
        SavedProfileLoadStatus loadStatus = LoadSavedProfile(name, prof);
        if (loadStatus == SavedProfileLoadStatus::NotFound) {
            fprintf(stderr, "Error: profile '%ls' not found.\n", name.c_str());
            return SandyExit::ConfigError;
        }
        if (loadStatus == SavedProfileLoadStatus::Invalid) {
            fprintf(stderr, "Error: profile '%ls' is corrupted or incomplete. Recreate it or delete it.\n",
                    name.c_str());
            return SandyExit::ConfigError;
        }

        printf("=== Profile: %ls ===\n", prof.name.c_str());
        printf("Created:     %ls\n", prof.created.c_str());
        printf("Type:        %ls\n", TokenModeName(prof.config.tokenMode));
        if (IsRestrictedTokenMode(prof.config.tokenMode))
            printf("Integrity:   %ls\n", prof.integrity.c_str());
        printf("SID:         %ls\n", prof.sidString.c_str());
        if (!prof.containerName.empty())
            printf("Container:   %ls\n", prof.containerName.c_str());

        if (!prof.config.parseError) {
            printf("\nConfiguration:\n");
            PrintResolvedConfig(prof.config);
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

        BeginRunSession(exePath, L"profile:" + prof.name, prof.name);
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
