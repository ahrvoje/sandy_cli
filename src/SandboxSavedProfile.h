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
        std::wstring type;         // "appcontainer" or "restricted"
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

        int wideLen = MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), (int)bytesRead, nullptr, 0);
        std::wstring content(wideLen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), (int)bytesRead, &content[0], wideLen);
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
    //   _token_mode         REG_SZ   "appcontainer" | "restricted"
    //   _cfg_integrity      REG_SZ   "low" | "medium"
    //   _workdir            REG_SZ   path (may be empty)
    //   _allow_network      REG_DWORD  0 | 1
    //   _allow_localhost     REG_DWORD  0 | 1
    //   _allow_lan           REG_DWORD  0 | 1
    //   _allow_system_dirs   REG_DWORD  0 | 1
    //   _allow_named_pipes   REG_DWORD  0 | 1
    //   _allow_clipboard_r   REG_DWORD  0 | 1
    //   _allow_clipboard_w   REG_DWORD  0 | 1
    //   _allow_child_procs   REG_DWORD  0 | 1
    //   _stdin_mode          REG_SZ   "NUL" | "" | path
    //   _env_inherit         REG_DWORD  0 | 1
    //   _timeout             REG_DWORD  seconds (0 = none)
    //   _memory_limit_mb     REG_DWORD  MB (0 = none)
    //   _max_processes       REG_DWORD  count (0 = none)
    //   _allow_count         REG_DWORD  number of allow entries
    //   _allow_0 .. _allow_N REG_SZ   "access|path"
    //   _deny_count          REG_DWORD  number of deny entries
    //   _deny_0  .. _deny_N  REG_SZ   "access|path"
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
            (cfg.tokenMode == TokenMode::AppContainer) ? L"appcontainer" : L"restricted");
        ok &= TryWriteRegSz(hKey, L"_cfg_integrity",
            (cfg.integrity == IntegrityLevel::Low) ? L"low" : L"medium");

        // --- Strings ---
        ok &= TryWriteRegSz(hKey, L"_workdir", cfg.workdir);
        ok &= TryWriteRegSz(hKey, L"_stdin_mode", cfg.stdinMode.empty() ? L"INHERIT" : cfg.stdinMode);

        // --- Booleans (REG_DWORD 0/1) ---
        ok &= TryWriteRegDword(hKey, L"_allow_network",      cfg.allowNetwork     ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_allow_localhost",     cfg.allowLocalhost   ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_allow_lan",           cfg.allowLan         ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_allow_system_dirs",   cfg.allowSystemDirs  ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_allow_named_pipes",   cfg.allowNamedPipes  ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_allow_clipboard_r",   cfg.allowClipboardRead  ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_allow_clipboard_w",   cfg.allowClipboardWrite ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_allow_child_procs",   cfg.allowChildProcesses ? 1 : 0);
        ok &= TryWriteRegDword(hKey, L"_env_inherit",         cfg.envInherit       ? 1 : 0);

        // --- Integers ---
        ok &= TryWriteRegDword(hKey, L"_timeout",         cfg.timeoutSeconds);
        ok &= TryWriteRegDword(hKey, L"_memory_limit_mb", static_cast<DWORD>(cfg.memoryLimitMB));
        ok &= TryWriteRegDword(hKey, L"_max_processes",   cfg.maxProcesses);

        // --- Allow folders: _allow_count + _allow_0, _allow_1, ... ---
        ok &= TryWriteRegDword(hKey, L"_allow_count", static_cast<DWORD>(cfg.folders.size()));
        for (DWORD i = 0; i < cfg.folders.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_allow_%lu", i);
            ok &= TryWriteRegSz(hKey, name,
                std::wstring(AccessLevelName(cfg.folders[i].access)) + L"|" + cfg.folders[i].path);
        }

        // --- Deny folders: _deny_count + _deny_0, _deny_1, ... ---
        ok &= TryWriteRegDword(hKey, L"_deny_count", static_cast<DWORD>(cfg.denyFolders.size()));
        for (DWORD i = 0; i < cfg.denyFolders.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_deny_%lu", i);
            ok &= TryWriteRegSz(hKey, name,
                std::wstring(AccessLevelName(cfg.denyFolders[i].access)) + L"|" + cfg.denyFolders[i].path);
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
        std::wstring mode = ReadRegSz(hKey, L"_token_mode");
        cfg.tokenMode = (mode == L"restricted") ? TokenMode::Restricted : TokenMode::AppContainer;

        std::wstring integ = ReadRegSz(hKey, L"_cfg_integrity");
        cfg.integrity = (integ == L"medium") ? IntegrityLevel::Medium : IntegrityLevel::Low;

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
        cfg.allowNetwork        = ReadRegDword(hKey, L"_allow_network")    != 0;
        cfg.allowLocalhost      = ReadRegDword(hKey, L"_allow_localhost")  != 0;
        cfg.allowLan            = ReadRegDword(hKey, L"_allow_lan")        != 0;
        cfg.allowSystemDirs     = ReadRegDword(hKey, L"_allow_system_dirs") != 0;
        cfg.allowNamedPipes     = ReadRegDword(hKey, L"_allow_named_pipes") != 0;
        cfg.allowClipboardRead  = ReadRegDword(hKey, L"_allow_clipboard_r") != 0;
        cfg.allowClipboardWrite = ReadRegDword(hKey, L"_allow_clipboard_w") != 0;
        cfg.allowChildProcesses = ReadRegDword(hKey, L"_allow_child_procs") != 0;
        cfg.envInherit          = ReadRegDword(hKey, L"_env_inherit")       != 0;

        // --- Integers ---
        cfg.timeoutSeconds = ReadRegDword(hKey, L"_timeout");
        cfg.memoryLimitMB  = ReadRegDword(hKey, L"_memory_limit_mb");
        cfg.maxProcesses   = ReadRegDword(hKey, L"_max_processes");

        // --- Allow folders ---
        DWORD allowCount = ReadRegDword(hKey, L"_allow_count");
        for (DWORD i = 0; i < allowCount; i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_allow_%lu", i);
            std::wstring val = ReadRegSz(hKey, name);
            // Format: "access|path"
            size_t sep = val.find(L'|');
            if (sep != std::wstring::npos) {
                FolderEntry entry;
                entry.access = ParseAccessTag(val.substr(0, sep));
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
                entry.access = ParseAccessTag(val.substr(0, sep));
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
        if (ProfileExists(name)) {
            fprintf(stderr, "Error: profile '%ls' already exists. Use --delete-profile first.\n",
                    name.c_str());
            return SandyExit::ConfigError;
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

        bool isAppContainer = (config.tokenMode == TokenMode::AppContainer);
        std::wstring sidString;
        std::wstring containerName;
        std::wstring typeStr = isAppContainer ? L"appcontainer" : L"restricted";
        std::wstring integrityStr = (config.integrity == IntegrityLevel::Low) ? L"low" : L"medium";

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
                return SandyExit::SetupError;
            }
            pSid = pContainerSid;
        } else {
            // Restricted Token: generate unique SID from GUID
            pSid = AllocateInstanceSid();
            if (!pSid) {
                fprintf(stderr, "Error: SID allocation failed (error %lu).\n", GetLastError());
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
            return SandyExit::SetupError;
        }

        // --- Stage 1: Create profile registry key FIRST ---
        // Validate we can commit metadata before modifying any filesystem ACLs.
        // If this fails, no grants have been applied — nothing to roll back.
        std::wstring regKey = std::wstring(kProfilesParentKey) + L"\\" + name;
        HKEY hKey = nullptr;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr,
                0, KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
            fprintf(stderr, "Error: cannot create registry key for profile.\n");
            if (isAppContainer)
                DeleteAppContainerProfile(containerName.c_str());
            FreeSid(pSid);
            return SandyExit::InternalError;
        }

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

        // Persist SID now so cleanup can find it if we crash during grant application
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
        if (isAppContainer && config.allowLocalhost) {
            if (!EnsureProfileLoopback(containerName)) {
                g_logger.Log(L"CREATE_PROFILE: profile-owned loopback enable FAILED");
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

        DWORD numKeys = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &numKeys,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        std::vector<std::wstring> stagingNames;
        for (DWORD i = 0; i < numKeys; i++) {
            wchar_t nm[256]; DWORD nl = 256;
            if (RegEnumKeyExW(hParent, i, nm, &nl, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;

            HKEY hSub = nullptr;
            std::wstring subKey = std::wstring(kProfilesParentKey) + L"\\" + nm;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0,
                              KEY_READ, &hSub) != ERROR_SUCCESS)
                continue;

            DWORD staging = 0, sz = sizeof(staging);
            if (RegQueryValueExW(hSub, L"_staging", nullptr, nullptr,
                                 reinterpret_cast<BYTE*>(&staging), &sz) == ERROR_SUCCESS
                && staging == 1) {
                // F1/R8: Check if the creator is still alive — skip live staging
                DWORD creatorPid = 0; ULONGLONG creatorCtime = 0;
                DWORD pidSz = sizeof(creatorPid);
                RegQueryValueExW(hSub, L"_staging_pid", nullptr, nullptr,
                                 reinterpret_cast<BYTE*>(&creatorPid), &pidSz);
                DWORD ctSz = sizeof(creatorCtime);
                RegQueryValueExW(hSub, L"_staging_ctime", nullptr, nullptr,
                                 reinterpret_cast<BYTE*>(&creatorCtime), &ctSz);
                if (creatorPid != 0 && IsProcessAlive(creatorPid, creatorCtime)) {
                    g_logger.LogFmt(L"STAGING_SKIP: profile '%s' creator PID %lu still alive",
                                    nm, creatorPid);
                } else {
                    stagingNames.push_back(nm);
                }
            }
            RegCloseKey(hSub);
        }
        RegCloseKey(hParent);

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

                // Delete AppContainer profile if present
                std::wstring containerName = ReadRegSz(hKey, L"_container");
                if (!containerName.empty()) {
                    containerCleanOk = TeardownPersistentProfileContainer(
                        containerName, L"STAGING_CLEANUP");
                }
                RegCloseKey(hKey);

                // Preserve metadata for retry until durable host state
                // has been fully reverted.
                if (!grantsRestored || !containerCleanOk) {
                    g_logger.LogFmt(L"STAGING_CLEANUP: profile '%s' rollback incomplete (acl=%s container=%s), preserving metadata",
                                    name.c_str(),
                                    grantsRestored ? L"OK" : L"FAILED",
                                    containerCleanOk ? L"OK" : L"FAILED");
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
        return !out.sidString.empty();
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

        // Revoke all grant ACLs
        printf("Revoking grants for profile '%ls'...\n", name.c_str());
        bool grantsRestored = RestoreGrantsFromKey(hKey);
        RegCloseKey(hKey);
        if (!grantsRestored) {
            fprintf(stderr, "Warning: ACL rollback failed for profile '%ls'.\n"
                    "Profile metadata preserved so --delete-profile can be retried safely.\n",
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

        DWORD numKeys = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &numKeys,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD i = 0; i < numKeys; i++) {
            wchar_t nm[256]; DWORD nl = 256;
            if (RegEnumKeyExW(hParent, i, nm, &nl, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;

            ProfileSummary ps;
            ps.name = nm;

            // Read creation date and type from subkey
            std::wstring subKey = std::wstring(kProfilesParentKey) + L"\\" + nm;
            HKEY hSub = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0,
                              KEY_READ, &hSub) == ERROR_SUCCESS) {
                ps.created = ReadRegSz(hSub, L"_created");
                ps.type = ReadRegSz(hSub, L"_type");
                RegCloseKey(hSub);
            }
            result.push_back(std::move(ps));
        }
        RegCloseKey(hParent);
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
            if (prof.type == L"appcontainer") {
                printf("    system_dirs     = %s\n", prof.config.allowSystemDirs ? "true" : "false");
                printf("    network         = %s\n", prof.config.allowNetwork ? "true" : "false");
                printf("    localhost        = %s\n", prof.config.allowLocalhost ? "true" : "false");
                printf("    lan             = %s\n", prof.config.allowLan ? "true" : "false");
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
                DeleteCleanupTask(g_instanceId);
                return SandyExit::SetupError;
            }
            pSid = pGrantSid;

            hRestrictedToken = CreateRestrictedSandboxToken(config.integrity, pGrantSid);
            if (!hRestrictedToken) {
                g_logger.LogFmt(L"ERROR: restricted token creation failed (error %lu)",
                                GetLastError());
                LocalFree(pGrantSid);
                DeleteCleanupTask(g_instanceId);
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
            DeleteCleanupTask(g_instanceId);
            ResetEmergencyCleanupState();
            fprintf(stderr, "Error: failed to persist live profile state for '%ls'.\n",
                    prof.name.c_str());
            return SandyExit::SetupError;
        }

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
