// =========================================================================
// SandboxDynamic.h — Dynamic config reload helpers
//
// Helper functions for live config reloading: immutable setting warnings,
// grant delta computation, file timestamp queries, and the revoke-reset
// helper for targeted grant removal.
//
// Does NOT depend on Sandbox.h — included by it.
// =========================================================================
#pragma once

#include "SandboxConfig.h"
#include "SandboxGrants.h"
#include <algorithm>

namespace Sandbox {

    // -----------------------------------------------------------------------
    // DynamicContext — state passed to the watcher thread
    // -----------------------------------------------------------------------
    struct DynamicContext {
        PSID              pSid;
        std::wstring      sidString;       // SID as string (for RemoveSidFromDacl)
        std::wstring      configPath;
        HANDLE            hProcess;
        bool              isAppContainer;
        SandboxConfig     currentConfig;   // current active config
        HANDLE            hStopEvent;      // signaled when child exits
    };

    // -----------------------------------------------------------------------
    // WarnImmutableChanges — warn if non-grant settings changed
    // -----------------------------------------------------------------------
    inline void WarnImmutableChanges(const SandboxConfig& oldCfg, const SandboxConfig& newCfg)
    {
        if (oldCfg.tokenMode != newCfg.tokenMode)
            g_logger.Log(L"DYNAMIC: WARNING — 'token' change ignored (immutable after launch)");
        if (oldCfg.integrity != newCfg.integrity)
            g_logger.Log(L"DYNAMIC: WARNING — 'integrity' change ignored (immutable after launch)");
        if (oldCfg.workdir != newCfg.workdir)
            g_logger.Log(L"DYNAMIC: WARNING — 'workdir' change ignored (immutable after launch)");
        if (oldCfg.allowNetwork != newCfg.allowNetwork)
            g_logger.Log(L"DYNAMIC: WARNING — 'network' change ignored (immutable after launch)");
        if (oldCfg.allowLocalhost != newCfg.allowLocalhost)
            g_logger.Log(L"DYNAMIC: WARNING — 'localhost' change ignored (immutable after launch)");
        if (oldCfg.allowLan != newCfg.allowLan)
            g_logger.Log(L"DYNAMIC: WARNING — 'lan' change ignored (immutable after launch)");
        if (oldCfg.allowNamedPipes != newCfg.allowNamedPipes)
            g_logger.Log(L"DYNAMIC: WARNING — 'named_pipes' change ignored (immutable after launch)");
        if (oldCfg.allowClipboardRead != newCfg.allowClipboardRead)
            g_logger.Log(L"DYNAMIC: WARNING — 'clipboard_read' change ignored (immutable after launch)");
        if (oldCfg.allowClipboardWrite != newCfg.allowClipboardWrite)
            g_logger.Log(L"DYNAMIC: WARNING — 'clipboard_write' change ignored (immutable after launch)");
        if (oldCfg.allowChildProcesses != newCfg.allowChildProcesses)
            g_logger.Log(L"DYNAMIC: WARNING — 'child_processes' change ignored (immutable after launch)");
        if (oldCfg.timeoutSeconds != newCfg.timeoutSeconds)
            g_logger.Log(L"DYNAMIC: WARNING — 'timeout' change ignored (immutable after launch)");
        if (oldCfg.memoryLimitMB != newCfg.memoryLimitMB)
            g_logger.Log(L"DYNAMIC: WARNING — 'memory' change ignored (immutable after launch)");
        if (oldCfg.maxProcesses != newCfg.maxProcesses)
            g_logger.Log(L"DYNAMIC: WARNING — 'processes' change ignored (immutable after launch)");
        if (oldCfg.stdinMode != newCfg.stdinMode)
            g_logger.Log(L"DYNAMIC: WARNING — 'stdin' change ignored (immutable after launch)");
        if (oldCfg.envInherit != newCfg.envInherit)
            g_logger.Log(L"DYNAMIC: WARNING — 'environment.inherit' change ignored (immutable after launch)");
    }

    // -----------------------------------------------------------------------
    // GrantKey — unique identity for a single grant entry.
    // Comparison key: lowercase(path) + accessLevel + isDeny
    // -----------------------------------------------------------------------
    struct GrantKey {
        std::wstring path;          // original-case path for applying operations
        std::wstring pathLower;     // lowercase for comparison
        AccessLevel  access;
        bool         isDeny;
        GrantScope   scope = GrantScope::Deep;

        bool operator==(const GrantKey& o) const {
            return pathLower == o.pathLower && access == o.access && isDeny == o.isDeny && scope == o.scope;
        }
        bool operator<(const GrantKey& o) const {
            if (pathLower != o.pathLower) return pathLower < o.pathLower;
            if (access != o.access) return access < o.access;
            if (isDeny != o.isDeny) return isDeny < o.isDeny;
            return scope < o.scope;
        }
    };

    inline std::wstring ToLower(const std::wstring& s) {
        std::wstring r = s;
        for (auto& c : r) c = towlower(c);
        return r;
    }

    // -----------------------------------------------------------------------
    // BuildGrantKeySet — extract all grant entries from a config as a set
    // -----------------------------------------------------------------------
    inline std::set<GrantKey> BuildGrantKeySet(const SandboxConfig& config)
    {
        std::set<GrantKey> keys;
        for (const auto& e : config.folders) {
            if (e.path.empty()) continue;
            std::wstring normalizedPath = NormalizeFsPath(e.path);
            keys.insert({ normalizedPath, ToLower(normalizedPath), e.access, false, e.scope });
        }
        for (const auto& e : config.denyFolders) {
            if (e.path.empty()) continue;
            std::wstring normalizedPath = NormalizeFsPath(e.path);
            keys.insert({ normalizedPath, ToLower(normalizedPath), e.access, true, e.scope });
        }
        return keys;
    }

    // -----------------------------------------------------------------------
    // GrantKey for registry entries
    // -----------------------------------------------------------------------
    struct RegGrantKey {
        std::wstring path;
        std::wstring pathLower;
        AccessLevel  access;       // Read or Write

        bool operator==(const RegGrantKey& o) const {
            return pathLower == o.pathLower && access == o.access;
        }
        bool operator<(const RegGrantKey& o) const {
            if (pathLower != o.pathLower) return pathLower < o.pathLower;
            return access < o.access;
        }
    };

    inline std::set<RegGrantKey> BuildRegKeySet(const SandboxConfig& config)
    {
        std::set<RegGrantKey> keys;
        for (const auto& k : config.registryRead)
            keys.insert({ k, ToLower(k), AccessLevel::Read });
        for (const auto& k : config.registryWrite)
            keys.insert({ k, ToLower(k), AccessLevel::Write });
        return keys;
    }

    // -----------------------------------------------------------------------
    // GetFileLastWriteTime — get the last write time of a file
    // -----------------------------------------------------------------------
    inline ULONGLONG GetFileLastWriteTime(const std::wstring& path)
    {
        WIN32_FILE_ATTRIBUTE_DATA data{};
        if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
            return 0;
        ULARGE_INTEGER li;
        li.LowPart = data.ftLastWriteTime.dwLowDateTime;
        li.HighPart = data.ftLastWriteTime.dwHighDateTime;
        return li.QuadPart;
    }

    // -----------------------------------------------------------------------
    // RevokePathEntries — revoke all ACEs we currently own on one path.
    //
    // Sandy's cleanup primitive is path+SID scoped: once we decide a path
    // must be rebuilt, we remove the SID-owned ACEs from that path and let
    // the caller re-apply the surviving same-path config entries in the
    // correct deny/allow order.
    //
    // Registry persistence is not updated here — the in-memory list remains
    // the source of truth for final RevokeAllGrants(), and --cleanup handles
    // stale recovery for any interrupted reload.
    // -----------------------------------------------------------------------
    inline bool RevokePathEntries(const std::wstring& path, const std::wstring& sidStr,
                                  SE_OBJECT_TYPE objType = SE_FILE_OBJECT,
                                  bool hadDeny = false,
                                  bool peekOnly = false)
    {
        std::wstring normalizedPath = (objType == SE_FILE_OBJECT)
            ? NormalizeFsPath(path)
            : path;

        // Remove ACEs from the object DACL
        int removed = RemoveSidFromDacl(normalizedPath, sidStr, objType, hadDeny, peekOnly);
        bool targetExists = false;
        if (objType == SE_FILE_OBJECT) {
            DWORD attrs = GetFileAttributesW(normalizedPath.c_str());
            targetExists = (attrs != INVALID_FILE_ATTRIBUTES);
        } else if (objType == SE_REGISTRY_KEY) {
            HKEY root = HKEY_CURRENT_USER;
            std::wstring subPath = normalizedPath;
            if (subPath.compare(0, 13, L"CURRENT_USER\\") == 0) {
                subPath = subPath.substr(13);
            } else if (subPath.compare(0, 8, L"MACHINE\\") == 0) {
                root = HKEY_LOCAL_MACHINE;
                subPath = subPath.substr(8);
            }
            HKEY hTest = nullptr;
            if (RegOpenKeyExW(root, subPath.c_str(), 0, KEY_READ, &hTest) == ERROR_SUCCESS) {
                targetExists = true;
                RegCloseKey(hTest);
            }
        }
        g_logger.LogFmt(L"DYNAMIC_REVOKE: %s -> %d ACEs removed",
                        normalizedPath.c_str(), removed);
        if (removed == 0 && targetExists) {
            g_logger.LogFmt(L"DYNAMIC_REVOKE: %s FAILED (target still exists, no ACEs removed)",
                            normalizedPath.c_str());
            return false;
        }

        AcquireSRWLockExclusive(&g_aclGrantsLock);
        for (auto it = g_aclGrants.begin(); it != g_aclGrants.end(); ) {
            if (_wcsicmp(it->path.c_str(), normalizedPath.c_str()) == 0 &&
                it->objType == objType) {
                it = g_aclGrants.erase(it);
            } else {
                ++it;
            }
        }
        ReleaseSRWLockExclusive(&g_aclGrantsLock);
        return true;
    }

} // namespace Sandbox
