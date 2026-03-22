#pragma once
// =========================================================================
// SandboxRecoveryLedger.h — Shared run recovery-ledger ownership helpers
//
// Centralizes the per-run registry ledger layout used by Sandy's crash
// recovery. Grants, transient-container retry metadata, and cleanup-task
// ownership all derive from these helpers so the ownership model stays
// consistent across normal exit, stale recovery, and emergency cleanup.
// =========================================================================

#include "SandboxTypes.h"
#include <vector>

namespace Sandbox {

    // Per-instance UUID — set once at startup.
    inline std::wstring g_instanceId;

    // Registry parents for run-owned recovery ledgers.
    constexpr const wchar_t* kGrantsParentKey = L"Software\\Sandy\\Grants";
    constexpr const wchar_t* kTransientContainersParentKey = L"Software\\Sandy\\TransientContainers";

    enum class RecoveryLedgerKind {
        Grants,
        TransientContainerRetry,
    };

    enum class RecoveryLedgerLiveness {
        Active,
        Stale,
        Incomplete,
    };

    inline bool RecoveryLedgerBlocksCleanup(RecoveryLedgerLiveness liveness)
    {
        return liveness != RecoveryLedgerLiveness::Stale;
    }

    inline const char* RecoveryLedgerLivenessJsonName(RecoveryLedgerLiveness liveness)
    {
        switch (liveness) {
        case RecoveryLedgerLiveness::Active:     return "active";
        case RecoveryLedgerLiveness::Stale:      return "stale";
        case RecoveryLedgerLiveness::Incomplete: return "incomplete";
        }
        return "incomplete";
    }

    inline const char* RecoveryLedgerLivenessTextLabel(RecoveryLedgerLiveness liveness)
    {
        switch (liveness) {
        case RecoveryLedgerLiveness::Active:     return "ACTIVE";
        case RecoveryLedgerLiveness::Stale:      return "STALE ";
        case RecoveryLedgerLiveness::Incomplete: return "INCOMPLETE";
        }
        return "INCOMPLETE";
    }

    struct RecoveryLedgerPresence {
        bool grants = false;
        bool transientContainerRetry = false;

        bool Any() const {
            return grants || transientContainerRetry;
        }
    };

    inline std::wstring GetRecoveryLedgerKey(RecoveryLedgerKind kind,
                                             const std::wstring& instanceId)
    {
        const wchar_t* parent = (kind == RecoveryLedgerKind::Grants)
            ? kGrantsParentKey
            : kTransientContainersParentKey;
        return std::wstring(parent) + L"\\" + instanceId;
    }

    inline const wchar_t* GetRecoveryLedgerParentKey(RecoveryLedgerKind kind)
    {
        return (kind == RecoveryLedgerKind::Grants)
            ? kGrantsParentKey
            : kTransientContainersParentKey;
    }

    inline bool OpenRecoveryLedgerKey(RecoveryLedgerKind kind,
                                      const std::wstring& instanceId,
                                      REGSAM samDesired,
                                      HKEY& hKey)
    {
        if (instanceId.empty()) return false;
        return RegOpenKeyExW(HKEY_CURRENT_USER,
                             GetRecoveryLedgerKey(kind, instanceId).c_str(),
                             0, samDesired, &hKey) == ERROR_SUCCESS;
    }

    inline std::vector<std::wstring> EnumRecoveryLedgerInstanceIds(RecoveryLedgerKind kind)
    {
        std::vector<std::wstring> instanceIds;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, GetRecoveryLedgerParentKey(kind), 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return instanceIds;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[128];
            DWORD nameLen = 128;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                              nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                instanceIds.push_back(name);
        }
        RegCloseKey(hParent);
        return instanceIds;
    }

    inline std::wstring GetGrantsRegKey()
    {
        return GetRecoveryLedgerKey(RecoveryLedgerKind::Grants, g_instanceId);
    }

    inline std::wstring GetTransientContainerRegKey(const std::wstring& instanceId)
    {
        return GetRecoveryLedgerKey(RecoveryLedgerKind::TransientContainerRetry, instanceId);
    }

    inline bool RecoveryLedgerExists(RecoveryLedgerKind kind,
                                     const std::wstring& instanceId)
    {
        HKEY hKey = nullptr;
        bool exists = OpenRecoveryLedgerKey(kind, instanceId, KEY_READ, hKey);
        if (exists)
            RegCloseKey(hKey);
        return exists;
    }

    inline RecoveryLedgerPresence QueryRecoveryLedgerPresence(const std::wstring& instanceId)
    {
        RecoveryLedgerPresence presence;
        presence.grants = RecoveryLedgerExists(RecoveryLedgerKind::Grants, instanceId);
        presence.transientContainerRetry =
            RecoveryLedgerExists(RecoveryLedgerKind::TransientContainerRetry, instanceId);
        return presence;
    }

    inline bool ShouldRetainCleanupTask(const std::wstring& instanceId,
                                        bool explicitRetryRequested = false)
    {
        if (explicitRetryRequested) return true;
        return QueryRecoveryLedgerPresence(instanceId).Any();
    }

} // namespace Sandbox
