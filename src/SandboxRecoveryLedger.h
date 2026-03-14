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
        if (instanceId.empty()) return false;

        HKEY hKey = nullptr;
        bool exists = RegOpenKeyExW(HKEY_CURRENT_USER,
                                    GetRecoveryLedgerKey(kind, instanceId).c_str(),
                                    0, KEY_READ, &hKey) == ERROR_SUCCESS;
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
