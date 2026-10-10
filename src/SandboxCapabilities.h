// =========================================================================
// SandboxCapabilities.h — Capability SIDs and process attribute list
//
// Self-contained utilities for building AppContainer capability sets
// and process thread attribute lists (SECURITY_CAPABILITIES, isolation
// policy, child process restrictions).
// Each function is an independently testable semantic unit.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include "SandboxProcess.h"

namespace Sandbox {

    // Every SID in caps is owned here and released with LocalFree.
    struct CapabilityState {
        std::vector<SID_AND_ATTRIBUTES> caps;
        bool failed = false;
    };

    inline void FreeCapabilities(CapabilityState& state)
    {
        for (auto& cap : state.caps)
            LocalFree(cap.Sid);
        state.caps.clear();
    }

    inline CapabilityState BuildCapabilities(const SandboxConfig& config)
    {
        CapabilityState state;
        if (config.capabilityNames.empty())
            return state;

        using DeriveFn = BOOL (WINAPI*)(LPCWSTR, PSID**, DWORD*, PSID**, DWORD*);
        auto derive = reinterpret_cast<DeriveFn>(
            GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "DeriveCapabilitySidsFromName"));
        if (!derive) {
            g_logger.Log(L"CAPABILITY: DeriveCapabilitySidsFromName unavailable");
            state.failed = true;
            return state;
        }

        for (const auto& name : config.capabilityNames) {
            PSID* groups = nullptr;
            PSID* caps = nullptr;
            DWORD groupCount = 0, capCount = 0;
            BOOL ok = derive(name.c_str(), &groups, &groupCount, &caps, &capCount);
            DWORD error = ok ? ERROR_INVALID_SID : GetLastError();
            if (!ok || capCount == 0) {
                g_logger.LogFmt(L"CAPABILITY: %s derivation failed (error %lu)", name.c_str(), error);
                state.failed = true;
            }
            for (DWORD i = 0; i < groupCount; ++i)
                LocalFree(groups[i]);
            LocalFree(groups);

            for (DWORD i = 0; i < capCount; ++i) {
                if (!ok || !IsValidSid(caps[i])) {
                    state.failed = true;
                    LocalFree(caps[i]);
                    continue;
                }
                bool duplicate = std::any_of(state.caps.begin(), state.caps.end(),
                    [&](const SID_AND_ATTRIBUTES& entry) { return EqualSid(entry.Sid, caps[i]) != FALSE; });
                if (duplicate) {
                    LocalFree(caps[i]);
                    continue;
                }
                state.caps.push_back({ caps[i], SE_GROUP_ENABLED });
                LPWSTR sid = nullptr;
                if (ConvertSidToStringSidW(caps[i], &sid)) {
                    g_logger.LogFmt(L"CAPABILITY: %s SID=%s", name.c_str(), sid);
                    LocalFree(sid);
                }
            }
            LocalFree(caps);
            if (state.failed)
                break;
        }
        return state;
    }

    // -----------------------------------------------------------------------
    // AttributeListState — holds the allocated attribute list buffer.
    // Caller must call FreeAttributeList() when done.
    //
    // Non-copyable: pAttrList points inside attrBuf.  A copy would clone the
    // vector (new address) but leave pAttrList pointing at the original,
    // dangling on the copy.  Move is safe because std::vector move preserves
    // the underlying buffer address.
    // -----------------------------------------------------------------------
    struct AttributeListState {
        LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = nullptr;
        std::vector<BYTE>           attrBuf;
        // The handles the child inherits (PROC_THREAD_ATTRIBUTE_HANDLE_LIST).
        // The attribute list points into this vector.
        std::vector<HANDLE>         inheritedHandles;
        bool                        valid = false;

        AttributeListState() = default;
        AttributeListState(const AttributeListState&) = delete;
        AttributeListState& operator=(const AttributeListState&) = delete;
        AttributeListState(AttributeListState&&) = default;
        AttributeListState& operator=(AttributeListState&&) = default;
    };

    // -----------------------------------------------------------------------
    // BuildAttributeList — build PROC_THREAD_ATTRIBUTE_LIST for CreateProcess.
    //
    // For AppContainer: SECURITY_CAPABILITIES + optional strict isolation +
    //                   optional child process restriction.
    // For Restricted:   optional child process restriction only.
    // For both:         the handle list — the child inherits the given
    //                   standard handles and no other handle of Sandy.
    //
    // Inputs:  config        — sandbox configuration
    //          pSC           — pointer to SECURITY_CAPABILITIES (AppContainer only)
    //          isRestricted  — true for restricted-token mode
    //          stdHandles    — stdin/stdout/stderr for the child; unusable
    //                          and duplicate entries are left out
    // Returns: AttributeListState with initialized list
    // Verifiable: pAttrList is non-null on success; attributes can be queried
    // -----------------------------------------------------------------------
    inline AttributeListState BuildAttributeList(const SandboxConfig& config,
                                                  SECURITY_CAPABILITIES* pSC,
                                                  bool isRestricted,
                                                  const std::vector<HANDLE>& stdHandles)
    {
        AttributeListState state;
        DWORD attrCount = 0;
        bool strictIsolation = false;
        bool needChildAttr = !config.allowChildProcesses;

        for (HANDLE h : stdHandles) {
            HANDLE usable = InheritableHandleOrNull(h);
            if (usable && std::find(state.inheritedHandles.begin(), state.inheritedHandles.end(), usable)
                              == state.inheritedHandles.end())
                state.inheritedHandles.push_back(usable);
        }
        bool needHandleList = !state.inheritedHandles.empty();

        // These values need to persist until CreateProcess is called
        static DWORD allAppPackagesPolicy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        static DWORD childProcessPolicy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;

        if (!isRestricted) {
            strictIsolation = (config.tokenMode == TokenMode::LPAC);
            attrCount = 1;  // SECURITY_CAPABILITIES
            if (strictIsolation) attrCount++;
            if (needChildAttr) attrCount++;
        } else {
            if (needChildAttr) attrCount = 1;
        }
        if (needHandleList) attrCount++;

        if (attrCount == 0) {
            state.valid = true;  // no attributes needed — this is valid
            return state;
        }

        SIZE_T attrSize = 0;
        InitializeProcThreadAttributeList(nullptr, attrCount, 0, &attrSize);
        state.attrBuf.resize(attrSize);
        state.pAttrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(state.attrBuf.data());
        if (!InitializeProcThreadAttributeList(state.pAttrList, attrCount, 0, &attrSize)) {
            fprintf(stderr, "[Error] InitializeProcThreadAttributeList failed.\n");
            state.pAttrList = nullptr;
            return state;
        }

        if (!isRestricted) {
            if (!UpdateProcThreadAttribute(state.pAttrList, 0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                pSC, sizeof(SECURITY_CAPABILITIES), nullptr, nullptr))
            {
                fprintf(stderr, "[Error] UpdateProcThreadAttribute (security) failed.\n");
                DeleteProcThreadAttributeList(state.pAttrList);
                state.pAttrList = nullptr;
                return state;
            }

            if (strictIsolation) {
                if (!UpdateProcThreadAttribute(state.pAttrList, 0,
                    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                    &allAppPackagesPolicy, sizeof(allAppPackagesPolicy), nullptr, nullptr))
                {
                    fprintf(stderr, "[Error] UpdateProcThreadAttribute (isolation policy) failed.\n");
                    DeleteProcThreadAttributeList(state.pAttrList);
                    state.pAttrList = nullptr;
                    return state;
                }
                g_logger.Log(L"ISOLATION: strict (ALL_APPLICATION_PACKAGES opt-out)");
            }
        }

        if (needChildAttr) {
            if (!UpdateProcThreadAttribute(state.pAttrList, 0,
                PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                &childProcessPolicy, sizeof(childProcessPolicy), nullptr, nullptr))
            {
                fprintf(stderr, "[Error] UpdateProcThreadAttribute (child process) failed.\n");
                DeleteProcThreadAttributeList(state.pAttrList);
                state.pAttrList = nullptr;
                return state;
            }
            g_logger.Log(L"CHILD_PROCESS: restricted (kernel-enforced)");
        }

        if (needHandleList) {
            if (!UpdateProcThreadAttribute(state.pAttrList, 0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                state.inheritedHandles.data(),
                state.inheritedHandles.size() * sizeof(HANDLE), nullptr, nullptr))
            {
                fprintf(stderr, "[Error] UpdateProcThreadAttribute (handle list) failed.\n");
                DeleteProcThreadAttributeList(state.pAttrList);
                state.pAttrList = nullptr;
                return state;
            }
        }

        state.valid = true;
        return state;
    }

    // -----------------------------------------------------------------------
    // FreeAttributeList — release the attribute list.
    //
    // Inputs:  state — AttributeListState from BuildAttributeList
    // Effect:  deletes the attribute list and clears state
    // -----------------------------------------------------------------------
    inline void FreeAttributeList(AttributeListState& state)
    {
        if (state.pAttrList) {
            DeleteProcThreadAttributeList(state.pAttrList);
            state.pAttrList = nullptr;
        }
        state.valid = false;
    }

} // namespace Sandbox
