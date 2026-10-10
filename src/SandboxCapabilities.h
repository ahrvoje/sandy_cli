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

    // -----------------------------------------------------------------------
    // CapabilityState — holds allocated capability SIDs and the array.
    // Caller must call FreeCapabilities() when done.
    // -----------------------------------------------------------------------
    struct CapabilityState {
        SID_AND_ATTRIBUTES caps[4] = {};
        DWORD  capCount = 0;
        PSID   pNetSid = nullptr;
        PSID   pLanSid = nullptr;
        PSID   pRegistrySid = nullptr;  // ConvertStringSidToSid: LocalFree
        PSID   pComSid = nullptr;       // ConvertStringSidToSid: LocalFree
        bool   failed = false;  // P3: true if any requested capability allocation failed
    };

    // -----------------------------------------------------------------------
    // BuildCapabilities — allocate explicitly requested capability SIDs.
    //
    // Inputs:  config — network flags and opt-in LPAC capabilities
    // Returns: CapabilityState with allocated SIDs
    // Verifiable: capCount matches requested capabilities;
    //             SIDs can be verified via ConvertSidToStringSidW
    //
    // NOTE: LanMode::WithLocalhost and LanMode::WithoutLocalhost both
    // require PRIVATE_NETWORK_CLIENT_SERVER capability.  Loopback
    // additionally needs CheckNetIsolation exemption (see SandboxCleanup.h).
    // There is no localhost-only capability SID — loopback always implies
    // LAN access.  The LanMode enum makes this explicit at the config level.
    // -----------------------------------------------------------------------
    inline CapabilityState BuildCapabilities(const SandboxConfig& config)
    {
        CapabilityState state;

        if (config.allowNetwork) {
            SID_IDENTIFIER_AUTHORITY appAuthority = SECURITY_APP_PACKAGE_AUTHORITY;
            if (AllocateAndInitializeSid(&appAuthority,
                SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT,
                SECURITY_CAPABILITY_BASE_RID,
                SECURITY_CAPABILITY_INTERNET_CLIENT,
                0, 0, 0, 0, 0, 0, &state.pNetSid))
            {
                state.caps[state.capCount].Sid = state.pNetSid;
                state.caps[state.capCount].Attributes = SE_GROUP_ENABLED;
                state.capCount++;
                LPWSTR capSidStr = nullptr;
                if (ConvertSidToStringSidW(state.pNetSid, &capSidStr)) {
                    std::wstring capMsg = std::wstring(L"CAPABILITY: INTERNET_CLIENT SID=") + capSidStr;
                    g_logger.Log(capMsg.c_str());
                    LocalFree(capSidStr);
                } else {
                    g_logger.Log(L"CAPABILITY: INTERNET_CLIENT");
                }
            } else {
                g_logger.LogFmt(L"CAPABILITY: INTERNET_CLIENT AllocateAndInitializeSid FAILED (error %lu)",
                                GetLastError());
                state.failed = true;
            }
        }

        if (config.lanMode != LanMode::Off) {
            SID_IDENTIFIER_AUTHORITY appAuthority = SECURITY_APP_PACKAGE_AUTHORITY;
            if (AllocateAndInitializeSid(&appAuthority,
                SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT,
                SECURITY_CAPABILITY_BASE_RID,
                SECURITY_CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER,
                0, 0, 0, 0, 0, 0, &state.pLanSid))
            {
                state.caps[state.capCount].Sid = state.pLanSid;
                state.caps[state.capCount].Attributes = SE_GROUP_ENABLED;
                state.capCount++;
                LPWSTR capSidStr = nullptr;
                if (ConvertSidToStringSidW(state.pLanSid, &capSidStr)) {
                    std::wstring capMsg = std::wstring(L"CAPABILITY: PRIVATE_NETWORK SID=") + capSidStr;
                    g_logger.Log(capMsg.c_str());
                    LocalFree(capSidStr);
                } else {
                    g_logger.Log(L"CAPABILITY: PRIVATE_NETWORK");
                }
            } else {
                g_logger.LogFmt(L"CAPABILITY: PRIVATE_NETWORK AllocateAndInitializeSid FAILED (error %lu)",
                                GetLastError());
                state.failed = true;
            }
        }

        // Windows named capabilities, as returned by DeriveCapabilitySidsFromName.
        // Each opt-in adds one SID to this token; it does not edit host ACLs.
        struct NamedCapability { bool enabled; const wchar_t* name; const wchar_t* sid; PSID* storage; };
        const NamedCapability named[] = {
            { config.allowRegistryRead, L"registryRead",
              L"S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681", &state.pRegistrySid },
            { config.allowCom, L"lpacCom",
              L"S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256", &state.pComSid },
        };
        for (const auto& cap : named) {
            if (!cap.enabled) continue;
            if (config.tokenMode == TokenMode::LPAC &&
                ConvertStringSidToSidW(cap.sid, cap.storage)) {
                state.caps[state.capCount++] = { *cap.storage, SE_GROUP_ENABLED };
                g_logger.LogFmt(L"CAPABILITY: %s SID=%s", cap.name, cap.sid);
            } else {
                g_logger.LogFmt(L"CAPABILITY: %s allocation failed or mode is not LPAC", cap.name);
                state.failed = true;
            }
        }

        return state;
    }

    // -----------------------------------------------------------------------
    // FreeCapabilities — release allocated capability SIDs.
    //
    // Inputs:  state — CapabilityState returned from BuildCapabilities
    // Effect:  FreeSid for built-in SIDs, LocalFree for string-derived SIDs
    // Verifiable: SID pointers become invalid after this call
    // -----------------------------------------------------------------------
    inline void FreeCapabilities(CapabilityState& state)
    {
        if (state.pNetSid) { FreeSid(state.pNetSid); state.pNetSid = nullptr; }
        if (state.pLanSid) { FreeSid(state.pLanSid); state.pLanSid = nullptr; }
        if (state.pRegistrySid) { LocalFree(state.pRegistrySid); state.pRegistrySid = nullptr; }
        if (state.pComSid) { LocalFree(state.pComSid); state.pComSid = nullptr; }
        state.capCount = 0;
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
