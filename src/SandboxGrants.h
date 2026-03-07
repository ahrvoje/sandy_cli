// =========================================================================
// SandboxGrants.h — Grant tracking, persistence, and revocation
//
// Tracks all ACL modifications made during a sandbox session, persists
// them to the registry for crash recovery, and removes only our ACEs
// on exit.  Multi-instance safe: only touches ACEs for our own SID.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include "SandboxACL.h"
#include <set>
#include <atomic>

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Grant record — one per modified object
    // -----------------------------------------------------------------------
    struct ACLGrant {
        std::wstring       path;
        SE_OBJECT_TYPE     objType;
        std::wstring       sidString;
        // SID of the principal granted/denied
        std::wstring       trappedSids;    // semicolon-separated trapped AC SIDs (deny entries only)
        bool               wasDenied = false;
    };

    // -----------------------------------------------------------------------
    // Global state — guarded by SRW lock
    // -----------------------------------------------------------------------
    inline std::vector<ACLGrant> g_aclGrants;
    inline SRWLOCK               g_aclGrantsLock = SRWLOCK_INIT;
    inline std::atomic<bool>     g_cleanedUp{false};

    // Per-instance UUID — set once at startup
    inline std::wstring g_instanceId;

    // Registry keys for grant persistence
    static const wchar_t* kGrantsParentKey = L"Software\\Sandy\\Grants";

    inline std::wstring GetGrantsRegKey() {
        return std::wstring(kGrantsParentKey) + L"\\" + g_instanceId;
    }

    // -----------------------------------------------------------------------
    // Registry helper: read REG_SZ value by enumeration index.
    // Skips metadata values (name starts with '_').
    // -----------------------------------------------------------------------
    inline bool ReadRegSzEnum(HKEY hKey, DWORD index,
                              std::wstring& name, std::wstring& data)
    {
        wchar_t vname[64];
        DWORD vnameLen = 64;
        DWORD dataSize = 0, dataType = 0;
        if (RegEnumValueW(hKey, index, vname, &vnameLen, nullptr, &dataType,
                          nullptr, &dataSize) != ERROR_SUCCESS)
            return false;
        if (vname[0] == L'_' || dataType != REG_SZ) return false;

        data.assign(dataSize / sizeof(wchar_t), L'\0');
        vnameLen = 64;
        if (RegEnumValueW(hKey, index, vname, &vnameLen, nullptr, nullptr,
                          reinterpret_cast<BYTE*>(&data[0]), &dataSize) != ERROR_SUCCESS)
            return false;
        while (!data.empty() && data.back() == L'\0') data.pop_back();
        name = vname;
        return true;
    }

    // -----------------------------------------------------------------------
    // Parsed grant record — output of ParseGrantRecord.
    // -----------------------------------------------------------------------
    struct GrantRecord {
        std::wstring type;          // "FILE" or "REG"
        std::wstring path;
        std::wstring sidString;
        std::wstring trappedSids;   // semicolon-separated trapped AC SIDs
        bool         wasDenied = false;
    };

    // -----------------------------------------------------------------------
    // ValidateSidPrefix — lightweight SID structure check.
    //
    // A valid SID string has the form S-<revision>-<authority>-...
    // We require at least S-<digit>-<digit> (e.g. "S-1-5").
    // -----------------------------------------------------------------------
    inline bool ValidateSidPrefix(const std::wstring& s)
    {
        // Minimum: "S-1-5" (5 chars)
        if (s.size() < 5) return false;
        if (s[0] != L'S' || s[1] != L'-') return false;
        // Revision must start with a digit
        if (!iswdigit(s[2])) return false;
        // Find dash after revision
        auto dash2 = s.find(L'-', 2);
        if (dash2 == std::wstring::npos || dash2 + 1 >= s.size()) return false;
        // Authority must start with a digit
        if (!iswdigit(s[dash2 + 1])) return false;
        return true;
    }

    // -----------------------------------------------------------------------
    // ParseGrantRecord — strict parser for persisted grant records.
    //
    // Expected format: TYPE|PATH|SID[|DENY:1][|TRAPPED:sid1;sid2]
    //   TYPE:  "FILE" or "REG"
    //   PATH:  non-empty, must be absolute (drive letter, UNC, or HKEY)
    //   SID:   must match S-<revision>-<authority>-... structure
    //   Flags: only DENY:1 and TRAPPED:<sids> are recognized;
    //          any unknown |KEY:... suffix rejects the record.
    //
    // On failure, sets `reason` with a diagnostic string for logging.
    // Returns false on malformed input; caller should skip + log.
    // -----------------------------------------------------------------------
    inline bool ParseGrantRecord(const std::wstring& data, GrantRecord& out,
                                 const wchar_t** reason = nullptr)
    {
        auto reject = [&](const wchar_t* msg) -> bool {
            if (reason) *reason = msg;
            return false;
        };

        // --- Field 1: TYPE ---
        auto sep1 = data.find(L'|');
        if (sep1 == std::wstring::npos) return reject(L"missing TYPE|PATH separator");
        out.type = data.substr(0, sep1);
        if (out.type != L"FILE" && out.type != L"REG")
            return reject(L"TYPE is not FILE or REG");

        // --- Field 2: PATH ---
        auto sep2 = data.find(L'|', sep1 + 1);
        if (sep2 == std::wstring::npos) return reject(L"missing PATH|SID separator");
        out.path = data.substr(sep1 + 1, sep2 - sep1 - 1);
        if (out.path.empty()) return reject(L"empty PATH");
        // Reject paths containing pipe (would indicate corrupt record)
        if (out.path.find(L'|') != std::wstring::npos)
            return reject(L"PATH contains pipe character");
        // Require absolute path (drive letter, UNC, or HKEY for registry)
        bool isAbsolute = (out.path.size() >= 2 && iswalpha(out.path[0]) && out.path[1] == L':') ||
                          (out.path.size() >= 2 && out.path[0] == L'\\' && out.path[1] == L'\\') ||
                          (out.path.compare(0, 4, L"HKEY") == 0);
        if (!isAbsolute)
            return reject(L"PATH is not absolute");

        // --- Field 3+: SID and optional flags ---
        std::wstring remaining = data.substr(sep2 + 1);
        auto pipePos = remaining.find(L'|');
        out.sidString = (pipePos != std::wstring::npos)
                        ? remaining.substr(0, pipePos) : remaining;

        // Validate SID: must match S-<revision>-<authority>-... structure
        if (!ValidateSidPrefix(out.sidString))
            return reject(L"SID does not match S-<rev>-<auth> format");

        // Parse optional |KEY:VALUE suffixes
        out.wasDenied = false;
        out.trappedSids.clear();
        if (pipePos != std::wstring::npos) {
            remaining = remaining.substr(pipePos);
            while (!remaining.empty() && remaining[0] == L'|') {
                remaining = remaining.substr(1);
                if (remaining.compare(0, 6, L"DENY:1") == 0) {
                    out.wasDenied = true;
                    remaining = remaining.substr(6);
                } else if (remaining.compare(0, 8, L"TRAPPED:") == 0) {
                    remaining = remaining.substr(8);
                    auto nextPipe = remaining.find(L'|');
                    out.trappedSids = (nextPipe != std::wstring::npos)
                                     ? remaining.substr(0, nextPipe) : remaining;
                    remaining = (nextPipe != std::wstring::npos)
                                ? remaining.substr(nextPipe) : L"";
                    // Validate each trapped SID substring
                    if (!out.trappedSids.empty()) {
                        std::wstring buf = out.trappedSids;
                        size_t pos = 0;
                        while (pos < buf.size()) {
                            auto semi = buf.find(L';', pos);
                            std::wstring one = (semi != std::wstring::npos)
                                ? buf.substr(pos, semi - pos) : buf.substr(pos);
                            if (!one.empty() && !ValidateSidPrefix(one))
                                return reject(L"TRAPPED SID has invalid format");
                            pos = (semi != std::wstring::npos) ? semi + 1 : buf.size();
                        }
                    }
                    out.wasDenied = true; // backward compat: trapped always means deny
                } else {
                    return reject(L"unknown flag suffix");
                }
            }
            // Reject trailing garbage after all known flags
            if (!remaining.empty())
                return reject(L"trailing garbage after flags");
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // Process liveness check — guards against PID reuse via creation time
    // -----------------------------------------------------------------------
    inline ULONGLONG GetCurrentProcessCreationTime()
    {
        FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
        if (GetProcessTimes(GetCurrentProcess(), &ftCreate, &ftExit, &ftKernel, &ftUser)) {
            ULARGE_INTEGER li;
            li.LowPart = ftCreate.dwLowDateTime;
            li.HighPart = ftCreate.dwHighDateTime;
            return li.QuadPart;
        }
        return 0;
    }

    inline bool IsProcessAlive(DWORD pid, ULONGLONG storedCreationTime)
    {
        if (!pid) return false;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
        if (!h) return false;

        // Zombie check — signaled = terminated
        if (WaitForSingleObject(h, 0) != WAIT_TIMEOUT) {
            CloseHandle(h);
            return false;
        }

        bool alive = true;
        if (storedCreationTime != 0) {
            FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
            if (GetProcessTimes(h, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                ULARGE_INTEGER li;
                li.LowPart = ftCreate.dwLowDateTime;
                li.HighPart = ftCreate.dwHighDateTime;
                alive = (li.QuadPart == storedCreationTime);
            }
        }
        CloseHandle(h);
        return alive;
    }

    inline bool ReadPidAndCtime(HKEY hKey, DWORD& pid, ULONGLONG& ctime)
    {
        pid = 0; ctime = 0;
        DWORD size = sizeof(DWORD);
        RegQueryValueExW(hKey, L"_pid", nullptr, nullptr,
                         reinterpret_cast<BYTE*>(&pid), &size);
        size = sizeof(ULONGLONG);
        RegQueryValueExW(hKey, L"_ctime", nullptr, nullptr,
                         reinterpret_cast<BYTE*>(&ctime), &size);
        return pid != 0;
    }

    // -----------------------------------------------------------------------
    // Save a grant to the in-memory list AND the registry.
    // Called by GrantObjectAccess and DenyObjectAccess via RecordGrantCallback.
    // Stores SID string (for ACE-level removal) — no SDDL snapshot.
    // -----------------------------------------------------------------------
    inline void RecordGrant(const std::wstring& path, SE_OBJECT_TYPE objType,
                            const std::wstring& sidString,
                            const std::wstring& trappedSids = L"",
                            bool isDeny = false)
    {
        AcquireSRWLockExclusive(&g_aclGrantsLock);

        // --- Persist to registry ---
        std::wstring regKey = GetGrantsRegKey();
        HKEY hKey = nullptr;
        DWORD disposition = 0;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr,
                0, KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC,
                nullptr, &hKey, &disposition) == ERROR_SUCCESS) {

            // On first creation, store identity and protect the key
            if (disposition == REG_CREATED_NEW_KEY) {
                DWORD pid = GetCurrentProcessId();
                RegSetValueExW(hKey, L"_pid", 0, REG_DWORD,
                               reinterpret_cast<const BYTE*>(&pid), sizeof(DWORD));

                ULONGLONG ct = GetCurrentProcessCreationTime();
                RegSetValueExW(hKey, L"_ctime", 0, REG_QWORD,
                               reinterpret_cast<const BYTE*>(&ct), sizeof(ULONGLONG));

                std::wstring containerName = ContainerNameFromId(g_instanceId);
                RegSetValueExW(hKey, L"_container", 0, REG_SZ,
                               reinterpret_cast<const BYTE*>(containerName.c_str()),
                               static_cast<DWORD>((containerName.size() + 1) * sizeof(wchar_t)));

                // Deny Restricted SID (S-1-5-12) write access to prevent tampering
                SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
                PSID pRestricted = nullptr;
                if (AllocateAndInitializeSid(&ntAuth, 1, SECURITY_RESTRICTED_CODE_RID,
                        0, 0, 0, 0, 0, 0, 0, &pRestricted)) {
                    EXPLICIT_ACCESSW deny{};
                    deny.grfAccessPermissions = KEY_ALL_ACCESS;
                    deny.grfAccessMode = DENY_ACCESS;
                    deny.grfInheritance = NO_INHERITANCE;
                    deny.Trustee.TrusteeForm = TRUSTEE_IS_SID;
                    deny.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pRestricted);

                    PACL pOldDacl = nullptr;
                    PSECURITY_DESCRIPTOR pKeySD = nullptr;
                    if (GetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                            nullptr, nullptr, &pOldDacl, nullptr, &pKeySD) == ERROR_SUCCESS) {
                        PACL pNewDacl = nullptr;
                        if (SetEntriesInAclW(1, &deny, pOldDacl, &pNewDacl) == ERROR_SUCCESS) {
                            SetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                                nullptr, nullptr, pNewDacl, nullptr);
                            LocalFree(pNewDacl);
                        }
                        LocalFree(pKeySD);
                    }
                    FreeSid(pRestricted);
                }
            }

            // Get next index
            DWORD nextIdx = 0;
            DWORD idxSize = sizeof(nextIdx);
            RegQueryValueExW(hKey, L"_nextIdx", nullptr, nullptr,
                             reinterpret_cast<BYTE*>(&nextIdx), &idxSize);

            // Format: TYPE|PATH|SID  or  TYPE|PATH|SID|DENY:1|TRAPPED:sid1;sid2
            std::wstring typeStr = (objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
            std::wstring data = typeStr + L"|" + path + L"|" + sidString;
            // Persist deny flag explicitly
            if (isDeny) {
                data += L"|DENY:1";
            }
            if (!trappedSids.empty()) {
                data += L"|TRAPPED:" + trappedSids;
            }

            wchar_t valueName[32];
            swprintf(valueName, 32, L"%lu", nextIdx);
            RegSetValueExW(hKey, valueName, 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(data.c_str()),
                           static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t)));

            // Increment counter
            nextIdx++;
            RegSetValueExW(hKey, L"_nextIdx", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&nextIdx), sizeof(nextIdx));

            g_logger.Log((L"REG_PERSIST: [" + std::to_wstring(nextIdx - 1) + L"] " + data).c_str());
            RegCloseKey(hKey);
        }

        // --- Save to in-memory list ---
        ACLGrant grant = { path, objType, sidString, trappedSids, isDeny };
        g_aclGrants.push_back(std::move(grant));

        ReleaseSRWLockExclusive(&g_aclGrantsLock);
    }

    // -----------------------------------------------------------------------
    // TryDeleteEmptyParentKeys — cascade-delete empty registry parents.
    // Deletes Software\Sandy\Grants if no subkeys or values remain, then
    // Software\Sandy itself if both Grants and WER are gone.
    //
    // Best-effort: logs but does not propagate failures.  Registry races
    // with other instances are benign — the key simply won't be empty.
    // -----------------------------------------------------------------------
    inline void TryDeleteEmptyParentKeys()
    {
        // Step 1: delete Grants parent if completely empty
        HKEY hGrants = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ, &hGrants) == ERROR_SUCCESS) {
            DWORD subKeys = 0, values = 0;
            LSTATUS qs = RegQueryInfoKeyW(hGrants, nullptr, nullptr, nullptr,
                             &subKeys, nullptr, nullptr, &values,
                             nullptr, nullptr, nullptr, nullptr);
            RegCloseKey(hGrants);
            if (qs != ERROR_SUCCESS) {
                g_logger.LogFmt(L"REG_CASCADE: RegQueryInfoKey(Grants) failed (error %lu)", qs);
                return; // can't determine state — don't delete
            }
            if (subKeys == 0 && values == 0) {
                LSTATUS ds = RegDeleteKeyW(HKEY_CURRENT_USER, kGrantsParentKey);
                if (ds == ERROR_SUCCESS)
                    g_logger.Log(L"REG_CASCADE: deleted empty Grants key");
                else
                    g_logger.LogFmt(L"REG_CASCADE: RegDeleteKey(Grants) failed (error %lu)", ds);
            } else {
                return; // Grants still has children; don't touch parent
            }
        }

        // Step 2: delete Software\Sandy if both Grants and WER are gone
        HKEY hSandy = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Sandy", 0,
                          KEY_READ, &hSandy) == ERROR_SUCCESS) {
            DWORD subKeys = 0, values = 0;
            LSTATUS qs = RegQueryInfoKeyW(hSandy, nullptr, nullptr, nullptr,
                             &subKeys, nullptr, nullptr, &values,
                             nullptr, nullptr, nullptr, nullptr);
            RegCloseKey(hSandy);
            if (qs != ERROR_SUCCESS) {
                g_logger.LogFmt(L"REG_CASCADE: RegQueryInfoKey(Sandy) failed (error %lu)", qs);
                return;
            }
            if (subKeys == 0 && values == 0) {
                LSTATUS ds = RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Sandy");
                if (ds == ERROR_SUCCESS)
                    g_logger.Log(L"REG_CASCADE: deleted empty Sandy key");
                else
                    g_logger.LogFmt(L"REG_CASCADE: RegDeleteKey(Sandy) failed (error %lu)", ds);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Clear this instance's persisted grants from registry
    // -----------------------------------------------------------------------
    inline void ClearPersistedGrants()
    {
        std::wstring regKey = GetGrantsRegKey();
        LSTATUS r = RegDeleteTreeW(HKEY_CURRENT_USER, regKey.c_str());
        g_logger.Log((L"REG_CLEAR: " + regKey + (r == ERROR_SUCCESS ? L" -> OK" : L" -> NOT_FOUND")).c_str());

        TryDeleteEmptyParentKeys();
    }

    // -----------------------------------------------------------------------
    // Collect path+SID pairs granted by OTHER live sandy instances.
    // Returns set of "path|sid" strings for precise skip logic.
    // -----------------------------------------------------------------------
    inline std::set<std::wstring> GetOtherInstancePathSids(const std::wstring& excludeId)
    {
        std::set<std::wstring> pathSids;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return pathSids;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[128];
            DWORD nameLen = 128;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;
            if (excludeId == name) continue;

            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + name;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            DWORD pid = 0; ULONGLONG ctime = 0;
            ReadPidAndCtime(hKey, pid, ctime);
            if (!IsProcessAlive(pid, ctime)) {
                RegCloseKey(hKey);
                continue;
            }

            DWORD valueCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &valueCount, nullptr, nullptr, nullptr, nullptr);
            for (DWORD vi = 0; vi < valueCount; vi++) {
                std::wstring vname, data;
                if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;
                GrantRecord rec;
                if (!ParseGrantRecord(data, rec)) continue;
                pathSids.insert(rec.path + L"|" + rec.sidString);
            }
            RegCloseKey(hKey);
        }
        RegCloseKey(hParent);
        return pathSids;
    }

    // -----------------------------------------------------------------------
    // Collect deny paths from OTHER live sandy instances.
    // Returns set of paths where another instance has a deny entry
    // (identified by TRAPPED: suffix in the registry value).
    // Used to prevent TreeSet from propagating into children with
    // PROTECTED_DACL set by another instance's deny rules.
    // -----------------------------------------------------------------------
    inline std::set<std::wstring> GetOtherInstanceDenyPaths(const std::wstring& excludeId)
    {
        std::set<std::wstring> denyPaths;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return denyPaths;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[128];
            DWORD nameLen = 128;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;
            if (excludeId == name) continue;

            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + name;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            DWORD pid = 0; ULONGLONG ctime = 0;
            ReadPidAndCtime(hKey, pid, ctime);
            if (!IsProcessAlive(pid, ctime)) {
                RegCloseKey(hKey);
                continue;
            }

            DWORD valueCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &valueCount, nullptr, nullptr, nullptr, nullptr);
            for (DWORD vi = 0; vi < valueCount; vi++) {
                std::wstring vname, data;
                if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;
                GrantRecord rec;
                if (!ParseGrantRecord(data, rec)) continue;
                if (!rec.wasDenied) continue;
                denyPaths.insert(rec.path);
            }
            RegCloseKey(hKey);
        }
        RegCloseKey(hParent);
        return denyPaths;
    }

    // -----------------------------------------------------------------------
    // RevokeAllGrants — remove all ACEs we added, using SID-based removal.
    // Multi-instance safe: only removes ACEs for our SID.
    // For shared SIDs (RT mode), skips paths used by other live instances.
    // Skips TreeSet when another instance has a deny on a child path
    // (to avoid propagating into children with PROTECTED_DACL).
    // Thread-safe, double-cleanup guarded.
    // -----------------------------------------------------------------------
    inline void RevokeAllGrants()
    {
        if (g_cleanedUp.exchange(true)) return;

        AcquireSRWLockExclusive(&g_aclGrantsLock);

        // Collect path+SID pairs from other live instances.
        // Only skip removal when another instance uses the SAME SID on the SAME path
        // (RT shared SID case). AppContainer instances have unique SIDs, so their
        // ACE removal never interferes even on overlapping paths.
        std::set<std::wstring> otherPathSids = GetOtherInstancePathSids(g_instanceId);

        // Collect deny paths from other live instances.
        // If our cleanup path is a parent of a deny path, we must skip TreeSet
        // to avoid propagating into children with PROTECTED_DACL.
        std::set<std::wstring> otherDenyPaths = GetOtherInstanceDenyPaths(g_instanceId);

        // Helper: check if any deny path is a child of the given path
        auto hasChildDeny = [&](const std::wstring& parentPath) -> bool {
            std::wstring prefix = parentPath;
            // Ensure prefix ends with backslash for correct prefix matching
            if (!prefix.empty() && prefix.back() != L'\\') prefix += L'\\';
            for (const auto& dp : otherDenyPaths) {
                if (dp.length() > prefix.length() &&
                    _wcsnicmp(dp.c_str(), prefix.c_str(), prefix.length()) == 0)
                    return true;
            }
            return false;
        };

        // Deduplicate: same path may appear for allow + deny — use composite key
        std::set<std::wstring> processed;
        int removed = 0, skipped = 0;
        for (auto it = g_aclGrants.rbegin(); it != g_aclGrants.rend(); ++it) {
            // Composite key: path + deny/allow type — allows both records to be processed
            std::wstring dedupKey = it->path + L"|" + (it->wasDenied ? L"D" : L"A");
            if (processed.count(dedupKey)) continue;
            processed.insert(dedupKey);

            // Skip only when another instance uses the same SID on the same path
            std::wstring pathSidKey = it->path + L"|" + it->sidString;
            if (otherPathSids.count(pathSidKey)) {
                g_logger.Log((L"ACL_SKIP: " + it->path + L" (same SID active in other instance)").c_str());
                skipped++;
                continue;
            }

            // For non-deny directory grants: skip TreeSet if another instance
            // has a deny on a child path (to preserve PROTECTED_DACL)
            bool needSkipTree = false;
            if (!it->wasDenied && it->objType == SE_FILE_OBJECT) {
                DWORD attrs = GetFileAttributesW(it->path.c_str());
                if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                    if (hasChildDeny(it->path)) {
                        needSkipTree = true;
                        g_logger.Log((L"ACL_NOTREE: " + it->path + L" (child has active deny in other instance)").c_str());
                    }
                }
            }

            int n = RemoveSidFromDacl(it->path, it->sidString, it->objType,
                                  it->wasDenied, it->trappedSids, needSkipTree);
            removed += n;
        }
        g_logger.LogFmt(L"REVOKE_SUMMARY: %d ACEs removed, %d paths skipped", removed, skipped);
        g_aclGrants.clear();
        ReleaseSRWLockExclusive(&g_aclGrantsLock);
        ClearPersistedGrants();
    }

    // -----------------------------------------------------------------------
    // RestoreGrantsFromKey — remove ACEs from a single registry subkey.
    // Parses TYPE|PATH|SID format and removes the SID's ACEs.
    // -----------------------------------------------------------------------
    inline void RestoreGrantsFromKey(HKEY hKey,
                                      const std::set<std::wstring>& protectedPaths = {})
    {
        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        std::set<std::wstring> processed;
        for (DWORD vi = 0; vi < valueCount; vi++) {
            std::wstring vname, data;
            if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;

            GrantRecord rec;
            const wchar_t* parseReason = nullptr;
            if (!ParseGrantRecord(data, rec, &parseReason)) {
                g_logger.LogFmt(L"GRANT_PARSE: malformed record (%ls), skipping: %ls",
                                parseReason ? parseReason : L"unknown", data.c_str());
                continue;
            }

            // Composite dedup key: path + deny/allow type
            std::wstring dedupKey = rec.path + L"|" + (rec.wasDenied ? L"D" : L"A");
            if (processed.count(dedupKey)) continue;
            processed.insert(dedupKey);

            if (protectedPaths.count(rec.path)) {
                g_logger.Log((L"ACL_SKIP_STALE: " + rec.path + L" (live instance active)").c_str());
                continue;
            }

            SE_OBJECT_TYPE objType = (rec.type == L"REG") ? SE_REGISTRY_KEY : SE_FILE_OBJECT;
            RemoveSidFromDacl(rec.path, rec.sidString, objType, rec.wasDenied, rec.trappedSids);
        }
    }

    // -----------------------------------------------------------------------
    // RestoreStaleGrants — cleanup after crash/power loss.
    // Processes dead PIDs only. Also deletes stale AppContainer profiles.
    // -----------------------------------------------------------------------
    inline void RestoreStaleGrants()
    {
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        std::vector<std::wstring> subKeys;
        for (DWORD idx = 0; idx < subKeyCount; idx++) {
            wchar_t name[128];
            DWORD nameLen = 128;
            if (RegEnumKeyExW(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                subKeys.push_back(name);
        }
        RegCloseKey(hParent);

        // Read _container from a subkey
        auto readContainer = [](HKEY hKey) -> std::wstring {
            DWORD size = 0;
            if (RegQueryValueExW(hKey, L"_container", nullptr, nullptr, nullptr, &size) != ERROR_SUCCESS)
                return {};
            std::wstring val(size / sizeof(wchar_t), L'\0');
            RegQueryValueExW(hKey, L"_container", nullptr, nullptr,
                             reinterpret_cast<BYTE*>(&val[0]), &size);
            while (!val.empty() && val.back() == L'\0') val.pop_back();
            return val;
        };

        // Collect paths from a subkey
        auto collectPaths = [](HKEY hKey, std::set<std::wstring>& outPaths) {
            DWORD valueCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &valueCount, nullptr, nullptr, nullptr, nullptr);
            for (DWORD vi = 0; vi < valueCount; vi++) {
                std::wstring vname, data;
                if (!ReadRegSzEnum(hKey, vi, vname, data)) continue;
                GrantRecord rec;
                if (!ParseGrantRecord(data, rec)) continue;
                outPaths.insert(rec.path);
            }
        };

        // Separate live vs stale
        std::set<std::wstring> livePaths;
        std::vector<std::wstring> staleKeys;

        for (const auto& subKey : subKeys) {
            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + subKey;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) != ERROR_SUCCESS) {
                staleKeys.push_back(subKey);
                continue;
            }

            DWORD pid = 0; ULONGLONG ctime = 0;
            ReadPidAndCtime(hKey, pid, ctime);
            if (IsProcessAlive(pid, ctime)) {
                collectPaths(hKey, livePaths);
                g_logger.Log((L"STALE_CHECK: " + subKey + L" -> ALIVE (PID=" + std::to_wstring(pid) + L")").c_str());
            } else {
                staleKeys.push_back(subKey);
                g_logger.Log((L"STALE_CHECK: " + subKey + L" -> DEAD (PID=" + std::to_wstring(pid) + L")").c_str());
            }
            RegCloseKey(hKey);
        }

        // Remove stale ACEs and delete registry subkeys
        for (const auto& subKey : staleKeys) {
            std::wstring fullKey = std::wstring(kGrantsParentKey) + L"\\" + subKey;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                              KEY_READ, &hKey) == ERROR_SUCCESS) {
                std::wstring containerName = readContainer(hKey);
                if (!containerName.empty()) {
                    HRESULT hr = DeleteAppContainerProfile(containerName.c_str());
                    g_logger.Log((L"PROFILE_DELETE: " + containerName +
                        (SUCCEEDED(hr) ? L" -> OK" : L" -> FAILED")).c_str());
                }
                RestoreGrantsFromKey(hKey, livePaths);
                RegCloseKey(hKey);
            }
            LSTATUS delResult = RegDeleteTreeW(HKEY_CURRENT_USER, fullKey.c_str());
            if (delResult != ERROR_SUCCESS) {
                g_logger.LogFmt(L"REG_DELETE_FAIL: %ls -> error %lu", fullKey.c_str(), delResult);
                delResult = RegDeleteKeyW(HKEY_CURRENT_USER, fullKey.c_str());
                if (delResult != ERROR_SUCCESS)
                    g_logger.LogFmt(L"REG_DELETE_FALLBACK_FAIL: %ls -> error %lu", fullKey.c_str(), delResult);
            }
            g_logger.Log((L"REG_DELETE: " + fullKey).c_str());
        }

        TryDeleteEmptyParentKeys();
    }

} // namespace Sandbox
