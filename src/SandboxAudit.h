// =========================================================================
// SandboxAudit.h — Procmon-based resource denial auditor
//
// Automates Process Monitor (Sysinternals) to capture all resource access
// denials experienced by the sandboxed child process and its descendants.
// Requires: Procmon on PATH + admin privileges.
// =========================================================================
#pragma once

#pragma warning(push)
#pragma warning(disable: 4996) // _wfopen, etc.

#include "framework.h"
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <functional>

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Find Procmon executable on PATH or common locations
    // -----------------------------------------------------------------------
    inline std::wstring FindProcmon()
    {
        wchar_t buf[MAX_PATH];
        // Prefer native 64-bit Procmon — the 32-bit Procmon.exe is a wrapper
        // that extracts Procmon64.exe to %TEMP% and re-launches, which can fail
        // if exe execution from temp is restricted.

        // F4/R11: Use explicit search directories instead of SearchPathW(nullptr, ...)
        // which consults current directory and full PATH — vulnerable to
        // search-order hijacking by a malicious binary placed earlier in PATH
        // or in the working directory.
        //
        // Build explicit search path: System32 + known Sysinternals locations + PATH.
        // SearchPathW with explicit first argument does NOT search current directory.
        wchar_t sysDir[MAX_PATH];
        GetSystemDirectoryW(sysDir, MAX_PATH);
        std::wstring searchDirs = std::wstring(sysDir) +
            L";C:\\SysinternalsSuite;C:\\Tools";
        wchar_t pathEnv[8192];
        if (GetEnvironmentVariableW(L"PATH", pathEnv, 8192))
            searchDirs += L";" + std::wstring(pathEnv);

        const wchar_t* names[] = { L"Procmon64.exe", L"Procmon64a.exe", L"Procmon.exe" };
        for (const auto* n : names) {
            if (SearchPathW(searchDirs.c_str(), n, nullptr, MAX_PATH, buf, nullptr)) {
                // Verify result is absolute (drive letter or UNC path)
                if ((buf[0] >= L'A' && buf[0] <= L'Z' && buf[1] == L':') ||
                    (buf[0] >= L'a' && buf[0] <= L'z' && buf[1] == L':') ||
                    (buf[0] == L'\\' && buf[1] == L'\\'))
                    return buf;
            }
        }

        // Fallback: known absolute paths (already trusted)
        const wchar_t* paths[] = {
            L"C:\\SysinternalsSuite\\Procmon64.exe",  L"C:\\SysinternalsSuite\\Procmon.exe",
            L"C:\\Tools\\Procmon64.exe",              L"C:\\Tools\\Procmon.exe",
        };
        for (const auto* p : paths)
            if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES)
                return p;
        return L"";
    }

    // -----------------------------------------------------------------------
    // Helper: run a process and wait for its handle to signal
    // -----------------------------------------------------------------------
    inline bool RunProcAndWait(const std::wstring& cmdLine, DWORD timeoutMs = 30000,
                               const std::wstring& appPath = L"")
    {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        std::wstring cmd = cmdLine;
        const wchar_t* app = appPath.empty() ? nullptr : appPath.c_str();
        if (!CreateProcessW(app, &cmd[0], nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            return false;
        DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
        bool ok = (waitResult == WAIT_OBJECT_0);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 5000);
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return ok;
    }

    // -----------------------------------------------------------------------
    // Helper: poll until no Procmon processes remain (handles single-instance
    // delegation where the launcher exits before the real instance does)
    // -----------------------------------------------------------------------
    inline bool WaitForProcmonExit(DWORD timeoutMs = 15000)
    {
        DWORD elapsed = 0;
        const DWORD poll = 500;
        while (elapsed < timeoutMs) {
            Sleep(poll);
            elapsed += poll;
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE) break;
            PROCESSENTRY32W pe = { sizeof(pe) };
            bool found = false;
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"Procmon.exe") == 0 ||
                        _wcsicmp(pe.szExeFile, L"Procmon64.exe") == 0 ||
                        _wcsicmp(pe.szExeFile, L"Procmon64a.exe") == 0) {
                        found = true;
                        break;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
            if (!found) return true;
        }
        return false;  // timed out
    }

    // -----------------------------------------------------------------------
    // Helper: wait for the root process's live descendant tree to quiesce.
    // This lets trace mode capture differently-named child processes instead
    // of stopping as soon as the launcher/root process exits.
    // -----------------------------------------------------------------------
    inline bool WaitForProcessTreeExit(DWORD rootPid, DWORD timeoutMs = 30000)
    {
        if (rootPid == 0) return true;

        DWORD elapsed = 0;
        const DWORD poll = 500;
        while (elapsed < timeoutMs) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE)
                return false;

            std::map<DWORD, DWORD> parents;
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(snap, &pe)) {
                do {
                    parents[pe.th32ProcessID] = pe.th32ParentProcessID;
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);

            bool foundDescendant = false;
            for (const auto& it : parents) {
                DWORD parent = it.second;
                std::set<DWORD> seen;
                while (parent != 0 && seen.insert(parent).second) {
                    if (parent == rootPid) {
                        foundDescendant = true;
                        break;
                    }
                    auto pIt = parents.find(parent);
                    if (pIt == parents.end())
                        break;
                    parent = pIt->second;
                }
                if (foundDescendant)
                    break;
            }

            if (!foundDescendant)
                return true;

            Sleep(poll);
            elapsed += poll;
        }

        return false;
    }

    // -----------------------------------------------------------------------
    // Helper: poll until a file exists and stops growing (conversion done)
    // -----------------------------------------------------------------------
    inline bool WaitForFile(const std::wstring& path, DWORD timeoutMs = 60000)
    {
        DWORD elapsed = 0;
        const DWORD poll = 500;
        LARGE_INTEGER prevSize = {};
        int stableCount = 0;
        while (elapsed < timeoutMs) {
            Sleep(poll);
            elapsed += poll;
            WIN32_FILE_ATTRIBUTE_DATA info;
            if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &info))
                continue;  // not yet created
            LARGE_INTEGER sz;
            sz.LowPart = info.nFileSizeLow;
            sz.HighPart = info.nFileSizeHigh;
            if (sz.QuadPart > 0 && sz.QuadPart == prevSize.QuadPart)
                stableCount++;
            else
                stableCount = 0;
            prevSize = sz;
            if (stableCount >= 2) return true;  // stable for 1+ second
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Helper: get unique temp file path (PID + tick suffix avoids collisions)
    // -----------------------------------------------------------------------
    inline std::wstring AuditTempPath(const wchar_t* prefix, const wchar_t* ext)
    {
        wchar_t tmp[MAX_PATH];
        GetTempPathW(MAX_PATH, tmp);
        wchar_t buf[96];
        swprintf(buf, 96, L"%ls_%lu_%llu%ls", prefix,
                 GetCurrentProcessId(), GetTickCount64(), ext);
        return std::wstring(tmp) + buf;
    }


    // -----------------------------------------------------------------------
    // CSV field parser (handles quoted fields with commas)
    // -----------------------------------------------------------------------
    inline std::vector<std::string> ParseCsvLine(const std::string& line)
    {
        std::vector<std::string> fields;
        bool inQ = false;
        std::string f;
        for (size_t i = 0; i < line.size(); i++) {
            char c = line[i];
            if (c == '"') {
                if (inQ && i + 1 < line.size() && line[i + 1] == '"') { f += '"'; i++; }
                else inQ = !inQ;
            } else if (c == ',' && !inQ) { fields.push_back(f); f.clear(); }
            else f += c;
        }
        fields.push_back(f);
        return fields;
    }

    // -----------------------------------------------------------------------
    // Categorize Procmon operation
    // -----------------------------------------------------------------------
    inline const char* AuditCategory(const std::string& op)
    {
        if (op.find("Reg") == 0) return "REG";
        if (op.find("TCP") != std::string::npos || op.find("UDP") != std::string::npos) return "NET";
        if (op == "Process Create" || op == "Process Exit") return "PROCESS";
        if (op == "Thread Create" || op == "Thread Exit") return "THREAD";
        if (op == "Load Image") return "IMAGE";
        return "FILE";
    }

    // -----------------------------------------------------------------------
    // CSV column mapping — shared by WriteAuditLog and AnalyzeProfileCsv.
    // Opens a Procmon CSV, strips BOM, parses header, and locates columns.
    // -----------------------------------------------------------------------
    struct CsvReader {
        std::ifstream stream;
        int cTime = -1, cProc = -1, cPid = -1, cOp = -1;
        int cPath = -1, cRes  = -1, cDet = -1, cTid = -1;

        bool Open(const std::wstring& csvPath) {
            char csvPathA[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, csvPath.c_str(), -1, csvPathA, MAX_PATH, nullptr, nullptr);
            stream.open(csvPathA);
            if (!stream.is_open()) return false;

            std::string hdr;
            std::getline(stream, hdr);
            if (hdr.size() >= 3 && (unsigned char)hdr[0] == 0xEF) hdr = hdr.substr(3);
            auto cols = ParseCsvLine(hdr);

            for (int i = 0; i < (int)cols.size(); i++) {
                if      (cols[i] == "Time of Day")   cTime = i;
                else if (cols[i] == "Process Name")  cProc = i;
                else if (cols[i] == "PID")           cPid  = i;
                else if (cols[i] == "Operation")     cOp   = i;
                else if (cols[i] == "Path")          cPath = i;
                else if (cols[i] == "Result")        cRes  = i;
                else if (cols[i] == "Detail")        cDet  = i;
                else if (cols[i] == "TID")           cTid  = i;
            }
            return true;
        }
    };

    // -----------------------------------------------------------------------
    // Parse Procmon CSV → write audit log filtered by child PID tree.
    // Returns process tree text (for session log). Empty string on failure.
    // -----------------------------------------------------------------------
    inline std::string WriteAuditLog(const std::wstring& csvPath, const std::wstring& auditLogPath,
                              DWORD childPid)
    {
        CsvReader csv;
        if (!csv.Open(csvPath)) return "";
        if (csv.cPid < 0 || csv.cOp < 0 || csv.cRes < 0) return "";

        const int cTime = csv.cTime, cProc = csv.cProc, cPid = csv.cPid;
        const int cOp = csv.cOp, cPath = csv.cPath, cRes = csv.cRes;
        const int cDet = csv.cDet, cTid = csv.cTid;
        // --- Single pass: build PID tree and write events simultaneously ---
        std::set<DWORD> pidTree;
        pidTree.insert(childPid);

        struct ProcInfo {
            std::string name;
            DWORD parentPid = 0;
            std::string exitCode;
            bool exited = false;
        };
        std::map<DWORD, ProcInfo> procs;

        FILE* out = _wfopen(auditLogPath.c_str(), L"w");
        if (!out) return "";

        int counts[6] = {}; // FILE, REG, NET, PROCESS, THREAD, IMAGE
        int total = 0;
        std::set<std::string> seen;  // dedup keys

        std::string line;
        while (std::getline(csv.stream, line)) {
            auto f = ParseCsvLine(line);
            int minCols = cPid; if (cOp > minCols) minCols = cOp; if (cRes > minCols) minCols = cRes;
            if ((int)f.size() <= minCols) continue;

            const auto& op = f[cOp];

            // --- PID tree expansion + process tracking ---
            if (op == "Process Create" && cDet >= 0 && (int)f.size() > cDet) {
                DWORD parentPid = (DWORD)atoi(f[cPid].c_str());
                DWORD newPid = 0;
                auto pos = f[cDet].find("PID: ");
                if (pos != std::string::npos) newPid = (DWORD)atoi(f[cDet].c_str() + pos + 5);

                if (newPid == childPid || pidTree.count(parentPid)) {
                    pidTree.insert(newPid);
                    ProcInfo pi;
                    pi.parentPid = parentPid;
                    pi.name = (cPath >= 0 && (int)f.size() > cPath) ? f[cPath] : "unknown";
                    auto slash = pi.name.rfind('\\');
                    if (slash != std::string::npos) pi.name = pi.name.substr(slash + 1);
                    procs[newPid] = pi;
                }
            }

            if (op == "Process Exit") {
                DWORD pid = (DWORD)atoi(f[cPid].c_str());
                if (pidTree.count(pid) && cDet >= 0 && (int)f.size() > cDet) {
                    auto pos = f[cDet].find("Exit Status: ");
                    if (pos != std::string::npos) {
                        procs[pid].exitCode = f[cDet].substr(pos + 13);
                        auto comma = procs[pid].exitCode.find(',');
                        if (comma != std::string::npos) procs[pid].exitCode = procs[pid].exitCode.substr(0, comma);
                        procs[pid].exited = true;
                        if (procs[pid].name.empty() && cProc >= 0 && (int)f.size() > cProc)
                            procs[pid].name = f[cProc];
                    }
                }
            }

            // --- Filter and write events ---
            DWORD pid = (DWORD)atoi(f[cPid].c_str());
            if (!pidTree.count(pid)) continue;

            const auto& res = f[cRes];
            if (res == "SUCCESS" || res.empty()) continue;
            if (op == "Process Create" || op == "Process Exit" ||
                op == "Thread Create" || op == "Thread Exit") continue;

            const char* cat = AuditCategory(op);
            std::string path = (cPath >= 0 && (int)f.size() > cPath) ? f[cPath] : "";
            std::string timeStr = (cTime >= 0 && (int)f.size() > cTime) ? f[cTime] : "??:??:??.???";
            if (timeStr.size() > 12) timeStr = timeStr.substr(0, 12);
            std::string tid = (cTid >= 0 && (int)f.size() > cTid) ? f[cTid] : "?";

            // Dedup — skip repeats silently
            std::string key = std::string(cat) + "|" + path + "|" + res;
            if (!seen.insert(key).second) continue;

            char buf[1024];
            snprintf(buf, sizeof(buf), "[%s] T:%-6s %-7s %-20s %s",
                     timeStr.c_str(), tid.c_str(), cat, res.c_str(), path.c_str());
            fprintf(out, "%s\n", buf);
            total++;

            if (strcmp(cat, "FILE") == 0)    counts[0]++;
            else if (strcmp(cat, "REG") == 0)     counts[1]++;
            else if (strcmp(cat, "NET") == 0)     counts[2]++;
            else if (strcmp(cat, "PROCESS") == 0) counts[3]++;
            else if (strcmp(cat, "THREAD") == 0)  counts[4]++;
            else if (strcmp(cat, "IMAGE") == 0)   counts[5]++;
        }

        // Ensure root is in procs (for tree display)
        if (procs.find(childPid) == procs.end()) {
            ProcInfo pi; pi.name = "child";
            procs[childPid] = pi;
        }

        // --- Summary ---
        fprintf(out, "\n=== Summary: %d unique events", total);
        const char* catNames[] = { "FILE", "REG", "NET", "PROCESS", "THREAD", "IMAGE" };
        for (int i = 0; i < 6; i++)
            if (counts[i]) fprintf(out, ", %d %s", counts[i], catNames[i]);
        fprintf(out, " ===\n");

        fclose(out);

        // --- Build process tree text (returned for session log) ---
        std::string treeText;
        std::function<void(DWORD, int)> buildTree = [&](DWORD pid, int depth) {
            auto it = procs.find(pid);
            if (it == procs.end()) return;
            const auto& pi = it->second;

            std::string prefix(depth * 2, ' ');
            if (depth > 0) prefix += "+- ";

            const char* status = "RUNNING";
            if (pi.exited) {
                if (pi.exitCode == "0") status = "OK";
                else if (pi.exitCode.find("C000") != std::string::npos) status = "CRASHED";
                else status = "FAILED";
            }

            char buf[256];
            snprintf(buf, sizeof(buf), "%s%s  PID:%lu  exit:%s  %s\n",
                    prefix.c_str(), pi.name.c_str(), (unsigned long)pid,
                    pi.exited ? pi.exitCode.c_str() : "?", status);
            treeText += buf;

            for (const auto& p : procs)
                if (p.second.parentPid == pid && p.first != pid)
                    buildTree(p.first, depth + 1);
        };
        buildTree(childPid, 0);

        return treeText;
    }

    // -----------------------------------------------------------------------
    // Write Procmon FilterRules to registry: include only the target process
    // Binary format: 1-byte version (01), 4-byte rule count,
    //   per rule: col (4B), rel (4B), action (1B), strlen (4B), UTF-16LE, 8B pad
    // -----------------------------------------------------------------------
    inline bool WriteProcmonIncludeFilter(const std::wstring& processName)
    {
        // Rule binary: col=0x9C75 (Process Name), rel=0 (is), action=1 (Include)
        const DWORD col = 0x9C75;
        const DWORD rel = 0;
        const BYTE  act = 1; // Include
        DWORD nameBytes = (DWORD)(processName.size() + 1) * sizeof(wchar_t);

        // Total: header(5) + rule(4+4+1+4+nameBytes+8)
        DWORD ruleSize = 4 + 4 + 1 + 4 + nameBytes + 8;
        DWORD totalSize = 5 + ruleSize;
        std::vector<BYTE> buf(totalSize, 0);

        BYTE* p = buf.data();
        *p++ = 1;                                  // version
        memcpy(p, "\x01\x00\x00\x00", 4); p += 4; // count = 1

        memcpy(p, &col, 4); p += 4;
        memcpy(p, &rel, 4); p += 4;
        *p++ = act;
        memcpy(p, &nameBytes, 4); p += 4;
        memcpy(p, processName.c_str(), nameBytes); p += nameBytes;
        // 8 bytes padding (already zeroed)

        HKEY hk;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Sysinternals\\Process Monitor",
                         0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return false;
        LONG rc = RegSetValueExW(hk, L"FilterRules", 0, REG_BINARY, buf.data(), totalSize);
        RegCloseKey(hk);
        return rc == ERROR_SUCCESS;
    }

    // -----------------------------------------------------------------------
    // Backup current Procmon FilterRules registry value.
    // Returns empty vector if no prior filter exists.
    // -----------------------------------------------------------------------
    inline std::vector<BYTE> BackupProcmonFilter()
    {
        std::vector<BYTE> backup;
        HKEY hk;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Sysinternals\\Process Monitor",
                         0, KEY_QUERY_VALUE, &hk) != ERROR_SUCCESS)
            return backup;
        DWORD type = 0, size = 0;
        if (RegQueryValueExW(hk, L"FilterRules", nullptr, &type, nullptr, &size) == ERROR_SUCCESS
            && type == REG_BINARY && size > 0) {
            backup.resize(size);
            RegQueryValueExW(hk, L"FilterRules", nullptr, nullptr, backup.data(), &size);
        }
        RegCloseKey(hk);
        return backup;
    }

    // -----------------------------------------------------------------------
    // Restore Procmon FilterRules from backup.
    // If backup is empty (no prior filter), deletes the value.
    // -----------------------------------------------------------------------
    inline void RestoreProcmonFilter(const std::vector<BYTE>& backup)
    {
        HKEY hk;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Sysinternals\\Process Monitor",
                         0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return;
        if (backup.empty()) {
            RegDeleteValueW(hk, L"FilterRules");
        } else {
            RegSetValueExW(hk, L"FilterRules", 0, REG_BINARY,
                          backup.data(), static_cast<DWORD>(backup.size()));
        }
        RegCloseKey(hk);
    }

    struct ProcmonFilterScope {
        std::vector<BYTE> backup;
        bool active = false;

        ProcmonFilterScope()
            : backup(BackupProcmonFilter()), active(true) {}

        void RestoreNow()
        {
            if (!active) return;
            RestoreProcmonFilter(backup);
            active = false;
        }

        ~ProcmonFilterScope()
        {
            RestoreNow();
        }
    };

    struct ProcmonCaptureScope {
        std::wstring procmonPath;
        std::wstring pmlPath;
        bool active = false;

        ProcmonCaptureScope() = default;

        ProcmonCaptureScope(const std::wstring& procmonExe,
                            const std::wstring& pml)
            : procmonPath(procmonExe), pmlPath(pml), active(true) {}

        void Dismiss()
        {
            active = false;
        }

        ~ProcmonCaptureScope()
        {
            if (!active || procmonPath.empty())
                return;
            RunProcAndWait(L"\"" + procmonPath + L"\" /Terminate", 10000, procmonPath);
            WaitForProcmonExit(10000);
            if (!pmlPath.empty()) {
                DeleteFileW(pmlPath.c_str());
                std::wstring csvPath = pmlPath;
                auto dot = csvPath.rfind(L'.');
                if (dot != std::wstring::npos)
                    csvPath = csvPath.substr(0, dot);
                csvPath += L".csv";
                DeleteFileW(csvPath.c_str());
            }
        }
    };

    // -----------------------------------------------------------------------
    // Check if any Procmon instance is currently running.
    // -----------------------------------------------------------------------
    inline bool IsProcmonRunning()
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe = { sizeof(pe) };
        bool found = false;
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"Procmon.exe") == 0 ||
                    _wcsicmp(pe.szExeFile, L"Procmon64.exe") == 0 ||
                    _wcsicmp(pe.szExeFile, L"Procmon64a.exe") == 0) {
                    found = true;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return found;
    }

    // -----------------------------------------------------------------------
    // Launch Procmon for capture — shared by audit and trace modes.
    // Refuses to proceed if Procmon is already running (to avoid killing
    // an unrelated user session). Starts a new instance with the given
    // backing file, and waits for the PML file to appear.
    // pmlPathOut receives the unique PML path for later stop/convert.
    // -----------------------------------------------------------------------
    inline bool LaunchProcmon(const std::wstring& procmonPath,
                              const wchar_t* tag, std::wstring& pmlPathOut,
                              DWORD startupSleepMs = 0)
    {
        pmlPathOut = AuditTempPath(L"sandy_audit", L".pml");
        DeleteFileW(pmlPathOut.c_str());

        // Refuse to proceed if Procmon is already running — we must not
        // kill an unrelated user debugging session.
        if (IsProcmonRunning()) {
            fprintf(stderr, "[%ls] Procmon is already running. Close it first to use Sandy %ls mode.\n",
                    tag, tag);
            return false;
        }

        // Start Procmon headless with backing file — CREATE_NO_WINDOW + SW_HIDE
        // ensures no UI appears even momentarily.
        std::wstring cmd = L"\"" + procmonPath + L"\" /Quiet /Minimized /AcceptEula "
                           L"/BackingFile \"" + pmlPathOut + L"\"";

        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(procmonPath.c_str(), &cmd[0], nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            fprintf(stderr, "[%ls] Failed to start Procmon (error %lu).\n", tag, GetLastError());
            return false;
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (!WaitForFile(pmlPathOut, 10000)) {
            fprintf(stderr, "[%ls] Procmon did not start capturing.\n", tag);
            // F5/R9: Kill the Procmon instance we just started to avoid leaking it
            RunProcAndWait(L"\"" + procmonPath + L"\" /Terminate", 10000, procmonPath);
            WaitForProcmonExit(10000);
            return false;
        }
        if (startupSleepMs > 0) Sleep(startupSleepMs);
        return true;
    }

    // -----------------------------------------------------------------------
    // Start Procmon for trace mode.
    // Capture-all is intentional: filtering by process name misses differently-
    // named descendants and forces Sandy to mutate the user's Procmon profile.
    // -----------------------------------------------------------------------
    inline bool StartProcmonProfile(const std::wstring& procmonPath, const std::wstring& exeName,
                                     std::wstring& pmlPathOut)
    {
        (void)exeName;
        // 3s sleep lets the kernel driver fully initialize before profiling
        return LaunchProcmon(procmonPath, L"Profile", pmlPathOut, 3000);
    }

    // -----------------------------------------------------------------------
    // Start Procmon audit (call BEFORE launching child process)
    // pmlPathOut receives the unique PML path for StopProcmonAudit.
    // -----------------------------------------------------------------------
    inline bool StartProcmonAudit(const std::wstring& procmonPath, std::wstring& pmlPathOut)
    {
        return LaunchProcmon(procmonPath, L"Audit", pmlPathOut);
    }

    // -----------------------------------------------------------------------
    // Terminate Procmon and convert PML → CSV.  Shared by audit/trace.
    // Returns true if csvPath was created successfully.
    // -----------------------------------------------------------------------
    inline bool StopAndConvertProcmon(const std::wstring& procmonPath,
                                     const std::wstring& pmlPath,
                                     const std::wstring& csvPath,
                                     const wchar_t* tag)
    {
        RunProcAndWait(L"\"" + procmonPath + L"\" /Terminate", 10000, procmonPath);
        if (!WaitForProcmonExit(15000))
            fprintf(stderr, "[%ls] Warning: Procmon did not exit cleanly.\n", tag);

        if (GetFileAttributesW(pmlPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "[%ls] PML log file not found — Procmon may not have captured.\n", tag);
            return false;
        }

        // Delete stale CSV from a previous run before conversion
        DeleteFileW(csvPath.c_str());

        std::wstring cvt = L"\"" + procmonPath + L"\" /Quiet /AcceptEula "
                           L"/OpenLog \"" + pmlPath + L"\" /SaveAs \"" + csvPath + L"\"";
        RunProcAndWait(cvt, 60000, procmonPath);

        if (!WaitForFile(csvPath, 60000)) {
            WaitForProcmonExit(30000);
            if (GetFileAttributesW(csvPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                fprintf(stderr, "[%ls] CSV export failed — Procmon did not produce output.\n", tag);
                DeleteFileW(pmlPath.c_str());
                return false;
            }
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // Stop Procmon audit and generate audit log (call AFTER child exits).
    // pmlPath must be the path returned by StartProcmonAudit.
    // Returns process tree text for session log. Empty string on failure.
    // -----------------------------------------------------------------------
    inline std::string StopProcmonAudit(const std::wstring& procmonPath,
                                 const std::wstring& auditLogPath,
                                 const std::wstring& pmlPath, DWORD childPid)
    {
        // Derive CSV path from PML path (same unique suffix, different extension)
        std::wstring csvPath = pmlPath;
        auto dot = csvPath.rfind(L'.');
        if (dot != std::wstring::npos) csvPath = csvPath.substr(0, dot);
        csvPath += L".csv";

        if (!StopAndConvertProcmon(procmonPath, pmlPath, csvPath, L"Audit"))
            return "";

        std::string treeText = WriteAuditLog(csvPath, auditLogPath, childPid);
        if (treeText.empty())
            fprintf(stderr, "[Audit] Failed to parse audit data.\n");

        DeleteFileW(pmlPath.c_str());
        DeleteFileW(csvPath.c_str());
        return treeText;
    }

} // namespace Sandbox

#pragma warning(pop)
