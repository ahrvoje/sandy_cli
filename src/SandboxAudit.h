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
        const wchar_t* names[] = { L"Procmon64.exe", L"Procmon64a.exe", L"Procmon.exe" };
        for (const auto* n : names)
            if (SearchPathW(nullptr, n, nullptr, MAX_PATH, buf, nullptr))
                return buf;

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
    inline bool RunProcAndWait(const std::wstring& cmdLine, DWORD timeoutMs = 30000)
    {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        std::wstring cmd = cmdLine;
        if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            return false;
        WaitForSingleObject(pi.hProcess, timeoutMs);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
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
    // Helper: get temp file path
    // -----------------------------------------------------------------------
    inline std::wstring AuditTempPath(const wchar_t* name)
    {
        wchar_t tmp[MAX_PATH];
        GetTempPathW(MAX_PATH, tmp);
        return std::wstring(tmp) + name;
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
    // Launch Procmon for capture — shared by audit and profile modes.
    // Terminates any existing instance, starts a new one with the given
    // backing file, and waits for the PML file to appear.
    // -----------------------------------------------------------------------
    inline bool LaunchProcmon(const std::wstring& procmonPath,
                              const wchar_t* tag, DWORD startupSleepMs = 0)
    {
        std::wstring pmlPath = AuditTempPath(L"sandy_audit.pml");
        DeleteFileW(pmlPath.c_str());

        // Kill any existing Procmon instance and wait for it to fully exit
        RunProcAndWait(L"\"" + procmonPath + L"\" /Terminate", 5000);
        WaitForProcmonExit(10000);

        // Start Procmon headless with backing file
        std::wstring cmd = L"\"" + procmonPath + L"\" /Quiet /Minimized /AcceptEula "
                           L"/BackingFile \"" + pmlPath + L"\"";

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                           0, nullptr, nullptr, &si, &pi)) {
            fprintf(stderr, "[%ls] Failed to start Procmon (error %lu).\n", tag, GetLastError());
            return false;
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (!WaitForFile(pmlPath, 10000)) {
            fprintf(stderr, "[%ls] Procmon did not start capturing.\n", tag);
            return false;
        }
        if (startupSleepMs > 0) Sleep(startupSleepMs);
        return true;
    }

    // -----------------------------------------------------------------------
    // Start Procmon for profile mode with include filter for target process
    // -----------------------------------------------------------------------
    inline bool StartProcmonProfile(const std::wstring& procmonPath, const std::wstring& exeName)
    {
        // Write FilterRules to registry: include only the target process name.
        // Procmon reads this at startup, so it must be set before launch.
        if (!WriteProcmonIncludeFilter(exeName)) {
            fprintf(stderr, "[Profile] Failed to set Procmon filter.\n");
            return false;
        }
        // 3s sleep lets the kernel driver fully initialize before profiling
        return LaunchProcmon(procmonPath, L"Profile", 3000);
    }

    // -----------------------------------------------------------------------
    // Start Procmon audit (call BEFORE launching child process)
    // -----------------------------------------------------------------------
    inline bool StartProcmonAudit(const std::wstring& procmonPath)
    {
        return LaunchProcmon(procmonPath, L"Audit");
    }

    // -----------------------------------------------------------------------
    // Terminate Procmon and convert PML → CSV.  Shared by audit/profile.
    // Returns true if csvPath was created successfully.
    // -----------------------------------------------------------------------
    inline bool StopAndConvertProcmon(const std::wstring& procmonPath,
                                     const std::wstring& pmlPath,
                                     const std::wstring& csvPath,
                                     const wchar_t* tag)
    {
        RunProcAndWait(L"\"" + procmonPath + L"\" /Terminate", 10000);
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
        RunProcAndWait(cvt, 60000);

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
    // Returns process tree text for session log. Empty string on failure.
    // -----------------------------------------------------------------------
    inline std::string StopProcmonAudit(const std::wstring& procmonPath,
                                 const std::wstring& auditLogPath, DWORD childPid)
    {
        std::wstring pmlPath = AuditTempPath(L"sandy_audit.pml");
        std::wstring csvPath = AuditTempPath(L"sandy_audit.csv");

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
