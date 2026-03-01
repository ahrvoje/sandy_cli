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
#include <sstream>
#include <algorithm>
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
        for (auto n : names)
            if (SearchPathW(nullptr, n, nullptr, MAX_PATH, buf, nullptr))
                return buf;

        const wchar_t* paths[] = {
            L"C:\\SysinternalsSuite\\Procmon64.exe",  L"C:\\SysinternalsSuite\\Procmon.exe",
            L"C:\\Tools\\Procmon64.exe",              L"C:\\Tools\\Procmon.exe",
        };
        for (auto p : paths)
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
    // Create PMC filter: exclude only Procmon noise, keep everything else
    // (PID filtering done in post-processing so we capture process tree)
    // -----------------------------------------------------------------------
    inline bool CreateAuditFilter(const std::wstring& pmcPath)
    {
        FILE* f = _wfopen(pmcPath.c_str(), L"w");
        if (!f) return false;
        fprintf(f,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<procmon>\n"
            "  <DestructiveFilter>0</DestructiveFilter>\n"
            "  <FilterRules>\n"
            "    <FilterRule><Column>Process Name</Column><Relation>is</Relation>"
            "<Action>Exclude</Action><Value>Procmon.exe</Value></FilterRule>\n"
            "    <FilterRule><Column>Process Name</Column><Relation>is</Relation>"
            "<Action>Exclude</Action><Value>Procmon64.exe</Value></FilterRule>\n"
            "    <FilterRule><Column>Result</Column><Relation>is</Relation>"
            "<Action>Exclude</Action><Value>SUCCESS</Value></FilterRule>\n"
            "    <FilterRule><Column>Result</Column><Relation>is</Relation>"
            "<Action>Exclude</Action><Value>REPARSE</Value></FilterRule>\n"
            "    <FilterRule><Column>Result</Column><Relation>is</Relation>"
            "<Action>Exclude</Action><Value>NO MORE ENTRIES</Value></FilterRule>\n"
            "    <FilterRule><Column>Result</Column><Relation>is</Relation>"
            "<Action>Exclude</Action><Value>NO MORE FILES</Value></FilterRule>\n"
            "    <FilterRule><Column>Result</Column><Relation>is</Relation>"
            "<Action>Exclude</Action><Value>END OF FILE</Value></FilterRule>\n"
            "    <FilterRule><Column>Result</Column><Relation>is</Relation>"
            "<Action>Exclude</Action><Value>FAST IO DISALLOWED</Value></FilterRule>\n"
            "    <FilterRule><Column>Result</Column><Relation>begins with</Relation>"
            "<Action>Exclude</Action><Value>BUFFER</Value></FilterRule>\n"
            "  </FilterRules>\n"
            "</procmon>\n");
        fclose(f);
        return true;
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
    // Parse Procmon CSV → write audit log filtered by child PID tree
    // -----------------------------------------------------------------------
    inline bool WriteAuditLog(const std::wstring& csvPath, const std::wstring& auditLogPath,
                              DWORD childPid)
    {
        // Convert wchar path to narrow for ifstream
        char csvPathA[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, csvPath.c_str(), -1, csvPathA, MAX_PATH, nullptr, nullptr);
        std::ifstream csv(csvPathA);
        if (!csv.is_open()) return false;

        // Find column indices from header
        std::string hdr;
        std::getline(csv, hdr);
        // Strip BOM if present
        if (hdr.size() >= 3 && (unsigned char)hdr[0] == 0xEF) hdr = hdr.substr(3);
        auto cols = ParseCsvLine(hdr);

        int cTime = -1, cProc = -1, cPid = -1, cOp = -1, cPath = -1, cRes = -1, cDet = -1, cTid = -1;
        for (int i = 0; i < (int)cols.size(); i++) {
            if (cols[i] == "Time of Day") cTime = i;
            else if (cols[i] == "Process Name") cProc = i;
            else if (cols[i] == "PID") cPid = i;
            else if (cols[i] == "Operation") cOp = i;
            else if (cols[i] == "Path") cPath = i;
            else if (cols[i] == "Result") cRes = i;
            else if (cols[i] == "Detail") cDet = i;
            else if (cols[i] == "TID") cTid = i;
        }
        if (cPid < 0 || cOp < 0 || cRes < 0) return false;

        // --- Pass 1: build process tree ---
        std::set<DWORD> pidTree;
        pidTree.insert(childPid);

        struct ProcInfo {
            std::string name;
            DWORD parentPid = 0, pid = 0;
            std::string exitCode;
            bool exited = false;
        };
        std::map<DWORD, ProcInfo> procs;

        std::vector<std::string> allLines;
        std::string line;
        while (std::getline(csv, line)) {
            allLines.push_back(line);
            auto f = ParseCsvLine(line);
            if ((int)f.size() <= cOp) continue;

            if (f[cOp] == "Process Create" && cDet >= 0 && (int)f.size() > cDet) {
                DWORD parentPid = (DWORD)atoi(f[cPid].c_str());
                // Detail: "PID: 1234, Parent PID: 5678, ..."
                DWORD newPid = 0;
                auto pos = f[cDet].find("PID: ");
                if (pos != std::string::npos) newPid = (DWORD)atoi(f[cDet].c_str() + pos + 5);

                if (newPid == childPid || pidTree.count(parentPid)) {
                    pidTree.insert(newPid);
                    ProcInfo pi;
                    pi.pid = newPid;
                    pi.parentPid = parentPid;
                    pi.name = (cPath >= 0 && (int)f.size() > cPath) ? f[cPath] : "unknown";
                    auto slash = pi.name.rfind('\\');
                    if (slash != std::string::npos) pi.name = pi.name.substr(slash + 1);
                    procs[newPid] = pi;
                }
            }

            if (f[cOp] == "Process Exit") {
                DWORD pid = (DWORD)atoi(f[cPid].c_str());
                if (pidTree.count(pid) && cDet >= 0 && (int)f.size() > cDet) {
                    auto pos = f[cDet].find("Exit Status: ");
                    if (pos != std::string::npos) {
                        procs[pid].exitCode = f[cDet].substr(pos + 13);
                        // Trim trailing comma/space
                        auto comma = procs[pid].exitCode.find(',');
                        if (comma != std::string::npos) procs[pid].exitCode = procs[pid].exitCode.substr(0, comma);
                        procs[pid].exited = true;
                        procs[pid].pid = pid;
                        if (procs[pid].name.empty() && cProc >= 0 && (int)f.size() > cProc)
                            procs[pid].name = f[cProc];
                    }
                }
            }
        }

        // Ensure root is in procs
        if (procs.find(childPid) == procs.end()) {
            ProcInfo pi; pi.pid = childPid; pi.name = "child";
            procs[childPid] = pi;
        }

        // --- Pass 2: filter events by PID tree, write audit log ---
        FILE* out = _wfopen(auditLogPath.c_str(), L"w");
        if (!out) return false;

        int counts[6] = {}; // FILE, REG, NET, PROCESS, THREAD, IMAGE
        int total = 0;
        std::map<std::string, int> dedup;          // key → count
        std::vector<std::string> dedupOrder;       // ordered keys
        std::vector<std::string> outputLines;      // formatted lines

        for (const auto& ln : allLines) {
            auto f = ParseCsvLine(ln);
            int minCols = cPid; if (cOp > minCols) minCols = cOp; if (cRes > minCols) minCols = cRes;
            if ((int)f.size() <= minCols) continue;

            DWORD pid = (DWORD)atoi(f[cPid].c_str());
            if (!pidTree.count(pid)) continue;

            const auto& op = f[cOp];
            const auto& res = f[cRes];
            if (res == "SUCCESS" || res.empty()) continue;
            if (op == "Process Create" || op == "Process Exit" ||
                op == "Thread Create" || op == "Thread Exit") continue;

            const char* cat = AuditCategory(op);
            std::string path = (cPath >= 0 && (int)f.size() > cPath) ? f[cPath] : "";
            std::string timeStr = (cTime >= 0 && (int)f.size() > cTime) ? f[cTime] : "??:??:??.???";
            if (timeStr.size() > 12) timeStr = timeStr.substr(0, 12);
            std::string tid = (cTid >= 0 && (int)f.size() > cTid) ? f[cTid] : "?";

            // Dedup
            std::string key = std::string(cat) + "|" + path + "|" + res;
            if (dedup.count(key)) { dedup[key]++; continue; }
            dedup[key] = 1;
            dedupOrder.push_back(key);

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

        // --- Process tree ---
        fprintf(out, "\n=== Process Tree ===\n");
        std::function<void(DWORD, int)> printTree = [&](DWORD pid, int depth) {
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

            fprintf(out, "%s%s  PID:%lu  exit:%s  %s\n",
                    prefix.c_str(), pi.name.c_str(), (unsigned long)pid,
                    pi.exited ? pi.exitCode.c_str() : "?", status);

            for (const auto& p : procs)
                if (p.second.parentPid == pid && p.first != pid)
                    printTree(p.first, depth + 1);
        };
        printTree(childPid, 0);

        // --- Summary ---
        fprintf(out, "\n=== Summary: %d unique events", total);
        const char* catNames[] = { "FILE", "REG", "NET", "PROCESS", "THREAD", "IMAGE" };
        for (int i = 0; i < 6; i++)
            if (counts[i]) fprintf(out, ", %d %s", counts[i], catNames[i]);
        fprintf(out, " ===\n");

        // --- Repeated events ---
        bool hasRepeats = false;
        for (const auto& key : dedupOrder) {
            if (dedup[key] > 1) {
                if (!hasRepeats) { fprintf(out, "\n=== Repeated (x count) ===\n"); hasRepeats = true; }
                auto s1 = key.find('|'), s2 = key.find('|', s1 + 1);
                fprintf(out, "  x%-4d %-7s %-20s %s\n", dedup[key],
                        key.substr(0, s1).c_str(),
                        key.substr(s2 + 1).c_str(),
                        key.substr(s1 + 1, s2 - s1 - 1).c_str());
            }
        }

        fclose(out);
        return true;
    }

    // -----------------------------------------------------------------------
    // Start Procmon audit (call BEFORE launching child process)
    // -----------------------------------------------------------------------
    inline bool StartProcmonAudit(const std::wstring& procmonPath)
    {
        std::wstring pmlPath = AuditTempPath(L"sandy_audit.pml");
        DeleteFileW(pmlPath.c_str());

        // Kill any existing Procmon instance and wait for it to fully exit
        RunProcAndWait(L"\"" + procmonPath + L"\" /Terminate", 5000);
        WaitForProcmonExit(10000);

        // Launch Procmon headless (no /LoadConfig — PMC XML causes Procmon
        // to apply settings and exit; all filtering is done in post-processing)
        std::wstring cmd = L"\"" + procmonPath + L"\" /Quiet /Minimized /AcceptEula "
                           L"/BackingFile \"" + pmlPath + L"\"";

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        std::wstring mut = cmd;
        if (!CreateProcessW(nullptr, &mut[0], nullptr, nullptr, FALSE,
                           0, nullptr, nullptr, &si, &pi)) {
            fprintf(stderr, "[Audit] Failed to start Procmon (error %lu).\n", GetLastError());
            return false;
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // Wait for PML file to appear (confirms driver loaded and capture started)
        if (!WaitForFile(pmlPath, 10000)) {
            fprintf(stderr, "[Audit] Procmon did not start capturing.\n");
            return false;
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // Stop Procmon audit and generate audit log (call AFTER child exits)
    // -----------------------------------------------------------------------
    inline bool StopProcmonAudit(const std::wstring& procmonPath,
                                 const std::wstring& auditLogPath, DWORD childPid)
    {
        std::wstring pmlPath = AuditTempPath(L"sandy_audit.pml");
        std::wstring csvPath = AuditTempPath(L"sandy_audit.csv");

        // Terminate Procmon — send the command, then poll until all
        // Procmon processes are gone (handles single-instance delegation)
        RunProcAndWait(L"\"" + procmonPath + L"\" /Terminate", 10000);
        if (!WaitForProcmonExit(15000))
            fprintf(stderr, "[Audit] Warning: Procmon did not exit cleanly.\n");

        // Verify PML exists before attempting conversion
        if (GetFileAttributesW(pmlPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "[Audit] PML log file not found — Procmon may not have captured.\n");
            return false;
        }

        // Convert PML → CSV
        std::wstring cvt = L"\"" + procmonPath + L"\" /Quiet /AcceptEula "
                           L"/OpenLog \"" + pmlPath + L"\" /SaveAs \"" + csvPath + L"\"";
        RunProcAndWait(cvt, 60000);

        // Poll until CSV appears and stabilizes (Procmon writes async)
        if (!WaitForFile(csvPath, 60000)) {
            // Procmon may still be running from the conversion
            WaitForProcmonExit(30000);
            // One more check after Procmon exits
            if (GetFileAttributesW(csvPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                fprintf(stderr, "[Audit] CSV export failed — Procmon did not produce output.\n");
                DeleteFileW(pmlPath.c_str());
                return false;
            }
        }

        // Parse CSV and write audit log
        bool ok = WriteAuditLog(csvPath, auditLogPath, childPid);
        if (!ok)
            fprintf(stderr, "[Audit] Failed to parse audit data.\n");

        // Cleanup temps
        DeleteFileW(pmlPath.c_str());
        DeleteFileW(csvPath.c_str());
        return ok;
    }

    // -----------------------------------------------------------------------
    // WER crash dump helpers — configures Windows Error Reporting to write
    // a minidump when the sandboxed process crashes.
    // -----------------------------------------------------------------------

    // Enable WER LocalDumps for a specific executable name.
    // Uses the default %LOCALAPPDATA%\CrashDumps folder.
    inline bool EnableCrashDumps(const std::wstring& exeName)
    {
        std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\" + exeName;
        HKEY hKey = nullptr;
        DWORD disp = 0;
        LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, nullptr,
                                   REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, &disp);
        if (rc != ERROR_SUCCESS) return false;

        // DumpType = 1 (MiniDump with thread/stack info, ~256KB)
        DWORD dumpType = 1;
        RegSetValueExW(hKey, L"DumpType", 0, REG_DWORD, (const BYTE*)&dumpType, sizeof(dumpType));

        // DumpCount = 3
        DWORD dumpCount = 3;
        RegSetValueExW(hKey, L"DumpCount", 0, REG_DWORD, (const BYTE*)&dumpCount, sizeof(dumpCount));

        RegCloseKey(hKey);
        return true;
    }

    // Remove the WER LocalDumps registry key for a specific executable.
    inline void DisableCrashDumps(const std::wstring& exeName)
    {
        std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\" + exeName;
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str());
    }

    // Check if exit code looks like a native crash.
    // Covers NTSTATUS codes (0xC000xxxx) and C runtime abort() (exit code 3).
    inline bool IsCrashExitCode(DWORD exitCode)
    {
        if ((exitCode & 0xF0000000) == 0xC0000000) return true;  // NTSTATUS
        if (exitCode == 3) return true;                           // abort()
        return false;
    }

    // Find a crash dump in %LOCALAPPDATA%\CrashDumps matching exeName.
    // If auditLogPath is set, copies the dump next to it (audit.log -> audit.dmp).
    inline std::wstring ReportCrashDump(const std::wstring& exeName,
                                         const std::wstring& auditLogPath)
    {
        wchar_t localAppData[MAX_PATH];
        if (!GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH))
            return L"";
        std::wstring dumpDir = std::wstring(localAppData) + L"\\CrashDumps";

        // Search for <exeName>*.dmp (e.g. "python.exe.1234.dmp")
        std::wstring pattern = dumpDir + L"\\" + exeName + L"*.dmp";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) return L"";

        std::wstring bestName;
        FILETIME bestTime = {};
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                if (CompareFileTime(&fd.ftLastWriteTime, &bestTime) > 0) {
                    bestTime = fd.ftLastWriteTime;
                    bestName = fd.cFileName;
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);

        if (bestName.empty()) return L"";

        std::wstring srcPath = dumpDir + L"\\" + bestName;

        // Copy dump next to the audit log (audit.log -> audit.dmp)
        std::wstring dstPath;
        if (!auditLogPath.empty()) {
            dstPath = auditLogPath;
            auto dot = dstPath.rfind(L'.');
            if (dot != std::wstring::npos)
                dstPath = dstPath.substr(0, dot);
            dstPath += L".dmp";
            CopyFileW(srcPath.c_str(), dstPath.c_str(), FALSE);
        } else {
            dstPath = srcPath;
        }

        return dstPath;
    }

} // namespace Sandbox

#pragma warning(pop)
