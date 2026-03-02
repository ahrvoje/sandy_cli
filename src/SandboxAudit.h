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
    // Parse Procmon CSV → write audit log filtered by child PID tree.
    // Returns process tree text (for session log). Empty string on failure.
    // -----------------------------------------------------------------------
    inline std::string WriteAuditLog(const std::wstring& csvPath, const std::wstring& auditLogPath,
                              DWORD childPid)
    {
        // Convert wchar path to narrow for ifstream
        char csvPathA[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, csvPath.c_str(), -1, csvPathA, MAX_PATH, nullptr, nullptr);
        std::ifstream csv(csvPathA);
        if (!csv.is_open()) return "";

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
        if (cPid < 0 || cOp < 0 || cRes < 0) return "";
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
        while (std::getline(csv, line)) {
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
    // Start Procmon for profile mode with include filter for target process
    // -----------------------------------------------------------------------
    inline bool StartProcmonProfile(const std::wstring& procmonPath, const std::wstring& exeName)
    {
        std::wstring pmlPath = AuditTempPath(L"sandy_audit.pml");
        DeleteFileW(pmlPath.c_str());

        // Write FilterRules to registry: include only the target process name.
        // Procmon reads this at startup, so it must be set before launch.
        if (!WriteProcmonIncludeFilter(exeName)) {
            fprintf(stderr, "[Profile] Failed to set Procmon filter.\n");
            return false;
        }

        // Kill any existing Procmon instance
        RunProcAndWait(L"\"" + procmonPath + L"\" /Terminate", 5000);
        WaitForProcmonExit(10000);

        // Start capture — Procmon reads FilterRules from registry at startup
        std::wstring cmd = L"\"" + procmonPath + L"\" /Quiet /Minimized /AcceptEula "
                           L"/BackingFile \"" + pmlPath + L"\"";

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                           0, nullptr, nullptr, &si, &pi)) {
            fprintf(stderr, "[Profile] Failed to start Procmon (error %lu).\n", GetLastError());
            return false;
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (!WaitForFile(pmlPath, 10000)) {
            fprintf(stderr, "[Profile] Procmon did not start capturing.\n");
            return false;
        }
        // Let the kernel driver fully initialize
        Sleep(3000);
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
        if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
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
    // Stop Procmon audit and generate audit log (call AFTER child exits).
    // Returns process tree text for session log. Empty string on failure.
    // -----------------------------------------------------------------------
    inline std::string StopProcmonAudit(const std::wstring& procmonPath,
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
            return "";
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
                return "";
            }
        }

        // Parse CSV and write audit log
        std::string treeText = WriteAuditLog(csvPath, auditLogPath, childPid);
        if (treeText.empty())
            fprintf(stderr, "[Audit] Failed to parse audit data.\n");

        // Cleanup temps
        DeleteFileW(pmlPath.c_str());
        DeleteFileW(csvPath.c_str());
        return treeText;
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

    // =====================================================================
    // Profile analysis — run unsandboxed with Procmon, classify resource
    // usage, and generate a compatibility report with suggested TOML config.
    // =====================================================================

    struct ProfileResult {
        // Access buckets (deduplicated directory-level paths)
        std::set<std::string> readDirs;       // directories read
        std::set<std::string> writeDirs;      // directories written
        std::set<std::string> exeDirs;        // directories executed from (DLL loads)

        // Flags detected
        bool usesNetwork = false;
        bool usesLocalhost = false;
        bool usesNamedPipes = false;
        bool usesCOM = false;
        bool writesUserProfile = false;
        bool writesSystemDirs = false;
        bool writesRegistry = false;         // HKCU writes
        bool writesHKLM = false;             // HKLM writes (unsandboxable)
        bool needsSystemDirs = false;        // loads DLLs from Windows/System32
        bool spawnsChildren = false;

        // Counts
        int totalEvents = 0;
        int fileEvents = 0;
        int regEvents = 0;
        int netEvents = 0;
        int pipeEvents = 0;
        int comEvents = 0;
        DWORD exitCode = 0;
    };

    // Normalize a file path to its parent directory for grouping
    inline std::string PathToDir(const std::string& path)
    {
        auto slash = path.find_last_of("\\/");
        if (slash != std::string::npos) return path.substr(0, slash);
        return path;
    }

    // Check if path is under a system directory
    inline bool IsSystemDir(const std::string& p)
    {
        // Case-insensitive prefix check
        auto lower = p;
        for (auto& c : lower) c = (char)tolower((unsigned char)c);
        return lower.find("c:\\windows") == 0 ||
               lower.find("c:\\program files") == 0;
    }

    inline bool IsUserProfile(const std::string& p)
    {
        auto lower = p;
        for (auto& c : lower) c = (char)tolower((unsigned char)c);
        return lower.find("c:\\users\\") == 0 &&
               lower.find("\\appdata\\local\\temp") == std::string::npos;
    }

    // -----------------------------------------------------------------------
    // Collapse subdirectories: if parent is in set, remove children
    // e.g. {C:\Py\Lib, C:\Py\Lib\re, C:\Py\Lib\re\__pycache__} → {C:\Py\Lib}
    // -----------------------------------------------------------------------
    inline void CollapseSubdirs(std::set<std::string>& dirs)
    {
        std::vector<std::string> sorted(dirs.begin(), dirs.end());
        std::sort(sorted.begin(), sorted.end());
        std::set<std::string> collapsed;

        for (size_t i = 0; i < sorted.size(); i++) {
            // Check if any previously added dir is a prefix of this one
            bool isChild = false;
            for (const auto& parent : collapsed) {
                if (sorted[i].size() > parent.size() &&
                    sorted[i].compare(0, parent.size(), parent) == 0 &&
                    (sorted[i][parent.size()] == '\\' || sorted[i][parent.size()] == '/')) {
                    isChild = true;
                    break;
                }
            }
            if (!isChild) collapsed.insert(sorted[i]);
        }
        dirs = collapsed;
    }

    // -----------------------------------------------------------------------
    // Analyze Procmon CSV for resource usage — single-pass streaming.
    // Handles million-event CSVs with constant memory (only unique dirs stored).
    // -----------------------------------------------------------------------
    inline ProfileResult AnalyzeProfileCsv(const std::wstring& csvPath, DWORD childPid,
                                            const std::string& exeName)
    {
        ProfileResult r;

        char csvPathA[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, csvPath.c_str(), -1, csvPathA, MAX_PATH, nullptr, nullptr);
        std::ifstream csv(csvPathA);
        if (!csv.is_open()) return r;

        std::string hdr;
        std::getline(csv, hdr);
        if (hdr.size() >= 3 && (unsigned char)hdr[0] == 0xEF) hdr = hdr.substr(3);
        auto cols = ParseCsvLine(hdr);

        int cPid = -1, cOp = -1, cPath = -1, cDet = -1, cName = -1;
        for (int i = 0; i < (int)cols.size(); i++) {
            if (cols[i] == "PID") cPid = i;
            else if (cols[i] == "Process Name") cName = i;
            else if (cols[i] == "Operation") cOp = i;
            else if (cols[i] == "Path") cPath = i;
            else if (cols[i] == "Detail") cDet = i;
        }
        if (cOp < 0) return r;

        // Single pass: build PID tree and classify events simultaneously.
        // Works because Procmon orders events chronologically — Process Create
        // events for children appear before the child's own file events.
        std::set<DWORD> pidTree;
        pidTree.insert(childPid);
        bool pidTreeWorking = false; // set true once we see childPid in CSV
        std::string line;

        while (std::getline(csv, line)) {
            auto f = ParseCsvLine(line);
            if ((int)f.size() <= cOp) continue;
            const auto& op = f[cOp];

            // --- PID tree expansion ---
            if (op == "Process Create" && cDet >= 0 && (int)f.size() > cDet) {
                DWORD parentPid = (cPid >= 0) ? (DWORD)atoi(f[cPid].c_str()) : 0;
                auto pos = f[cDet].find("PID: ");
                if (pos != std::string::npos) {
                    DWORD newPid = (DWORD)atoi(f[cDet].c_str() + pos + 5);
                    if (newPid == childPid || pidTree.count(parentPid))
                        pidTree.insert(newPid);
                }
            }

            // --- Match: PID tree or process name fallback ---
            bool match = false;
            if (cPid >= 0) {
                DWORD pid = (DWORD)atoi(f[cPid].c_str());
                if (pidTree.count(pid)) {
                    match = true;
                    pidTreeWorking = true;
                }
            }
            // Fallback to process name if PID tree hasn't matched anything yet
            if (!match && !pidTreeWorking && cName >= 0 && (int)f.size() > cName) {
                match = (f[cName] == exeName);
            }
            if (!match) continue;

            // --- Skip lifecycle noise ---
            if (op == "Thread Create" || op == "Thread Exit" || op == "Process Exit" ||
                op == "Process Profiling") continue;

            r.totalEvents++;

            std::string path = (cPath >= 0 && (int)f.size() > cPath) ? f[cPath] : "";

            // --- Classify ---
            if (op == "Process Create") {
                r.spawnsChildren = true;
            }
            else if (op.find("TCP") != std::string::npos || op.find("UDP") != std::string::npos) {
                r.usesNetwork = true;
                r.netEvents++;
                if (path.find("localhost") != std::string::npos || path.find("127.0.0.1") != std::string::npos ||
                    path.find("::1") != std::string::npos)
                    r.usesLocalhost = true;
            }
            else if (op == "Load Image") {
                std::string dir = PathToDir(path);
                if (!dir.empty()) r.exeDirs.insert(dir);
                if (IsSystemDir(path)) r.needsSystemDirs = true;
                r.fileEvents++;
            }
            else if (op.find("Reg") == 0) {
                r.regEvents++;
                if (op == "RegSetValue" || op == "RegDeleteKey" || op == "RegDeleteValue") {
                    auto lower = path;
                    for (auto& c : lower) c = (char)tolower((unsigned char)c);
                    if (lower.find("hklm") == 0) r.writesHKLM = true;
                    else r.writesRegistry = true;
                }
            }
            else if (path.find("\\Device\\NamedPipe\\") != std::string::npos ||
                     path.find("\\Pipe\\") != std::string::npos) {
                r.usesNamedPipes = true;
                r.pipeEvents++;
            }
            else if (path.find("\\RPC Control\\") != std::string::npos) {
                r.usesCOM = true;
                r.comEvents++;
            }
            else {
                // File operations — only track directory, not individual paths
                r.fileEvents++;
                if (op == "CreateFile" || op == "WriteFile" || op == "SetDispositionInformationFile" ||
                    op == "SetRenameInformationFile") {
                    bool isWrite = false;
                    if (op == "CreateFile" && cDet >= 0 && (int)f.size() > cDet) {
                        const auto& det = f[cDet];
                        auto daPos = det.find("Desired Access:");
                        auto dispPos = det.find(", Disposition:");
                        if (daPos != std::string::npos) {
                            std::string da = det.substr(daPos, dispPos != std::string::npos ? dispPos - daPos : 60);
                            isWrite = da.find("Write") != std::string::npos ||
                                      da.find("Delete") != std::string::npos ||
                                      da.find("All Access") != std::string::npos ||
                                      da.find("Generic All") != std::string::npos;
                        }
                    }
                    if (op != "CreateFile") isWrite = true;

                    if (isWrite) {
                        if (IsSystemDir(path)) r.writesSystemDirs = true;
                        if (IsUserProfile(path)) r.writesUserProfile = true;
                        std::string dir = PathToDir(path);
                        if (!dir.empty()) r.writeDirs.insert(dir);
                    } else {
                        std::string dir = PathToDir(path);
                        if (!dir.empty()) r.readDirs.insert(dir);
                    }
                } else {
                    std::string dir = PathToDir(path);
                    if (!dir.empty()) r.readDirs.insert(dir);
                }
            }
        }

        // Post-processing: collapse subdirectories and remove overlaps
        CollapseSubdirs(r.readDirs);
        CollapseSubdirs(r.writeDirs);
        CollapseSubdirs(r.exeDirs);

        // Remove system dirs from readDirs (covered by system_dirs flag)
        for (auto it = r.readDirs.begin(); it != r.readDirs.end(); ) {
            if (IsSystemDir(*it)) it = r.readDirs.erase(it);
            else ++it;
        }
        // Remove write dirs from read dirs (write implies read)
        for (const auto& d : r.writeDirs) r.readDirs.erase(d);
        // Clean exe dirs
        for (auto it = r.exeDirs.begin(); it != r.exeDirs.end(); ) {
            if (IsSystemDir(*it)) it = r.exeDirs.erase(it);
            else ++it;
        }
        for (const auto& d : r.exeDirs) r.readDirs.erase(d);

        return r;
    }

    // -----------------------------------------------------------------------
    // Write profile report with verdict and suggested TOML
    // -----------------------------------------------------------------------
    inline bool WriteProfileReport(const std::wstring& reportPath, const ProfileResult& r,
                                    const std::wstring& exePath)
    {
        FILE* out = _wfopen(reportPath.c_str(), L"w");
        if (!out) return false;

        // Extract exe basename
        auto slash = exePath.find_last_of(L"\\/");
        std::wstring exeName = (slash != std::wstring::npos) ? exePath.substr(slash + 1) : exePath;

        fprintf(out, "=== Sandy Profile Report ===\n");
        fprintf(out, "Executable: %ls\n", exePath.c_str());
        fprintf(out, "Exit code:  %lu (0x%08lX)%s\n", r.exitCode, r.exitCode,
                r.exitCode == 0 ? " OK" : "");
        fprintf(out, "Events:     %d total", r.totalEvents);
        if (r.fileEvents) fprintf(out, ", %d file", r.fileEvents);
        if (r.regEvents) fprintf(out, ", %d reg", r.regEvents);
        if (r.netEvents) fprintf(out, ", %d net", r.netEvents);
        if (r.pipeEvents) fprintf(out, ", %d pipe", r.pipeEvents);
        if (r.comEvents) fprintf(out, ", %d COM", r.comEvents);
        fprintf(out, "\n\n");

        // --- Verdict ---
        bool sandboxable = !r.writesSystemDirs && !r.writesHKLM;
        bool appcontainerOK = sandboxable && !r.usesNamedPipes && !r.usesCOM && !r.writesRegistry;
        bool restrictedLowOK = sandboxable && !r.writesUserProfile;
        bool restrictedMedOK = sandboxable;

        fprintf(out, "--- Verdict ---\n");
        fprintf(out, "Sandboxable:     %s\n", sandboxable ? "YES" : "NO");
        if (sandboxable) {
            fprintf(out, "AppContainer:    %s%s\n",
                    appcontainerOK ? "YES" : "NO",
                    (appcontainerOK && !r.usesNamedPipes) ? " (recommended)" : "");
            fprintf(out, "Restricted Low:  %s\n", restrictedLowOK ? "YES" : "NO");
            fprintf(out, "Restricted Med:  YES\n");
        }
        fprintf(out, "\n");

        // --- Blockers ---
        if (!sandboxable || !appcontainerOK || !restrictedLowOK) {
            fprintf(out, "--- Blockers ---\n");
            if (r.writesSystemDirs)
                fprintf(out, "  SYSTEM WRITE    Writes to C:\\Windows or System32 (blocked in all modes)\n");
            if (r.writesHKLM)
                fprintf(out, "  HKLM WRITE      Writes to HKLM registry (blocked in all modes)\n");
            if (r.usesNamedPipes && !r.usesCOM)
                fprintf(out, "  NAMED PIPES     Uses named pipes (blocks AppContainer)\n");
            if (r.usesCOM)
                fprintf(out, "  COM/RPC         Uses COM/RPC servers (blocks AppContainer)\n");
            if (r.writesRegistry)
                fprintf(out, "  HKCU WRITE      Writes to HKCU registry (blocks AppContainer)\n");
            if (r.writesUserProfile)
                fprintf(out, "  PROFILE WRITE   Writes to user profile (blocks Restricted Low IL)\n");
            fprintf(out, "\n");
        }

        if (!sandboxable) {
            fprintf(out, "Cannot sandbox this process in either mode.\n");
            fclose(out);
            return true;
        }

        // --- Required config ---
        fprintf(out, "--- Required Config ---\n");
        if (!r.readDirs.empty()) {
            fprintf(out, "  [access] read:\n");
            for (const auto& d : r.readDirs) fprintf(out, "    %s\n", d.c_str());
        }
        if (!r.writeDirs.empty()) {
            fprintf(out, "  [access] write:\n");
            for (const auto& d : r.writeDirs) fprintf(out, "    %s\n", d.c_str());
        }
        if (r.needsSystemDirs) fprintf(out, "  system_dirs = true\n");
        if (r.usesNetwork) fprintf(out, "  network = true\n");
        if (r.usesLocalhost) fprintf(out, "  localhost = true\n");
        if (r.usesNamedPipes) fprintf(out, "  named_pipes = true\n");
        fprintf(out, "\n");

        // --- Suggested TOML ---
        fprintf(out, "--- Suggested TOML Config ---\n");
        fprintf(out, "[sandbox]\n");

        // Pick best mode
        if (appcontainerOK) {
            fprintf(out, "token = 'appcontainer'\n");
        } else if (restrictedLowOK) {
            fprintf(out, "token = 'restricted'\nintegrity = 'low'\n");
        } else {
            fprintf(out, "token = 'restricted'\nintegrity = 'medium'\n");
        }

        // Access section
        if (!r.readDirs.empty() || !r.writeDirs.empty()) {
            fprintf(out, "\n[access]\n");
            if (!r.readDirs.empty()) {
                fprintf(out, "read = [");
                bool first = true;
                for (const auto& d : r.readDirs) {
                    if (!first) fprintf(out, ", ");
                    fprintf(out, "'%s'", d.c_str());
                    first = false;
                }
                fprintf(out, "]\n");
            }
            if (!r.writeDirs.empty()) {
                fprintf(out, "write = [");
                bool first = true;
                for (const auto& d : r.writeDirs) {
                    if (!first) fprintf(out, ", ");
                    fprintf(out, "'%s'", d.c_str());
                    first = false;
                }
                fprintf(out, "]\n");
            }
        }

        // Allow section — all mandatory keys for selected mode
        fprintf(out, "\n[allow]\n");
        if (appcontainerOK) {
            fprintf(out, "system_dirs = %s\n", r.needsSystemDirs ? "true" : "false");
            fprintf(out, "network = %s\n", r.usesNetwork ? "true" : "false");
            fprintf(out, "localhost = %s\n", r.usesLocalhost ? "true" : "false");
            fprintf(out, "lan = false\n");
        } else {
            fprintf(out, "named_pipes = %s\n", r.usesNamedPipes ? "true" : "false");
        }
        fprintf(out, "stdin = true\n");
        fprintf(out, "clipboard_read = false\n");
        fprintf(out, "clipboard_write = false\n");
        fprintf(out, "child_processes = %s\n", r.spawnsChildren ? "true" : "false");

        // Environment section
        fprintf(out, "\n[environment]\n");
        fprintf(out, "inherit = true\n");

        fclose(out);
        return true;
    }

    // -----------------------------------------------------------------------
    // Run a profile analysis: launch unsandboxed with Procmon, then analyze
    // -----------------------------------------------------------------------
    inline int RunProfile(const std::wstring& exePath, const std::wstring& exeArgs,
                           const std::wstring& reportPath)
    {
        // Require Procmon
        std::wstring procmonExe = FindProcmon();
        if (procmonExe.empty()) {
            fprintf(stderr, "[Profile] Procmon not found on PATH. Profile requires Procmon.\n");
            return 1;
        }

        // Extract exe basename for Procmon filter and analysis
        auto exeSlash = exePath.find_last_of(L"\\/");
        std::wstring exeBase = (exeSlash != std::wstring::npos) ? exePath.substr(exeSlash + 1) : exePath;

        // Start Procmon with include filter for target process
        if (!StartProcmonProfile(procmonExe, exeBase)) {
            fprintf(stderr, "[Profile] Failed to start Procmon capture.\n");
            return 1;
        }
        fprintf(stderr, "[Profile] Capturing resource usage...\n");

        // Launch the process unsandboxed (normal token)
        std::wstring cmdLine = L"\"" + exePath + L"\"";
        if (!exeArgs.empty()) cmdLine += L" " + exeArgs;

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        std::wstring cmd = cmdLine;
        if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE,
                           0, nullptr, nullptr, &si, &pi)) {
            fprintf(stderr, "[Profile] Failed to launch process (error %lu).\n", GetLastError());
            RunProcAndWait(L"\"" + procmonExe + L"\" /Terminate", 5000);
            return 1;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        fprintf(stderr, "[Profile] Process exited with code %lu (0x%08lX). Analyzing...\n", exitCode, exitCode);

        // Stop Procmon and convert PML → CSV
        std::wstring pmlPath = AuditTempPath(L"sandy_audit.pml");
        std::wstring csvPath = AuditTempPath(L"sandy_audit.csv");

        RunProcAndWait(L"\"" + procmonExe + L"\" /Terminate", 10000);
        WaitForProcmonExit(15000);

        if (GetFileAttributesW(pmlPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "[Profile] PML not found — Procmon may not have captured.\n");
            return 1;
        }

        // Delete any stale CSV from a previous run
        DeleteFileW(csvPath.c_str());

        std::wstring cvt = L"\"" + procmonExe + L"\" /Quiet /AcceptEula "
                           L"/OpenLog \"" + pmlPath + L"\" /SaveAs \"" + csvPath + L"\"";
        RunProcAndWait(cvt, 60000);
        if (!WaitForFile(csvPath, 60000)) {
            WaitForProcmonExit(30000);
            if (GetFileAttributesW(csvPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                fprintf(stderr, "[Profile] CSV export failed.\n");
                DeleteFileW(pmlPath.c_str());
                return 1;
            }
        }

        // Analyze events
        char exeNameA[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, exeBase.c_str(), -1, exeNameA, MAX_PATH, nullptr, nullptr);
        ProfileResult result = AnalyzeProfileCsv(csvPath, pi.dwProcessId, exeNameA);
        result.exitCode = exitCode;

        // Write report
        if (WriteProfileReport(reportPath, result, exePath))
            fprintf(stderr, "[Profile] Report written to: %ls\n", reportPath.c_str());
        else
            fprintf(stderr, "[Profile] Failed to write report.\n");

        // Cleanup
        DeleteFileW(pmlPath.c_str());
        DeleteFileW(csvPath.c_str());

        return 0;
    }

} // namespace Sandbox

#pragma warning(pop)
