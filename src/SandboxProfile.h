// =========================================================================
// SandboxProfile.h — Unsandboxed profiling and compatibility analysis
//
// Runs a process unsandboxed under Procmon, classifies its resource
// usage, and generates a compatibility report with a suggested TOML
// config for sandboxing.
// =========================================================================
#pragma once

#pragma warning(push)
#pragma warning(disable: 4996) // _wfopen, etc.

#include "SandboxAudit.h"
#include <set>
#include <algorithm>

namespace Sandbox {

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
    // Count path components below drive root
    // e.g. "C:\" = 0, "C:\Users" = 1, "C:\Users\H\AppData" = 3
    // -----------------------------------------------------------------------
    inline int PathComponentCount(const std::string& p)
    {
        int depth = 0;
        for (size_t i = 0; i < p.size(); i++)
            if ((p[i] == '\\' || p[i] == '/') && i > 2) depth++;
        return depth;
    }

    // -----------------------------------------------------------------------
    // Filter probe noise: remove drive roots, shallow paths, and well-known
    // transient entries that don't represent real access requirements.
    // Runtime path probes (Python sys.path, DLL search order) touch root
    // directories without actually needing access to them.
    // -----------------------------------------------------------------------
    inline void FilterProbeNoise(std::set<std::string>& dirs)
    {
        for (auto it = dirs.begin(); it != dirs.end(); ) {
            const auto& p = *it;
            auto lower = p;
            for (auto& c : lower) c = (char)tolower((unsigned char)c);

            bool isNoise = false;

            // Drive roots (C:\, D:\, etc.) — always probe noise
            if (p.size() <= 3) isNoise = true;

            // Well-known transient system paths accessed during module search
            else if (lower == "c:\\system volume information" ||
                     lower == "c:\\$recycle.bin" ||
                     lower == "c:\\config.sys" ||
                     lower == "c:\\recovery" ||
                     lower == "c:\\programdata" ||
                     lower == "c:\\documents and settings")
                isNoise = true;

            // Depth-1 paths under C:\ (e.g. "C:\Users" bare) are almost always
            // probe artifacts unless they are real app directories
            else if (PathComponentCount(lower) == 0 && lower.find("c:\\") == 0) {
                // Keep known useful depth-1 dirs (repos, Python installations)
                // but filter out broad directories that are clearly probes
                if (lower == "c:\\users" || lower == "c:\\programdata")
                    isNoise = true;
            }

            if (isNoise) it = dirs.erase(it);
            else ++it;
        }
    }

    // -----------------------------------------------------------------------
    // Collapse subdirectories: if parent is in set, remove children
    // e.g. {C:\Py\Lib, C:\Py\Lib\re, C:\Py\Lib\re\__pycache__} → {C:\Py\Lib}
    // -----------------------------------------------------------------------
    inline void CollapseSubdirs(std::set<std::string>& dirs)
    {
        // First filter transient probe noise
        FilterProbeNoise(dirs);

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

        CsvReader csv;
        if (!csv.Open(csvPath)) return r;
        if (csv.cOp < 0) return r;

        const int cPid = csv.cPid, cOp = csv.cOp, cPath = csv.cPath;
        const int cDet = csv.cDet, cName = csv.cProc;

        // Single pass: build PID tree and classify events simultaneously.
        // Works because Procmon orders events chronologically — Process Create
        // events for children appear before the child's own file events.
        std::set<DWORD> pidTree;
        pidTree.insert(childPid);
        bool pidTreeWorking = false; // set true once we see childPid in CSV
        std::string line;

        while (std::getline(csv.stream, line)) {
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
            fprintf(out, "  [allow] read:\n");
            for (const auto& d : r.readDirs) fprintf(out, "    %s\n", d.c_str());
        }
        if (!r.writeDirs.empty()) {
            fprintf(out, "  [allow] write:\n");
            for (const auto& d : r.writeDirs) fprintf(out, "    %s\n", d.c_str());
        }
        if (r.needsSystemDirs) fprintf(out, "  system_dirs = true\n");
        if (r.usesNetwork) fprintf(out, "  network = true\n");
        if (r.usesLocalhost) fprintf(out, "  localhost = true\n");
        if (r.usesNamedPipes) fprintf(out, "  named_pipes = true\n");
        fprintf(out, "\n");

        // --- Suggested TOML (fully compliant with Sandy's strict parser) ---
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
        fprintf(out, "workdir = 'inherit'\n");

        // Access section — all 6 keys mandatory
        auto printPathList = [&](const char* key, const std::set<std::string>& dirs) {
            if (dirs.empty()) {
                fprintf(out, "%s = []\n", key);
            } else {
                fprintf(out, "%s = [", key);
                bool first = true;
                for (const auto& d : dirs) {
                    if (!first) fprintf(out, ", ");
                    fprintf(out, "'%s'", d.c_str());
                    first = false;
                }
                fprintf(out, "]\n");
            }
        };
        fprintf(out, "\n[allow]\n");
        printPathList("read", r.readDirs);
        printPathList("write", r.writeDirs);
        fprintf(out, "execute = []\n");
        fprintf(out, "append = []\n");
        fprintf(out, "delete = []\n");
        fprintf(out, "all = []\n");

        // Deny section — all 6 keys mandatory
        fprintf(out, "\n[deny]\n");
        fprintf(out, "read = []\n");
        fprintf(out, "write = []\n");
        fprintf(out, "execute = []\n");
        fprintf(out, "append = []\n");
        fprintf(out, "delete = []\n");
        fprintf(out, "all = []\n");

        // Privileges section — all mandatory keys for selected mode
        fprintf(out, "\n[privileges]\n");
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

        // Registry section — required for restricted mode
        if (!appcontainerOK) {
            fprintf(out, "\n[registry]\n");
            fprintf(out, "read = []\n");
            fprintf(out, "write = []\n");
        }

        // Environment section — both keys mandatory
        fprintf(out, "\n[environment]\n");
        fprintf(out, "inherit = true\n");
        fprintf(out, "pass = []\n");

        // Limit section — all 3 keys mandatory
        fprintf(out, "\n[limit]\n");
        fprintf(out, "timeout = 0\n");
        fprintf(out, "memory = 0\n");
        fprintf(out, "processes = 0\n");

        fclose(out);
        return true;
    }

    // -----------------------------------------------------------------------
    // Run a trace analysis: launch unsandboxed with Procmon, then analyze
    // -----------------------------------------------------------------------
    inline int RunTrace(const std::wstring& exePath, const std::wstring& exeArgs,
                           const std::wstring& reportPath)
    {
        // Require Procmon
        std::wstring procmonExe = FindProcmon();
        if (procmonExe.empty()) {
            fprintf(stderr, "[Trace] Procmon not found on PATH. Trace requires Procmon.\n");
            return 1;
        }

        // Extract exe basename for Procmon filter and analysis
        auto exeSlash = exePath.find_last_of(L"\\/");
        std::wstring exeBase = (exeSlash != std::wstring::npos) ? exePath.substr(exeSlash + 1) : exePath;

        // Start Procmon with include filter for target process
        std::wstring pmlPath;
        if (!StartProcmonProfile(procmonExe, exeBase, pmlPath)) {
            fprintf(stderr, "[Trace] Failed to start Procmon capture.\n");
            return 1;
        }
        fprintf(stderr, "[Trace] Capturing resource usage...\n");

        // Launch the process unsandboxed (normal token)
        std::wstring cmdLine = L"\"" + exePath + L"\"";
        if (!exeArgs.empty()) cmdLine += L" " + exeArgs;

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        std::wstring cmd = cmdLine;
        if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE,
                           0, nullptr, nullptr, &si, &pi)) {
            fprintf(stderr, "[Trace] Failed to launch process (error %lu).\n", GetLastError());
            RunProcAndWait(L"\"" + procmonExe + L"\" /Terminate", 5000);
            return 1;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        fprintf(stderr, "[Trace] Process exited with code %lu (0x%08lX). Analyzing...\n", exitCode, exitCode);

        // Stop Procmon and convert PML → CSV
        // Derive CSV path from PML path (same unique suffix, different extension)
        std::wstring csvPath = pmlPath;
        auto csvDot = csvPath.rfind(L'.');
        if (csvDot != std::wstring::npos) csvPath = csvPath.substr(0, csvDot);
        csvPath += L".csv";

        if (!StopAndConvertProcmon(procmonExe, pmlPath, csvPath, L"Trace"))
            return 1;

        // Analyze events
        char exeNameA[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, exeBase.c_str(), -1, exeNameA, MAX_PATH, nullptr, nullptr);
        ProfileResult result = AnalyzeProfileCsv(csvPath, pi.dwProcessId, exeNameA);
        result.exitCode = exitCode;

        // Write report
        if (WriteProfileReport(reportPath, result, exePath))
            fprintf(stderr, "[Trace] Report written to: %ls\n", reportPath.c_str());
        else
            fprintf(stderr, "[Trace] Failed to write report.\n");

        // Cleanup
        DeleteFileW(pmlPath.c_str());
        DeleteFileW(csvPath.c_str());

        return 0;
    }

} // namespace Sandbox

#pragma warning(pop)
