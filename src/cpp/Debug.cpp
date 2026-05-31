#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <set>

static std::string originalBytes = "";
static std::string patchedBytes  = "";

class Internal {
public:
    int     processId = 0;
    HANDLE  pHandle   = nullptr;
    bool    is64Bit   = false;

    // ── Process Management ──────────────────────────────────────────

    bool SetProcess(const std::vector<std::string>& processNames) {
        processId = 0;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &pe32)) {
            do {
                std::string exeFile(pe32.szExeFile);
                std::string nameOnly = exeFile;
                if (nameOnly.length() > 4 &&
                    _stricmp(nameOnly.substr(nameOnly.length() - 4).c_str(), ".exe") == 0)
                    nameOnly = nameOnly.substr(0, nameOnly.length() - 4);

                for (const auto& name : processNames) {
                    if (_stricmp(nameOnly.c_str(), name.c_str()) == 0) {
                        processId = pe32.th32ProcessID;
                        break;
                    }
                }
                if (processId > 0) break;
            } while (Process32Next(snapshot, &pe32));
        }
        CloseHandle(snapshot);

        if (processId <= 0) return false;

        pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!pHandle) return false;

        BOOL isWow64 = FALSE;
        IsWow64Process(pHandle, &isWow64);

        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        bool is64BitOS = (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
        this->is64Bit = is64BitOS && !isWow64;

        return true;
    }

    // ── Page Filter ─────────────────────────────────────────────────

    static bool CanReadPage(const MEMORY_BASIC_INFORMATION& page) {
        if (page.State != MEM_COMMIT)    return false;
        if (page.Protect == PAGE_NOACCESS) return false;
        if (page.Protect & PAGE_GUARD)   return false;
        if (page.Type == MEM_IMAGE)      return false;
        return true;
    }

    // ── Pattern Parsing ─────────────────────────────────────────────

    struct PatternData {
        std::vector<BYTE> bytes;
        std::vector<BYTE> mask;
        int               length = 0;
        bool              valid  = false;
    };

    static PatternData ParsePattern(const std::string& patternString) {
        PatternData p;
        if (patternString.empty()) return p;

        std::vector<std::string> parts;
        std::istringstream iss(patternString);
        std::string token;
        while (iss >> token) parts.push_back(token);

        if (parts.empty()) return p;

        p.bytes.resize(parts.size());
        p.mask.resize(parts.size());
        p.length = static_cast<int>(parts.size());
        p.valid  = true;

        for (size_t i = 0; i < parts.size(); i++) {
            if (parts[i] == "??" || parts[i] == "?") {
                p.mask[i]  = 0x00;
                p.bytes[i] = 0x00;
            } else {
                p.mask[i]  = 0xFF;
                p.bytes[i] = static_cast<BYTE>(std::stoul(parts[i], nullptr, 16));
            }
        }
        return p;
    }

    // ── AoB Scan (parallel) ─────────────────────────────────────────

    std::vector<uintptr_t> AoBScan(const std::string& search) {
        std::vector<uintptr_t> foundAddresses;
        std::mutex mtx;

        PatternData pattern = ParsePattern(search);
        if (!pattern.valid) return foundAddresses;

        std::vector<MEMORY_BASIC_INFORMATION> memoryRegions;

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        uintptr_t minStart = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
        uintptr_t maxEnd   = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);
        uintptr_t currentAddr = minStart;

        while (currentAddr < maxEnd) {
            MEMORY_BASIC_INFORMATION mem;
            if (VirtualQueryEx(pHandle,
                    reinterpret_cast<LPCVOID>(currentAddr),
                    &mem, sizeof(mem)) == 0)
                break;

            if (CanReadPage(mem))
                memoryRegions.push_back(mem);

            currentAddr = reinterpret_cast<uintptr_t>(mem.BaseAddress) + mem.RegionSize;
        }

        unsigned int numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;

        std::atomic<size_t> nextRegionIdx{0};

        auto worker = [&]() {
            while (true) {
                size_t idx = nextRegionIdx.fetch_add(1);
                if (idx >= memoryRegions.size()) break;

                const auto& region    = memoryRegions[idx];
                uintptr_t   baseAddr  = reinterpret_cast<uintptr_t>(region.BaseAddress);
                SIZE_T      regionSize = region.RegionSize;

                uintptr_t offset = 0;
                while (offset < regionSize) {
                    SIZE_T chunkSize = static_cast<SIZE_T>(std::min(
                        static_cast<ULONGLONG>(regionSize - offset),
                        static_cast<ULONGLONG>(67108864)));
                    if (chunkSize == 0) break;

                    uintptr_t chunkAddress = baseAddr + offset;
                    std::vector<BYTE> buffer(chunkSize);
                    SIZE_T bytesRead = 0;

                    if (ReadProcessMemory(pHandle,
                            reinterpret_cast<LPCVOID>(chunkAddress),
                            buffer.data(), chunkSize, &bytesRead) && bytesRead > 0)
                    {
                        if (bytesRead < static_cast<SIZE_T>(pattern.length)) {
                            offset += chunkSize;
                            continue;
                        }

                        const SIZE_T limit    = bytesRead - pattern.length;
                        const BYTE*  pBuffer  = buffer.data();
                        const BYTE*  pPattern = pattern.bytes.data();
                        const BYTE*  pMask    = pattern.mask.data();

                        for (SIZE_T i = 0; i <= limit; i++) {
                            if (pMask[0] == 0xFF && pBuffer[i] != pPattern[0])
                                continue;

                            bool match = true;
                            for (int j = 1; j < pattern.length; j++) {
                                if (pMask[j] == 0xFF && pBuffer[i + j] != pPattern[j]) {
                                    match = false;
                                    break;
                                }
                            }

                            if (match) {
                                std::lock_guard<std::mutex> lock(mtx);
                                foundAddresses.push_back(chunkAddress + i);
                            }
                        }
                    }
                    offset += chunkSize;
                }
            }
        };

        std::vector<std::thread> threads;
        threads.reserve(numThreads);
        for (unsigned int t = 0; t < numThreads; t++)
            threads.emplace_back(worker);
        for (auto& t : threads)
            t.join();

        return foundAddresses;
    }

    // ── AoB Replace ─────────────────────────────────────────────────

    bool AobReplace(uintptr_t address, const std::string& bytePattern) const {
        try {
            std::vector<BYTE> arr = StringToByteArray(bytePattern);
            SIZE_T bytesWritten = 0;
            return WriteProcessMemory(pHandle,
                reinterpret_cast<LPVOID>(address),
                arr.data(), arr.size(), &bytesWritten) != 0;
        } catch (...) {}
        return false;
    }

    static std::vector<BYTE> StringToByteArray(const std::string& hexString) {
        std::vector<BYTE> result;
        std::istringstream iss(hexString);
        std::string hex;
        while (iss >> hex)
            result.push_back(static_cast<BYTE>(std::stoul(hex, nullptr, 16)));
        return result;
    }
};

static Internal mem;

// ── Debug State ─────────────────────────────────────────────────────
bool debugMode = false;
std::vector<uintptr_t> lastFound;
std::set<uintptr_t> patchedSet;

// ── Commands ────────────────────────────────────────────────────────

void CmdPid(const std::string& param) {
    int pid;
    try { pid = std::stoi(param); }
    catch (...) { std::cout << "Invalid PID\n"; return; }

    HANDLE hCheck = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hCheck) {
        std::cout << "Process not found with PID: " << pid << "\n";
        return;
    }
    CloseHandle(hCheck);

    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!handle) {
        std::cout << "Failed to open process. Run as admin?\n";
        return;
    }

    mem.pHandle   = handle;
    mem.processId = pid;

    BOOL isWow64 = FALSE;
    IsWow64Process(handle, &isWow64);

    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    bool is64BitOS = (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
    mem.is64Bit = is64BitOS && !isWow64;

    std::cout << "Attached to PID: " << pid
              << " (" << (mem.is64Bit ? "64-bit" : "32-bit") << ")\n";
}

void CmdName(const std::string& param) {
    if (param.empty()) {
        std::cout << "Usage: name <exe_name>\n";
        return;
    }

    bool success = mem.SetProcess({param});
    if (!success) {
        std::cout << "Failed to attach to process: " << param << "\n";
        return;
    }
    std::cout << "Attached to: " << param
              << " (PID: " << mem.processId
              << ", " << (mem.is64Bit ? "64-bit" : "32-bit") << ")\n";
}

void CmdUndo() {
    if (patchedSet.empty()) {
        std::cout << "No patched occurrences to undo.\n";
        return;
    }
    int count = 0;
    for (uintptr_t addr : patchedSet) {
        if (mem.AobReplace(addr, originalBytes)) {
            count++;
        }
    }
    patchedSet.clear();
    std::cout << "Unpatched " << count << " occurrence(s). All patches undone.\n";
}

void CmdInject() {
    if (!mem.pHandle) {
        std::cout << "No process attached. Use pid or name first.\n";
        return;
    }

    if (debugMode && !patchedSet.empty()) {
        CmdUndo(); // Restore bytes before scanning again
    }

    std::cout << "Scanning...\n";
    std::vector<uintptr_t> addresses = mem.AoBScan(originalBytes);

    if (!debugMode) {
        if (addresses.empty()) {
            std::cout << "No occurrences found.\n";
            return;
        }
        for (uintptr_t addr : addresses) {
            mem.AobReplace(addr, patchedBytes);
            patchedSet.insert(addr);
        }
        std::cout << "Patched " << addresses.size() << " address(es). Done.\n";
    } else {
        lastFound = addresses;
        patchedSet.clear();

        if (lastFound.empty()) {
            std::cout << "No occurrences found.\n";
        } else if (lastFound.size() == 1) {
            std::cout << "Found 1 occurrence:\n";
            std::cout << "  1: 0x" << std::uppercase << std::hex << lastFound[0] << std::dec << "\n";
            std::cout << "Use: patch, unpatch, all, undo\n";
        } else {
            std::cout << "Found " << lastFound.size() << " occurrences:\n";
            for (size_t i = 0; i < lastFound.size(); i++) {
                std::cout << "  " << (i + 1) << ": 0x" << std::uppercase << std::hex << lastFound[i] << std::dec << "\n";
            }
            std::cout << "Use: patch <x>, unpatch <y>, all, undo\n";
        }
    }
}

void CmdPatch(const std::string& param) {
    if (lastFound.empty()) {
        std::cout << "No occurrences found. Run inject first.\n";
        return;
    }
    int x = -1;
    if (param.empty()) {
        if (lastFound.size() == 1) {
            x = 1; // Auto-select if only 1
        } else {
            std::cout << "Specify occurrence to patch: patch <x>\n";
            return;
        }
    } else {
        try { x = std::stoi(param); }
        catch (...) { std::cout << "Invalid number.\n"; return; }
    }

    if (x < 1 || x > (int)lastFound.size()) {
        std::cout << "Invalid occurrence number. Range: 1 to " << lastFound.size() << "\n";
        return;
    }

    uintptr_t addr = lastFound[x - 1];
    if (patchedSet.count(addr)) {
        std::cout << "Occurrence " << x << " is already patched.\n";
        return;
    }

    if (mem.AobReplace(addr, patchedBytes)) {
        patchedSet.insert(addr);
        std::cout << "Patched occurrence " << x << ".\n";
    } else {
        std::cout << "Failed to patch occurrence " << x << ".\n";
    }
}

void CmdUnpatch(const std::string& param) {
    if (lastFound.empty()) {
        std::cout << "No occurrences found. Run inject first.\n";
        return;
    }
    int y = -1;
    if (param.empty()) {
        if (lastFound.size() == 1) {
            y = 1; // Auto-select if only 1
        } else {
            std::cout << "Specify occurrence to unpatch: unpatch <y>\n";
            return;
        }
    } else {
        try { y = std::stoi(param); }
        catch (...) { std::cout << "Invalid number.\n"; return; }
    }

    if (y < 1 || y > (int)lastFound.size()) {
        std::cout << "Invalid occurrence number. Range: 1 to " << lastFound.size() << "\n";
        return;
    }

    uintptr_t addr = lastFound[y - 1];
    if (patchedSet.count(addr) == 0) {
        std::cout << "Warning: Occurrence " << y << " was not patched earlier.\n";
        return;
    }

    if (mem.AobReplace(addr, originalBytes)) {
        patchedSet.erase(addr);
        std::cout << "Unpatched occurrence " << y << ".\n";
    } else {
        std::cout << "Failed to unpatch occurrence " << y << ".\n";
    }
}

void CmdAll() {
    if (lastFound.empty()) {
        std::cout << "No occurrences found. Run inject first.\n";
        return;
    }
    int count = 0;
    for (size_t i = 0; i < lastFound.size(); i++) {
        uintptr_t addr = lastFound[i];
        if (patchedSet.count(addr) == 0) {
            if (mem.AobReplace(addr, patchedBytes)) {
                patchedSet.insert(addr);
                count++;
            }
        }
    }
    std::cout << "Patched " << count << " new occurrence(s). All occurrences are now patched.\n";
}

void CmdDebug() {
    debugMode = !debugMode;
    std::cout << "Debug mode " << (debugMode ? "enabled" : "disabled") << ".\n";
    if (!debugMode) {
        if (!patchedSet.empty()) {
            CmdUndo();
        }
        lastFound.clear();
        patchedSet.clear();
    }
}

// ── Main ────────────────────────────────────────────────────────────

int main() {
    std::cout << "SniperFix Console (64-bit)\n";
    std::cout << "Commands: pid <id> | name <exe> | inject | debug | patch <x> | unpatch <y> | all | undo | exit\n";

    while (true) {
        std::cout << "> ";
        std::string input;
        if (!std::getline(std::cin, input) || input.empty()) continue;

        size_t start = input.find_first_not_of(" \t\r\n");
        size_t end   = input.find_last_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        input = input.substr(start, end - start + 1);

        std::string cmd, param;
        size_t spacePos = input.find(' ');
        if (spacePos != std::string::npos) {
            cmd  = input.substr(0, spacePos);
            param = input.substr(spacePos + 1);
            size_t p = param.find_first_not_of(" \t");
            param = (p != std::string::npos) ? param.substr(p) : "";
        } else {
            cmd = input;
        }

        std::transform(cmd.begin(), cmd.end(), cmd.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if      (cmd == "pid")    CmdPid(param);
        else if (cmd == "name")   CmdName(param);
        else if (cmd == "inject") CmdInject();
        else if (cmd == "debug")  CmdDebug();
        else if (cmd == "patch" || cmd == "p")   CmdPatch(param);
        else if (cmd == "unpatch" || cmd == "up") CmdUnpatch(param);
        else if (cmd == "all")    CmdAll();
        else if (cmd == "undo")   CmdUndo();
        else if (cmd == "exit")   return 0;
        else std::cout << "Unknown command. Use: pid <id>, name <exe>, inject, debug, patch <x>, unpatch <y>, all, undo, exit\n";
    }
}
