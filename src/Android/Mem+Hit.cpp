#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>

#include <sys/uio.h>      // process_vm_readv / process_vm_writev
#include <errno.h>
#include <unistd.h>

// ── Configuration ────────────────────────────────────────────────────────────
static constexpr size_t READ_CHUNK = 64 * 1024;   // 64 KiB chunks

// ── Aimbot Specifics ─────────────────────────────────────────────────────────
static const std::string aimbotPatternStr = "FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A5 43";
static constexpr long AIMBOT_READ_OFFSET  = 0xB8;  // headOffset
static constexpr long AIMBOT_WRITE_OFFSET = 0xB4;  // chestOffset

// ── Pattern byte ─────────────────────────────────────────────────────────────
struct PatternByte {
    bool    isWildcard;
    uint8_t value;
};

// ── Memory region from /proc/<pid>/maps ──────────────────────────────────────
struct MemoryRegion {
    uintptr_t   start;
    uintptr_t   end;
    std::string perms;
    std::string pathname;
};

// ── Match info ───────────────────────────────────────────────────────────────
struct MatchInfo {
    uintptr_t   addr;
    std::string perms;
    std::string pathname;
};

// ── Parse "FF ?? AB 67 8E" → vector<PatternByte> ────────────────────────────
std::vector<PatternByte> parseAOB(const std::string& aob)
{
    std::vector<PatternByte> pattern;
    std::istringstream iss(aob);
    std::string token;

    while (iss >> token) {
        PatternByte pb{};
        if (token == "??" || token == "?") {
            pb.isWildcard = true;
            pb.value      = 0x00;
        } else {
            pb.isWildcard = false;
            try {
                unsigned long v = std::stoul(token, nullptr, 16);
                if (v > 0xFF) {
                    std::cerr << "[!] Invalid byte value: " << token << "\n";
                    continue;
                }
                pb.value = static_cast<uint8_t>(v);
            } catch (...) {
                std::cerr << "[!] Invalid byte token: " << token << "\n";
                continue;
            }
        }
        pattern.push_back(pb);
    }
    return pattern;
}

void printPattern(const std::string& label, const std::vector<PatternByte>& pattern)
{
    std::cout << label;
    for (const auto& p : pattern) {
        if (p.isWildcard) std::cout << "?? ";
        else              printf("%02X ", p.value);
    }
    std::cout << "(" << pattern.size() << " bytes)\n";
}

// ── Read /proc/<pid>/maps ────────────────────────────────────────────────────
std::vector<MemoryRegion> getMemoryRegions(pid_t pid, bool rwOnly)
{
    std::vector<MemoryRegion> regions;
    std::string path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream ifs(path);

    if (!ifs.is_open()) {
        std::cerr << "[!] Cannot open " << path << ": " << strerror(errno) << "\n";
        return regions;
    }

    std::string line;
    while (std::getline(ifs, line)) {
        uintptr_t start = 0, end = 0;
        char perms[5] = {};

        if (sscanf(line.c_str(), "%lx-%lx %4s", &start, &end, perms) < 3)
            continue;

        if (perms[0] != 'r')          // must be at least readable
            continue;

        if (rwOnly && perms[1] != 'w') // skip non-writable when rwOnly
            continue;

        std::string pathname;
        size_t pos = line.find('/');
        if (pos != std::string::npos)
            pathname = line.substr(pos);
        else {
            pos = line.find('[');
            if (pos != std::string::npos)
                pathname = line.substr(pos);
        }

        regions.push_back({start, end, perms, pathname});
    }
    return regions;
}

// ── Read remote process memory via process_vm_readv ──────────────────────────
ssize_t remoteRead(pid_t pid, uintptr_t remoteAddr, uint8_t* localBuf, size_t size)
{
    struct iovec local[1]  = { { localBuf, size } };
    struct iovec remote[1] = { { reinterpret_cast<void*>(remoteAddr), size } };

    ssize_t n = process_vm_readv(pid, local, 1, remote, 1, 0);
    if (n < 0) {
        if (errno != EFAULT && errno != EIO && errno != ENOMEM)
            perror("[!] process_vm_readv");
        return 0;
    }
    return n;
}

// ── Write remote process memory via process_vm_writev ────────────────────────
ssize_t remoteWrite(pid_t pid, uintptr_t remoteAddr, const uint8_t* localBuf, size_t size)
{
    struct iovec local[1]  = { { const_cast<uint8_t*>(localBuf), size } };
    struct iovec remote[1] = { { reinterpret_cast<void*>(remoteAddr), size } };

    ssize_t n = process_vm_writev(pid, local, 1, remote, 1, 0);
    return n;
}

// ── Scan one memory region for the AOB pattern ──────────────────────────────
std::vector<uintptr_t> scanRegion(pid_t pid,
                                  const MemoryRegion& region,
                                  const std::vector<PatternByte>& pattern)
{
    std::vector<uintptr_t> matches;
    size_t regionSize = region.end - region.start;
    size_t patLen     = pattern.size();

    if (regionSize == 0 || patLen == 0 || regionSize < patLen)
        return matches;

    std::vector<uint8_t> buf(READ_CHUNK + patLen - 1);
    size_t leftover = 0;

    uintptr_t cursor = region.start;

    while (cursor < region.end) {
        size_t toRead = std::min(READ_CHUNK, static_cast<size_t>(region.end - cursor));

        ssize_t n = remoteRead(pid, cursor, buf.data() + leftover, toRead);
        if (n <= 0) {
            cursor += toRead;
            leftover = 0;
            continue;
        }

        size_t total = leftover + static_cast<size_t>(n);

        size_t scanEnd = (total >= patLen) ? total - patLen + 1 : 0;
        for (size_t i = 0; i < scanEnd; ++i) {
            bool found = true;
            for (size_t j = 0; j < patLen; ++j) {
                if (!pattern[j].isWildcard && buf[i + j] != pattern[j].value) {
                    found = false;
                    break;
                }
            }
            if (found)
                matches.push_back(cursor - leftover + i);
        }

        if (total >= patLen) {
            leftover = patLen - 1;
            memmove(buf.data(), buf.data() + total - leftover, leftover);
        } else {
            leftover = total;
        }

        cursor += static_cast<size_t>(n);
    }

    return matches;
}

// ── Hex+ASCII context around a match ─────────────────────────────────────────
void printContext(pid_t pid, uintptr_t addr, size_t patLen,
                  size_t before = 8, size_t after = 8)
{
    uintptr_t ctxStart = (addr >= before) ? addr - before : 0;
    size_t    ctxSize  = before + patLen + after;

    std::vector<uint8_t> ctx(ctxSize);
    ssize_t n = remoteRead(pid, ctxStart, ctx.data(), ctxSize);
    if (n <= 0) return;

    printf("    hex : ");
    for (ssize_t i = 0; i < n; ++i) printf("%02X ", ctx[i]);
    printf("\n    asc : ");
    for (ssize_t i = 0; i < n; ++i) {
        char c = (ctx[i] >= 0x20 && ctx[i] <= 0x7E) ? static_cast<char>(ctx[i]) : '.';
        printf(" %c ", c);
    }
    printf("\n");
}

// ── Aimbot Mode Logic ────────────────────────────────────────────────────────
void runAimbot(pid_t pid, bool rwOnly)
{
    auto pattern = parseAOB(aimbotPatternStr);
    if (pattern.empty()) {
        std::cerr << "[!] Failed to parse internal aimbot pattern.\n";
        return;
    }
    printPattern("[*] Aimbot Pattern: ", pattern);

    auto regions = getMemoryRegions(pid, rwOnly);
    std::cout << "[*] " << regions.size()
              << (rwOnly ? " rw/rwx" : " readable")
              << " region(s) found.  Scanning without pausing target...\n\n";

    std::vector<uintptr_t> bases;
    for (const auto& region : regions) {
        auto matches = scanRegion(pid, region, pattern);
        for (auto addr : matches) {
            bases.push_back(addr);
            printf("  [+] Found @ 0x%016lX  (%s  %s)\n",
                   static_cast<unsigned long>(addr),
                   region.perms.c_str(),
                   region.pathname.empty() ? "[anon]" : region.pathname.c_str());
        }
    }

    if (bases.empty()) {
        std::cout << "\n[!] No occurrences found.\n";
        return;
    }

    std::cout << "\n[*] Found " << bases.size() << " occurrence(s). Swapping hitbox offsets...\n";
    for (uintptr_t base : bases) {
        uintptr_t addrHead  = base + AIMBOT_READ_OFFSET;
        uintptr_t addrChest = base + AIMBOT_WRITE_OFFSET;

        int32_t headVal  = 0;
        int32_t chestVal = 0;

        ssize_t r1 = remoteRead(pid, addrHead, reinterpret_cast<uint8_t*>(&headVal), sizeof(headVal));
        ssize_t r2 = remoteRead(pid, addrChest, reinterpret_cast<uint8_t*>(&chestVal), sizeof(chestVal));

        if (r1 != sizeof(headVal) || r2 != sizeof(chestVal)) {
            printf("  [!] Failed to read offsets at 0x%lX\n", static_cast<unsigned long>(base));
            continue;
        }

        printf("  [*] 0x%016lX: Head[%d] Chest[%d] -> Swapping\n",
               static_cast<unsigned long>(base), headVal, chestVal);

        // Write headVal to chest address, and chestVal to head address
        ssize_t w1 = remoteWrite(pid, addrChest, reinterpret_cast<uint8_t*>(&headVal), sizeof(headVal));
        ssize_t w2 = remoteWrite(pid, addrHead,  reinterpret_cast<uint8_t*>(&chestVal), sizeof(chestVal));

        if (w1 == sizeof(headVal) && w2 == sizeof(chestVal)) {
            printf("  [✓] Patched  0x%016lX\n", static_cast<unsigned long>(base));
        } else {
            printf("  [✗] Failed   0x%016lX - %s\n",
                   static_cast<unsigned long>(base), strerror(errno));
        }
    }
    std::cout << "[*] Aimbot patching process finished.\n";
}

// ── Usage ────────────────────────────────────────────────────────────────────
void printUsage(const char* prog)
{
    std::cerr << "Usage:\n"
              << "  " << prog << " <pid> <AOB> [--replaceAoB=\"XX XX\"] [--rw] [--ctx]\n"
              << "  " << prog << " <pid> --Aimbot [--rw]\n\n"
              << "  AOB format     : \"FF ?? AB 67 8E\"   (?? or ? = wildcard)\n"
              << "  --replaceAoB=  : Replacement pattern (must match search length, ?? = keep original)\n"
              << "  --Aimbot       : Built-in hitbox swap scan (no AOB args needed)\n"
              << "  --rw           : scan only rw / rwx regions (default: all readable)\n"
              << "  --ctx          : show hex+ASCII context around each match\n";
}

// ══════════════════════════════════════════════════════════════════════════════
int main(int argc, char* argv[])
{
    if (argc < 3) { printUsage(argv[0]); return 1; }

    pid_t       pid       = 0;
    std::string aobStr;
    std::string replaceStr;
    bool        rwOnly    = false;
    bool        showCtx   = false;
    bool        aimbotMode = false;

    // Parse arguments dynamically
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--Aimbot") {
            aimbotMode = true;
        } else if (arg.rfind("--replaceAoB=", 0) == 0) {
            replaceStr = arg.substr(13);
        } else if (arg == "--rw") {
            rwOnly = true;
        } else if (arg == "--ctx") {
            showCtx = true;
        } else if (pid == 0) {
            try { pid = std::stoi(arg); } catch (...) {}
        } else if (aobStr.empty()) {
            aobStr = arg;
        }
    }

    if (pid == 0) {
        std::cerr << "[!] Invalid or missing PID.\n";
        printUsage(argv[0]);
        return 1;
    }

    // ── Aimbot Mode ────────────────────────────────────────────────────
    if (aimbotMode) {
        runAimbot(pid, rwOnly);
        return 0;
    }

    // ── Manual AOB Mode ────────────────────────────────────────────────
    if (aobStr.empty()) {
        std::cerr << "[!] Missing AOB pattern.\n";
        printUsage(argv[0]);
        return 1;
    }

    auto searchPattern = parseAOB(aobStr);
    if (searchPattern.empty()) {
        std::cerr << "[!] Empty / invalid search AOB pattern.\n";
        return 1;
    }
    printPattern("[*] Search  : ", searchPattern);

    std::vector<PatternByte> replacePattern;
    bool doReplace = !replaceStr.empty();

    if (doReplace) {
        replacePattern = parseAOB(replaceStr);
        if (replacePattern.empty()) {
            std::cerr << "[!] Empty / invalid replace AOB pattern.\n";
            return 1;
        }
        if (replacePattern.size() != searchPattern.size()) {
            std::cerr << "[!] Length mismatch! Search is " << searchPattern.size()
                      << " bytes, but Replace is " << replacePattern.size() << " bytes.\n";
            return 1;
        }
        printPattern("[*] Replace : ", replacePattern);
    }

    auto regions = getMemoryRegions(pid, rwOnly);
    std::cout << "[*] " << regions.size()
              << (rwOnly ? " rw/rwx" : " readable")
              << " region(s) found.  Scanning without pausing target...\n\n";

    std::vector<MatchInfo> allMatches;

    for (const auto& region : regions) {
        auto matches = scanRegion(pid, region, searchPattern);
        if (matches.empty()) continue;

        for (auto addr : matches) {
            allMatches.push_back({addr, region.perms, region.pathname});
            printf("  [+] 0x%016lX  (%s  %s)\n",
                   static_cast<unsigned long>(addr),
                   region.perms.c_str(),
                   region.pathname.empty() ? "[anon]" : region.pathname.c_str());
            if (showCtx && !doReplace)
                printContext(pid, addr, searchPattern.size());
        }
    }

    std::cout << "\n[*] Scan complete.  Total matches: " << allMatches.size() << "\n";

    if (doReplace && !allMatches.empty()) {
        size_t patLen = searchPattern.size();
        std::cout << "[*] Applying replacement to " << allMatches.size() << " match(es)...\n";

        for (const auto& match : allMatches) {
            std::vector<uint8_t> original(patLen);
            ssize_t r = remoteRead(pid, match.addr, original.data(), patLen);
            if (r != static_cast<ssize_t>(patLen)) {
                printf("  [!] Failed to read @ 0x%lX for patching\n", static_cast<unsigned long>(match.addr));
                continue;
            }

            std::vector<uint8_t> patched = original;
            for (size_t i = 0; i < patLen; ++i) {
                if (!replacePattern[i].isWildcard) {
                    patched[i] = replacePattern[i].value;
                }
            }

            ssize_t w = remoteWrite(pid, match.addr, patched.data(), patLen);
            if (w == static_cast<ssize_t>(patLen)) {
                printf("  [✓] Patched  0x%016lX  (%s  %s)\n",
                       static_cast<unsigned long>(match.addr),
                       match.perms.c_str(),
                       match.pathname.empty() ? "[anon]" : match.pathname.c_str());
                if (showCtx) printContext(pid, match.addr, patLen);
            } else {
                printf("  [✗] Failed   0x%016lX  (%s  %s) - %s\n",
                       static_cast<unsigned long>(match.addr),
                       match.perms.c_str(),
                       match.pathname.empty() ? "[anon]" : match.pathname.c_str(),
                       strerror(errno));
            }
        }
        std::cout << "[*] Replacement process finished.\n";
    }

    return 0;
}
