using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace AimbotModular
{
    class Program
    {
        // ── Aimbot Pattern & Offsets ──
        static string aimbotPattern = "FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A5 43";

        static string headOffset  = "B8";   // readOffset
        static string chestOffset = "B4";   // writeOffset

        static INTERNAL mem = new INTERNAL();
        static HashSet<long> appliedAddresses = new HashSet<long>();

        static void Main(string[] args)
        {
            Console.WriteLine("=== Aimbot Modular (64-bit) ===");
            Console.WriteLine("Commands: pid <id> | name <exe> | inject | reset | exit");

            while (true)
            {
                Console.Write("> ");
                string input = Console.ReadLine();
                if (string.IsNullOrEmpty(input)) continue;

                string[] parts = input.Trim().Split(new char[] { ' ' }, 2);
                string cmd = parts[0].ToLowerInvariant();
                string param = parts.Length > 1 ? parts[1].Trim() : "";

                switch (cmd)
                {
                    case "pid":
                        CmdPid(param);
                        break;
                    case "name":
                        CmdName(param);
                        break;
                    case "inject":
                        CmdInject();
                        break;
                    case "reset":
                        CmdReset();
                        break;
                    case "exit":
                        return;
                    default:
                        Console.WriteLine("Unknown command. Use: pid <id>, name <exe>, inject, reset, exit");
                        break;
                }
            }
        }

        // ── Attach by PID ──
        static void CmdPid(string param)
        {
            int pid;
            if (!int.TryParse(param, out pid))
            {
                Console.WriteLine("Invalid PID");
                return;
            }

            try
            {
                Process.GetProcessById(pid);
            }
            catch
            {
                Console.WriteLine("Process not found with PID: " + pid);
                return;
            }

            IntPtr handle = INTERNAL.OpenProcess(0x1F0FFF, false, pid);
            if (handle == IntPtr.Zero)
            {
                Console.WriteLine("Failed to open process. Run as admin?");
                return;
            }

            mem.pHandle = handle;
            bool isWow64;
            INTERNAL.IsWow64Process(handle, out isWow64);
            mem.Is64Bit = (Environment.Is64BitOperatingSystem && !isWow64);

            Console.WriteLine("Attached to PID: " + pid + " (" + (mem.Is64Bit ? "64-bit" : "32-bit") + ")");
        }

        // ── Attach by Process Name ──
        static void CmdName(string param)
        {
            if (string.IsNullOrEmpty(param))
            {
                Console.WriteLine("Usage: name <exe_name>");
                return;
            }

            bool success = mem.SetProcess(new string[] { param });
            if (!success)
            {
                Console.WriteLine("Failed to attach to process: " + param);
                return;
            }
            Console.WriteLine("Attached to: " + param + " (PID: " + mem.processId + ", " + (mem.Is64Bit ? "64-bit" : "32-bit") + ")");
        }

        // ── Aimbot Inject (Script 1 logic) ──
        static void CmdInject()
        {
            if (mem.pHandle == IntPtr.Zero)
            {
                Console.WriteLine("No process attached. Use pid or name first.");
                return;
            }

            Console.WriteLine("Scanning for aimbot pattern...");

            long readOff  = Convert.ToInt64(headOffset, 16);   // B8
            long writeOff = Convert.ToInt64(chestOffset, 16);  // B4

            IEnumerable<long> results = mem.AoBScan(aimbotPattern).GetAwaiter().GetResult();
            List<long> addresses = results.ToList();

            if (addresses.Count == 0)
            {
                Console.WriteLine("No occurrences found.");
                return;
            }

            Console.WriteLine("Found " + addresses.Count + " occurrence(s):");

            int patched = 0;
            foreach (long baseAddr in addresses)
            {
                long addrHead  = baseAddr + readOff;   // base + B8
                long addrChest = baseAddr + writeOff;  // base + B4

                if (appliedAddresses.Contains(addrHead))
                {
                    Console.WriteLine("  0x" + baseAddr.ToString("X") + " - Already patched, skipping.");
                    continue;
                }

                int headVal  = mem.ReadInt(addrHead);
                int chestVal = mem.ReadInt(addrChest);

                Console.WriteLine("  0x" + baseAddr.ToString("X") +
                    " - Head[" + headVal + "] Chest[" + chestVal + "] -> Swapping");

                // Swap head ↔ chest
                mem.WriteInt(addrChest, headVal);
                mem.WriteInt(addrHead,  chestVal);

                appliedAddresses.Add(addrHead);
                patched++;
            }

            Console.WriteLine("Patched " + patched + " new address(es). Total applied: " + appliedAddresses.Count);
        }

        // ── Reset applied tracking ──
        static void CmdReset()
        {
            appliedAddresses.Clear();
            Console.WriteLine("Applied addresses cleared. You can re-inject.");
        }
    }

    // ══════════════════════════════════════════════════
    //  INTERNAL — Combined framework from both scripts
    // ══════════════════════════════════════════════════
    public class INTERNAL
    {
        #region WinAPI Imports
        [DllImport("kernel32.dll")]
        private static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
        public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, UIntPtr dwLength);

        [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
        public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION32 lpBuffer, UIntPtr dwLength);
        #endregion

        #region Fields & Constants
        public int processId;
        public IntPtr pHandle;
        private bool _is64Bit;
        public bool Is64Bit
        {
            get { return _is64Bit; }
            set { _is64Bit = value; }
        }

        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const uint MEM_COMMIT = 0x1000;
        private const uint PAGE_NOACCESS = 0x01;
        #endregion

        #region Structs
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION32
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public uint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION64
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public uint __alignment1;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
            public uint __alignment2;
        }

        public struct MEMORY_BASIC_INFORMATION
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public long RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            private ushort reserved;
            public uint pageSize;
            public UIntPtr minimumApplicationAddress;
            public UIntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }
        #endregion

        #region VirtualQuery Wrapper
        public UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer)
        {
            if (this.Is64Bit || IntPtr.Size == 8)
            {
                MEMORY_BASIC_INFORMATION64 info64;
                UIntPtr result = Native_VirtualQueryEx(hProcess, lpAddress, out info64, new UIntPtr((uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64))));
                lpBuffer = new MEMORY_BASIC_INFORMATION
                {
                    BaseAddress = info64.BaseAddress,
                    AllocationBase = info64.AllocationBase,
                    AllocationProtect = info64.AllocationProtect,
                    RegionSize = (long)info64.RegionSize,
                    State = info64.State,
                    Protect = info64.Protect,
                    Type = info64.Type
                };
                return result;
            }
            else
            {
                MEMORY_BASIC_INFORMATION32 info32;
                UIntPtr result = Native_VirtualQueryEx(hProcess, lpAddress, out info32, new UIntPtr((uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION32))));
                lpBuffer = new MEMORY_BASIC_INFORMATION
                {
                    BaseAddress = info32.BaseAddress,
                    AllocationBase = info32.AllocationBase,
                    AllocationProtect = info32.AllocationProtect,
                    RegionSize = info32.RegionSize,
                    State = info32.State,
                    Protect = info32.Protect,
                    Type = info32.Type
                };
                return result;
            }
        }
        #endregion

        #region Process Management
        public bool SetProcess(string[] processNames)
        {
            processId = 0;
            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                string processName = process.ProcessName;
                if (Array.Exists(processNames, delegate(string name) { return name.Equals(processName, StringComparison.CurrentCultureIgnoreCase); }))
                {
                    processId = process.Id;
                    break;
                }
            }
            if (processId <= 0) return false;

            pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
            if (pHandle == IntPtr.Zero) return false;

            bool isWow64;
            IsWow64Process(pHandle, out isWow64);
            this.Is64Bit = (Environment.Is64BitOperatingSystem && !isWow64);

            return true;
        }
        #endregion

        #region Page Filter
        public bool CanReadPage(MEMORY_BASIC_INFORMATION page)
        {
            if (page.State != MEM_COMMIT) return false;
            if (page.Protect == PAGE_NOACCESS) return false;
            if ((page.Protect & 0x100) != 0) return false;  // Skip PAGE_GUARD
            if (page.Type == 0x1000000) return false;       // Skip MEM_IMAGE
            return true;
        }
        #endregion

        #region High Performance AoB Scan (Chunked + Unsafe)
        private struct PatternData
        {
            public byte[] Bytes;
            public byte[] Mask;
            public int Length;
            public bool Valid;
        }

        private PatternData ParsePattern(string patternString)
        {
            if (string.IsNullOrWhiteSpace(patternString)) return new PatternData { Valid = false };

            string[] parts = patternString.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            PatternData p = new PatternData
            {
                Bytes = new byte[parts.Length],
                Mask = new byte[parts.Length],
                Length = parts.Length,
                Valid = true
            };

            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i] == "??" || parts[i] == "?")
                {
                    p.Mask[i] = 0x00;
                    p.Bytes[i] = 0x00;
                }
                else
                {
                    p.Mask[i] = 0xFF;
                    p.Bytes[i] = Convert.ToByte(parts[i], 16);
                }
            }
            return p;
        }

        public Task<IEnumerable<long>> AoBScan(string search)
        {
            return Task.Run(() =>
            {
                ConcurrentBag<long> foundAddresses = new ConcurrentBag<long>();
                PatternData pattern = ParsePattern(search);
                if (!pattern.Valid) return (IEnumerable<long>)foundAddresses;

                List<MEMORY_BASIC_INFORMATION> memoryRegions = new List<MEMORY_BASIC_INFORMATION>();
                SYSTEM_INFO sysInfo;
                GetSystemInfo(out sysInfo);

                ulong minStart = sysInfo.minimumApplicationAddress.ToUInt64();
                ulong maxEnd = sysInfo.maximumApplicationAddress.ToUInt64();
                UIntPtr currentAddr = new UIntPtr(minStart);

                while (currentAddr.ToUInt64() < maxEnd)
                {
                    MEMORY_BASIC_INFORMATION mem;
                    if (VirtualQueryEx(pHandle, currentAddr, out mem) == UIntPtr.Zero) break;

                    if (CanReadPage(mem))
                    {
                        memoryRegions.Add(mem);
                    }

                    currentAddr = new UIntPtr(currentAddr.ToUInt64() + (ulong)mem.RegionSize);
                }

                Parallel.ForEach(memoryRegions, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, (region) =>
                {
                    long offset = 0;
                    while (offset < region.RegionSize)
                    {
                        int chunkSize = (int)Math.Min(region.RegionSize - offset, 67108864L);
                        if (chunkSize <= 0) break;

                        UIntPtr chunkAddress = new UIntPtr(region.BaseAddress.ToUInt64() + (ulong)offset);
                        byte[] buffer = new byte[chunkSize];

                        if (ReadProcessMemory(pHandle, chunkAddress, buffer, (UIntPtr)chunkSize, IntPtr.Zero))
                        {
                            unsafe
                            {
                                fixed (byte* pBuffer = buffer)
                                fixed (byte* pPattern = pattern.Bytes)
                                fixed (byte* pMask = pattern.Mask)
                                {
                                    int limit = chunkSize - pattern.Length;

                                    for (int i = 0; i <= limit; i++)
                                    {
                                        if (pMask[0] == 0xFF && pBuffer[i] != pPattern[0]) continue;

                                        bool match = true;
                                        for (int j = 1; j < pattern.Length; j++)
                                        {
                                            if (pMask[j] == 0xFF && pBuffer[i + j] != pPattern[j])
                                            {
                                                match = false;
                                                break;
                                            }
                                        }

                                        if (match)
                                        {
                                            foundAddresses.Add((long)chunkAddress + i);
                                        }
                                    }
                                }
                            }
                        }
                        offset += chunkSize;
                    }
                });

                return (IEnumerable<long>)foundAddresses;
            });
        }
        #endregion

        #region Read / Write Helpers
        public int ReadInt(long address)
        {
            try
            {
                byte[] buffer = new byte[4];
                ReadProcessMemory(pHandle, new UIntPtr((ulong)address), buffer, (UIntPtr)4, IntPtr.Zero);
                return BitConverter.ToInt32(buffer, 0);
            }
            catch
            {
                return 0;
            }
        }

        public bool WriteInt(long address, int value)
        {
            try
            {
                if (pHandle == IntPtr.Zero) return false;
                byte[] data = BitConverter.GetBytes(value);
                UIntPtr target = new UIntPtr((ulong)address);
                return WriteProcessMemory(pHandle, target, data, (UIntPtr)data.Length, IntPtr.Zero);
            }
            catch { return false; }
        }

        public bool AobReplace(long address, string bytePattern)
        {
            try
            {
                byte[] array = StringToByteArray(bytePattern);
                UIntPtr target = new UIntPtr((ulong)address);
                return WriteProcessMemory(pHandle, target, array, (UIntPtr)array.Length, IntPtr.Zero);
            }
            catch (Exception) { }
            return false;
        }

        private byte[] StringToByteArray(string hexString)
        {
            return (from hex in hexString.Split(' ')
                    select byte.Parse(hex, NumberStyles.HexNumber)).ToArray();
        }
        #endregion
    }
}
