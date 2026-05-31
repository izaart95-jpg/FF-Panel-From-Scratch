using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

// This is a Memory Manager which scans game's code and replaces with patched code
// In This case the originalByte is the memory which is executed whenever player opens scope of sniper
// Then the patched bytes contains 2 modifications those 2 mods are of normal guns where the scope auto sticks to player
// by adding normal gun bytes to sniper this code works 

namespace MemoryMain
{
    class Program
    {
        static string originalBytes = "9A 99 99 3E FF FF FF FF 08 00 00 00 00 00 60 40 CD CC 8C 3F 8F C2 F5 3C CD CC CC 3D 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F 33 33 13 40 00 00 B0 3F 00 00 80 3F 01";   // Array of Bytes To Scan
        static string patchedBytes = "9A 99 99 3E FF FF FF FF 08 00 00 00 00 00 60 40 CD CC 8C 3F 8F C2 F5 3C CD CC CC 3D 06 00 00 00 00 00 19 3F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F 33 33 13 40 00 00 B0 3F 00 00 80 3F 01"; // AoB to replace
        static INTERNAL mem = new INTERNAL();

        static void Main(string[] args)
        {
            Console.WriteLine("CSHARP Console (64-bit)");
            Console.WriteLine("Commands: pid <id> | name <exe> | inject | exit");

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
                    case "exit":
                        return;
                    default:
                        Console.WriteLine("Unknown command. Use: pid <id>, name <exe>, inject, exit");
                        break;
                }
            }
        }

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

            IntPtr handle = INTERNAL.OpenProcess(ProcessAccessFlags.AllAccess, false, pid);
            if (handle == IntPtr.Zero)
            {
                Console.WriteLine("Failed to open process. Run as admin?");
                return;
            }

            mem.processId = pid;
            mem._processHandle = handle;
            Console.WriteLine("Attached to PID: " + pid);
        }

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
            Console.WriteLine("Attached to: " + param + " (PID: " + mem.processId + ")");
        }

        static void CmdInject()
        {
            if (mem._processHandle == IntPtr.Zero)
            {
                Console.WriteLine("No process attached. Use pid or name first.");
                return;
            }

            Console.WriteLine("Scanning...");
            IEnumerable<long> results = mem.AoBScan(originalBytes).GetAwaiter().GetResult();
            List<long> addresses = results.ToList();

            if (addresses.Count == 0)
            {
                Console.WriteLine("No occurrences found.");
                return;
            }

            Console.WriteLine("Found " + addresses.Count + " occurrence(s):");
            foreach (long addr in addresses)
            {
                Console.WriteLine("  0x" + addr.ToString("X"));
            }

            foreach (long addr in addresses)
            {
                mem.AobReplace(addr, patchedBytes);
            }
            Console.WriteLine("Patched " + addresses.Count + " address(es). Done.");
        }
    }

    public class INTERNAL
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, IntPtr lpNumberOfBytesWritten);

        public struct PatternData
        {
            public byte[] pattern { get; set; }
            public byte[] mask { get; set; }
        }

        public struct MemoryPage
        {
            public IntPtr Start;
            public int Size;
            public MemoryPage(IntPtr start, int size) { Start = start; Size = size; }
        }

        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public int processId;
        public IntPtr _processHandle;

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
            _processHandle = OpenProcess(ProcessAccessFlags.AllAccess, false, processId);
            if (_processHandle == IntPtr.Zero) return false;
            return true;
        }

        public async Task<IEnumerable<long>> AoBScan(string bytePattern)
        {
            return await AobScan(bytePattern);
        }

        private async Task<IEnumerable<long>> AobScan(string pattern)
        {
            PatternData patternData = GetPatternDataFromPattern(pattern);
            List<long> addressRet = new List<long>();
            await Task.Run(delegate
            {
                List<MemoryPage> list = new List<MemoryPage>();
                long ptr = 0;
                while (true)
                {
                    MEMORY_BASIC_INFORMATION lpBuffer;
                    int result = VirtualQueryEx(_processHandle, new IntPtr(ptr), out lpBuffer, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                    if (result == 0) break;

                    long baseAddr = lpBuffer.BaseAddress.ToInt64();
                    long regionSize = (long)lpBuffer.RegionSize.ToUInt64();

                    if (CanReadPage(lpBuffer))
                    {
                        // Split large regions into 1GB chunks to prevent OutOfMemoryException
                        long offset = 0;
                        while (offset < regionSize)
                        {
                            int chunkSize = (int)Math.Min(regionSize - offset, 1073741824L);
                            if (chunkSize > 0)
                            {
                                list.Add(new MemoryPage(new IntPtr(baseAddr + offset), chunkSize));
                            }
                            offset += chunkSize;
                        }
                    }

                    long nextAddr = baseAddr + regionSize;
                    if (nextAddr <= ptr) break; // Overflow guard or end of memory
                    ptr = nextAddr;
                }

                int patternLength = patternData.pattern.Length;
                Parallel.ForEach(list, delegate(MemoryPage addresss)
                {
                    byte[] array = new byte[addresss.Size];
                    IntPtr lpNumberOfBytesRead;
                    if (ReadProcessMemory(_processHandle, addresss.Start, array, (IntPtr)addresss.Size, out lpNumberOfBytesRead))
                    {
                        long bytesRead = lpNumberOfBytesRead.ToInt64();
                        int bytesToSearch = (int)Math.Min(bytesRead, (long)addresss.Size);

                        if (bytesToSearch > 0 && bytesToSearch >= patternLength)
                        {
                            byte[] searchArray = array;
                            if (bytesToSearch < addresss.Size)
                            {
                                Array.Resize(ref searchArray, bytesToSearch);
                            }

                            int num = -patternLength;
                            do
                            {
                                num = FindPattern(searchArray, patternData.pattern, patternData.mask, num + patternLength);
                                if (num >= 0)
                                {
                                    lock (addressRet)
                                    {
                                        addressRet.Add(addresss.Start.ToInt64() + num);
                                    }
                                }
                            } while (num != -1);
                        }
                    }
                });
            });
            return addressRet.OrderBy(delegate(long c) { return c; }).AsEnumerable();
        }

        public bool CanReadPage(MEMORY_BASIC_INFORMATION page)
        {
            if (page.State != 0x1000)       // Must be MEM_COMMIT
                return false;
            if (page.Protect == 0x01)        // Skip PAGE_NOACCESS
                return false;
            if ((page.Protect & 0x100) != 0) // Skip PAGE_GUARD
                return false;
            return true;
        }

        private PatternData GetPatternDataFromPattern(string pattern)
        {
            string[] patternParts = pattern.Split(' ');
            PatternData patternData = new PatternData
            {
                pattern = patternParts.Select(delegate(string s) { return s.Contains("??") ? (byte)0x00 : byte.Parse(s, NumberStyles.HexNumber); }).ToArray(),
                mask = patternParts.Select(delegate(string s) { return s.Contains("??") ? (byte)0x00 : (byte)0xFF; }).ToArray()
            };
            return patternData;
        }

        public bool AobReplace(long address, string bytePattern)
        {
            try
            {
                byte[] array = StringToByteArray(bytePattern);
                return WriteProcessMemory(_processHandle, new IntPtr(address), array, (IntPtr)array.Length, IntPtr.Zero);
            }
            catch (Exception) { }
            return false;
        }

        private byte[] StringToByteArray(string hexString)
        {
            return (from hex in hexString.Split(' ')
                    select byte.Parse(hex, NumberStyles.HexNumber)).ToArray();
        }

        private int FindPattern(byte[] body, byte[] pattern, byte[] masks, int start)
        {
            int result = -1;
            if (body.Length == 0 || pattern.Length == 0 || start > body.Length - pattern.Length || pattern.Length > body.Length)
                return result;
            for (int i = start; i <= body.Length - pattern.Length; i++)
            {
                if ((body[i] & masks[0]) != (pattern[0] & masks[0]))
                    continue;
                bool flag = true;
                for (int num = pattern.Length - 1; num >= 1; num--)
                {
                    if ((body[i + num] & masks[num]) != (pattern[num] & masks[num]))
                    {
                        flag = false;
                        break;
                    }
                }
                if (flag) { result = i; break; }
            }
            return result;
        }
    }

    [Flags]
    public enum ProcessAccessFlags
    {
        AllAccess = 0x001F0FFF
    }

    [Flags]
    public enum ThreadAccess : int
    {
        SUSPEND_RESUME = 0x0002
    }
}
