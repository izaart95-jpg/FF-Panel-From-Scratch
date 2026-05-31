# Aimbot Hitbox Swapper

A high-performance, console-based memory manipulation tool that exploits game hitbox data structures to convert standard aim-assist into an automatic headshot aimbot. Unlike traditional memory patches that modify code execution (instruction patching), this tool manipulates data structures to trick the game engine.

---

## How It Works: The Core Mechanism

Most shooter games with aim-assist prioritize locking onto the Chest hitbox because it is the largest and feels "fair." Headshots require manual precision but yield higher damage.

This tool reverses the game's internal hitbox identifiers. By finding the enemy entity structure in memory and swapping the IDs of the Head and Chest, the game's own aim-assist logic is exploited:

1. The aim-assist locks onto the biggest target (the Chest).
2. The game engine reads the ID at the Chest memory address.
3. Because the IDs were swapped, the engine evaluates the hit as a Headshot.
Result: Easy, automatic headshots using the game's built-in aiming mechanics.

---

## Technical Breakdown
### 1. Array of Bytes (AoB) Signature Scan

The tool scans the target process memory for a specific 118-byte pattern:
FF FF FF FF 00 00 00 00 ... ?? ?? ?? ?? ... A5 43
The ?? act as wildcards (mask bytes) for dynamic data that changes per player/entity. The surrounding static bytes identify the base address of the hitbox/bone structure.
### 2. Hitbox Offsets
Once the base address is found, the tool navigates to two specific offsets within that structure:
- `0xB4` (Chest Offset)
- `0xB8` (Head Offset)

### 3. The 4-Byte Integer Swap
The game stores the hitbox IDs as standard 32-bit integers (int). The tool reads exactly 4 bytes from each offset, swaps their values, and writes them back:
```csharp
int headVal  = ReadInt(baseAddr + 0xB8); // Read Head ID
int chestVal = ReadInt(baseAddr + 0xB4); // Read Chest ID

WriteInt(baseAddr + 0xB4, headVal);      // Write Head ID into Chest slot
WriteInt(baseAddr + 0xB8, chestVal);     // Write Chest ID into Head slot
```
### 4. Duplicate Prevention
A HashSet tracks appliedAddresses. If the scanner finds the same entity structure again, it skips it to prevent swapping the values back to their original state.

### 5. High-Performance Chunked Scanner
The memory scanner uses:

- VirtualQueryEx to map committed, accessible memory pages.
- Chunking (64MB max per read) to handle massive memory regions without overflowing.
- Parallel Processing (Parallel.ForEach) utilizing all CPU cores.
- Unsafe pointers for rapid byte-by-byte comparison inside the compiled loop.
