# Sniper Scope External Tool – Guide & Resources

> **Disclaimer**  
> This document is provided for **educational and research purposes only**. The techniques described involve memory manipulation and reverse engineering, which may violate the terms of service of many applications. Use this information responsibly and only on systems you own or have explicit permission to test.

## Overview

This guide explains how to build and configure an external memory manipulation tool that modifies game behavior related to sniper scope functionality. The tool works by scanning memory for a specific byte signature (original bytes) and replacing it with a custom byte pattern (patched bytes).

## Step 1: Download the Memory File

You have two source files to choose from. The `Debug.cpp` version is recommended for development and testing.

| File | URL |
|------|-----|
| `Program.cs` (Recommended) | [Download](https://raw.githubusercontent.com/izaart95-jpg/FF-Panel-From-Scratch/refs/heads/main/src/Memory/cs/Program.cs) |
| `Core-Mem.cs` | [Download](https://raw.githubusercontent.com/izaart95-jpg/FF-Panel-From-Scratch/refs/heads/main/src/Memory/cs/Core-Mem.cs) |

**Im proceeding with `Program.cs` for this guide.**

## Step 2: Dump Il2cpp and Find `initbase`

Dump the Il2cpp metadata from the target process and locate the `initbase` address. This is required for reverse engineering Unity games.

Refer to standard Il2cpp dumping tools (e.g., Il2CppDumper) to extract the structures. 
Recommended: [Watch this tutorial](https://youtu.be/X-g085tyoAk?si=YjLEius-29b-njav)
## Step 3: Locate the Sniper Scope Routine

You need to find the code that executes when a player **opens a sniper scope near an enemy/entity**.

You can locate it either:
- **Statically** – using the dumped Il2cpp structures.
- **Dynamically** – using a debugger (e.g., x64dbg, Cheat Engine).

> **Hint (as of 31 May 2026):**  
> The following byte signature corresponds to that code:
> 
> `9A 99 99 3E FF FF FF FF 08 00 00 00 00 00 60 40 CD CC 8C 3F 8F C2 F5 3C CD CC CC 3D 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F 33 33 13 40 00 00 B0 3F 00 00 80 3F 01`

## Step 4: Compare with Normal Scope Code

Find the code that runs when a **normal (non‑sniper) scope** is opened near an enemy/entity.  
Compare the two byte arrays and identify the differences.

Then, experiment by modifying individual bytes from the original sniper scope signature and test in‑game.  
Through iterative testing, you will arrive at a set of bytes that works as the **AOB (Array of Bytes) signature**.

For this specific case, the working signature is:

`9A 99 99 3E FF FF FF FF 08 00 00 00 00 00 60 40 CD CC 8C 3F 8F C2 F5 3C CD CC CC 3D 06 00 00 00 00 00 19 3F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F 33 33 13 40 00 00 B0 3F 00 00 80 3F 01`

## Configuring the Memory Tool

The memory scanner works by scanning for `originalBytes` and replacing each occurrence with `patchedBytes`.

In either `Core-Mem.cs` or `Program.cs`, locate and modify these two variables:

```csharp
static string originalBytes = "";   
static string patchedBytes = "";
```

Then compile it using MSVS or cli tool for eg. csc.exe which stands for csharp compiler

### Important:
- The fewer bytes you modify, the smaller the signature footprint, which reduces the chance of detection.
