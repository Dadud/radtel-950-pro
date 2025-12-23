# Ghidra Analysis Guide

This guide explains how to analyze RT-950 and RT-950 Pro firmware using Ghidra.

## Prerequisites

1. **Ghidra** - Download from https://ghidra-sre.org/
2. **Java 17+** - Required for Ghidra
3. **Processor Specification**: ARM Cortex-M4F (Thumb mode)
4. **Memory Map**: AT32F403A microcontroller

## Analysis Process

### Step 1: Create New Project

1. Launch Ghidra
2. File → New Project → Non-Shared Project
3. Name: `RT-950-Firmware-Analysis`
4. Choose project location

### Step 2: Import Firmware File

1. File → Import File
2. Select `RT_950_V0.29_251104.BTF` (RT-950) or Pro firmware
3. Accept default import options
4. Click "OK" when analysis options appear

### Step 3: Configure Analysis Options

**Language:**
- Select: `ARM:LE:32:v8` (ARM Little Endian, 32-bit, v8)
- OR: `ARM:LE:32:Cortex` (Cortex-M specific)

**Analysis Options:**
- ✅ Decompiler Parameter ID
- ✅ Decompiler Parameter ID (Register)
- ✅ Reference
- ✅ Create Address Tables
- ✅ Create Function Start Addresses
- ✅ Disassemble Entry Points
- ✅ ARM Constant Reference Analyzer
- ✅ Decompiler Switch Analysis

**Memory Map:**
- Add memory block: `FLASH` at `0x08000000`, length `0x100000` (1MB), read-only
- Add memory block: `RAM` at `0x20000000`, length `0x18000` (96KB), read-write

### Step 4: Analyze

1. Click "Analyze"
2. Wait for analysis to complete
3. Review functions in the Symbol Tree

### Step 5: Identify Entry Points

**Reset Vector:**
- Check `0x08000004` - should contain address of reset handler
- Reset handler typically at `0x08000000` or vector table offset

**Common Functions to Look For:**
- System initialization (clock setup)
- GPIO configuration
- SPI initialization (RF transceiver)
- LCD initialization
- UART setup

### Step 6: Compare RT-950 vs RT-950 Pro

1. Open both firmware files in separate Ghidra windows
2. Compare function addresses:
   - Do they start at same base address?
   - Are functions in same relative positions?
3. Compare register usage patterns
4. Compare memory map usage
5. Look for hardware-specific differences

## Expected Differences

### Hardware Differences
- **RT-950**: Single-band or different RF setup?
- **RT-950 Pro**: Dual-band (VHF/UHF), dual BK4829 chips

### Memory Layout
- Flash size may differ
- RAM usage patterns may differ
- Frame buffer locations may differ

### Function Addresses
- May be offset due to different firmware sizes
- Some functions may be removed/added

## Useful Ghidra Features

### Function Comparison
- Tools → Diff → Function Diff
- Compare equivalent functions between versions

### Scripting
- Window → Python
- Write scripts to extract register values, function addresses, etc.

### Decompiler
- View → Decompiler
- C-like pseudocode view
- Easier to understand than assembly

## Extracting Information

### Register Values
1. Search for immediate values in assembly
2. Look for `MOV` or `LDR` instructions with large constants
3. These often indicate register addresses

### Function Entry Points
1. Look for `FUN_` prefixes in symbol table
2. Or create naming convention: `init_system`, `init_gpio`, etc.

### Memory Map
1. Look for load/store operations with specific addresses
2. Frame buffer accesses: `0x20000BD0`
3. Peripheral registers: `0x40000000` - `0x60000000`

## Output Files

Save your Ghidra projects:
- RT-950: `firmware/rt950/ghidra_project/`
- RT-950 Pro: `firmware/rt950pro/ghidra_project/`

Export findings:
- Function list: CSV export
- Memory map: Documentation
- Register usage: Custom notes

## Notes

- RT-950 firmware may be encrypted (check file header)
- If encrypted, use update tool (`RT-950_EnUPDATE.exe`) to extract decrypted version
- Compare binary sizes and structure before/after decryption

