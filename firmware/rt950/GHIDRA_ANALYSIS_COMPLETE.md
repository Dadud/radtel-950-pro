# ✅ Ghidra Analysis Complete!

**Date**: 2025-12-23  
**Firmware**: RT_950_V0.29_251104.BTF  
**Status**: ✅ Analysis completed successfully

## Project Location

**Ghidra Project**: `firmware/rt950/ghidra_project/RT-950-Analysis/`

## How to View Results

### Option 1: Open in Ghidra GUI
1. Launch Ghidra
2. **File → Open Project**
3. Navigate to: `firmware/rt950/ghidra_project/`
4. Select: **RT-950-Analysis**
5. Click **Open**

### Option 2: View Project Files
The project contains:
- `RT-950-Analysis.gpr` - Project configuration
- `RT-950-Analysis.rep/` - Analysis data repository

## What to Look For

Once the project is open in Ghidra:

### 1. Function List
- Press **Ctrl+Shift+E** (or **Window → Symbol Tree**)
- Expand **Functions** folder
- All analyzed functions will be listed
- Functions are typically named `FUN_0800xxxx`

### 2. Entry Points
- **Reset Handler**: `0x08003191` (confirmed from vector table)
- **Exception Handlers**: NMI, Hard Fault, Mem Fault, etc.

### 3. Memory Map
- **Flash**: `0x08000000` - `0x0804E164` (318,692 bytes)
- **RAM**: `0x20000000` - `0x20015940` (86.3 KB used)

### 4. Key Functions to Identify

#### System Initialization
- Reset handler at `0x08003191`
- System clock configuration
- GPIO initialization

#### Driver Functions
- BK4829 initialization (single or dual chip?)
- LCD display driver
- SPI flash driver
- Rotary encoder driver

#### Radio Functions
- VFO control
- Channel management
- CTCSS/DCS handling

#### UI Functions
- Menu system
- Display rendering
- Keypad handling

## Next Steps

### 1. Compare with RT-950 Pro
- Open both projects in separate Ghidra windows
- Compare function addresses
- Look for differences in driver code (single vs dual BK4829)
- Document memory layout differences

### 2. Extract Function List
- **File → Export Program → Function Start Addresses**
- Save as CSV or text file
- Compare with RT-950 Pro function list

### 3. Analyze Key Drivers
- Locate BK4829 initialization function
- Check if single or dual transceiver setup
- Compare register usage patterns

### 4. Update Comparison Document
- Add findings to `docs/RT950_COMPARISON.md`
- Document function address mappings
- Note hardware differences found

## Exporting Data from Ghidra

### Function List
```
File → Export Program → Function Start Addresses
```

### Strings
```
Search → For Strings...
Edit → Select All
Right-click → Export → CSV
```

### Decompiled Code
```
Right-click function → Copy Special → Decompiled C
```

## Quick Reference

| Address | Type | Description |
|---------|------|-------------|
| `0x08000000` | Flash Base | Start of firmware |
| `0x08003191` | Reset Handler | Entry point |
| `0x20000000` | RAM Base | Start of SRAM |
| `0x20015940` | Stack Top | 86.3 KB RAM used |

## Analysis Scripts

All scripts are in `scripts/`:
- `ghidra_analyze_direct.py` - Re-run analysis if needed
- `analyze_binary_deep.py` - Binary analysis (already completed)
- `extract_ghidra_results.py` - Check project status

## Notes

- Analysis used **ARM Cortex-M** processor specification
- All functions should be analyzed and named
- Decompiler output available for C-like pseudocode
- Cross-references automatically generated

---

**The project is ready for interactive analysis in Ghidra!**

