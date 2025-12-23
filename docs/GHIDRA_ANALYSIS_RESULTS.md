# Ghidra Analysis Results

**Status:** Analysis in progress or completed

## Running Automatic Analysis

To automatically analyze the RT-950 firmware using Ghidra:

### Option 1: Python Script (Recommended)
```bash
python scripts/ghidra_analyze_direct.py firmware/rt950/RT_950_V0.29_251104.BTF
```

### Option 2: Batch Script (Windows)
```bash
scripts\run_ghidra_simple.bat
```

### Option 3: Manual Ghidra
1. Open Ghidra
2. File → Import File
3. Select `firmware/rt950/RT_950_V0.29_251104.BTF`
4. Choose processor: `ARM:LE:32:Cortex`
5. Click Analyze

## Expected Analysis Output

After analysis completes, you should find:

- **Project Directory**: `firmware/rt950/ghidra_project/RT-950-Analysis/`
- **Function List**: Available in Ghidra Symbol Tree
- **Disassembly**: Full disassembly of firmware code
- **Decompiler Output**: C-like pseudocode for functions

## What to Extract

1. **Function Addresses**
   - System initialization functions
   - Driver initialization (BK4829, LCD, SPI)
   - Radio control functions
   - UI/menu functions

2. **Register Usage**
   - GPIO register addresses
   - Peripheral base addresses
   - Memory-mapped I/O addresses

3. **Memory Map**
   - Frame buffer locations
   - Stack/heap configuration
   - Flash/RAM layout

4. **String References**
   - Error messages
   - Menu text
   - Feature names

## Comparison with RT-950 Pro

Once both firmwares are analyzed, compare:

- Function addresses and offsets
- Register usage patterns
- Memory layout differences
- Feature differences (single vs dual band)

See [RT950_COMPARISON.md](RT950_COMPARISON.md) for comparison framework.

