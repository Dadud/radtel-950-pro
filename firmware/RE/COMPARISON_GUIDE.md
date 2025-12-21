# Firmware Version Comparison Guide

## Available Versions

### V0.18 (Previous)
- **Location**: `firmware/RE/analysis_export/`
- **Files**: 
  - `decrypted.bin` (0.36 MB)
  - `decrypted.bin.c` (1.07 MB)
  - `decrypted.bin.lst` (25.35 MB)

### V0.24 (Latest - Dec 2025)
- **Location**: `firmware/RE/v0.24_analysis/`
- **Files**:
  - `decrypted_v0.24.bin` (0.36 MB)
  - `decrypted_v0.24.bin.c` (1.15 MB)
  - `decrypted_v0.24.bin.lst` (24.83 MB)

## Quick Comparison Methods

### Method 1: Using the Decompile Script

```bash
cd firmware
python scripts/decompile_firmware.py --compare \
    decrypted.bin \
    decrypted_v0.24.bin \
    RE/v0.18_vs_v0.24_comparison
```

This will create a comparison directory with both versions side-by-side.

### Method 2: Manual Comparison with Diff Tools

#### Visual Studio Code
```bash
code --diff RE/analysis_export/decrypted.bin.c RE/v0.24_analysis/decrypted_v0.24.bin.c
```

#### WinMerge (Windows)
1. Open WinMerge
2. File → Open
3. Select both `.c` files
4. Compare!

#### Git Diff (if Git available)
```bash
git diff --no-index \
    RE/analysis_export/decrypted.bin.c \
    RE/v0.24_analysis/decrypted_v0.24.bin.c \
    > comparison_diff.txt
```

### Method 3: Ghidra Version Tracking

1. Open Ghidra GUI
2. Open project: `RE/rt950pro-correct.gpr`
3. Import `decrypted_v0.24.bin` as a new program
4. Use **Tools → Version Tracking** to compare

## V0.24 Changes to Focus On

Based on the changelog, these areas likely changed:

### 1. Channel/Zone Name Display
- **Changelog**: "Fix channel names not displayed in small font", "Add zone name display on main interface"
- **Search for**: Functions dealing with font rendering, channel/zone name display

### 2. Zone Management (Major Change!)
- **Changelog**: "Change number of areas to 10 and channels per area to 99"
- **Impact**: Likely changed data structures, array sizes, validation functions
- **Look for**: Constants like area count, channel count limits

### 3. CTCSS/DCS Decoding
- **Changelog**: "Fix CTCSS decoding bug"
- **Search for**: CTCSS/DCS decode functions, tone detection

### 4. Spectrum Interface
- **Changelog**: Multiple spectrum-related changes
  - Center/current frequency font changes
  - Left/right key adjustment for center frequency
  - Auto band switching fix
  - RSSI table optimization
- **Search for**: Spectrum rendering, frequency display functions

### 5. APRS
- **Changelog**: "Fix APRS not sent correctly on first boot"
- **Search for**: APRS initialization, channel switching on boot

### 6. Standby LED
- **Changelog**: "Add standby indicator light, green light blinks every 5 seconds"
- **Search for**: LED control, timer functions for blinking

### 7. Frequency Stepping
- **Changelog**: "Left/right keys adjustment", "Increase AM step frequency by 9K"
- **Search for**: Frequency adjustment functions, step size constants

## Key Functions to Compare

Search for these function patterns in both versions:

```bash
# Channel/Zone management
grep -i "channel.*name\|zone.*name" *.c

# CTCSS/DCS
grep -i "ctcss\|dcs\|tone" *.c

# Spectrum
grep -i "spectrum\|rssi" *.c

# APRS
grep -i "aprs" *.c

# Frequency step
grep -i "step.*frequency\|freq.*step" *.c

# LED/Timer
grep -i "led\|timer\|blink" *.c
```

## File Size Differences

| File | V0.18 | V0.24 | Difference |
|------|-------|-------|------------|
| Binary | 372 KB | 369 KB | -3 KB (slightly smaller) |
| C Code | 1.07 MB | 1.15 MB | +80 KB (more code/functions) |
| Listing | 25.35 MB | 24.83 MB | -520 KB (different code density) |

The C code is larger in V0.24, suggesting:
- More functions were successfully decompiled
- New functions were added
- Code structure changed (better decompilation)

## Notes

- Both versions use correct base address: `0x08000000`
- All function addresses use format: `FUN_0800xxxx` (correct!)
- Use the changelog as a guide for what changed
- Focus on the 12 specific changes listed in V0.24 changelog


