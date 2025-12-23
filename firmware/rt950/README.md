# RT-950 (Non-Pro) Firmware Analysis

This folder contains firmware and analysis files for the **RT-950** (non-Pro) radio model.

## Firmware Files

- **RT_950_V0.29_251104.BTF** (318 KB) - Binary firmware file for RT-950
- **RT-950_EnUPDATE.exe** - Windows firmware update tool
- **ReadMeEn.txt** - Release notes (V0.27-V0.29)
- **950Instruction.docx/pdf** - Instruction manuals

## Firmware Version: V0.29 (Released 2025-11-04)

### V0.29 Changes
1. Updated spectrum interface and fixed related bugs
2. Optimized spectrum functionality: added 5 kHz stepping and backlight-off option
3. Enabled independent configuration of PF1 and PTTC functions
4. Added menus for DTMF code-delay, code-duration, and inter-code spacing
5. Added the ability to customize zone names
6. Improved stability to prevent APRS crashes

### V0.28 Changes
1. Fixed crash bug in scanning and addition function under zone mode

### V0.27 Changes
1. Added single PTT mode (can be toggled on/off via menu)
2. Added temporary scan list feature (custom-mapped to long-pressing keys 0-9)
3. Added channel scanning with add and delete set functions

## Analysis Status

⚠️ **Analysis in progress** - See [../COMPARISON.md](../COMPARISON.md) for RT-950 vs RT-950 Pro comparison.

## Ghidra Analysis

To analyze this firmware in Ghidra:

1. Import the `.BTF` file into a new Ghidra project
2. Use AT32F403A processor specification (ARM Cortex-M4F)
3. Analyze the binary for:
   - Function entry points
   - Register usage patterns
   - Hardware initialization sequences
   - Memory map differences from RT-950 Pro

## Differences from RT-950 Pro

(To be documented after analysis)

- Hardware differences
- Feature differences
- Memory layout differences
- Driver differences

