# RT-950 Pro Firmware Analysis

This folder contains firmware and analysis files for the **RT-950 Pro** radio model.

## Firmware Files

- **RT_950Pro_V0.24_251201.BTF** - Binary firmware file for RT-950 Pro
- **RT-950_EnUPDATE.exe** - Windows firmware update tool
- **ReadMeEn.txt** - Release notes
- **950Instruction.docx/pdf** - Instruction manuals

## Firmware Version: V0.24 (Released 2025-12-01)

### Release Notes

See `ReadMeEn.txt` for complete release notes.

## Analysis Status

⚠️ **Analysis in progress** - See comparison documents for differences between RT-950 and RT-950 Pro.

## Ghidra Analysis

To analyze this firmware in Ghidra:

1. Import the `.BTF` file into a new Ghidra project
2. Use AT32F403A processor specification (ARM Cortex-M4F)
3. Analyze the binary for:
   - Function entry points
   - Register usage patterns
   - Hardware initialization sequences
   - Memory map differences from RT-950

## Comparison with RT-950

See:
- **Main Comparison**: [`../../docs/RT950_COMPARISON.md`](../../docs/RT950_COMPARISON.md)
- **Differences Summary**: [`../../docs/RT950_DIFFERENCES_SUMMARY.md`](../../docs/RT950_DIFFERENCES_SUMMARY.md)

## Key Differences from RT-950

- **Dual-band operation** (VHF/UHF vs single-band)
- **Dual BK4829 transceivers** (U11 and U12)
- **KISS TNC mode** for APRS over Bluetooth
- **Larger firmware size** (more features)

