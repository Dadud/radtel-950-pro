# RT-950 Pro Firmware V0.24 Analysis

## Firmware Information

- **Version**: V0.24 (Released: 2025-12-01)
- **File**: decrypted_v0.24.bin
- **Size**: 369.27 KB (378,136 bytes)
- **Base Address**: 0x08000000
- **Processor**: ARM:LE:32:Cortex (ARM Cortex-M4)
- **Decompiled**: 2025-12-20 12:12:14

## V0.24 Changelog

1. Fix the issue where channel names are not displayed in small font
2. Add zone name display on the main interface
3. Change the number of areas to 10 and the number of channels per area to 99
4. Fix the CTCSS decoding bug
5. Spectrum interface - Change center frequency to small font and current frequency to large font
6. Add left/right key adjustment for center frequency in spectrum mode
7. Add left/right keys in radio mode for adjustment by minimum step frequency
8. Fix the issue where APRS is not sent correctly on first boot (not sent via the configured APRS-CH)
9. Add standby indicator light, green light blinks every 5 seconds after screen off
10. Fix the issue where work band does not automatically switch based on frequency in spectrum mode
11. Optimize RSSI table display in spectrum mode
12. In radio mode, increase AM step frequency by 9K

## Files

- decrypted_v0.24.bin - Original firmware binary (decrypted from BTF)
- decrypted_v0.24.bin.c - Decompiled C code (1.15 MB)
- decrypted_v0.24.bin.lst - Assembly listing (24.8 MB)
- README.md - This file

## Comparison

To compare with V0.18 firmware:

\\\ash
python decompile_firmware.py --compare decrypted.bin decrypted_v0.24.bin
\\\

Or use the existing v0.18 analysis in:
- irmware/RE/analysis_export/ (from earlier export)

## Key Areas to Check

Based on the changelog, focus on:
- Channel/zone name display functions
- Zone management (changed from previous area/channel limits)
- CTCSS/DCS decoding functions
- Spectrum interface rendering
- APRS initialization and channel switching
- Standby LED control
- RSSI display in spectrum mode
- AM frequency step handling

