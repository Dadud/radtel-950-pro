# RT-950 V0.29 Firmware Analysis Summary

**Analysis Date:** 2025-12-23  
**Firmware Version:** V0.29 (Released 2025-11-04)  
**Status:** ✅ Ready for Ghidra analysis

## Quick Facts

- **File Size**: 318,692 bytes (311 KB)
- **Format**: Unencrypted ARM Cortex-M binary
- **Vector Table**: Present and valid
- **RAM Usage**: 86.3 KB of 96 KB total
- **Stack Pointer**: `0x20015940`

## Vector Table

| Vector | Address | Description |
|--------|---------|-------------|
| Stack Pointer | `0x20015940` | Top of RAM (86.3 KB used) |
| Reset Handler | `0x08003191` | Entry point (offset 0x003191) |
| NMI Handler | `0x08017B59` | Non-maskable interrupt |
| Hard Fault | `0x08013B0D` | Hard fault handler |
| Mem Fault | `0x080163F5` | Memory management fault |
| Bus Fault | `0x080037DF` | Bus fault handler |
| Usage Fault | `0x080208A1` | Usage fault handler |

## Analysis Results

### Binary Structure
- ✅ Standard ARM Cortex-M vector table at offset 0x00
- ✅ Reset handler at `0x08003191` (code starts ~0x08003000)
- ✅ No encryption markers found
- ✅ Valid exception handler addresses

### Code Patterns
- 67 function prologues (PUSH {lr})
- 3 function returns (BX LR)
- ~100 function calls (BL instructions)
- Normal ARM Thumb-2 code structure

## Next Steps

1. **Ghidra Analysis** (Manual)
   - Follow guide: `../GHIDRA_ANALYSIS.md`
   - Import firmware file
   - Analyze functions and memory map
   - Extract driver initialization sequences

2. **Comparison with RT-950 Pro**
   - See: `../../docs/RT950_COMPARISON.md`
   - Compare function addresses
   - Identify hardware differences
   - Document feature differences

3. **Build System Integration**
   - Create unified firmware build
   - Add RT-950 compile-time flags
   - Test on both models

## Tools

- **Analysis Script**: `../../scripts/analyze_firmware.py`
  ```bash
  python scripts/analyze_firmware.py firmware/rt950/RT_950_V0.29_251104.BTF
  ```

- **Ghidra Guide**: `../GHIDRA_ANALYSIS.md`

## References

- Comparison Document: `../../docs/RT950_COMPARISON.md`
- Ghidra Analysis: `../GHIDRA_ANALYSIS.md`
- Main README: `../../README.md`

