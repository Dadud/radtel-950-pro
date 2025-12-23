# RT-950 Pro V0.24 Firmware Analysis Summary

**Analysis Date:** 2025-12-23  
**Firmware Version:** V0.24 (Released 2025-12-01)  
**Status:** ✅ Ready for Ghidra analysis

## Quick Facts

- **File Size**: 378,136 bytes (369.3 KB)
- **Format**: Unencrypted ARM Cortex-M binary
- **Vector Table**: Present and valid
- **RAM Usage**: 87.1 KB of 96 KB total
- **Stack Pointer**: `0x20015C98`

## Vector Table

| Vector | Address | Description |
|--------|---------|-------------|
| Stack Pointer | `0x20015C98` | Top of RAM (87.1 KB used) |
| Reset Handler | `0x080032A1` | Entry point (offset 0x0032A1) |
| NMI Handler | `0x0801AEE9` | Non-maskable interrupt |
| Hard Fault | `0x0801699D` | Hard fault handler |
| Mem Fault | `0x0801958D` | Memory management fault |
| Bus Fault | `0x0800A23B` | Bus fault handler |
| Usage Fault | `0x08024A69` | Usage fault handler |

## Analysis Results

### Binary Structure
- ✅ Standard ARM Cortex-M vector table at offset 0x00
- ✅ Reset handler at `0x080032A1` (code starts ~0x08003000)
- ✅ No encryption markers found
- ✅ Valid exception handler addresses

### Code Patterns
- 41 function prologues (PUSH {lr})
- 3 function returns (BX LR)
- ~100 function calls (BL instructions)
- Normal ARM Thumb-2 code structure

## Comparison with RT-950 V0.29

| Aspect | RT-950 V0.29 | RT-950 Pro V0.24 |
|--------|--------------|------------------|
| **Size** | 311.2 KB | 369.3 KB |
| **Stack Pointer** | `0x20015940` (86.3 KB) | `0x20015C98` (87.1 KB) |
| **Reset Handler** | `0x08003191` | `0x080032A1` |
| **Code Offset** | 0x003191 | 0x0032A1 |

**Key Differences:**
- RT-950 Pro is **~58 KB larger** (dual-band features, KISS TNC)
- Similar header space (~3 KB before code starts)
- Both use similar RAM usage (~86-87 KB)

## Next Steps

1. **Ghidra Analysis** (Running)
   - Import firmware file
   - Analyze functions and memory map
   - Extract driver initialization sequences
   - Compare with RT-950 function addresses

2. **Comparison Analysis**
   - Run comparison script
   - Document function address differences
   - Identify dual-band specific code

3. **Unified Build Verification**
   - Verify unified build system works with Pro firmware analysis
   - Update function address mappings if needed

## Tools

- **Analysis Script**: `../../scripts/analyze_binary_deep.py`
  ```bash
  python scripts/analyze_binary_deep.py firmware/rt950pro/RT_950Pro_V0.24_251201.BTF
  ```

- **Ghidra Analysis**: `../../scripts/ghidra_analyze_direct.py`
  ```bash
  python scripts/ghidra_analyze_direct.py firmware/rt950pro/RT_950Pro_V0.24_251201.BTF
  ```

## References

- Comparison Document: `../../docs/RT950_COMPARISON.md`
- Differences Summary: `../../docs/RT950_DIFFERENCES_SUMMARY.md`
- Ghidra Analysis: `../GHIDRA_ANALYSIS.md`
- Main README: `../../README.md`

