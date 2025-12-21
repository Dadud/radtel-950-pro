# RT-950 Pro Firmware Analysis Export

This folder contains the complete Ghidra analysis export of the RT-950 Pro firmware, imported at the **correct base address** (`0x08000000`).

## Files

### `decrypted.bin`
- Original firmware binary (decrypted from BTF file)
- Base address: `0x08000000`
- Size: ~372 KB

### `decrypted.bin.c`
- C code export from Ghidra decompiler
- Contains all decompiled functions with proper addresses
- Function addresses are correct: `FUN_0800xxxx` (not `FUN_800xxxx`)
- Size: ~1.1 MB

### `decrypted.bin.lst`
- Complete assembly listing
- Includes all disassembled instructions, data, and symbols
- Useful for detailed analysis
- Size: ~25.4 MB

### `rt950pro-correct.gpr`
- Ghidra project file
- Open this in Ghidra GUI to continue analysis
- Project name: `rt950pro-correct`

## Memory Map

The firmware was imported with the following memory layout:

| Region     | Start        | End          | Description              |
|------------|--------------|--------------|--------------------------|
| Flash      | `0x08000000` | `0x080FFFFF` | Internal flash memory    |
| SRAM       | `0x20000000` | `0x20017FFF` | Internal SRAM            |

**Note**: The binary was imported at base address `0x08000000`, which is correct for AT32F403A MCU.

## Key Addresses

| Address      | Description                           |
|--------------|---------------------------------------|
| `0x08000000` | Vector table (SP, Reset, NMI, etc.)   |
| `0x08000004` | Reset vector → entry point            |

All function addresses now use the correct format: `FUN_0800xxxx` instead of `FUN_800xxxx`.

## Next Steps

1. Open `rt950pro-correct.gpr` in Ghidra GUI
2. Run `setup-artery-cortex-m-memory-map.py` script to configure peripheral memory regions
3. Continue reverse engineering with proper memory mappings

## Export Date

Exported on: 2025-12-20

## Related Files

- Original firmware: `firmware/decrypted.bin`
- Ghidra project: `firmware/RE/rt950pro-correct.gpr`
- Setup script: `firmware/scripts/setup-artery-cortex-m-memory-map.py`


