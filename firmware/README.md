# RT-950 Pro Firmware

## Files

- `decrypted.bin` - Firmware decrypted from the BTF file (v0.18 firmware update). Use `scripts/fwcrypt_io.py` to decrypt/encrypt.

## Directories

- `RE/` - Reverse engineering artifacts (Ghidra projects, disassembly, protocol notes). See `RE/README.md` for Ghidra setup instructions.
- `RE/firmware dumps/` - USB captures of the firmware update process
- `scripts/` - Python tools for firmware manipulation
- `reference firmware/` - OEM firmware files and update tools

## Ghidra Setup

**IMPORTANT**: When importing `decrypted.bin` into Ghidra, use base address `0x08000000` (not `0x80000000`).

See `RE/README.md` for complete setup instructions.

## Quick Reference

| File | Base Address | Description |
|------|--------------|-------------|
| `decrypted.bin` | `0x08000000` | Main application firmware |
| `RE/firmware dumps/bootloader_dec.bin` | `0x08000000` | Bootloader |
