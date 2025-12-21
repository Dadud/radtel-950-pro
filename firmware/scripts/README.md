# Firmware Processing Scripts

Collection of scripts for RT-950 Pro firmware analysis.

## Main Script

### `process_firmware.py` ⭐ **START HERE**

Complete automated workflow - decrypts, decompiles, and organizes firmware.

```bash
python process_firmware.py --btf firmware.BTF
```

**Features:**
- ✅ Automatic BTF decryption
- ✅ Ghidra decompilation
- ✅ Version detection
- ✅ Organized output
- ✅ Comparison support

**See:** Main [README.md](../README.md) for full documentation.

## Supporting Scripts

### `fwcrypt_io.py`

Decrypts/encrypts BTF firmware files.

```bash
python fwcrypt_io.py --infile firmware.BTF --outfile firmware_decrypted.bin
```

**Purpose:** Converts encrypted BTF files to plain binary.

### `decompile_firmware.py`

Decompiles firmware binaries using Ghidra headless analyzer.

```bash
python decompile_firmware.py firmware.bin
python decompile_firmware.py --compare v1.bin v2.bin
python decompile_firmware.py --batch firmware_dir/
```

**Purpose:** 
- Single file decompilation
- Version comparison
- Batch processing

**See:** [README_DECOMPILE.md](README_DECOMPILE.md) for detailed documentation.

### `setup-artery-cortex-m-memory-map.py`

Ghidra script to configure AT32F403A memory regions.

**Purpose:** Sets up proper memory map in Ghidra projects.

**Usage:** Run from Ghidra Script Manager after importing firmware.

## Script Relationships

```
process_firmware.py (Main)
    ├── Uses fwcrypt_io.py (Decryption)
    └── Uses decompile_firmware.py (Decompilation)
            └── Uses setup-artery-cortex-m-memory-map.py (Memory setup)
```

## Quick Reference

| Task | Command |
|------|---------|
| Process firmware | `python process_firmware.py --btf file.BTF` |
| Decrypt only | `python fwcrypt_io.py --infile file.BTF --outfile output.bin` |
| Decompile only | `python decompile_firmware.py firmware.bin` |
| Compare versions | `python process_firmware.py --btf v1.BTF --compare-with v2.bin` |

## Requirements

All scripts require:
- Python 3.6+
- Ghidra 12.0+ (for decompilation)
- Java JDK 21+ (for Ghidra)

Scripts auto-detect installations.

## Documentation

- **Main Workflow**: [../README.md](../README.md)
- **Quick Start**: [../QUICKSTART.md](../QUICKSTART.md)
- **Decompile Details**: [README_DECOMPILE.md](README_DECOMPILE.md)
- **Comparison Guide**: [../RE/COMPARISON_GUIDE.md](../RE/COMPARISON_GUIDE.md)


