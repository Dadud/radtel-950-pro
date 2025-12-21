# RT-950 Pro Firmware Analysis

Complete toolkit for analyzing and reverse engineering RT-950 Pro firmware.

## Quick Start

```bash
# 1. Get the latest firmware BTF file (download from manufacturer)
# 2. Process it:
python firmware/scripts/process_firmware.py --btf path/to/firmware.BTF
```

See **[QUICKSTART.md](QUICKSTART.md)** for detailed instructions.

## Overview

This repository contains tools and documentation for:
- ✅ Decrypting RT-950 Pro firmware (BTF format)
- ✅ Decompiling firmware to C code and assembly
- ✅ Comparing firmware versions
- ✅ Reverse engineering analysis

## Repository Structure

```
firmware/
├── QUICKSTART.md                    # Start here! Quick setup guide
├── README.md                        # This file
├── decrypted.bin                    # Current firmware (V0.18)
├── scripts/
│   ├── process_firmware.py          # 🎯 Main workflow script (USE THIS!)
│   ├── decompile_firmware.py        # Ghidra decompilation
│   ├── fwcrypt_io.py                # BTF decryption
│   ├── setup-artery-cortex-m-memory-map.py  # Ghidra memory setup
│   └── README_DECOMPILE.md          # Script documentation
└── RE/
    ├── README.md                    # Reverse engineering guide
    ├── COMPARISON_GUIDE.md          # Version comparison guide
    ├── analysis_export/             # V0.18 analysis
    ├── v0.24_analysis/              # V0.24 analysis
    └── ...
```

## Main Workflow Script

**`scripts/process_firmware.py`** - One script to rule them all!

This script automates the entire process:
1. Decrypts BTF files
2. Decompiles with Ghidra
3. Organizes output
4. Creates summaries

### Usage Examples

```bash
# Process a BTF file
python scripts/process_firmware.py --btf firmware.BTF

# Process latest from Downloads
python scripts/process_firmware.py --latest

# Compare with existing version
python scripts/process_firmware.py --btf v0.24.BTF --compare-with RE/analysis_v0.18/firmware.bin
```

## Prerequisites

- **Python 3.6+**
- **Ghidra 12.0+** ([Download](https://ghidra-sre.org/))
- **Java JDK 21+** ([Eclipse Temurin](https://adoptium.net/))

Scripts auto-detect installations - no configuration needed!

## What's Included

### Scripts

| Script | Purpose |
|--------|---------|
| `process_firmware.py` | **Main workflow** - Complete automation |
| `decompile_firmware.py` | Ghidra decompilation with correct base address |
| `fwcrypt_io.py` | BTF file decryption |
| `setup-artery-cortex-m-memory-map.py` | Ghidra memory map configuration |

### Documentation

| File | Description |
|------|-------------|
| `QUICKSTART.md` | **Start here** - Quick setup guide |
| `RE/README.md` | Reverse engineering documentation |
| `RE/COMPARISON_GUIDE.md` | Version comparison workflows |
| `scripts/README_DECOMPILE.md` | Detailed script documentation |

## Key Features

### ✅ Correct Base Address

All firmware is imported at `0x08000000` (not `0x80000000`), fixing GitHub issue #1.

### ✅ Automated Workflow

One command does everything:
```bash
python scripts/process_firmware.py --btf firmware.BTF
```

### ✅ Version Comparison

Easy comparison of firmware versions:
```bash
python scripts/process_firmware.py --btf v0.24.BTF --compare-with v0.18.bin
```

### ✅ Organized Output

Each analysis is organized in its own directory with:
- Decompiled C code
- Assembly listing
- Original binary
- Summary README

## Memory Map

The RT-950 Pro uses AT32F403ARGT7 MCU:

| Region     | Start        | End          | Size   | Description              |
|------------|--------------|--------------|--------|--------------------------|
| Flash      | `0x08000000` | `0x080FFFFF` | 1 MB   | Internal flash memory    |
| SRAM       | `0x20000000` | `0x20017FFF` | 96 KB  | Internal SRAM            |

**Important**: Firmware must be loaded at base address `0x08000000`.

## Firmware Versions

| Version | Location | Status |
|---------|----------|--------|
| V0.18   | `RE/analysis_export/` | Analyzed |
| V0.24   | `RE/v0.24_analysis/` | Analyzed |

## Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/JKI757/radtel-950-pro.git
   cd radtel-950-pro
   ```

2. **Install prerequisites** (Python, Ghidra, Java)

3. **Download firmware** BTF file from manufacturer

4. **Process it**
   ```bash
   python firmware/scripts/process_firmware.py --btf path/to/firmware.BTF
   ```

5. **Analyze the output** in `firmware/RE/analysis_v<VERSION>/`

## Workflow Overview

```
BTF File → Decrypt → Decompile → Analysis
    ↓          ↓          ↓           ↓
  .BTF      .bin      .c + .lst   README.md
```

1. **Decryption**: BTF files are encrypted - `fwcrypt_io.py` decrypts them
2. **Decompilation**: Ghidra analyzes and decompiles to C code
3. **Organization**: Output is organized with summaries and documentation
4. **Analysis**: Review C code, compare versions, reverse engineer

## Example Workflow

```bash
# Process latest firmware
python firmware/scripts/process_firmware.py --latest

# Output will be in: firmware/RE/analysis_v0.24/
# Contains:
#   - decrypted_v0.24.bin
#   - decrypted_v0.24.bin.c  (decompiled C code)
#   - decrypted_v0.24.bin.lst (assembly listing)
#   - README.md (summary)

# Compare with previous version
python firmware/scripts/process_firmware.py \
    --btf RT_950Pro_V0.24.BTF \
    --compare-with RE/analysis_v0.18/decrypted.bin
```

## Contributing

When adding new firmware versions:
1. Use `process_firmware.py` to process it
2. Update this README with version info
3. Document any notable changes in the version's README

## Troubleshooting

See [QUICKSTART.md](QUICKSTART.md) troubleshooting section for common issues.

## License

See repository root LICENSE file.

## Related Documentation

- [Quick Start Guide](QUICKSTART.md) - Get started in 3 steps
- [Reverse Engineering Guide](RE/README.md) - Detailed RE documentation
- [Comparison Guide](RE/COMPARISON_GUIDE.md) - Version comparison workflows
- [Script Documentation](scripts/README_DECOMPILE.md) - Script reference
