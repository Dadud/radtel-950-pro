# RT-950 Pro Firmware Analysis - Quick Start Guide

This guide will help you process and analyze RT-950 Pro firmware from scratch.

## Prerequisites

1. **Python 3.6+** - [Download Python](https://www.python.org/downloads/)
2. **Ghidra 12.0+** - [Download Ghidra](https://ghidra-sre.org/)
3. **Java JDK 21+** - [Eclipse Temurin](https://adoptium.net/) (recommended)

## Quick Start (3 Steps)

### Step 1: Clone the Repository

```bash
git clone https://github.com/JKI757/radtel-950-pro.git
cd radtel-950-pro
```

### Step 2: Download Latest Firmware

Download the latest firmware `.BTF` file from the manufacturer and save it to your Downloads folder, or any location you prefer.

**Example**: `RT_950Pro_V0.24_251201.BTF`

### Step 3: Process the Firmware

```bash
# Navigate to firmware directory
cd firmware/scripts

# Process the BTF file (replace with your path)
python process_firmware.py --btf ../../Downloads/RT_950Pro_V0.24_251201.BTF
```

That's it! The script will:
1. ✅ Decrypt the BTF file
2. ✅ Decompile using Ghidra
3. ✅ Create organized output in `firmware/RE/analysis_v<VERSION>/`

## Output Location

Processed firmware will be in:
```
firmware/RE/analysis_v<VERSION>/
├── firmware_decrypted.bin    # Decrypted binary
├── firmware_decrypted.bin.c  # Decompiled C code
├── firmware_decrypted.bin.lst # Assembly listing
└── README.md                 # Summary information
```

## Common Usage Examples

### Process Latest Firmware from Downloads

```bash
python process_firmware.py --latest
```

Automatically finds and processes the most recent BTF file in your Downloads folder.

### Specify Output Directory

```bash
python process_firmware.py --btf firmware.BTF --output RE/my_analysis/
```

### Compare Two Versions

```bash
# First, process the new version
python process_firmware.py --btf v0.24.BTF

# Then compare with existing version
python process_firmware.py --btf v0.24.BTF --compare-with RE/analysis_v0.18/firmware_decrypted.bin
```

### Process Without Keeping Binary (Save Space)

```bash
python process_firmware.py --btf firmware.BTF --no-keep-binary
```

## Configuration

The scripts auto-detect Ghidra and Java installations. If you need to customize paths, edit:

- `firmware/scripts/decompile_firmware.py` - Lines 24-25 (GHIDRA_PATH, JAVA_HOME)

## Troubleshooting

### "Ghidra not found"

The script searches common locations. If Ghidra is installed elsewhere:
1. Edit `decompile_firmware.py`
2. Set `GHIDRA_PATH` to your Ghidra installation directory

### "Java not found"

Install Java JDK 21+ (Eclipse Temurin recommended):
- Windows: Download from [adoptium.net](https://adoptium.net/)
- The script will auto-detect it

### "Permission denied" or "Access denied"

- Make sure you have write permissions to the output directory
- Run as administrator if needed (Windows)

### Scripts take a long time

- Decompilation can take 5-15 minutes depending on firmware size
- This is normal - Ghidra is analyzing the entire binary
- Be patient and let it complete

## What You Get

After processing, you'll have:

1. **Decompiled C Code** - Human-readable C code with function names
2. **Assembly Listing** - Complete disassembly for detailed analysis
3. **Organized Structure** - Everything in one directory with documentation

## Next Steps

- **Compare Versions**: Use the comparison guide to see what changed
- **Analyze Functions**: Search the C code for specific functionality
- **Use Ghidra GUI**: Open the exported project for interactive analysis

## Getting Help

- Check `firmware/RE/COMPARISON_GUIDE.md` for comparison workflows
- See `firmware/scripts/README_DECOMPILE.md` for detailed script documentation
- Review existing analyses in `firmware/RE/` for examples

## Full Documentation

For detailed information, see:
- `firmware/RE/README.md` - Reverse engineering documentation
- `firmware/scripts/README_DECOMPILE.md` - Script documentation
- `firmware/RE/COMPARISON_GUIDE.md` - Version comparison guide


