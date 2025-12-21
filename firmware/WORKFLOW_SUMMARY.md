# Complete Firmware Processing Workflow

## Overview

This repository provides a complete, automated workflow for processing RT-950 Pro firmware files. Anyone can clone the repo and process firmware with a single command.

## The Workflow

```
┌─────────────┐
│  BTF File   │  (Downloaded from manufacturer)
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│  Decrypt (BTF)   │  process_firmware.py
└──────┬───────────┘
       │
       ▼
┌─────────────┐
│  Binary     │  (.bin file)
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│  Decompile       │  Ghidra headless
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  Analysis Files  │  .c + .lst + README
└──────────────────┘
```

## One Command Solution

```bash
python firmware/scripts/process_firmware.py --btf firmware.BTF
```

That's it! The script handles everything:
1. ✅ Decryption
2. ✅ Decompilation  
3. ✅ Organization
4. ✅ Documentation

## What Gets Created

After running the script, you'll have:

```
firmware/RE/analysis_v<VERSION>/
├── firmware_decrypted.bin      # Decrypted binary (369 KB)
├── firmware_decrypted.bin.c    # Decompiled C code (~1.1 MB)
├── firmware_decrypted.bin.lst  # Assembly listing (~25 MB)
└── README.md                   # Summary with version info
```

## For New Users

### Step 1: Clone Repository
```bash
git clone https://github.com/JKI757/radtel-950-pro.git
cd radtel-950-pro
```

### Step 2: Install Prerequisites
- Python 3.6+ (comes with most systems)
- Ghidra 12.0+ ([Download](https://ghidra-sre.org/))
- Java JDK 21+ ([Eclipse Temurin](https://adoptium.net/))

### Step 3: Download Firmware
Get the latest `.BTF` file from the manufacturer.

### Step 4: Process It
```bash
python firmware/scripts/process_firmware.py --btf path/to/firmware.BTF
```

Done! Analysis files are in `firmware/RE/analysis_v<VERSION>/`

## Key Features

### ✅ Zero Configuration
- Auto-detects Ghidra installation
- Auto-detects Java installation
- Auto-extracts version numbers
- Works out of the box

### ✅ Correct Setup
- Uses proper base address (`0x08000000`)
- Correct processor settings (ARM Cortex-M4)
- Proper memory map configuration

### ✅ Organized Output
- Each version in its own directory
- Version-tagged for easy identification
- Includes summaries and documentation

### ✅ Comparison Ready
- Easy version comparison
- Side-by-side analysis directories
- Diff-friendly file structure

## Example: Processing V0.24

```bash
# Download RT_950Pro_V0.24_251201.BTF to Downloads folder

# Process it
python firmware/scripts/process_firmware.py --latest

# Output:
# ✓ Decryption successful!
# ✓ Decompilation successful!
# ✓ Processing Complete!
# Output directory: firmware/RE/analysis_v0.24/
```

## Advanced Usage

### Compare Versions
```bash
python firmware/scripts/process_firmware.py \
    --btf v0.24.BTF \
    --compare-with RE/analysis_v0.18/firmware_decrypted.bin
```

### Custom Output Directory
```bash
python firmware/scripts/process_firmware.py \
    --btf firmware.BTF \
    --output RE/my_custom_analysis/
```

### Save Space (No Binary)
```bash
python firmware/scripts/process_firmware.py \
    --btf firmware.BTF \
    --no-keep-binary
```

## Script Architecture

The workflow uses three main scripts:

1. **`process_firmware.py`** (Main entry point)
   - Orchestrates the entire workflow
   - Handles file organization
   - Creates summaries

2. **`fwcrypt_io.py`** (Decryption)
   - Decrypts BTF files
   - Extracts keys from firmware
   - XOR-based decryption

3. **`decompile_firmware.py`** (Decompilation)
   - Runs Ghidra headless
   - Configures memory map
   - Exports C code and assembly

## File Naming Convention

Output directories follow this pattern:
- `analysis_v0.24/` - Version 0.24
- `analysis_v0.18/` - Version 0.18
- `analysis_20251220/` - Timestamp if version unknown

## Integration with Existing Work

The script is designed to:
- ✅ Not overwrite existing analyses
- ✅ Use version tags to organize
- ✅ Make comparison easy
- ✅ Maintain clean directory structure

## Troubleshooting

If something goes wrong:

1. **Check prerequisites** are installed
2. **Verify BTF file** is valid (can open in hex editor)
3. **Check disk space** (decompilation needs ~50MB per version)
4. **Review logs** in script output

Most issues are:
- Missing Ghidra/Java (auto-detection fails)
- Invalid BTF file (corrupted download)
- Insufficient disk space

## Success Indicators

You'll know it worked when you see:
```
✓ Decryption successful!
✓ Decompilation successful!
✓ Processing Complete!
```

And you'll have files in the output directory with:
- `.c` file (decompiled C code)
- `.lst` file (assembly listing)
- `README.md` (summary)

## Next Steps After Processing

1. **Review the C code** - Look for functions of interest
2. **Compare versions** - See what changed between versions
3. **Use Ghidra GUI** - Open project for interactive analysis
4. **Search for features** - Find specific functionality

## Documentation

- **Quick Start**: [QUICKSTART.md](QUICKSTART.md)
- **Main README**: [README.md](README.md)
- **RE Guide**: [RE/README.md](RE/README.md)
- **Comparison**: [RE/COMPARISON_GUIDE.md](RE/COMPARISON_GUIDE.md)

## Benefits of This Approach

✅ **Reproducible** - Same results every time
✅ **Automated** - No manual steps
✅ **Correct** - Uses proper settings
✅ **Organized** - Clean file structure
✅ **Documented** - Everything explained
✅ **Accessible** - Works for beginners

Anyone can now clone the repo and process firmware!


