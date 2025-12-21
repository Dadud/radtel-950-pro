# Firmware Decompilation Automation - Summary

## Created Files

### Main Script
- **`decompile_firmware.py`** - Main Python script for automated firmware decompilation

### Documentation
- **`README_DECOMPILE.md`** - Complete usage guide and documentation

## Features

✅ **Single File Decompilation**
   - Decompile one firmware `.bin` file
   - Automatically uses correct base address (`0x08000000`)
   - Exports C code and assembly listing

✅ **Version Comparison**
   - Compare two firmware versions side-by-side
   - Generates diff reports
   - Creates organized comparison directory

✅ **Batch Processing**
   - Process multiple firmware files at once
   - Useful for analyzing firmware update sequences

✅ **Automatic Configuration**
   - Auto-detects Ghidra and Java installations
   - Uses correct processor settings (ARM:LE:32:Cortex)
   - Handles all Ghidra project management automatically

## Quick Start

```bash
# Decompile firmware
python decompile_firmware.py firmware.bin

# Compare versions
python decompile_firmware.py --compare v1.bin v2.bin

# Batch process
python decompile_firmware.py --batch firmware_folder/
```

## Key Advantages

1. **Correct Base Address**: Uses `0x08000000` (fixes GitHub issue #1)
2. **Automated**: No manual Ghidra GUI work required
3. **Reproducible**: Same settings every time
4. **Organized Output**: Clean directory structure with summaries
5. **Comparison Ready**: Built-in version comparison support

## Use Cases

- **Firmware Update Analysis**: Compare versions to see what changed
- **Security Research**: Analyze firmware for vulnerabilities
- **Reverse Engineering**: Get C code from binary firmware
- **Automated Testing**: Integrate into CI/CD pipelines
- **Documentation**: Generate readable code from binary blobs

## Integration

The script can be easily integrated into:
- CI/CD pipelines
- Automated analysis workflows
- Firmware testing frameworks
- Security scanning tools


