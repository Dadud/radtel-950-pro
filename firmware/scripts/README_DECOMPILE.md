# Firmware Decompilation Script

Automatically decompiles RT-950 Pro firmware `.bin` files using Ghidra headless analyzer. This script uses the correct base address (`0x08000000`) and settings we established for the RT-950 Pro firmware.

## Features

- ✅ Automatic firmware decompilation to C code and assembly
- ✅ Compare two firmware versions side-by-side
- ✅ Batch process multiple firmware files
- ✅ Uses correct base address (`0x08000000`)
- ✅ Generates organized output with summaries

## Requirements

- Python 3.6+
- Ghidra 12.0+ installed
- Java JDK 21+ (Eclipse Temurin recommended)
- Script automatically finds Ghidra and Java, or you can modify paths in the script

## Usage

### Decompile a Single Firmware

```bash
python decompile_firmware.py firmware.bin
```

This creates a `firmware_decompiled/` directory with:
- `firmware.bin` - Original binary
- `firmware.c` - Decompiled C code
- `firmware.lst` - Assembly listing
- `README.md` - Summary information

### Decompile to Specific Directory

```bash
python decompile_firmware.py firmware.bin output_directory/
```

### Compare Two Firmware Versions

```bash
python decompile_firmware.py --compare v1.bin v2.bin
```

This creates a comparison directory with:
- `version1/` - Decompiled version 1
- `version2/` - Decompiled version 2
- `COMPARISON_REPORT.md` - Comparison instructions
- `diff_summary.txt` - Quick diff (if available)

### Batch Decompile All .bin Files

```bash
python decompile_firmware.py --batch firmware_directory/
```

Processes all `.bin` files in the specified directory.

## Configuration

Edit these variables at the top of `decompile_firmware.py` if needed:

```python
GHIDRA_PATH = r"C:\Users\dadud\Downloads\ghidra_12.0_PUBLIC_20251205\ghidra_12.0_PUBLIC"
JAVA_HOME = r"C:\Program Files\Eclipse Adoptium\jdk-21.0.9.10-hotspot"
BASE_ADDRESS = "0x08000000"  # AT32F403A flash base address
PROCESSOR = "ARM:LE:32:Cortex"  # ARM Cortex-M4
```

## Output Format

### C Code Export

Functions are exported with correct addresses:
```c
void FUN_08000630(int param_1,undefined4 param_2,undefined4 param_3,int param_4);
void FUN_080006dc(uint param_1);
```

All addresses use format `FUN_0800xxxx` (correct base address).

### Assembly Listing

Complete disassembly with:
- All instructions
- Data definitions
- Symbol references
- Cross-references

## Comparison Tips

When comparing firmware versions:

1. **Use a diff tool**: VS Code, WinMerge, or Beyond Compare work well
2. **Check function changes**: Look for modified function implementations
3. **New functions**: Functions present in new version but not old
4. **Removed functions**: Functions in old version but not new
5. **String changes**: Modified string literals can indicate feature changes
6. **Ghidra version tracking**: Open both projects in Ghidra GUI for advanced comparison

## Example Workflow

```bash
# Decompile old firmware
python decompile_firmware.py RT_950Pro_V0.17.bin

# Decompile new firmware  
python decompile_firmware.py RT_950Pro_V0.18.bin

# Compare them
python decompile_firmware.py --compare RT_950Pro_V0.17.bin RT_950Pro_V0.18.bin

# Open comparison in VS Code
code comparison_RT_950Pro_V0.17_vs_RT_950Pro_V0.18/
```

## Troubleshooting

### "Ghidra not found"
- Edit `GHIDRA_PATH` in the script
- Or ensure Ghidra is in a standard location

### "Java not found"
- Install Java JDK 21+ (Eclipse Temurin)
- Or edit `JAVA_HOME` in the script
- Or add Java to system PATH

### Export files missing
- Check Ghidra logs for errors
- Ensure output directory is writable
- Check disk space

### Project already exists
- The script uses `-overwrite` flag
- Old projects in `ghidra_projects/` can be manually deleted

## Advanced Usage

### Custom Export Script

The script automatically creates `export_all_custom.java` in the scripts directory. You can modify this to export additional formats (JSON, XML, etc.) if needed.

### Integration with CI/CD

The script can be integrated into automated workflows:

```bash
# In a CI script
python decompile_firmware.py --batch firmware_builds/
# Analyze results, generate reports, etc.
```

## Notes

- The script uses temporary Ghidra projects that are cleaned up automatically
- Large firmware files may take several minutes to decompile
- C code export quality depends on Ghidra's decompiler analysis
- Assembly listings are always accurate regardless of decompiler quality


