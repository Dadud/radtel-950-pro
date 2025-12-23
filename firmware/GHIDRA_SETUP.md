# Ghidra Setup for Firmware Analysis

## Quick Setup

### Option 1: Automatic Setup (Recommended)
1. Download Ghidra from: https://ghidra-sre.org/
2. Extract to: `firmware/ghidra/` folder in this repository
3. Run analysis scripts - they will auto-detect Ghidra

### Option 2: Custom Location
1. Extract Ghidra anywhere on your system
2. Update the path in analysis scripts or set environment variable

## Directory Structure

```
firmware/
├── ghidra/              # Extract Ghidra here (not in git)
│   └── ghidra_X.X_PUBLIC/
│       ├── support/
│       │   └── analyzeHeadless.bat (or analyzeHeadless on Linux)
│       └── ...
├── rt950/              # RT-950 firmware
└── rt950pro/           # RT-950 Pro firmware (if available)
```

## Download Ghidra

1. Visit: https://ghidra-sre.org/Release.html
2. Download the latest release (`.zip` file)
3. Extract to `firmware/ghidra/` folder

Example:
```bash
# Windows (PowerShell)
mkdir firmware\ghidra -Force
Expand-Archive -Path ~\Downloads\ghidra_X.X_PUBLIC.zip -DestinationPath firmware\ghidra

# Linux/Mac
mkdir -p firmware/ghidra
unzip ~/Downloads/ghidra_X.X_PUBLIC.zip -d firmware/ghidra
```

## Verification

After extracting, verify Ghidra is found:

```bash
# Check if detected
python scripts/ghidra_analyze_direct.py --check

# Or manually verify
ls firmware/ghidra/*/support/analyzeHeadless*
```

## Running Analysis

Once Ghidra is in place:

```bash
# Analyze RT-950 firmware
python scripts/ghidra_analyze_direct.py firmware/rt950/RT_950_V0.29_251104.BTF

# Or use the batch script (Windows)
scripts\run_ghidra_simple.bat
```

## Why Not Include Ghidra in Git?

- **Size**: Ghidra is ~200-300 MB (would bloat repository)
- **Updates**: Ghidra releases frequently (better to download latest)
- **License**: Apache 2.0 (could include, but standard practice is to download separately)
- **Platform**: Users may need different versions for different OS

## Alternative: Use System-Wide Ghidra

If you have Ghidra installed system-wide, scripts will try to find it automatically. You can also:

1. Set environment variable: `GHIDRA_INSTALL_DIR`
2. Or update script paths manually

## Troubleshooting

### Script can't find Ghidra
- Check `firmware/ghidra/` folder exists
- Verify `analyzeHeadless.bat` (or `analyzeHeadless` on Linux) is present
- Update path in script if using custom location

### Analysis fails
- Ensure Java is installed (Ghidra requires Java 17+)
- Check firmware file path is correct
- Review error messages for specific issues

