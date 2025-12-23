# Quick Start: Ghidra Setup

## For New Users

1. **Download Ghidra**: https://ghidra-sre.org/Release.html
2. **Extract to repo**: Extract the zip file to `firmware/ghidra/` folder
3. **Run analysis**: `python scripts/ghidra_analyze_direct.py`

That's it! The scripts will automatically find Ghidra in the `firmware/ghidra/` folder.

## Detailed Setup

See [firmware/GHIDRA_SETUP.md](firmware/GHIDRA_SETUP.md) for complete instructions.

## Why Not in Git?

Ghidra is ~200-300 MB and updates frequently. Keeping it out of git keeps the repository lean and lets users get the latest version.

