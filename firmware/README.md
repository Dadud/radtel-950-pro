# Firmware Analysis Directory

This directory contains firmware binaries and analysis for different RT-950 radio models.

## Directory Structure

```
firmware/
├── rt950/          # RT-950 (Non-Pro) firmware
│   ├── RT_950_V0.29_251104.BTF
│   └── README.md
└── rt950pro/       # RT-950 Pro firmware (if available)
    └── README.md
```

## Firmware Versions

### RT-950 (Non-Pro)
- **V0.29** (2025-11-04) - Current version in repository
  - Spectrum interface updates
  - DTMF configuration menus
  - APRS stability improvements

### RT-950 Pro
- **V0.24** (and earlier) - Previously analyzed versions
  - See main project README.md for details

## Analysis Process

1. **Decryption**: Firmware files (`.BTF`) may be encrypted/obfuscated
2. **Decompilation**: Use Ghidra to analyze ARM Cortex-M4F binaries
3. **Comparison**: Compare function addresses, register usage, memory maps

## Tools Required

- **Ghidra** - Reverse engineering framework
  - ARM Cortex-M processor specification
  - AT32F403A memory map
- **Hex Editor** - For binary analysis
- **Update Tools** - RT-950_EnUPDATE.exe for firmware extraction (if needed)

## Comparison Results

See [docs/RT950_COMPARISON.md](../docs/RT950_COMPARISON.md) for detailed comparison between RT-950 and RT-950 Pro firmware.

## Notes

⚠️ **These are proprietary firmware files for reverse engineering purposes only.**
- Do not redistribute without permission
- Use only for research and open-source firmware development
- Respect copyright and licensing terms

