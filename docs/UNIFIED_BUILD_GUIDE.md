# Unified Firmware Build Guide

**Status:** ✅ Ready to Use

## Overview

The firmware now builds for both RT-950 and RT-950 Pro from a single codebase. Model-specific features are automatically enabled/disabled based on the `RADIO_MODEL` CMake option.

---

## Quick Build Commands

### RT-950 (Non-Pro)
```bash
cd build/output
cmake .. -DRADIO_MODEL=RT950 -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

**Output:** `rt950_firmware.elf`, `rt950_firmware.bin`

### RT-950 Pro
```bash
cd build/output
cmake .. -DRADIO_MODEL=RT950PRO -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

**Output:** `rt950pro_firmware.elf`, `rt950pro_firmware.bin`

---

## What Gets Automatically Removed for RT-950

When building for RT-950 (non-Pro), the following are automatically excluded:

### Hardware Features
- ❌ **Dual BK4829 Support** - Only VHF transceiver included
- ❌ **UHF Band** - 400-520 MHz band removed
- ❌ **KISS TNC Mode** - APRS over Bluetooth removed

### Code Removal
- All `BK4829_INSTANCE_UHF` references excluded
- `BAND_UHF` enum value removed
- Dual-band switching logic excluded
- UHF frequency limit checks removed

### Size Reduction
- Smaller binary (single BK4829 driver code)
- Reduced RAM usage (no UHF state)
- Fewer menu items (no dual-band options)

---

## Configuration System

### Model Selection

The configuration is defined in `src/config/radio_model.h` and selected via CMake:

```cmake
cmake -DRADIO_MODEL=RT950 ..      # RT-950 (non-Pro)
cmake -DRADIO_MODEL=RT950PRO ..   # RT-950 Pro
```

### Automatic Configuration

| Feature | RT-950 | RT-950 Pro |
|---------|--------|------------|
| BK4829 Count | 1 | 2 |
| Dual-Band | Disabled | Enabled |
| UHF Band | Removed | Enabled |
| KISS TNC | Disabled | Enabled |
| Code Offset | 0x003191 | 0x000000 |

---

## Code Examples

### Conditional BK4829 Access

```c
#include "config/radio_model.h"

void Radio_InitRF(void) {
    BK4829_Init(BK4829_INSTANCE_VHF);  // Always present
    
#if BK4829_INSTANCE_COUNT > 1
    BK4829_Init(BK4829_INSTANCE_UHF);  // Pro only
#endif
}
```

### Band Selection

```c
#include "config/radio_model.h"

bool Radio_CanUseBand(Band_t band) {
    if (band == BAND_VHF || band == BAND_FM) {
        return true;  // Always supported
    }
#if DUAL_BAND_ENABLED
    if (band == BAND_UHF) {
        return true;  // Pro only
    }
#endif
    return false;
}
```

### Feature Checks

```c
#include "config/radio_model.h"

void UI_ShowMainMenu(void) {
    Menu_AddItem("VFO", Menu_VFO);
    Menu_AddItem("Memory", Menu_Memory);
    
#if FEATURE_ENABLED(KISS_TNC)
    Menu_AddItem("KISS TNC", Menu_KISSTNC);  // Pro only
#endif
    
    Menu_AddItem("Settings", Menu_Settings);
}
```

---

## Verification

### Check Build Configuration

After running CMake, verify the configuration:

```bash
# Check CMake output for:
# -- Building for: RT-950 (non-Pro)
# OR
# -- Building for: RT-950 Pro
```

### Verify Feature Removal

Compare binary sizes:
```bash
# RT-950 build should be smaller
size rt950_firmware.elf
size rt950pro_firmware.elf
```

### Check Compiled Features

Use `strings` to verify UHF references are removed:
```bash
strings rt950_firmware.elf | grep -i "uhf\|dual.*band"
# Should return nothing for RT-950
```

---

## Troubleshooting

### Build Fails with "Unknown RADIO_MODEL"

**Error:**
```
CMake Error: RADIO_MODEL must be RT950 or RT950PRO
```

**Solution:**
```bash
cmake .. -DRADIO_MODEL=RT950      # or RT950PRO
```

### Compilation Error: "BK4829_INSTANCE_UHF undeclared"

**Cause:** Code uses `BK4829_INSTANCE_UHF` without checking `BK4829_INSTANCE_COUNT`

**Fix:** Add conditional compilation:
```c
#if BK4829_INSTANCE_COUNT > 1
    BK4829_Init(BK4829_INSTANCE_UHF);
#endif
```

### Linker Error: Undefined Reference

**Cause:** Function or variable referenced but excluded by `#if`

**Fix:** Ensure all references to model-specific code are properly guarded.

---

## Implementation Details

### Configuration Header

`src/config/radio_model.h` defines:
- Model enumeration (`RADIO_MODEL_RT950`, `RADIO_MODEL_RT950PRO`)
- Feature flags (`DUAL_BAND_ENABLED`, `FEATURE_KISS_TNC`, etc.)
- Hardware configuration (`BK4829_INSTANCE_COUNT`)
- Convenience macros (`IS_DUAL_BK4829()`, `FEATURE_ENABLED()`)

### Updated Drivers

The following drivers now support model-specific builds:

- **BK4829 Driver** (`src/drivers/bk4829.*`)
  - Array size matches `BK4829_INSTANCE_COUNT`
  - UHF instance only defined for Pro

- **Radio Layer** (`src/radio/radio.*`)
  - `BAND_UHF` only defined for Pro
  - Band selection logic adapts automatically

- **Main Application** (`src/main.c`)
  - UHF initialization excluded for RT-950

---

## Next Steps

1. **Test Builds**
   - Verify both models compile successfully
   - Check binary sizes match expectations
   - Test feature removal

2. **Hardware Testing**
   - Flash RT-950 build to RT-950 hardware
   - Verify single-band operation works
   - Confirm dual-band features are inaccessible

3. **Additional Features**
   - Add more feature flags as needed
   - Implement runtime model detection (optional)
   - Optimize for each model's hardware

---

## References

- **Configuration Header**: `src/config/radio_model.h`
- **Build System**: `build/CMakeLists.txt`
- **Comparison**: `docs/RT950_DIFFERENCES_SUMMARY.md`
- **Unified Build System**: `docs/UNIFIED_BUILD_SYSTEM.md`

---

**Last Updated:** 2025-12-23

