# Unified Firmware Build System

**Status:** ✅ Implemented  
**Models Supported:** RT-950, RT-950 Pro

## Overview

The firmware codebase now supports building for both RT-950 and RT-950 Pro from a single source tree. Model-specific features are automatically enabled/disabled via compile-time configuration.

---

## Quick Start

### Build for RT-950 (non-Pro)
```bash
cd build/output
cmake .. -DRADIO_MODEL=RT950 -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Build for RT-950 Pro
```bash
cd build/output
cmake .. -DRADIO_MODEL=RT950PRO -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

---

## Configuration System

### Radio Model Selection

Model selection is done via CMake:

```bash
cmake -DRADIO_MODEL=RT950 ..      # RT-950 (non-Pro)
cmake -DRADIO_MODEL=RT950PRO ..   # RT-950 Pro (default)
```

### Configuration Header

All model-specific configuration is in `src/config/radio_model.h`:

| Setting | RT-950 | RT-950 Pro |
|---------|--------|------------|
| `BK4829_INSTANCE_COUNT` | 1 | 2 |
| `DUAL_BAND_ENABLED` | 0 | 1 |
| `CODE_BASE_OFFSET` | 0x003191 | 0x000000 |
| `FEATURE_KISS_TNC` | 0 | 1 |
| `FREQ_BAND_COUNT` | 1 | 2 |

---

## Automatic Feature Removal

When building for RT-950, the following are automatically removed/disabled:

### Hardware Differences

1. **Dual BK4829 Support**
   - RT-950: Only `BK4829_INSTANCE_VHF` compiled
   - RT-950 Pro: Both `BK4829_INSTANCE_VHF` and `BK4829_INSTANCE_UHF`

2. **UHF Band Support**
   - RT-950: UHF frequency limits not defined
   - RT-950 Pro: Full VHF + UHF support

3. **KISS TNC**
   - RT-950: KISS TNC code excluded
   - RT-950 Pro: KISS TNC enabled

### Code Examples

#### Conditional BK4829 Access

```c
#include "config/radio_model.h"

void Radio_Init(void) {
    BK4829_Init(BK4829_INSTANCE_VHF);
    
#if BK4829_INSTANCE_COUNT > 1
    BK4829_Init(BK4829_INSTANCE_UHF);  // Only compiled for Pro
#endif
}
```

#### Dual-Band Feature Checks

```c
bool Radio_CanTransmitOnBand(RadioBand_t band) {
#if DUAL_BAND_ENABLED
    return (band == BAND_VHF || band == BAND_UHF);
#else
    return (band == BAND_VHF);  // Single-band only
#endif
}
```

#### Feature Macros

```c
#include "config/radio_model.h"

void UI_ShowMenu(void) {
    // ... common menu items ...
    
#if FEATURE_ENABLED(KISS_TNC)
    Menu_AddItem("KISS TNC", Menu_KISSTNC);  // Pro only
#endif
}
```

---

## Driver Updates

### BK4829 Driver (`src/drivers/bk4829.h`)

**Automatically configured:**
- Enum size matches `BK4829_INSTANCE_COUNT`
- UHF instance only defined for Pro builds
- Compile-time validation ensures consistency

**Usage:**
```c
// Works for both models
BK4829_Init(BK4829_INSTANCE_VHF);

// Only compiles for Pro
#if BK4829_INSTANCE_COUNT > 1
BK4829_Init(BK4829_INSTANCE_UHF);
#endif
```

### Radio Layer (`src/radio/radio.h`)

**Automatically configured:**
- UHF frequency limits only defined for Pro
- `VFO_COUNT` from model config
- Band selection logic adapts

### Linker Scripts

- **RT-950**: `src/arch/AT32F403AxG_FLASH_RT950.ld` (if needed for code offset)
- **RT-950 Pro**: `src/arch/AT32F403AxG_FLASH.ld` (default)

---

## Build Output

### Project Names

- **RT-950**: `rt950_firmware.elf`, `rt950_firmware.bin`
- **RT-950 Pro**: `rt950pro_firmware.elf`, `rt950pro_firmware.bin`

### Size Comparison

Expected size differences:
- RT-950: Smaller (single BK4829, no KISS TNC)
- RT-950 Pro: Larger (dual BK4829, additional features)

---

## Adding Model-Specific Code

### Method 1: Conditional Compilation

```c
#if RADIO_MODEL == RADIO_MODEL_RT950
    // RT-950 specific code
#elif RADIO_MODEL == RADIO_MODEL_RT950PRO
    // RT-950 Pro specific code
#endif
```

### Method 2: Feature Macros

```c
#if FEATURE_ENABLED(KISS_TNC)
    // KISS TNC code
#endif
```

### Method 3: Hardware Checks

```c
#if IS_DUAL_BK4829()
    // Dual BK4829 code
#elif IS_SINGLE_BK4829()
    // Single BK4829 code
#endif
```

---

## Validation

The configuration system includes compile-time validation:

- ✅ BK4829_INSTANCE_COUNT must be 1 or 2
- ✅ Dual-band requires 2 BK4829 instances
- ✅ Unknown RADIO_MODEL values cause compilation error

---

## Testing

### Build Both Models

```bash
# Clean build
rm -rf build/output/*

# Build RT-950
mkdir -p build/output/rt950
cd build/output/rt950
cmake ../../.. -DRADIO_MODEL=RT950
make -j$(nproc)

# Build RT-950 Pro
mkdir -p ../rt950pro
cd ../rt950pro
cmake ../../.. -DRADIO_MODEL=RT950PRO
make -j$(nproc)
```

### Verify Feature Removal

Check that RT-950 build is smaller:
```bash
size rt950_firmware.elf
size rt950pro_firmware.elf
```

---

## Future Enhancements

### Potential Additions

1. **Runtime Model Detection**
   - Detect model at boot time
   - Fallback if compile-time config mismatches hardware

2. **Feature Flags**
   - Additional feature toggles (GPS, Bluetooth, etc.)
   - User-configurable feature set

3. **Model-Specific Optimizations**
   - RT-950: Optimize for single-band operation
   - RT-950 Pro: Optimize for dual-band switching

---

## References

- **Configuration Header**: `src/config/radio_model.h`
- **Build System**: `build/CMakeLists.txt`
- **Comparison Document**: `docs/RT950_DIFFERENCES_SUMMARY.md`
- **Model Differences**: `docs/RT950_COMPARISON.md`

---

**Last Updated:** 2025-12-23

