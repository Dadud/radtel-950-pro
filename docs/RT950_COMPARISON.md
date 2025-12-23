# RT-950 vs RT-950 Pro Comparison

**Analysis Date:** 2025-12-23  
**RT-950 Firmware:** V0.29 (2025-11-04)  
**RT-950 Pro Firmware:** V0.24 (and earlier)

## Overview

This document compares the RT-950 (non-Pro) and RT-950 Pro firmware to identify differences that will enable building firmware for both radio models.

---

## Firmware Files

### RT-950 (Non-Pro)
- **File**: `RT_950_V0.29_251104.BTF`
- **Size**: 318,692 bytes (~311 KB)
- **SHA256**: `DAF691BC3B7593EC5B16FA66BA6B6228FE95640D24D8A9CA880A3B3199DB8DF3`
- **Vector Table**: ✅ Present at offset 0x00 (unencrypted binary)
  - Stack Pointer: `0x20015940` (86.3 KB RAM used, 96KB total)
  - Reset Handler: `0x08003191`
  - NMI Handler: `0x08017B59`
  - Hard Fault: `0x08013B0D`
  - Mem Fault: `0x080163F5`
  - Bus Fault: `0x080037DF`
  - Usage Fault: `0x080208A1`
- **Status**: ✅ Unencrypted, ready for Ghidra analysis
- **Analysis Tool**: Use `scripts/analyze_firmware.py` for binary analysis

### RT-950 Pro
- **File**: `RT_950_Pro_V0.24.BTF` (previous versions analyzed)
- **Size**: ~(to be confirmed from previous analysis)
- **Status**: Previously decrypted and analyzed

---

## Expected Hardware Differences

### RF Configuration

| Feature | RT-950 | RT-950 Pro |
|---------|--------|------------|
| **Bands** | Single-band? (TBD) | Dual-band (VHF/UHF) |
| **Transceivers** | Single BK4829? | Dual BK4829 (U11, U12) |
| **SPI Interface** | Hardware SPI only? | Hardware + Software SPI |

### Display

| Feature | RT-950 | RT-950 Pro |
|---------|--------|------------|
| **Resolution** | 320×240 (likely same) | 320×240 |
| **Controller** | Unknown (TBD) | ILI9341/ST7789 inferred |
| **Interface** | 8080 parallel (likely) | 8080 parallel |

### Other Hardware

| Component | RT-950 | RT-950 Pro |
|-----------|--------|------------|
| **MCU** | AT32F403A (likely) | AT32F403ARGT7 |
| **Flash** | 1MB (likely) | 1MB internal + external SPI |
| **RAM** | 96KB (likely) | 96KB SRAM |
| **GPS** | Present? (TBD) | NMEA module (UART) |
| **Bluetooth** | Present? (TBD) | Serial module (UART) |
| **Broadcast RX** | SI4732? (TBD) | SI4732 FM/AM (I2C) |

---

## Firmware Differences (To Be Analyzed)

### Initial Findings from Binary Analysis

**Vector Table Comparison:**
- RT-950 Stack Pointer: `0x20015940` (86.3 KB RAM usage)
- RT-950 Pro Stack Pointer: (to be compared from Pro analysis)
- RT-950 Reset Handler: `0x08003191` (offset 0x003191 from flash base)
- RT-950 Pro Reset Handler: (to be compared)

**File Size:**
- RT-950: 318,692 bytes (311 KB)
- RT-950 Pro: (to be confirmed from previous analysis)

**Code Patterns:**
- RT-950 has 67 PUSH {lr} patterns (function prologues)
- 3 BX LR patterns (function returns)
- ~100 BL instructions (function calls)
- Indicates normal ARM Thumb code structure

**Possible Implications:**
- ✅ RT-950 firmware is **unencrypted** (no decryption needed)
- Different feature sets may result in different code sizes
- Memory layout may differ (RT-950 uses 86.3 KB RAM vs Pro)
- Some functions may be shared, others model-specific
- Reset handler offset suggests code starts at ~0x08003000

---

## Feature Differences (From Release Notes)

### RT-950 V0.29 Features
- Single PTT mode (toggle on/off)
- Temporary scan list (keys 0-9)
- Channel scanning with add/delete
- Spectrum interface with 5 kHz stepping
- DTMF configuration menus (delay, duration, spacing)
- Customizable zone names
- APRS improvements

### RT-950 Pro Features (From Previous Analysis)
- Dual-band operation (VHF/UHF)
- KISS TNC mode (APRS over Bluetooth)
- Dual BK4829 transceivers
- (Additional features from Pro analysis)

---

## Memory Map Comparison (To Be Analyzed)

### RT-950 Pro (Known)
- **Flash Base**: `0x08000000`
- **RAM Base**: `0x20000000`
- **Frame Buffer**: `0x20000BD0` (320×240 RGB565)
- **Stack**: Top of RAM

### RT-950 (To Be Confirmed)
- **Stack Pointer**: `0x20015940` (indicates 96KB RAM)
- **Flash Base**: Likely `0x08000000` (standard ARM)
- **Frame Buffer**: (to be determined via analysis)

---

## Function Address Comparison (Ghidra Analysis Required)

After Ghidra analysis, compare:

1. **System Initialization Functions**
   - Clock configuration
   - GPIO setup
   - Peripheral initialization

2. **Driver Functions**
   - BK4829 initialization (may differ for single vs dual)
   - LCD initialization
   - SPI flash operations

3. **Radio Functions**
   - VFO control
   - Channel management
   - CTCSS/DCS

4. **UI Functions**
   - Menu system
   - Display rendering
   - Keypad handling

---

## Build System Strategy

To support both RT-950 and RT-950 Pro:

### Option 1: Compile-Time Configuration

```c
// config/radio_model.h
#define RADIO_MODEL_RT950     0
#define RADIO_MODEL_RT950PRO  1

#ifndef RADIO_MODEL
#define RADIO_MODEL  RADIO_MODEL_RT950PRO  // Default
#endif

#if RADIO_MODEL == RADIO_MODEL_RT950
  #define BK4829_INSTANCE_COUNT  1
  #define DUAL_BAND_ENABLED      0
#elif RADIO_MODEL == RADIO_MODEL_RT950PRO
  #define BK4829_INSTANCE_COUNT  2
  #define DUAL_BAND_ENABLED      1
#endif
```

### Option 2: Shared Drivers with Model Detection

```c
// Runtime detection (if possible)
bool Radio_IsDualBand(void) {
    // Check hardware or firmware version
    return (RADIO_MODEL == RADIO_MODEL_RT950PRO);
}
```

### Option 3: Separate Build Targets

```cmake
# CMakeLists.txt
option(BUILD_RT950 "Build for RT-950 (non-Pro)" OFF)
option(BUILD_RT950PRO "Build for RT-950 Pro" ON)

if(BUILD_RT950)
    add_definitions(-DRADIO_MODEL=0)
elseif(BUILD_RT950PRO)
    add_definitions(-DRADIO_MODEL=1)
endif()
```

---

## Analysis Status

### ✅ Completed
- [x] Downloaded RT-950 V0.29 firmware
- [x] Extracted firmware binary
- [x] Analyzed file header (vector table present, unencrypted)
- [x] Extracted vector table addresses (stack, reset, exceptions)
- [x] Created firmware analysis script (`scripts/analyze_firmware.py`)
- [x] Created comparison framework
- [x] Created Ghidra analysis guide (`firmware/GHIDRA_ANALYSIS.md`)

### 🔄 In Progress
- [ ] Ghidra analysis of RT-950 firmware
- [ ] Function address extraction
- [ ] Memory map comparison
- [ ] Hardware difference identification

### ⏳ Pending
- [ ] Compare initialization sequences
- [ ] Identify shared vs model-specific code
- [ ] Document register usage differences
- [ ] Create unified build system
- [ ] Test firmware on both models

---

## Next Steps

1. **Complete Ghidra Analysis**
   - Import RT-950 firmware into Ghidra
   - Extract function addresses and names
   - Compare with RT-950 Pro analysis
   - Document differences

2. **Hardware Verification**
   - Compare pinout schematics (if available)
   - Verify hardware differences
   - Confirm feature set differences

3. **Build System Implementation**
   - Create model-specific configuration
   - Implement conditional compilation
   - Test builds for both models

4. **Driver Abstraction**
   - Create unified driver interface
   - Handle single vs dual BK4829
   - Abstract hardware differences

---

## References

- RT-950 Firmware: `firmware/rt950/RT_950_V0.29_251104.BTF`
- RT-950 Pro Analysis: Previous Ghidra projects
- Hardware Pinout: `docs/pinout.md`
- BK4829 Driver: `src/drivers/bk4829.c`
- Ghidra Analysis Guide: `firmware/GHIDRA_ANALYSIS.md`

---

**Note:** This document will be updated as analysis progresses. See git history for change log.

