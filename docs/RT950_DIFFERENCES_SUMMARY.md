# RT-950 vs RT-950 Pro: Key Differences Summary

**Analysis Date:** 2025-12-23  
**RT-950 Firmware:** V0.29 (311.2 KB)  
**RT-950 Pro Firmware:** V0.24 (size unknown)

---

## 🔍 Executive Summary

The RT-950 and RT-950 Pro firmwares share significant code but have important differences:

1. **RT-950 firmware is ~10% smaller** (311 KB vs likely ~350 KB for Pro)
2. **Functions are at different addresses** - consistent ~2-3 KB offset earlier
3. **BK4829 initialization is missing/different** - suggests single vs dual transceiver
4. **Code starts later in RT-950** - has header space before main code

---

## 🎯 Critical Differences

### 1. RF Transceiver Configuration

| Aspect | RT-950 | RT-950 Pro |
|--------|--------|------------|
| **BK4829_Init Function** | ❌ Not found at `0x08007f04` | ✅ Present at `0x08007f04` |
| **Number of Transceivers** | Likely **1** (single-band) | **2** (dual-band VHF/UHF) |
| **SPI Interface** | Unknown (needs analysis) | Hardware + Software SPI |
| **Initialization** | Different sequence | 50+ register writes |

**Implication**: RT-950 is likely **single-band**, RT-950 Pro is **dual-band**.

### 2. Code Organization

| Aspect | RT-950 | RT-950 Pro |
|--------|--------|------------|
| **Reset Handler** | `0x08003191` | Likely `0x08000000` |
| **Code Start Offset** | `0x003191` (~3 KB) | `0x000000` (start) |
| **Header Space** | ~3 KB before code | Minimal/no header |
| **Firmware Size** | 311.2 KB | Unknown (likely larger) |

**Implication**: RT-950 has bootloader/header space; Pro code starts immediately.

### 3. Function Address Offsets

All matching functions are found **earlier** in RT-950 firmware:

| Function Category | Average Offset | Notes |
|-------------------|---------------|-------|
| LCD Functions | ~1.1-1.2 KB earlier | LCD code shifted up |
| SPI Flash | ~3.1-3.7 KB earlier | Flash code shifted up |
| Encoder | ~2.3 KB earlier | Encoder code shifted up |
| Display | ~802 bytes earlier | Display code shifted up |

**Implication**: RT-950 firmware is more compact, functions relocated.

---

## 📊 Detailed Function Comparison

### Functions Found in Both (Offset Differences)

| Function | Pro Address | RT-950 Address | Offset | Purpose |
|----------|-------------|----------------|--------|---------|
| LCD_WriteCommand | `0x080271c0` | `0x08026D62` | -1118 bytes | LCD command write |
| LCD_WriteData | `0x08027220` | `0x08026D62` | -1214 bytes | LCD data write |
| Display_BufferFlush | `0x080037b0` | `0x0800348E` | -802 bytes | LCD DMA flush |
| SPIFlash_Erase4K | `0x080210c0` | `0x080202E8` | -3544 bytes | 4KB erase |
| SPIFlash_Erase32K | `0x08020f80` | `0x080202E8` | -3224 bytes | 32KB erase |
| SPIFlash_Erase64K | `0x08020ff0` | `0x080202E8` | -3336 bytes | 64KB erase |
| SPIFlash_Read | `0x08021180` | `0x080202E8` | -3736 bytes | Flash read |
| Encoder_HandleQuadrature | `0x0800e2e0` | `0x0800D9E2` | -2302 bytes | Encoder decoder |

### Functions Missing in RT-950

| Function | Pro Address | Status | Reason |
|----------|-------------|--------|--------|
| **BK4829_Init** | `0x08007f04` | ❌ Not Found | Different RF hardware/config |

---

## 🖥️ Hardware Differences (Inferred)

### Confirmed from Firmware Analysis

1. **Single vs Dual RF Transceiver**
   - RT-950: Missing BK4829_Init suggests single chip
   - RT-950 Pro: Dual BK4829 confirmed from schematic

2. **Memory Layout**
   - RT-950: 86.3 KB RAM used (96 KB total)
   - RT-950 Pro: Unknown RAM usage
   - Both: 96 KB total SRAM

3. **Bootloader/Header**
   - RT-950: ~3 KB header space (0x000000-0x003191)
   - RT-950 Pro: Code starts at flash base

### Likely Hardware Differences

| Component | RT-950 | RT-950 Pro |
|-----------|--------|------------|
| **Bands** | Single-band (likely) | Dual-band (VHF/UHF) |
| **BK4829 Count** | 1 chip | 2 chips (U11, U12) |
| **SPI Configuration** | Hardware SPI only? | Hardware + Software SPI |
| **Display** | Same (320×240) | Same (320×240) |
| **MCU** | AT32F403A | AT32F403ARGT7 (likely same) |

---

## 🔧 Build System Implications

To support both radios, the firmware needs:

### Compile-Time Configuration

```c
// config/radio_model.h
#define RADIO_MODEL_RT950     0
#define RADIO_MODEL_RT950PRO  1

#if RADIO_MODEL == RADIO_MODEL_RT950
  #define BK4829_INSTANCE_COUNT  1
  #define DUAL_BAND_ENABLED      0
  #define CODE_BASE_OFFSET       0x003191  // Header space
#elif RADIO_MODEL == RADIO_MODEL_RT950PRO
  #define BK4829_INSTANCE_COUNT  2
  #define DUAL_BAND_ENABLED      1
  #define CODE_BASE_OFFSET       0x000000  // Start at base
#endif
```

### Driver Abstraction

- **BK4829 Driver**: Conditional compilation for single vs dual
- **Linker Script**: Different code start addresses
- **Initialization**: Model-specific init sequences

---

## 📝 Next Steps

1. **Complete Ghidra Analysis**
   - Extract full function list from RT-950 Ghidra project
   - Compare with RT-950 Pro function list
   - Identify all missing/changed functions

2. **Verify Hardware Differences**
   - Confirm single vs dual BK4829 from RT-950 hardware
   - Check pinout differences (if schematic available)
   - Verify band configuration

3. **Memory Map Analysis**
   - Confirm frame buffer location in RT-950
   - Verify RAM layout differences
   - Check flash layout (channel storage, etc.)

4. **Build System Implementation**
   - Create model-specific linker scripts
   - Implement conditional compilation
   - Test builds for both models

---

## 📚 References

- **Comparison Data**: `firmware/rt950/analysis/detailed_comparison.json`
- **Full Comparison**: `docs/RT950_COMPARISON.md`
- **RT-950 Analysis**: `firmware/rt950/analysis/binary_analysis.json`
- **RT-950 Pro Functions**: `docs/Function_Names.csv`
- **Ghidra Projects**: 
  - RT-950: `firmware/rt950/ghidra_project/RT-950-Analysis/`
  - RT-950 Pro: (if available)

---

**Last Updated:** 2025-12-23

