# OpenRTX Port Feasibility Analysis

Analysis of porting OpenRTX firmware to RT-950/RT-950 Pro and ability to return to stock firmware.

## Executive Summary

**Port Feasibility**: **MEDIUM** - Significant work required but foundation exists  
**Stock Recovery**: **YES** - Multiple recovery methods available

---

## 1. OpenRTX Overview

[OpenRTX](https://github.com/OpenRTX/OpenRTX) is a modular open-source radio firmware designed for digital amateur radio devices. Currently supports:
- TYT MD-380/390
- TYT MD-UV380/390
- TYT MD-9600
- Radioddity GD77
- Baofeng DM-1801/1701
- Connect Systems CS7000-M17
- Module17

**Key Features**:
- M17 digital voice protocol support
- Modular architecture with platform abstraction
- DMR support (where applicable)
- Modern UI framework
- Open-source (GPL-3.0)

---

## 2. Hardware Compatibility Analysis

### MCU Comparison

| Aspect | OpenRTX (Supported Radios) | RT-950/RT-950 Pro | Compatibility |
|--------|---------------------------|-------------------|---------------|
| **MCU Family** | STM32F405, NXP MKL17, etc. | **AT32F403ARGT7** | ⚠️ **DIFFERENT** |
| **Core** | Cortex-M4F | Cortex-M4F | ✅ **SAME** |
| **Clock** | 168MHz (STM32F405) | 240MHz | ✅ **FASTER** |
| **Flash** | 1MB | 1MB | ✅ **SAME** |
| **RAM** | 192KB (STM32F405) | 96KB | ⚠️ **HALF** |
| **Register Map** | STM32 | AT32 | ⚠️ **SIMILAR BUT NOT IDENTICAL** |

**Key Finding**: AT32F403A is **register-compatible** with STM32F4 series (Artery designed it as a drop-in replacement), but differences exist in:
- Clock management registers
- Some peripheral register addresses
- DMA channel assignments

### Critical Hardware Differences

1. **RAM Constraint**: RT-950 has **96KB RAM** vs 192KB in typical OpenRTX targets
   - OpenRTX may need optimization for lower RAM
   - Current RT-950 firmware uses ~38KB for frame buffer
   - Available RAM: ~58KB (tight for OpenRTX)

2. **RF Transceiver**: OpenRTX targets use different RF chips
   - OpenRTX: HR-C6000 (DMR), CC1310 (some models)
   - RT-950: **BK4829** (FM-only, no DMR hardware)
   - **Major Porting Challenge**: RF driver completely different

3. **Display**: OpenRTX uses various displays
   - RT-950: 320×240 TFT, RGB565, 8080 parallel
   - Similar to some OpenRTX targets
   - **Portable**: Display driver should be adaptable

---

## 3. Current Project Status vs OpenRTX Requirements

### ✅ What We Have (Good Foundation)

1. **Hardware Abstraction Layer (HAL)**
   - GPIO, SPI, UART, ADC, DAC, DMA, Timer HALs implemented
   - AT32F403A-specific register definitions
   - **Status**: Foundation exists, but needs OpenRTX API compatibility layer

2. **Driver Layer**
   - BK4829 RF driver (basic)
   - LCD display driver
   - Keypad, encoder drivers
   - Audio, GPS, Bluetooth drivers
   - **Status**: Drivers exist but need OpenRTX interface adaptation

3. **Hardware Documentation**
   - Complete pinout mapping
   - Memory map documented
   - Peripheral addresses confirmed
   - **Status**: Excellent hardware understanding

4. **Build System**
   - CMake-based build system
   - Unified build for RT-950/RT-950 Pro
   - Linker scripts configured
   - **Status**: Build infrastructure ready

### ❌ What We're Missing (Porting Requirements)

1. **OpenRTX Platform Layer**
   - OpenRTX uses platform abstraction (`platform/` directory)
   - Need to create RT-950 platform implementation
   - **Effort**: High - requires understanding OpenRTX architecture

2. **OpenRTX UI Framework**
   - OpenRTX has its own UI system
   - Need to adapt or port UI framework
   - **Effort**: High - UI is complex

3. **M17 Support**
   - OpenRTX has M17 implementation
   - RT-950 has DAC/ADC for M17
   - **Effort**: Medium - can leverage OpenRTX M17 code

4. **DMR Support**
   - RT-950 **CANNOT** support DMR (BK4829 is FM-only)
   - OpenRTX heavily relies on DMR for some targets
   - **Effort**: N/A - Not possible with current hardware

---

## 4. Porting Complexity Assessment

### Difficulty Level: **MEDIUM-HIGH**

**Reasons**:
- ✅ Cortex-M4F core compatibility
- ✅ Similar memory constraints (tight but workable)
- ✅ Register-compatible MCU (AT32 ≈ STM32)
- ⚠️ Different RF transceiver (major rewrite needed)
- ⚠️ Lower RAM (96KB vs 192KB)
- ⚠️ No DMR hardware (significant feature loss)

### Estimated Effort

| Task | Complexity |
|------|-----------|
| Platform layer port | High |
| RF driver rewrite | High |
| UI adaptation | Medium-High |
| M17 integration | Medium |
| Testing & debugging | High |
| **Total** | **High** |

### Biggest Challenges

1. **RF Driver**: BK4829 is completely different from OpenRTX's RF chips
   - Must rewrite entire RF abstraction layer
   - FM-only (no DMR capability)
   - Dual-band support (Pro) adds complexity

2. **RAM Constraints**: 96KB is tight for OpenRTX
   - May need significant optimization
   - Some features may need to be disabled
   - Frame buffer management critical

3. **Platform Abstraction**: OpenRTX's platform layer needs RT-950 implementation
   - Must understand OpenRTX architecture deeply
   - Create RT-950-specific platform code
   - Ensure API compatibility

---

## 5. Can We Return to Stock Firmware?

### ✅ **YES - Multiple Recovery Methods Available**

### Method 1: SWD/JTAG Recovery (Most Reliable)

**Requirements**:
- SWD programmer (ST-Link, J-Link, etc.)
- SWD pins: SWDIO=PA13, SWCLK=PA14
- Ground connection

**Procedure**:
1. Connect SWD programmer (do NOT connect VDD)
2. Power on radio
3. Use OpenOCD/ST-Link to flash stock firmware:

```bash
# Backup current firmware first
openocd -f interface/stlink.cfg -f target/stm32f4x.cfg \
  -c "init; halt; dump_image backup.bin 0x08000000 0x100000"

# Flash stock firmware (from firmware/rt950pro/RT_950Pro_V0.24_251201.BTF)
openocd -f interface/stlink.cfg -f target/stm32f4x.cfg \
  -c "program RT_950Pro_V0.24_251201.BTF 0x08000000 verify reset exit"
```

**Advantage**: Works even if bootloader is corrupted  
**Status**: ✅ **CONFIRMED** - SWD access documented, firmware files available

### Method 2: USB Bootloader Recovery

**Requirements**:
- USB connection to PC
- OEM bootloader still functional
- Stock firmware file (.BTF format)

**Procedure**:
1. Enter bootloader mode (button combination - consult OEM docs)
2. Connect via USB (appears as COM port)
3. Use OEM update tool (`RT-950_EnUPDATE.exe` from firmware package)

**Advantage**: No hardware modification needed  
**Status**: ⚠️ **UNCERTAIN** - Bootloader may have signature checks

### Method 3: Firmware Files Available

**Stock Firmware Files in Repository**:
- `firmware/rt950pro/RT_950Pro_V0.24_251201.BTF` - RT-950 Pro V0.24
- `firmware/rt950/RT_950_V0.29_251104.BTF` - RT-950 V0.29
- OEM update tools included in firmware packages

**Status**: ✅ **AVAILABLE** - Firmware files ready for recovery

---

## 6. Recommendations

### If You Want to Port OpenRTX:

1. **Start with Platform Layer**
   - Study OpenRTX platform abstraction (`platform/` directory)
   - Create minimal RT-950 platform implementation
   - Get basic system running first

2. **Focus on FM Features First**
   - Skip DMR support (not possible with BK4829)
   - Implement M17 over FM
   - Focus on FM radio features

3. **Optimize for RAM**
   - OpenRTX may need RAM optimization for 96KB
   - Consider disabling some features
   - Optimize frame buffer usage

4. **Incremental Porting**
   - Port one subsystem at a time
   - Test each component thoroughly
   - Don't try to port everything at once

### Alternative Approach:

**Instead of full OpenRTX port, consider**:
- **Adopting OpenRTX concepts**: Modular architecture, UI patterns
- **Selective feature adoption**: M17 code, UI components
- **Hybrid approach**: Use OpenRTX code where applicable, custom code for BK4829

This would be **less risky** than full port.

---

## 7. Risk Assessment

### Porting Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Brick during porting** | Medium | High | ✅ SWD recovery available |
| **RAM exhaustion** | High | High | Optimize, disable features |
| **RF driver complexity** | High | Medium | Start simple, iterate |
| **Scope creep** | High | Medium | Incremental approach |

### Recovery Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **SWD pins inaccessible** | Low | High | Confirm pin access before starting |
| **Bootloader corrupted** | Low | Medium | SWD recovery works even if bootloader dead |
| **Firmware file corrupted** | Low | Medium | Verify firmware file integrity |

---

## 8. Current Readiness Score

### Foundation Readiness: **7/10**

**Strengths**:
- ✅ Hardware well-documented
- ✅ HAL layer exists
- ✅ Drivers implemented
- ✅ Build system ready
- ✅ Firmware recovery available

**Weaknesses**:
- ⚠️ No OpenRTX platform layer
- ⚠️ Different RF transceiver
- ⚠️ RAM constraints
- ⚠️ No OpenRTX architecture experience

### Recommendation: **START WITH SMALL STEPS**

1. **First**: Clone OpenRTX repository, study architecture
2. **Second**: Create minimal RT-950 platform stub
3. **Third**: Port one small subsystem (e.g., GPIO)
4. **Fourth**: Gradually expand port

**Don't attempt full port immediately** - incremental approach reduces risk.

---

## 9. Conclusion

**Port Feasibility**: **MEDIUM**
- Hardware is compatible enough
- Foundation exists
- Major challenges: RF driver, RAM, platform layer

**Stock Recovery**: **YES** ✅
- SWD recovery method available
- Stock firmware files in repository
- Multiple recovery paths

**Recommendation**: 
- **Before porting**: Ensure SWD access works, backup stock firmware via SWD
- **Porting approach**: Incremental, start small, test frequently
- **Recovery**: Keep SWD programmer handy, test recovery procedure first

---

**Last Updated**: 2025-12-23  
**Status**: Preliminary analysis - needs OpenRTX codebase study for detailed assessment

