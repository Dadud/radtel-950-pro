# Source Code Documentation & AI Reasoning

This document explains the structure of the source code and the AI's reasoning for implementation decisions. **All code in this project is AI-generated based on reverse engineering analysis.**

> **⚠️ See [main README.md](../README.md) for disclaimers and warnings about AI-generated content**

---

## Understanding the Codebase Structure

The source code is organized into several layers:

### 1. Architecture Layer (`src/arch/`)
[**Documentation:** `docs/src_arch.md`](src_arch.md)

Hardware-specific startup code and linker scripts:
- **Startup Assembly**: Vector table, reset handler, exception handlers
- **Linker Script**: Memory layout, stack/heap configuration
- **System Init**: Clock configuration, peripheral initialization

**AI Reasoning:**
- Based on Artery AT32 SDK structure (known vendor pattern)
- Memory map derived from OEM firmware analysis (0x08000000 flash base, 0x20000000 RAM base)
- Stack size estimated from frame buffer location and SRAM size

---

### 2. Hardware Abstraction Layer (`src/hal/`)
[**Documentation:** `docs/src_hal.md`](src_hal.md)

Low-level hardware peripheral drivers:
- **GPIO**: Pin configuration, read/write operations
- **SPI**: Hardware and software SPI implementations
- **UART**: Serial communication drivers
- **ADC/DAC**: Analog I/O for battery monitoring and audio
- **DMA**: Direct memory access for LCD and audio streaming
- **Timer**: Timing and PWM generation

**AI Reasoning:**
- Register addresses from AT32F403A datasheet
- Peripheral behavior inferred from OEM firmware register writes
- API design follows common embedded HAL patterns for consistency

---

### 3. Driver Layer (`src/drivers/`)
[**Documentation:** `docs/src_drivers.md`](src_drivers.md)

High-level device drivers:
- **BK4829**: RF transceiver control ([detailed reasoning](src_drivers_bk4829.md))
- **LCD**: Display driver ([detailed reasoning](src_drivers_lcd.md))
- **SPI Flash**: External memory operations ([detailed reasoning](src_drivers_spi_flash.md))
- **Encoder**: Rotary encoder quadrature decoding ([detailed reasoning](src_drivers_encoder.md))
- **Keypad**: Matrix scanning
- **Audio**: Tone generation and audio path
- **Power**: Battery monitoring and power management
- **SI4732**: FM/AM broadcast receiver

**AI Reasoning:**
- Initialization sequences extracted from OEM firmware function analysis (Ghidra)
- Register values captured from reverse engineering
- Protocol implementations based on datasheet specifications (where available)

---

### 4. Radio Layer (`src/radio/`)
[**Documentation:** `docs/src_radio.md`](src_radio.md)

Radio-specific functionality:
- **VFO**: Variable frequency oscillator control
- **Channel**: Channel memory management
- **CTCSS**: Continuous tone coded squelch system
- **Scan**: Frequency scanning algorithms
- **Radio**: Main radio state machine

**AI Reasoning:**
- Behavior inferred from OEM firmware menu interactions
- Frequency calculation based on BK4829 datasheet (26 MHz crystal)
- Channel storage format inferred from SPI flash layout analysis

---

### 5. Protocol Layer (`src/protocols/`)
[**Documentation:** `docs/src_protocols.md`](src_protocols.md)

Communication protocols:
- **Bluetooth**: UART-based Bluetooth module control
- **GPS**: NMEA sentence parsing
- **CDC**: USB CDC protocol for firmware updates

**AI Reasoning:**
- Protocol details captured from USB packet analysis (USB CDC)
- NMEA format is standard (no reverse engineering needed)
- Bluetooth AT command set is typical for serial BT modules

---

### 6. UI Layer (`src/ui/`)
[**Documentation:** `docs/src_ui.md`](src_ui.md)

User interface components:
- **Display**: Screen rendering and graphics primitives
- **Menu**: Menu system framework
- **Fonts**: Character rendering
- **UI**: Main UI state machine

**AI Reasoning:**
- Display buffer location from OEM firmware memory map (0x20000BD0)
- Menu structure inferred from observed behavior
- Font format assumed from common embedded graphics patterns

---

### 7. Configuration Layer (`src/config/`)
[**Documentation:** `docs/src_config.md`](src_config.md)

Settings and calibration data:
- **Settings**: Radio configuration storage
- **EEPROM**: Non-volatile memory interface (if present)

**AI Reasoning:**
- Settings structure inferred from OEM firmware memory accesses
- Storage location assumed to be SPI flash (based on channel memory location)
- Format guessed from typical embedded systems patterns

---

## AI Reasoning Documentation Files

Detailed explanations for each module:

| Module | Documentation File | Key Reasoning |
|--------|-------------------|---------------|
| **Architecture** | [`docs/src_arch.md`](src_arch.md) | Startup code, memory layout, system initialization |
| **HAL Layer** | [`docs/src_hal.md`](src_hal.md) | Peripheral register access, low-level hardware control |
| **BK4829 Driver** | [`docs/src_drivers_bk4829.md`](src_drivers_bk4829.md) | RF transceiver initialization, frequency programming |
| **LCD Driver** | [`docs/src_drivers_lcd.md`](src_drivers_lcd.md) | Display interface, frame buffer, DMA streaming |
| **SPI Flash** | [`docs/src_drivers_spi_flash.md`](src_drivers_spi_flash.md) | External memory operations, erase/write algorithms |
| **Encoder** | [`docs/src_drivers_encoder.md`](src_drivers_encoder.md) | Quadrature decoding state machine |
| **Radio Functions** | [`docs/src_radio.md`](src_radio.md) | VFO, channels, CTCSS, scanning |
| **Protocols** | [`docs/src_protocols.md`](src_protocols.md) | Bluetooth, GPS, USB CDC |
| **UI System** | [`docs/src_ui.md`](src_ui.md) | Menu, display, user interface |
| **Configuration** | [`docs/src_config.md`](src_config.md) | Settings storage, calibration |

---

## How to Read This Documentation

Each documentation file explains:
1. **What the code does** - Functional description
2. **Why it's structured this way** - AI's reasoning for design decisions
3. **Source of information** - Where the AI got the data (Ghidra analysis, datasheets, etc.)
4. **Confidence level** - How certain the AI is about the implementation
5. **Potential issues** - Known problems or assumptions that may be wrong

**Remember:** All of this is AI-generated and may contain hallucinations or inaccuracies. Verify against actual hardware!

---

## General AI Reasoning Principles

The AI made decisions based on:

1. **Reverse Engineering Data**:
   - Ghidra disassembly of OEM firmware
   - Register value dumps from FUN_* functions
   - USB packet captures
   - Memory map analysis

2. **Industry Standards**:
   - Common embedded HAL patterns
   - Typical microcontroller startup sequences
   - Standard communication protocols (SPI, I2C, UART)

3. **Datasheet Information**:
   - AT32F403A datasheet (where available)
   - BK4829 datasheet (DS-BK4829-E01 V1.0)
   - Component specifications

4. **Pattern Matching**:
   - Similarities to other embedded projects (OpenRTX, Quansheng firmware)
   - Typical radio firmware structures
   - Common embedded C coding patterns

**Important:** The AI often had to make educated guesses where information was incomplete. These assumptions should be verified with actual hardware testing.

