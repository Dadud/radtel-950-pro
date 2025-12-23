# Radtel RT-950 Pro Clean-Room Firmware

> **⚠️ For disclaimers and warnings, see the [main README.md](../README.md)**

---

## Overview

This project is a complete clean-room re-implementation of the Radtel RT-950 Pro dual-band mobile radio firmware. The goal is to provide an open-source alternative that can be extended, customized, and improved by the amateur radio community.

### Target Hardware

| Component | Description | Status |
|-----------|-------------|--------|
| MCU | Artery AT32F403ARGT7 (Cortex-M4F @ 240MHz) | **CONFIRMED** |
| Flash | 1MB internal + external SPI NOR | **CONFIRMED** |
| RAM | 96KB SRAM | **CONFIRMED** |
| Display | 320×240 TFT (8080 parallel interface) | **CONFIRMED** |
| RF VHF | BK4829 transceiver (hardware SPI) | **CONFIRMED** |
| RF UHF | BK4829 transceiver (software SPI) | **CONFIRMED** |
| Broadcast RX | SI4732 FM/AM receiver (I2C) | **HIGH confidence** |
| GPS | NMEA module (UART) | **CONFIRMED** |
| Bluetooth | Serial module (UART) | **CONFIRMED** |

---

## Project Structure

```
src/
├── main.c                  # Application entry point
├── arch/                   # CPU and startup code
│   ├── startup_at32f403a.s # Vector table and reset handler
│   ├── system_at32f403a.c  # System initialization
│   └── AT32F403AxG_FLASH.ld # Linker script
├── hal/                    # Hardware Abstraction Layer
│   ├── system.h            # System clock and timing
│   ├── gpio.h              # GPIO configuration
│   ├── spi.h               # SPI (hardware + software)
│   ├── uart.h              # UART communication
│   ├── adc.h               # ADC for battery/audio
│   ├── dac.h               # DAC for tone generation
│   ├── dma.h               # DMA for LCD/audio
│   └── timer.h             # Timer peripherals
├── drivers/                # Device drivers
│   ├── lcd.h/c             # TFT display driver [IMPLEMENTED]
│   ├── keypad.h            # Matrix keypad
│   ├── encoder.h/c         # Rotary encoder [IMPLEMENTED]
│   ├── bk4829.h/c          # RF transceiver [IMPLEMENTED]
│   ├── si4732.h            # Broadcast receiver
│   ├── spi_flash.h/c       # External flash storage [IMPLEMENTED]
│   ├── audio.h             # Audio subsystem
│   └── power.h             # Power management
├── radio/                  # Radio core functionality
│   ├── radio.h             # Radio state machine
│   ├── channel.h           # Channel memory
│   └── vfo.h               # VFO management
├── ui/                     # User interface
│   ├── display.h           # Display manager
│   ├── menu.h              # Menu system
│   └── ui.h                # UI state machine
├── protocols/              # Communication protocols
│   ├── cdc_protocol.h      # USB CDC for programming
│   ├── gps.h               # GPS NMEA parser
│   └── bluetooth.h         # Bluetooth interface
├── config/                 # Configuration storage
│   ├── settings.h          # Settings management
│   └── eeprom.h            # EEPROM abstraction
└── README.md               # This file

build/
└── CMakeLists.txt          # CMake build configuration
```

---

## Confidence Levels

Each hardware mapping and function behavior is tagged with a confidence level:

| Level | Meaning |
|-------|---------|
| **CONFIRMED** | Verified through multiple sources, captured traces, or unambiguous disassembly |
| **HIGH** | Strong evidence from firmware analysis, consistent with hardware expectations |
| **MEDIUM** | Reasonable inference from context, likely correct but needs verification |
| **LOW** | Speculative, based on limited evidence, requires hardware testing |

---

## Hardware Mappings

### GPIO Pin Assignments

#### Port A (CONFIRMED/HIGH confidence)
| Pin | Function | Confidence | Notes |
|-----|----------|------------|-------|
| PA0 | VOX detect (ADC) | HIGH | ADC2 channel 0 |
| PA1 | Battery sense (ADC) | CONFIRMED | ADC2 channel 1 |
| PA4 | Beep/tone output | CONFIRMED | DAC1 output |
| PA5 | APC control | HIGH | May be DAC2 |
| PA8 | GPS enable | HIGH | Power control |
| PA9 | USART1 TX (Bluetooth) | CONFIRMED | 115200 baud |
| PA10 | USART1 RX (Bluetooth) | CONFIRMED | 115200 baud |
| PA11 | Power latch | HIGH | Hold to stay on |

#### Port B (CONFIRMED/HIGH confidence)
| Pin | Function | Confidence | Notes |
|-----|----------|------------|-------|
| PB4 | Encoder phase A | CONFIRMED | Interrupt-driven |
| PB5 | Encoder phase B | CONFIRMED | Interrupt-driven |
| PB6 | SI4732 I2C SCK | HIGH | Software I2C |
| PB7 | SI4732 I2C SDA | HIGH | Software I2C |
| PB12 | SPI Flash CS | CONFIRMED | Active low |
| PB13 | SPI Flash SCK | CONFIRMED | |
| PB14 | SPI Flash MISO | CONFIRMED | |
| PB15 | SPI Flash MOSI | CONFIRMED | |

#### Port C (CONFIRMED)
| Pin | Function | Confidence | Notes |
|-----|----------|------------|-------|
| PC0-3 | Keypad rows | CONFIRMED | Active high scan |
| PC6 | LCD backlight | CONFIRMED | PWM capable |
| PC7 | PTT detect | CONFIRMED | Input |
| PC13 | Red LED | CONFIRMED | Status indicator |
| PC14 | Green LED | CONFIRMED | Status indicator |

#### Port D (CONFIRMED)
| Pin | Function | Confidence | Notes |
|-----|----------|------------|-------|
| PD0 | LCD WR# | CONFIRMED | Write strobe |
| PD1 | LCD CS# | CONFIRMED | Chip select |
| PD2 | LCD RESET | CONFIRMED | Active low |
| PD3 | LCD RS (D/C#) | CONFIRMED | Data/Command |
| PD4-7 | Keypad columns | CONFIRMED | Input with pulldown |
| PD8-15 | LCD data bus | CONFIRMED | 8-bit parallel |

#### Port E (CONFIRMED/HIGH confidence)
| Pin | Function | Confidence | Notes |
|-----|----------|------------|-------|
| PE0 | Power switch | CONFIRMED | Input |
| PE1 | Speaker mute | HIGH | Active low |
| PE3 | PTT output | CONFIRMED | TX control |
| PE4 | PA enable | CONFIRMED | Power amplifier |
| PE8 | BK4829 #1 CS | CONFIRMED | Hardware SPI |
| PE10 | BK4829 #2 SCK | CONFIRMED | Software SPI |
| PE11 | BK4829 #2 SDA | CONFIRMED | Software SPI |
| PE15 | BK4829 #2 CS | CONFIRMED | Software SPI |

### Memory Map

| Address | Size | Description | Confidence |
|---------|------|-------------|------------|
| 0x08000000 | 1MB | Internal Flash | CONFIRMED |
| 0x20000000 | 96KB | SRAM | CONFIRMED |
| 0x20000BD0 | 153.6KB | Frame buffer | CONFIRMED |
| 0x40010800 | - | GPIOA | CONFIRMED |
| 0x40010C00 | - | GPIOB | CONFIRMED |
| 0x40011000 | - | GPIOC | CONFIRMED |
| 0x40011400 | - | GPIOD | CONFIRMED |
| 0x40011800 | - | GPIOE | CONFIRMED |
| 0x40013000 | - | SPI1 | CONFIRMED |
| 0x40013800 | - | USART1 | CONFIRMED |
| 0x40007400 | - | DAC | CONFIRMED |
| 0x40012800 | - | ADC2 | CONFIRMED |
| 0x40020430 | - | DMA2 | CONFIRMED |

### External SPI Flash Layout (INFERRED)

| Address | Size | Content | Confidence |
|---------|------|---------|------------|
| 0x00000 | 4KB | Reserved | HIGH |
| 0x01000 | 64KB | Channels 0-999 | HIGH |
| 0x11000 | 4KB | VFO settings | HIGH |
| 0x12000 | 4KB | Radio settings | HIGH |
| 0x13000 | 4KB | Calibration data | MEDIUM |
| 0x20000 | - | Additional storage | MEDIUM |

---

## Building the Firmware

### Prerequisites

1. **ARM GCC Toolchain** (arm-none-eabi-gcc 10.x or later)
   ```bash
   # Ubuntu/Debian
   sudo apt install gcc-arm-none-eabi
   
   # Windows: Download from ARM website
   # macOS: brew install arm-none-eabi-gcc
   ```

2. **CMake** (3.20 or later)
   ```bash
   sudo apt install cmake
   ```

3. **Make** or **Ninja**
   ```bash
   sudo apt install make ninja-build
   ```

### Build Instructions

```bash
# Clone and enter project
cd radtel-950-pro/src

# Create build directory
mkdir -p ../build/output
cd ../build/output

# Configure
cmake ../.. -DCMAKE_BUILD_TYPE=Release

# Build
make -j$(nproc)
# or
ninja

# Output files:
# - rt950pro_firmware.elf (for debugging)
# - rt950pro_firmware.bin (for flashing)
# - rt950pro_firmware.hex (Intel HEX format)
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| CMAKE_BUILD_TYPE | Debug | Debug or Release |
| ENABLE_GPS | ON | Include GPS support |
| ENABLE_BLUETOOTH | ON | Include Bluetooth support |
| ENABLE_FM | ON | Include FM broadcast RX |

---

## Flashing the Firmware

### ⚠️ WARNINGS

1. **BACKUP YOUR ORIGINAL FIRMWARE FIRST**
   - Use `radtel_flash.py --read` to dump your current firmware
   - Store the backup safely

2. **BOOTLOADER REQUIREMENTS**
   - The OEM bootloader may perform signature checks
   - You may need to bypass these checks
   - Flashing untested firmware can brick your radio

3. **ANTENNA REQUIREMENT**
   - Always have an antenna connected when transmitting
   - Transmitting without an antenna can damage the PA

### Methods

#### Method 1: USB CDC (OEM Bootloader)

If the OEM bootloader accepts unsigned images:

```bash
python firmware/scripts/radtel_flash.py \
    --port /dev/ttyACM0 \
    --raw build/output/rt950pro_firmware.bin
```

#### Method 2: SWD/JTAG (Requires Hardware)

Using OpenOCD and ST-Link:

```bash
openocd -f interface/stlink.cfg \
        -f target/stm32f4x.cfg \
        -c "program rt950pro_firmware.elf verify reset exit"
```

**Pin connections:**
- SWDIO: PA13
- SWCLK: PA14
- GND: Any ground pin
- VDD: 3.3V (reference only, do not power from programmer)

---

## Implementation Status

### Drivers with CONFIRMED Register Values

| Driver | Status | Source |
|--------|--------|--------|
| BK4829 RF Transceiver | ✅ Complete init sequence | FUN_08007f04 |
| SPI Flash | ✅ All erase/read/write commands | FUN_080210c0, FUN_08020f80, FUN_08020ff0 |
| Rotary Encoder | ✅ Quadrature state machine | FUN_0800e2e0 |
| LCD Display | ✅ 8080 bus protocol | FUN_080271c0, FUN_08027220 |

### Drivers Needing Hardware Verification

| Driver | Status | Notes |
|--------|--------|-------|
| Keypad Matrix | ⚠️ Pins confirmed, scan logic needed | FUN_08013618 |
| SI4732 FM/AM RX | ⚠️ I2C address unconfirmed | 0x11 or 0x63? |
| Audio DAC | ⚠️ DMA setup needed | FUN_0800dca0 |
| GPS UART | ⚠️ NMEA parsing needed | FUN_08013f90 |
| Bluetooth UART | ⚠️ Command protocol unknown | FUN_0800834c |

---

## Known Issues and TODOs

### Critical (Must Fix Before Use)

- [ ] **TX Safety**: No hardware TX lockout - software must prevent illegal transmissions
- [ ] **Calibration**: RF calibration data format unknown - may affect TX power accuracy
- [ ] **Bootloader**: Signature bypass method undocumented

### High Priority

- [x] ~~Test BK4829 initialization sequence~~ → **CONFIRMED from Ghidra**
- [x] ~~Implement SPI flash erase/read/write~~ → **CONFIRMED from Ghidra**
- [x] ~~Implement encoder quadrature decoding~~ → **CONFIRMED from Ghidra**
- [ ] Verify LCD controller ID (ILI9341/ST7789/other)
- [ ] Verify SI4732 I2C address (0x11 vs 0x63)
- [ ] Validate battery voltage divider ratio
- [ ] Test GPS NMEA parsing with real module

### Medium Priority

- [ ] Implement DCS encode/decode
- [ ] Add DTMF encode/decode
- [ ] Implement APRS support
- [ ] Add spectrum display mode
- [ ] Implement band relay control
- [ ] Implement keypad matrix scanning

### Low Priority

- [ ] Custom boot logo
- [ ] Additional UI themes
- [ ] Extended memory channels
- [ ] MDC1200/STAR signaling

---

## Contributing

### Code Style

- C11 standard
- 4-space indentation
- Doxygen-style comments
- Function names: `Module_Action()` (PascalCase)
- Variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- All hardware accesses must be documented with confidence level

### Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Test on real hardware if possible
4. Document confidence levels for any new hardware assumptions
5. Submit pull request with detailed description

### Hardware Verification

If you have access to an RT-950 Pro and test equipment:

1. Logic analyzer traces are extremely valuable
2. Document any discovered pin functions
3. Capture SPI/I2C traffic for device initialization
4. Measure voltage levels and timing

---

## Legal Notice

This project is a clean-room reverse engineering effort for educational and interoperability purposes. 

- The original firmware is copyright Radtel
- The AT32 SDK is provided by Artery Technology
- This implementation contains NO proprietary code

Amateur radio operators are responsible for ensuring their transmissions comply with applicable regulations. This firmware provides no guarantee of regulatory compliance.

---

## License

This clean-room implementation is released under the MIT License.

```
MIT License

Copyright (c) 2024 RT-950 Pro Open Firmware Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Acknowledgments

- Artery Technology for the AT32 SDK and documentation
- The amateur radio reverse engineering community
- Contributors to related projects (Quansheng UV-K5 firmware, etc.)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.3.0 | 2024-12-20 | Updated with v0.24 firmware analysis |
| | | - Zone/channel limits: 10 zones × 99 channels (990 total) |
| | | - Standby LED: Green LED blinks every 5 seconds (PC14) |
| | | - Core register sequences unchanged from v0.18 |
| | | - CTCSS decoding bug fixes noted |
| 0.2.0 | 2024-12-20 | Added confirmed register values from Ghidra analysis |
| | | - BK4829: Complete 50+ register init sequence from FUN_08007f04 |
| | | - SPI Flash: Erase commands 0x20/0x52/0xD8/0xC7 confirmed |
| | | - Encoder: Quadrature state machine from FUN_0800e2e0 |
| | | - LCD: Command staging buffer at 0x2000A1D0 |
| 0.1.0 | 2024-12-20 | Initial clean-room skeleton |


