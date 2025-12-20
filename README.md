# Radtel RT-950 Pro Open Firmware Project

A clean-room firmware re-implementation for the Radtel RT-950 Pro dual-band mobile radio.

## ⚠️ IMPORTANT DISCLAIMER

**This is experimental firmware under active development.**

- NO proprietary source code is included
- All behavior is INFERRED from binary analysis
- Flashing custom firmware may void your warranty and could damage your radio
- **Always backup your original firmware before flashing**
- Use at your own risk

---

## Project Overview

This repository collects reverse engineering artifacts, documentation, and a buildable clean-room firmware skeleton for the Radtel RT-950 Pro. The goal is to enable an open, hackable replacement firmware for the amateur radio community.

### What's Included

| Directory | Contents |
|-----------|----------|
| `src/` | **Clean-room firmware source tree** (buildable skeleton) |
| `build/` | CMake build system configuration |
| `docs/` | Hardware documentation, pinout tables, function catalogue |
| `firmware/` | Decrypted binaries, Ghidra projects, USB captures |
| `reference project/` | Vendor AT32 BSP reference project |
| `artery_cortex-m4/` | AT32 SDK and peripheral libraries |
| `Datasheets/` | Component datasheets |

---

## Hardware Specifications

### Target MCU

| Parameter | Value | Status |
|-----------|-------|--------|
| MCU | Artery AT32F403ARGT7 | **CONFIRMED** |
| Core | ARM Cortex-M4F @ 240MHz | **CONFIRMED** |
| Flash | 1MB internal | **CONFIRMED** |
| RAM | 96KB SRAM | **CONFIRMED** |
| External Flash | 16MB SPI NOR (SPIM) | **CONFIRMED** |

### RF Front-End

| Component | Interface | Status |
|-----------|-----------|--------|
| BK4819 #1 (VHF/UHF) | Hardware SPI1, CS on PE8 | **CONFIRMED** |
| BK4819 #2 (VHF/UHF) | Software SPI on GPIOE (SCK=PE10, SDA=PE11, CS=PE15) | **CONFIRMED** |
| SI4732 FM/AM Receiver | Bit-banged I2C (SCK=PB6, SDA=PB7) | **HIGH confidence** |

### Display

| Parameter | Value | Status |
|-----------|-------|--------|
| Resolution | 320×240 pixels | **CONFIRMED** |
| Interface | 8080 parallel (8-bit) on PD8-PD15 | **CONFIRMED** |
| Pixel Format | RGB565 | **CONFIRMED** |
| Controller | ILI93xx / ST77xx class (MIPI-DCS commands) | **INFERRED** |
| Frame Buffer | 0x20000BD0 (153.6KB) | **CONFIRMED** |

### Peripherals

| Function | Pins | Interface | Status |
|----------|------|-----------|--------|
| GPS | PB10 RX, PB11 TX | USART3 @ 9600 baud NMEA | **CONFIRMED** |
| Bluetooth | PA9 TX, PA10 RX | USART1 @ 115200 baud | **CONFIRMED** |
| Keypad | PC0-3 rows, PD4-7 columns | Matrix scan | **CONFIRMED** |
| Rotary Encoder | PB4 (A), PB5 (B) | Quadrature | **CONFIRMED** |
| PTT | PC7 detect, PE3 output, PE4 PA enable | GPIO | **CONFIRMED** |
| LEDs | PC13 (red), PC14 (green) | GPIO | **CONFIRMED** |
| Audio DAC | PA4 (tone/CTCSS output) | DAC1 + DMA2 | **CONFIRMED** |
| Battery ADC | PA1 | ADC2 channel 1 | **CONFIRMED** |
| SPI Flash | PB12-15 | Hardware SPI | **CONFIRMED** |
| LCD Backlight | PC6 | PWM capable | **CONFIRMED** |

### Complete Pinout

See [`docs/pinout.md`](docs/pinout.md) for the full GPIO mapping extracted from firmware analysis.

---

## Memory Map

| Address | Size | Description |
|---------|------|-------------|
| 0x08000000 | 1MB | Internal Flash |
| 0x08400000 | 16MB | External SPIM Flash |
| 0x20000000 | 96KB | SRAM |
| 0x20000BD0 | ~38KB | Display frame buffer |
| 0x20018000 | - | Top of stack (`_estack`) |

### External SPI Flash Layout (INFERRED)

| Offset | Size | Content |
|--------|------|---------|
| 0x00000 | 4KB | Reserved |
| 0x01000 | 64KB | Channel memory (0-999) |
| 0x11000 | 4KB | VFO settings |
| 0x12000 | 4KB | Radio settings |
| 0x13000 | 4KB | Calibration data |

---

## Building the Firmware

### Prerequisites

1. **ARM GCC Toolchain** (arm-none-eabi-gcc 10.x or later)
   ```bash
   # Ubuntu/Debian
   sudo apt install gcc-arm-none-eabi
   
   # Windows: Download from https://developer.arm.com/downloads/-/gnu-rm
   # macOS
   brew install arm-none-eabi-gcc
   ```

2. **CMake** (3.20 or later)
   ```bash
   sudo apt install cmake
   ```

3. **Make** or **Ninja**

### Build Instructions

```bash
# Enter project directory
cd radtel-950-pro

# Create build output directory
mkdir -p build/output
cd build/output

# Configure
cmake ../.. -DCMAKE_BUILD_TYPE=Release

# Build
make -j$(nproc)
# or: ninja

# Output files:
# - rt950pro_firmware.elf (for debugging)
# - rt950pro_firmware.bin (for flashing)
# - rt950pro_firmware.hex (Intel HEX format)
```

---

## Flashing

### ⚠️ BACKUP FIRST

```bash
python firmware/scripts/radtel_flash.py --port COM3 --read backup.bin
```

### Method 1: USB CDC (OEM Bootloader)

The OEM bootloader uses a binary protocol over USB CDC:
- Frame format: `0xAA [cmd] [len] [data...] [crc16] 0x55`
- CRC: CRC16/XMODEM
- See [`docs/bootloader.md`](docs/bootloader.md) for protocol details

```bash
python firmware/scripts/radtel_flash.py --port COM3 --raw build/output/rt950pro_firmware.bin
```

**Note**: The OEM bootloader may reject unsigned images. Signature bypass is undocumented.

### Method 2: SWD/JTAG

Using OpenOCD with ST-Link or J-Link:

```bash
openocd -f interface/stlink.cfg \
        -f target/stm32f4x.cfg \
        -c "program rt950pro_firmware.elf verify reset exit"
```

**SWD Pins**: SWDIO=PA13, SWCLK=PA14

---

## Project Status

### Completed ✅

- [x] MCU and memory map identification
- [x] Complete GPIO pinout mapping
- [x] Display interface analysis (8080 parallel, MIPI-DCS)
- [x] RF transceiver interface mapping (dual BK4819)
- [x] Audio/DAC subsystem analysis
- [x] Bootloader protocol documentation
- [x] Clean-room firmware skeleton with modular structure
- [x] **BK4819 initialization sequence** - 50+ registers from FUN_08007f04
- [x] **SPI Flash driver** - Erase/read/write with confirmed commands
- [x] **Rotary encoder driver** - Quadrature state machine from FUN_0800e2e0
- [x] **LCD driver** - 8080 bus protocol with confirmed addresses

### Drivers with Confirmed Register Values

| Driver | Source Function | Key Details |
|--------|-----------------|-------------|
| BK4819 RF | FUN_08007f04 | AGC table (16 entries), audio filters, squelch |
| SPI Flash | FUN_080210c0/f80/ff0 | 4K/32K/64K erase: 0x20/0x52/0xD8 |
| Encoder | FUN_0800e2e0 | Debounce=200, CW=0x14, CCW=0x16 |
| LCD | FUN_080271c0/27220 | Cmd buffer 0x2000A1D0, FB 0x20000BD0 |

### In Progress

- [ ] Keypad matrix scanning (pins confirmed, logic needed)
- [ ] Menu system framework
- [ ] Audio DAC/DMA setup

### TODO (Requires Hardware Validation)

- [ ] Verify LCD controller ID (read 0x04/0xD3)
- [ ] Confirm SI4732 I2C address (0x11 vs 0x63)
- [ ] Test GPS NMEA parsing with real module
- [ ] Verify battery voltage divider ratio
- [ ] RF calibration data format

---

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/pinout.md`](docs/pinout.md) | Complete GPIO pin assignments |
| [`docs/display.md`](docs/display.md) | LCD interface details and DMA usage |
| [`docs/audio_tones.md`](docs/audio_tones.md) | CTCSS/DCS tone generation, APRS/AFSK |
| [`docs/spi_flash.md`](docs/spi_flash.md) | External flash operations |
| [`docs/Function_Names.csv`](docs/Function_Names.csv) | Firmware function catalogue |
| [`firmware/README.md`](firmware/README.md) | Ghidra setup and binary files |
| [`src/README.md`](src/README.md) | Clean-room firmware documentation |

---

## Firmware Encryption

OEM firmware uses "FwCrypt" encryption:
- XOR-based with rotating key
- First 0x800 bytes are skipped (bootloader header)
- Decrypt/encrypt with: `python firmware/scripts/fwcrypt_io.py`

---

## Contributing

### Code Style

- C11 standard
- 4-space indentation
- Function names: `Module_Action()` (PascalCase)
- Variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- All hardware assumptions must be documented with confidence levels

### Hardware Verification Needed

If you have an RT-950 Pro and test equipment:
1. Logic analyzer traces are extremely valuable
2. Capture SPI/I2C traffic during device initialization
3. Measure voltage levels and timing
4. Document any discovered pin functions

### Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Test on real hardware if possible
4. Document confidence levels for any new hardware assumptions
5. Submit pull request with detailed description

---

## Fork Lineage & Credits

This repository is a fork with the following lineage:

```
JKI757/radtel-950-pro (original)
    └── nicsure/radtel-950-pro (reverse engineering work)
        └── Dadud/radtel-950-pro (this fork - clean-room firmware)
```

### Acknowledgments

- **[JKI757](https://github.com/JKI757/radtel-950-pro)** - Original repository and initial research
- **[nicsure](https://github.com/nicsure/radtel-950-pro)** - Extensive reverse engineering work, Ghidra analysis, and hardware documentation
- **Artery Technology** - AT32 SDK and peripheral libraries
- **Radtel** - Original hardware and OEM firmware
- The amateur radio reverse engineering community
- Contributors to related projects (Quansheng UV-K5 firmware, OpenRTX, etc.)

---

## Legal Notice

This project is a clean-room reverse engineering effort for **educational and interoperability purposes**.

- The original firmware is copyright Radtel
- The AT32 SDK is provided by Artery Technology
- This implementation contains NO proprietary code
- All behavior is inferred from binary analysis

**Amateur radio operators are responsible for ensuring their transmissions comply with applicable regulations.** This firmware provides no guarantee of regulatory compliance.

---

## License

This clean-room implementation is released under the **MIT License**.

```
MIT License

Copyright (c) 2024-2025 RT-950 Pro Open Firmware Contributors

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
