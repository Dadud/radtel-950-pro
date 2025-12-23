# Branch Comparison: master vs old-master-backup

## Overview

This document compares the **master** branch (current open-source firmware) with the **old-master-backup** branch.

## Key Difference

The **old-master-backup** branch (older state) contains:
1. **Header-only API definitions** - Minimal implementations, mostly headers
2. **Massive reference project** - Entire Artery SDK, FreeRTOS, LWIP libraries, and examples (6,400+ files)
3. **KISS TNC analysis** - Bug reports and firmware analysis
4. **BK4829 datasheet findings** - Applied corrections

The **master** branch (current state) contains:
1. **Full source code implementations** - Complete driver and HAL implementations (~8,300+ lines of code)
2. **Clean structure** - Focused on open-source firmware project (without reference SDK)
3. **Documentation** - KISS TNC analysis, bug reports, datasheet findings
4. **AI disclaimer warnings** - Additional commit (20e9b1e) with disclaimers

## Source Code Changes (src/ directory)

### Files Added in master (not in old-master-backup):

#### Configuration
- `src/config/eeprom.c` - EEPROM implementation (224 lines)
- `src/config/eeprom.h` - EEPROM header

#### Drivers (Full implementations removed)
- `src/drivers/audio.c` - Audio driver (366 lines)
- `src/drivers/keypad.c` - Keypad driver (290 lines)
- `src/drivers/power.c` - Power management (308 lines)
- `src/drivers/si4732.c` - SI4732 FM receiver (412 lines)

#### HAL Layer (Full implementations removed)
- `src/hal/adc.c` - ADC implementation (200 lines)
- `src/hal/adc.h` - ADC header
- `src/hal/dac.c` - DAC implementation (170 lines)
- `src/hal/dac.h` - DAC header
- `src/hal/dma.c` - DMA implementation (240 lines)
- `src/hal/dma.h` - DMA header
- `src/hal/i2c.c` - I2C implementation (452 lines)
- `src/hal/i2c.h` - I2C header
- `src/hal/spi.c` - SPI implementation (273 lines)
- `src/hal/timer.c` - Timer implementation (284 lines)
- `src/hal/timer.h` - Timer header
- `src/hal/uart.c` - UART implementation (197 lines)
- `src/hal/uart.h` - UART header

#### Protocols (Full implementations removed)
- `src/protocols/bluetooth.c` - Bluetooth implementation (182 lines)
- `src/protocols/cdc_protocol.c` - CDC protocol implementation (173 lines)
- `src/protocols/gps.c` - GPS implementation (281 lines)

#### Radio (Full implementations removed)
- `src/radio/channel.c` - Channel management (256 lines)
- `src/radio/channel.h` - Channel header
- `src/radio/ctcss.c` - CTCSS implementation (221 lines)
- `src/radio/ctcss.h` - CTCSS header
- `src/radio/radio.c` - Radio control (402 lines)
- `src/radio/scan.c` - Scanning (187 lines)
- `src/radio/scan.h` - Scan header
- `src/radio/vfo.c` - VFO control (201 lines)
- `src/radio/vfo.h` - VFO header

#### UI (Full implementations removed)
- `src/ui/display.c` - Display driver (290 lines)
- `src/ui/fonts.c` - Font rendering (271 lines)
- `src/ui/fonts.h` - Font header
- `src/ui/menu.c` - Menu system (268 lines)
- `src/ui/ui.c` - UI implementation (276 lines)
- `src/ui/ui.h` - UI header

### Files Modified (Headers kept, implementations removed):

Headers retained in master with expanded API definitions:
- `src/config/settings.h` - Settings structure definitions
- `src/protocols/bluetooth.h` - Bluetooth API
- `src/protocols/cdc_protocol.h` - CDC protocol API
- `src/protocols/gps.h` - GPS API
- `src/ui/display.h` - Display API
- `src/ui/menu.h` - Menu API

### Summary Statistics

**old-master-backup branch** (older):
- Header-only APIs: Minimal structure
- API definitions primarily
- Reference SDK included (6,400+ files)

**master branch** (current):
- Complete implementations: ~8,335 lines of source code ADDED
- Full driver stack implementations
- Working firmware code
- Reference SDK removed (cleaner structure)

**Net change**: +7,222 lines of source code added in master

## Additional Content in old-master-backup

### Reference Project (6,400+ files)
- Complete Artery AT32F403A/407 firmware library
- FreeRTOS middleware
- LWIP networking stack
- USB device class drivers
- Hundreds of example projects
- Build system configurations

### Documentation
- KISS TNC analysis and bug reports
- Firmware reverse engineering notes
- Bootloader protocol documentation
- Firmware comparison guides

## Rationale

The **master** branch represents **active development**:
1. Full implementations added based on reverse engineering
2. Complete driver stack for actual firmware
3. Reference SDK removed for cleaner structure
4. Active development branch

The **old-master-backup** branch represents an **earlier state**:
1. Header-only structure (API definitions)
2. Reference SDK included for hardware understanding
3. KISS TNC analysis and datasheet findings
4. Historical snapshot before full implementation

## Recommendation

- Use **master** for: Active firmware development with full implementations
- Use **old-master-backup** for: Reference to earlier API-only structure, reference SDK access

---

**Note**: The master branch has one additional commit (20e9b1e) adding AI-generated content disclaimers that old-master-backup doesn't have.

