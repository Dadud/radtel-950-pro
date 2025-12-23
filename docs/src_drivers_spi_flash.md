# SPI Flash Driver Documentation (`src/drivers/spi_flash.c`)

**AI Reasoning:** This document explains the AI's reasoning for the SPI Flash driver implementation.

> **⚠️ This is AI-generated content - verify against hardware before use**

---

## Overview

The SPI Flash driver handles external 16MB SPI NOR flash memory operations for channel storage and settings.

---

## Why SPI Flash?

**AI Reasoning:**
- External flash needed for channel memory (1000 channels × 64 bytes = 64KB minimum)
- Settings storage requires non-volatile memory
- OEM firmware uses SPI flash (observed erase/write commands)
- Hardware SPI interface on PB12-15

**Evidence:**
- FUN_080210c0: 4KB sector erase (command 0x20)
- FUN_08020f80: 32KB block erase (command 0x52)
- FUN_08020ff0: 64KB block erase (command 0xD8)
- FUN_08021180: Read data (command 0x03)

**Confidence:** **HIGH** - Flash operations confirmed from OEM firmware

---

## SPI Flash Commands

### Why These Commands?

**AI Reasoning:**
- Standard SPI NOR flash command set (JEDEC standard)
- Commands extracted from OEM firmware function analysis:

| Function | Command | Operation |
|----------|---------|-----------|
| FUN_080210c0 | 0x20 | 4KB sector erase |
| FUN_08020f80 | 0x52 | 32KB block erase |
| FUN_08020ff0 | 0xD8 | 64KB block erase |
| FUN_08021064 | 0xC7 | Chip erase |
| FUN_08021180 | 0x03 | Read data |
| FUN_08021314 | 0x02 | Page program (write) |

**Confidence:** **HIGH** - Commands directly from OEM firmware

---

## Flash Layout (Inferred)

### Why This Layout?

**AI Reasoning:**
- Channel memory: 0x01000 - 0x11000 (64KB, 1000 channels)
- VFO settings: 0x11000 - 0x12000 (4KB)
- Radio settings: 0x12000 - 0x13000 (4KB)
- Calibration: 0x13000 - 0x14000 (4KB)

**Assumptions:**
- Channel size: 64 bytes (typical for radio channel data)
- Settings blocks: 4KB each (power of 2, common size)
- Reserved area: 0x00000 - 0x01000 (bootloader/meta data?)

**Confidence:** **LOW** - Layout is completely guessed, needs verification

**Potential Issues:**
- Layout may be completely different
- Channel size may not be 64 bytes
- Settings may be stored elsewhere
- Calibration data format unknown

---

## Erase Timeout Handling

### Why This Timeout Value?

**AI Reasoning:**
- Timeout value observed in OEM firmware: -0x15A0 = 5536 iterations
- Flash erase operations can take 10s-100s of milliseconds
- Polling on status register (command 0x05) until ready

**Implementation:**
```c
#define ERASE_TIMEOUT_LOOPS  5536
while (loops-- > 0) {
    if (SPI_Flash_ReadStatus() & 0x01 == 0) break;  // Not busy
    HAL_DelayUs(ERASE_POLL_DELAY_US);
}
```

**Confidence:** **HIGH** - Timeout value from OEM firmware

---

## Write Protection

### Why Write Enable Command?

**AI Reasoning:**
- Standard SPI flash requires WREN (0x06) before write/erase
- Prevents accidental corruption
- Write protect bits may be set in flash

**Sequence:**
1. Write Enable (0x06)
2. Erase/Program command
3. Poll status until complete

**Confidence:** **HIGH** - Standard SPI flash behavior

---

## Software SPI Implementation

### Why Software SPI?

**AI Reasoning:**
- Hardware SPI1 may be used for BK4829
- Flash uses separate SPI bus (PB12-15)
- Software SPI gives flexibility
- Timing requirements less strict than RF transceiver

**Confidence:** **MEDIUM** - Software SPI observed, but hardware SPI might also work

**Potential Issues:**
- Software SPI may be too slow for large operations
- Timing may not meet flash requirements

---

## Key AI Assumptions

1. **Flash Commands**: Directly from OEM firmware (HIGH confidence)
2. **Erase Sizes**: 4K/32K/64K confirmed (HIGH confidence)
3. **Memory Layout**: Completely guessed (LOW confidence)
4. **Channel Format**: Assumed 64 bytes (LOW confidence)
5. **SPI Interface**: Software SPI inferred (MEDIUM confidence)

---

## Verification Needed

- [ ] Identify actual flash chip model (read JEDEC ID)
- [ ] Verify erase block sizes match flash chip
- [ ] Test actual flash layout (where are channels stored?)
- [ ] Verify channel data format (size and structure)
- [ ] Test write/read operations actually work
- [ ] Confirm SPI timing meets flash requirements
- [ ] Verify settings storage location
- [ ] Test calibration data access

---

## Data Sources

1. **OEM Firmware**: FUN_080210c0, FUN_08020f80, FUN_08020ff0, FUN_08021180
2. **Standard SPI Flash**: JEDEC command set (public standard)
3. **Memory Analysis**: Flash layout guessed from typical patterns

