# LCD Display Driver Documentation (`src/drivers/lcd.c`)

**AI Reasoning:** This document explains the AI's reasoning for the LCD driver implementation.

> **⚠️ This is AI-generated content - verify against hardware before use**

---

## Overview

The LCD driver controls the 320×240 TFT display using an 8080-style parallel interface.

---

## Why 8080 Parallel Interface?

**AI Reasoning:**
- OEM firmware uses GPIO toggles for data bus (PD8-PD15 observed)
- Control pins (WR, CS, RS, RST) all on GPIOD
- No hardware LCD controller peripheral observed
- 8080 interface is common for small TFT displays

**Evidence:**
- FUN_080271c0 / FUN_08027220: Write command/data functions
- PD8-PD15 used as 8-bit data bus
- WR strobe toggled in software loops

**Confidence:** **HIGH** - Confirmed from OEM firmware analysis

---

## Frame Buffer Location (0x20000BD0)

### Why This Address?

**AI Reasoning:**
- Frame buffer address found in OEM firmware: DAT_08015790 → 0x20000BD0
- Size: 320 × 240 × 2 bytes (RGB565) = 153,600 bytes
- Located in SRAM (0x20000000 base)
- Leaves room for stack above this location

**Memory Layout:**
```
0x20000000 - Start of SRAM
0x20000BD0 - Frame buffer (153.6 KB)
0x20018000 - Top of RAM / Stack
```

**Confidence:** **HIGH** - Directly from OEM firmware memory map

**Potential Issues:**
- Frame buffer may overlap with stack if stack grows too large
- Location must be preserved in linker script

---

## 8080 Interface Implementation

### Why This Pin Mapping?

**AI Reasoning:**
- Data bus: PD8-PD15 (8 pins, 8-bit transfers)
- WR: PD0 (write strobe)
- CS: PD1 (chip select)
- RST: PD2 (reset)
- RS (D/C): PD3 (command/data select)

**Implementation:**
```c
LCD_WRITE_DATA_BUS(d) - Writes byte to PD8-PD15
LCD_RS_LOW() - Command mode
LCD_RS_HIGH() - Data mode
lcd_strobe_wr() - Toggles WR to clock data
```

**Confidence:** **HIGH** - Pin assignments confirmed from OEM firmware register writes

---

## MIPI-DCS Commands

### Why These Commands?

**AI Reasoning:**
- Command sequences match ILI9341/ST7789 controllers (common TFT controllers)
- Window commands: 0x2A (column), 0x2B (row), 0x2C (RAM write)
- Typical display controller command set

**Commands Used:**
- 0x2A: Set column address
- 0x2B: Set row address  
- 0x2C: Memory write (start pixel transfer)

**Confidence:** **MEDIUM** - Commands inferred from OEM firmware, controller ID not verified

**Potential Issues:**
- Controller may not be ILI9341/ST7789 - could be different model
- Command sequences may need adjustment
- Initialization sequence is guessed (not fully extracted from OEM)

---

## DMA Transfer (Frame Buffer Flush)

### Why DMA?

**AI Reasoning:**
- FUN_080037b0 in OEM firmware uses DMA2 (base 0x40020430)
- Streaming 153.6 KB frame buffer would be slow via software loops
- DMA allows CPU to do other work while transferring

**Current Implementation:**
- Placeholder: Uses software loop (LCD_DrawImage)
- TODO: Implement DMA transfer for performance

**Confidence:** **HIGH** - DMA usage confirmed, but implementation incomplete

**Potential Issues:**
- DMA configuration may need tuning
- Transfer completion detection needed
- May need double-buffering to avoid tearing

---

## RGB565 Pixel Format

### Why This Format?

**AI Reasoning:**
- 2 bytes per pixel (320×240×2 = 153,600 bytes)
- Matches frame buffer size exactly
- Common embedded display format
- Balanced between color depth and memory usage

**Confidence:** **HIGH** - Format confirmed from buffer size calculation

---

## Command Staging Buffer (0x2000A1D0)

### Why This Buffer?

**AI Reasoning:**
- Observed in OEM firmware: DAT_08015410 → 0x2000A1D0
- Used for command packet building
- Allows building complex command sequences before sending

**Confidence:** **MEDIUM** - Address found in OEM firmware, purpose inferred

**Potential Issues:**
- Buffer size unknown
- May not be necessary for all operations

---

## Initialization Sequence

### Why This Sequence?

**AI Reasoning:**
- Initialization sequence is guessed based on typical ILI9341/ST7789 startup
- Not fully extracted from OEM firmware (too complex to reverse)
- Follows standard TFT display initialization pattern

**Typical Sequence:**
1. Hardware reset (RST pin)
2. Software reset command (0x01)
3. Exit sleep (0x11)
4. Display on (0x29)
5. Normal mode (0x13)
6. Set pixel format
7. Set display orientation

**Confidence:** **LOW** - Initialization sequence is guessed, needs hardware verification

**Potential Issues:**
- Sequence may be completely wrong
- Display may not initialize at all
- Orientation may be incorrect
- Color format may need adjustment

---

## Key AI Assumptions

1. **Frame Buffer Address**: Directly from OEM firmware (HIGH confidence)
2. **Pin Assignments**: Confirmed from register writes (HIGH confidence)
3. **Interface Type**: 8080 parallel confirmed (HIGH confidence)
4. **Controller Type**: Guessed ILI9341/ST7789 (LOW confidence)
5. **Initialization**: Guessed from typical patterns (LOW confidence)
6. **DMA Usage**: Confirmed but not implemented (MEDIUM confidence)

---

## Verification Needed

- [ ] Read display ID register (0x04) to identify actual controller
- [ ] Verify frame buffer location doesn't conflict with stack/heap
- [ ] Test pixel writes actually appear on display
- [ ] Verify color format (RGB565 vs RGB888 vs other)
- [ ] Test display orientation (may be rotated)
- [ ] Implement and test DMA transfer
- [ ] Verify initialization sequence works
- [ ] Test backlight control (PC6 PWM)

---

## Data Sources

1. **OEM Firmware**: FUN_080271c0, FUN_08027220, FUN_080037b0, FUN_0801cb52
2. **Memory Map**: Frame buffer address from DAT_08015790
3. **Register Analysis**: GPIO register writes for pin assignments
4. **Pattern Matching**: ILI9341/ST7789 command sets (standard)

