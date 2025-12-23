# BK4829 RF Transceiver Driver Documentation

**AI Reasoning:** This document explains the AI's reasoning for the BK4829 driver implementation.

> **⚠️ This is AI-generated content - verify against hardware before use**

---

## Overview

The BK4829 driver controls the dual RF transceivers in the RT-950 Pro. This is one of the most critical drivers as it handles all RF functionality.

**Files:**
- `src/drivers/bk4829.h` - Register definitions and API
- `src/drivers/bk4829.c` - Implementation

---

## Why Two BK4829 Instances?

**AI Reasoning:**
- Schematic shows two BK4829 chips (U11 and U12)
- One for VHF band, one for UHF band (typical dual-band radio design)
- Shared SPI bus but separate chip selects (PE8 for U11, PE15 for U12)

**Evidence:**
- Schematic: `docs/RT950Pro.pdf` shows U11 and U12 both labeled BK4829
- Pinout: PE8 = SEN1, PE15 = SEN2 (separate chip selects)
- OEM firmware: Separate initialization sequences observed

**Confidence:** **HIGH** - Confirmed from schematic

---

## SPI Interface Implementation

### Why 3-Wire SPI?

**AI Reasoning:**
- BK4829 datasheet confirms 3-wire SPI: SCK, SCN (CS), SDATA
- SCK max frequency: 8 MHz (from datasheet)
- Data latched on SCK rising edge, output on falling edge

**Implementation:**
- Hardware SPI1 for BK4829 #1 (VHF) - higher performance
- Software SPI (bit-bang) for BK4829 #2 (UHF) - flexibility when hardware SPI busy

**Confidence:** **HIGH** - Confirmed from BK4829 datasheet (DS-BK4829-E01 V1.0)

**Potential Issues:**
- Software SPI timing may not meet 8 MHz requirement
- Clock phase/polarity may need adjustment

---

## Register Definitions

### Why These Register Addresses?

**AI Reasoning:**
- Register addresses (0x00-0x7F) extracted from OEM firmware analysis
- Function FUN_08007f04 writes to specific register addresses
- Register values captured from Ghidra disassembly

**Example from OEM firmware:**
```
FUN_08007f04 writes:
- Register 0x37: 0x9D1F (RF filter)
- Register 0x13: 0x03DF (AGC)
- Register 0x49: 0x2AB2 (Audio)
```

**Confidence:** **HIGH** - Register values directly extracted from OEM firmware

---

## Initialization Sequence

### Why This Order?

**AI Reasoning:**
- Initialization sequence extracted from FUN_08007f04 (Ghidra analysis)
- 50+ register writes in specific order
- Soft reset first (register 0x00 = 0x8000, then 0x0000)
- AGC table programming (16 entries to register 0x09)
- Audio filter configuration
- RF filter settings

**Sequence:**
1. CS pin configuration
2. SPI initialization
3. Wait 100ms (power-up delay)
4. Soft reset
5. RF filter setup
6. AGC configuration
7. Audio settings
8. Enable controls

**Confidence:** **HIGH** - Directly from OEM firmware reverse engineering

**Potential Issues:**
- Timing delays may need adjustment (100ms wait may be too long/short)
- Some register values may be calibration-specific

---

## Frequency Calculation

### Why 26 MHz Crystal Reference?

**AI Reasoning:**
- **CORRECTED** from initial 12.8 MHz assumption
- BK4829 datasheet (DS-BK4829-E01 V1.0) confirms 26 MHz crystal
- Schematic shows CY1 = 26 MHz crystal
- Frequency calculation formula updated accordingly

**Frequency Formula:**
```
RX mode: f_locked = Ndiv × (fwanted - fIF)
TX mode: f_locked = Ndiv × fwanted
```

**Current Implementation:**
- Simplified fractional-N calculation
- Assumes: Frequency ≈ (N + F/65536) × 26000000

**Confidence:** **MEDIUM** - Crystal frequency confirmed, but exact register programming formula requires full datasheet register map

**Potential Issues:**
- Simplified formula may not match actual BK4829 behavior
- Ndiv and fIF values unknown (full register map not in public datasheet)
- Frequency accuracy may be poor until proper formula is verified

---

## AGC Table (Register 0x09)

### Why These Values?

**AI Reasoning:**
- 16-entry AGC gain table observed in OEM firmware
- Written sequentially to register 0x09 with address bits (0x009, 0x109, 0x209, etc.)
- Values extracted directly from FUN_08007f04:

```
0x006F, 0x106B, 0x2067, 0x3062, 0x4050, 0x5047,
0x603A, 0x702C, 0x8041, 0x9037, 0xA025, 0xB017,
0xC0E4, 0xD0CB, 0xE0B5, 0xF09F
```

**Confidence:** **HIGH** - Directly captured from OEM firmware

**Potential Issues:**
- AGC table may be radio-specific (calibration)
- Values may need adjustment for different RF front-end configurations

---

## Power Control

### Why These Register Bits?

**AI Reasoning:**
- Register 0x3F appears to control enable states
- Bit 0x8000: RX enable (inferred)
- Bit 0x4000: TX enable (inferred)
- Bit 0x0100: Synthesizer enable (observed in frequency setting)

**TX/RX Switching:**
```c
if (enable_rx) {
    reg3f |= 0x8000;    // Enable RX
    reg3f &= ~0x4000;   // Disable TX
}
```

**Confidence:** **MEDIUM** - Inferred from observed register writes, may be incorrect

**Potential Issues:**
- Bit assignments may be wrong
- TX/RX switching timing may need adjustment
- PTT control may require additional register settings

---

## RSSI Reading

### Why This Formula?

**AI Reasoning:**
- RSSI register: 0x65 (observed in OEM firmware)
- Raw value read as 9-bit value (mask 0x01FF)
- Conversion formula guessed: `rssi_dbm = (raw_value & 0x01FF) - 220`

**Confidence:** **LOW** - Formula is completely guessed, needs hardware verification

**Potential Issues:**
- Conversion formula is likely incorrect
- Offset value (220) is arbitrary
- RSSI reading may not work at all

---

## CTCSS/DCS Configuration

### Why This Approach?

**AI Reasoning:**
- CTCSS frequency register: 0x51 (observed)
- CTCSS settings register: 0x52 (observed)
- DCS code register: 0x68 (observed)
- Conversion formula guessed: `reg_value = frequency * 20.64` (for CTCSS)

**Confidence:** **LOW** - Formula guessed, needs verification

**Potential Issues:**
- CTCSS frequency conversion may be completely wrong
- DCS encoding unknown
- Tone detection may not work

---

## Key AI Assumptions

1. **Initialization Sequence**: Directly from OEM firmware (HIGH confidence)
2. **Register Values**: Captured from reverse engineering (HIGH confidence)
3. **Frequency Calculation**: Simplified formula, needs verification (MEDIUM confidence)
4. **RSSI Formula**: Completely guessed (LOW confidence)
5. **CTCSS Formula**: Estimated (LOW confidence)
6. **Register Bit Meanings**: Partially inferred (MEDIUM confidence)

---

## Verification Needed

- [ ] Verify frequency setting accuracy with frequency counter
- [ ] Test SPI timing meets BK4829 requirements
- [ ] Confirm initialization sequence works (radio responds)
- [ ] Calibrate RSSI readings against known signal levels
- [ ] Test CTCSS encode/decode with actual tones
- [ ] Verify TX power levels match settings
- [ ] Test squelch operation
- [ ] Confirm TX/RX switching works correctly
- [ ] Measure actual RF output frequencies

---

## Data Sources

1. **OEM Firmware**: FUN_08007f04 - Initialization sequence
2. **BK4829 Datasheet**: DS-BK4829-E01 V1.0 - Crystal frequency, SPI interface
3. **Schematic**: RT950Pro.pdf - Pin assignments, chip count
4. **Ghidra Analysis**: Register addresses and values
5. **USB Captures**: (if any RF-related commands exist)

