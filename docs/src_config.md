# Configuration Layer Documentation (`src/config/`)

**AI Reasoning:** This document explains the AI's reasoning for the configuration layer implementation.

> **⚠️ This is AI-generated content - verify against hardware before use**

---

## Overview

The configuration layer manages settings storage and retrieval from non-volatile memory.

---

## Settings Structure

### Why This Layout?

**AI Reasoning:**
- Settings stored in SPI flash (non-volatile)
- Structure inferred from OEM firmware memory accesses
- Offset +0x1D used for TNC type (observed in KISS TNC analysis)

**Settings Location:**
- Base address: 0x2000A83C (DAT_08014150 in OEM firmware)
- Stored in SPI flash during save operation
- Loaded to RAM at startup

**Known Offsets:**
- +0x03: TX Delay
- +0x11: APRS Enable
- +0x1D: TNC Type (0=MacAPRS, 1=WinAPRS, 3=KISS)
- +0x1E, +0x1F: Unknown

**Confidence:** **MEDIUM** - Some offsets confirmed, structure guessed

**Potential Issues:**
- Structure may be completely different
- Unknown fields may be important
- Save/load logic may not work

---

## EEPROM Interface

### Why EEPROM Module?

**AI Reasoning:**
- Some settings may be in internal EEPROM (if present)
- Separate from SPI flash storage
- May store calibration data

**Confidence:** **LOW** - EEPROM existence not confirmed

**Potential Issues:**
- MCU may not have EEPROM
- EEPROM may not be used at all
- Settings may all be in SPI flash

---

## Key AI Assumptions

1. **Settings Structure**: Partially confirmed, mostly guessed (MEDIUM confidence)
2. **Storage Location**: SPI flash inferred (MEDIUM confidence)
3. **EEPROM**: Existence unknown (LOW confidence)

---

## Verification Needed

- [ ] Reverse engineer complete settings structure
- [ ] Verify settings save/load actually works
- [ ] Identify all setting fields
- [ ] Test calibration data storage
- [ ] Verify EEPROM exists and is used

---

## Data Sources

1. **OEM Firmware**: Settings structure offsets (DAT_08014150)
2. **Memory Access Analysis**: Observed offsets for known settings
3. **KISS TNC Analysis**: TNC type offset (+0x1D) confirmed

