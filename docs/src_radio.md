# Radio Layer Documentation (`src/radio/`)

**AI Reasoning:** This document explains the AI's reasoning for the radio layer implementation.

> **⚠️ This is AI-generated content - verify against hardware before use**

---

## Overview

The radio layer provides high-level radio functionality: VFO control, channel management, CTCSS/DCS, and scanning.

---

## VFO (Variable Frequency Oscillator) Control

### Why Separate VFO Module?

**AI Reasoning:**
- Dual-band radio needs separate VFOs for each band
- VFO stores current frequency, step size, mode
- Allows quick frequency entry and adjustment
- Standard radio firmware pattern

**Structure:**
```c
typedef struct {
    uint32_t frequency_hz;      // Current frequency
    uint8_t step_size_khz;      // Tuning step (5, 6.25, 10, 12.5, 25 kHz)
    BK4829_Modulation_t mode;   // FM, AM, etc.
    uint8_t squelch_level;      // Squelch threshold
} VFO_Config_t;
```

**AI Reasoning:**
- Frequency in Hz provides precision
- Step sizes match common amateur radio bands
- Structure allows per-band configuration

**Confidence:** **MEDIUM** - Structure guessed from typical radio firmware patterns

---

## Channel Memory

### Why Channel Structure?

**AI Reasoning:**
- Radio stores up to 1000 channels (typical for mobile radios)
- Each channel stores frequency, CTCSS, name, etc.
- Stored in SPI flash (non-volatile)

**Assumed Channel Format:**
```c
typedef struct {
    uint32_t frequency_hz;
    uint16_t ctcss_freq;
    uint8_t tx_power;
    uint8_t bandwidth;
    char name[16];
    // ... more fields
} Channel_t;
```

**Confidence:** **LOW** - Format completely guessed, needs reverse engineering

**Potential Issues:**
- Channel structure may be completely different
- Size may not be 64 bytes
- Field order may be different
- Some fields may not exist

---

## CTCSS (Continuous Tone Coded Squelch System)

### Why This Implementation?

**AI Reasoning:**
- Standard 38 CTCSS tones (67.0 Hz to 254.1 Hz)
- Tone table from OEM firmware: DAT_8000ca00
- BK4829 has hardware CTCSS encode/decode

**Frequency Encoding:**
- Store as tenths of Hz (e.g., 885 = 88.5 Hz)
- Conversion formula for BK4829 register: guessed

**Confidence:** **MEDIUM** - Tone list from OEM firmware, encoding guessed

**Potential Issues:**
- BK4829 register encoding formula may be wrong
- Tone generation may not work
- Detection threshold may need adjustment

---

## DCS (Digital Coded Squelch)

### Why This Approach?

**AI Reasoning:**
- DCS codes are standard 23/24-bit patterns
- BK4829 supports DCS (confirmed from datasheet)
- DCS codes stored as integers (e.g., 023, 754)

**Confidence:** **LOW** - DCS implementation mostly guessed

**Potential Issues:**
- DCS encoding/decoding may not work
- Code format may be different
- Inverted DCS codes (N codes) may need special handling

---

## Scanning

### Why These Scan Modes?

**AI Reasoning:**
- **Frequency Scan**: Step through frequency range
- **Channel Scan**: Step through stored channels
- **Memory Scan**: Scan specific channel groups
- **Priority Scan**: Monitor priority channel while scanning

**Typical Radio Features:**
- Scan delay (dwell time on each frequency)
- Resume conditions (timeout, carrier, squelch)
- Skip locked-out channels

**Confidence:** **LOW** - Scan modes guessed from typical radio behavior

**Potential Issues:**
- Scan algorithm may not match OEM behavior
- Priority scan logic unknown
- Resume conditions may be different

---

## Key AI Assumptions

1. **VFO Structure**: Guessed from typical patterns (MEDIUM confidence)
2. **Channel Format**: Completely guessed (LOW confidence)
3. **CTCSS Tones**: List from OEM firmware (HIGH confidence), encoding guessed (LOW)
4. **Scan Modes**: Guessed from typical radios (LOW confidence)

---

## Verification Needed

- [ ] Reverse engineer actual channel memory format
- [ ] Test VFO frequency setting accuracy
- [ ] Verify CTCSS encode/decode works
- [ ] Test DCS functionality
- [ ] Verify scan modes match OEM behavior
- [ ] Test channel save/load from flash
- [ ] Verify step size behavior
- [ ] Test dual-band VFO switching

---

## Data Sources

1. **OEM Firmware**: CTCSS tone table (DAT_8000ca00)
2. **BK4829 Datasheet**: CTCSS/DCS capabilities
3. **Pattern Matching**: Typical mobile radio firmware structures

