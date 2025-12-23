# Rotary Encoder Driver Documentation (`src/drivers/encoder.c`)

**AI Reasoning:** This document explains the AI's reasoning for the rotary encoder implementation.

> **⚠️ This is AI-generated content - verify against hardware before use**

---

## Overview

The rotary encoder driver decodes quadrature signals from a mechanical rotary encoder for frequency/menu navigation.

---

## Quadrature Decoding

### Why State Machine Approach?

**AI Reasoning:**
- Rotary encoders produce quadrature signals (two phases, 90° offset)
- State machine detects direction based on phase sequence
- Debouncing required (mechanical encoders have switch bounce)

**Hardware:**
- Phase A: PB4 (mask 0x10 in OEM firmware)
- Phase B: PB5 (mask 0x20 in OEM firmware)

**Evidence:**
- FUN_0800e2e0: Encoder handler function in OEM firmware
- State machine logic observed in disassembly
- Debounce delay: 200 ticks (pbVar1[4] = 200)

**Confidence:** **HIGH** - Pins and debounce confirmed from OEM firmware

---

## State Machine Logic

### Why These States?

**AI Reasoning:**
- **IDLE**: Waiting for first phase transition
- **PHASE_A**: Phase A changed first (determines direction)
- **PHASE_B**: Phase B changed first (determines opposite direction)

**Quadrature Pattern:**
```
CW:  A=0,B=0 → A=1,B=0 → A=1,B=1 → A=0,B=1 → A=0,B=0
CCW: A=0,B=0 → A=0,B=1 → A=1,B=1 → A=1,B=0 → A=0,B=0
```

**AI Reasoning:**
- Direction determined by which phase changes first
- Valid transitions only (skip invalid states due to noise/bounce)
- Debounce timer prevents false triggers

**Confidence:** **HIGH** - Logic extracted from FUN_0800e2e0 disassembly

---

## Debouncing

### Why 200 Ticks?

**AI Reasoning:**
- Value directly from OEM firmware: pbVar1[4] = 200
- Assuming 1ms tick rate: 200ms debounce
- Prevents switch bounce from causing multiple events

**Implementation:**
- On transition, start debounce timer
- Only accept new transition after debounce expires
- Ignore transitions during debounce period

**Confidence:** **HIGH** - Value from OEM firmware

**Potential Issues:**
- 200ms may be too long (slow response)
- May need shorter debounce for rapid rotation

---

## Direction Codes

### Why 0x14 (CW) and 0x16 (CCW)?

**AI Reasoning:**
- Event codes observed in OEM firmware
- 0x14 generated for clockwise rotation
- 0x16 generated for counter-clockwise rotation
- These are passed to UI/menu system

**Confidence:** **HIGH** - Event codes from OEM firmware

---

## Acceleration Detection

### Why Acceleration?

**AI Reasoning:**
- Allows rapid scrolling through frequencies/menus
- Common feature in embedded UI systems
- Speed calculated from time between events

**Implementation:**
- Track time between encoder events
- Faster rotation = higher acceleration multiplier
- Applied to step size (e.g., 10 kHz → 1 MHz per click)

**Confidence:** **MEDIUM** - Feature inferred, specific algorithm guessed

**Potential Issues:**
- Acceleration algorithm may not match OEM behavior
- Threshold values are guessed
- May need tuning for good UX

---

## Position Tracking

### Why 32-bit Signed Integer?

**AI Reasoning:**
- Allows large accumulated position (millions of steps)
- Signed allows negative values (backwards rotation)
- 32-bit sufficient for any practical use case

**API:**
```c
int32_t Encoder_GetPosition(void);
int32_t Encoder_GetDelta(void);  // Since last read
```

**Confidence:** **HIGH** - Standard approach for encoder position tracking

---

## Key AI Assumptions

1. **Pins**: Confirmed PB4/PB5 from OEM firmware (HIGH confidence)
2. **State Machine**: Extracted from disassembly (HIGH confidence)
3. **Debounce**: 200 ticks from OEM firmware (HIGH confidence)
4. **Event Codes**: 0x14/0x16 confirmed (HIGH confidence)
5. **Acceleration**: Algorithm guessed (LOW confidence)

---

## Verification Needed

- [ ] Test encoder actually produces expected quadrature signals
- [ ] Verify debounce time feels right (not too slow/fast)
- [ ] Test rapid rotation (acceleration detection)
- [ ] Confirm direction is correct (CW increases, CCW decreases)
- [ ] Test with noisy encoder (switch bounce handling)
- [ ] Verify event codes match OEM behavior

---

## Data Sources

1. **OEM Firmware**: FUN_0800e2e0 - Encoder handler function
2. **Register Analysis**: GPIOB pin assignments (PB4/PB5)
3. **Standard Patterns**: Common quadrature decoding algorithms

