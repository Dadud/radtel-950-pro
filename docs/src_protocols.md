# Protocol Layer Documentation (`src/protocols/`)

**AI Reasoning:** This document explains the AI's reasoning for protocol layer implementations.

> **⚠️ This is AI-generated content - verify against hardware before use**

---

## Overview

The protocol layer handles communication protocols: Bluetooth, GPS, and USB CDC.

---

## Bluetooth Protocol (`protocols/bluetooth.c`)

### Why This Implementation?

**AI Reasoning:**
- Bluetooth module connected via UART (USART1, PA9/PA10)
- 115200 baud rate (observed in Bluetooth_UART1_Init)
- AT command set (typical for serial Bluetooth modules)

**Hardware:**
- TX: PA9 (USART1)
- RX: PA10 (USART1)
- Baud: 115200 (confirmed from OEM firmware)

**Confidence:** **HIGH** - UART and baud rate confirmed

**AI Assumptions:**
- AT command set is guessed (not extracted from OEM firmware)
- Module type unknown (HC-05, BC417, etc.)
- Pairing/connection logic guessed

**Potential Issues:**
- AT commands may be completely different
- Connection process may not work
- Baud rate may need adjustment

---

## GPS Protocol (`protocols/gps.c`)

### Why NMEA Parsing?

**AI Reasoning:**
- GPS modules use standard NMEA 0183 format
- USART3 configured for 9600 baud (observed in OEM firmware)
- NMEA sentences are public standard (no reverse engineering needed)

**NMEA Sentences:**
- `$GPRMC`: Recommended minimum specific GPS data
- `$GPGGA`: Global positioning system fix data
- `$GPGSV`: GPS satellite data

**Confidence:** **HIGH** - NMEA is standard format, baud rate confirmed

**Potential Issues:**
- GPS module may use different baud rate
- May need different sentence types
- Parsing may have bugs

---

## USB CDC Protocol (`protocols/cdc_protocol.c`)

### Why Binary Protocol?

**AI Reasoning:**
- OEM bootloader uses binary protocol over USB CDC
- Frame format: `0xAA [cmd] [len] [data...] [crc16] 0x55`
- Captured from USB packet analysis
- Used for firmware updates and memory access

**Protocol Details:**
- Start byte: 0xAA
- End byte: 0x55
- CRC-16 XMODEM for validation
- Commands: 0x42 (binary mode), 0x0A (version), etc.

**Confidence:** **HIGH** - Protocol captured from USB analysis

**Potential Issues:**
- Some commands may be missing
- Error handling may be incomplete
- Signature checks may prevent flashing

---

## Key AI Assumptions

1. **Bluetooth AT Commands**: Completely guessed (LOW confidence)
2. **GPS NMEA**: Standard format (HIGH confidence)
3. **USB CDC Protocol**: Captured from USB analysis (HIGH confidence)

---

## Verification Needed

- [ ] Test Bluetooth AT commands actually work
- [ ] Verify GPS NMEA parsing extracts correct data
- [ ] Test USB CDC protocol with OEM bootloader
- [ ] Verify baud rates are correct
- [ ] Test connection establishment
- [ ] Verify error handling

---

## Data Sources

1. **OEM Firmware**: UART initialization functions, baud rates
2. **USB Captures**: CDC protocol frame format
3. **Standards**: NMEA 0183 (public standard)

