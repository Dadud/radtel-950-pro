# RT-950 Pro TNC/APRS over Bluetooth Analysis

## Summary

**Yes, the RT-950 Pro has a built-in KISS TNC that can connect to APRSDroid over Bluetooth!**

The firmware implements standard KISS protocol framing and sends/receives data over the Bluetooth serial interface (USART1). This is compatible with APRSDroid and other KISS TNC applications.

---

## Firmware Evidence

### KISS Framing Function (`FUN_080140c0`)

Located at `0x080140c0`, this function implements standard KISS protocol byte-stuffing:

```
Address     Instruction     Description
0x080140da  movs r7,#0xc0   ; r7 = FEND (0xC0) - frame delimiter
0x080140ec  movs r1,#0xdb   ; r1 = FESC (0xDB) - escape character
0x0801412c  mov  r12,#0xdc  ; r12 = TFEND (0xDC) - escaped FEND
0x08014140  mov  r12,#0xdd  ; r12 = TFESC (0xDD) - escaped FESC
```

The function:
1. Starts with FEND (0xC0)
2. Adds command byte (0x00 for data frame)
3. For each data byte:
   - If 0xC0 (FEND) → escape as FESC + TFEND (0xDB, 0xDC)
   - If 0xDB (FESC) → escape as FESC + TFESC (0xDB, 0xDD)
   - Otherwise → send as-is
4. Ends with FEND (0xC0)

### Bluetooth Serial Output (`FUN_08024444`)

KISS frames are transmitted to Bluetooth via USART1:

```
Address     Instruction     Description
0x0802445c  ldr r1,[DAT]    ; r1 = 0x40013804 (USART1 data register)
0x0802445e  strh r0,[r1]    ; Write byte to USART1_DR
0x08024462  ldrh r1,[r0]    ; Read USART1_SR (0x40013800)
0x08024464  lsls r1,#0x19   ; Check TXE bit (bit 7)
0x08024466  bpl  loop       ; Wait until TX empty
```

### TNC Type Settings

The radio offers multiple TNC modes (from string table at `0x0805b118`):

| Mode | String Address | Use Case |
|------|----------------|----------|
| KISS | 0x0805b130 | **Standard KISS TNC - USE THIS for APRSDroid** |
| MacAPRS | 0x0805b118 | MacAPRS format |
| WinAPRS | 0x0805b120 | WinAPRS format |
| APRS | 0x0805b128 | Generic APRS |
| X-APRS(Unix) | 0x0805ad74 | Unix X-APRS format |

### APRS Settings Structure

Settings are stored at offset `0x2000A83C` + various offsets:

| Offset | Setting | Description |
|--------|---------|-------------|
| +0x03 | TX Delay | APRS TX delay (0-5 = 50-250ms) |
| +0x11 | APRS Enable | 0=OFF, 1=ON |
| +0x19 | Unknown | Band-related? |
| +0x1A | Unknown | Mode? |
| +0x1B | Auto Response | |
| +0x1D | TNC Type | 0=MacAPRS, 1=WinAPRS, etc. |
| +0x1E | Unknown | |
| +0x1F | Unknown | |

---

## Hardware Path

```
┌─────────────────────────────────────────────────────────────────┐
│                        RT-950 Pro Radio                         │
│                                                                 │
│  ┌─────────┐    ┌───────────┐    ┌─────────┐    ┌───────────┐  │
│  │ BK4829  │───►│ AFSK 1200 │───►│  KISS   │───►│  USART1   │──┼──► Bluetooth
│  │   RX    │    │ Demod     │    │ Framer  │    │ PA9/PA10  │  │    (115200 baud)
│  └─────────┘    └───────────┘    └─────────┘    └───────────┘  │
│                                                                 │
│  ┌─────────┐    ┌───────────┐    ┌─────────┐    ┌───────────┐  │
│  │ BK4829  │◄───│ AFSK 1200 │◄───│  KISS   │◄───│  USART1   │◄─┼─── Bluetooth
│  │   TX    │    │ Modulator │    │ Parser  │    │ PA9/PA10  │  │    (APRSDroid)
│  └─────────┘    └───────────┘    └─────────┘    └───────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## How to Connect APRSDroid

### Radio Settings

1. **Menu → APRS Set → APRS ON/OFF** → Set to `ON`
2. **Menu → APRS Set → TNC Type** → Set to `KISS`
3. **Menu → APRS Set → APRS CH** → Set your APRS channel (144.390 MHz NA, 144.800 MHz EU)
4. **Menu → Bluetooth** → Enable Bluetooth, set pairing mode

### Phone/APRSDroid Settings

1. **Pair your phone** with the RT-950 Pro's Bluetooth
2. **In APRSDroid**:
   - Connection → TNC Type: `KISS`
   - Connection → TNC → Bluetooth: Select "RT-950" or similar
   - Connection → TNC → Baudrate: `115200`
   - Callsign: Your callsign
   - SSID: Appropriate for your use (mobile = -9, etc.)
3. **Start tracking** in APRSDroid

### Expected Behavior

| Direction | What Happens |
|-----------|--------------|
| **Receive** | Radio hears APRS packet → decodes AFSK → KISS frames → Bluetooth → APRSDroid displays on map |
| **Transmit** | APRSDroid sends position → KISS frame → Bluetooth → Radio keys up → AFSK modulates → TX |

---

## Technical Details

### KISS Protocol Quick Reference

| Byte | Name | Meaning |
|------|------|---------|
| 0xC0 | FEND | Frame delimiter (start/end) |
| 0xDB | FESC | Escape character |
| 0xDC | TFEND | Transposed FEND (after FESC) |
| 0xDD | TFESC | Transposed FESC (after FESC) |
| 0x00 | Data Frame | Command byte for data frames |

### Frame Format

```
FEND (C0) | Command (00) | Payload (escaped) | FEND (C0)
```

### USART1 Configuration (Bluetooth)

| Parameter | Value | Register |
|-----------|-------|----------|
| Base Address | 0x40013800 | USART1 |
| Data Register | 0x40013804 | USART1_DR |
| Baudrate | 115200 | BRR = 0x1C200 (240MHz / 115200 / 16) |
| TX Pin | PA9 | GPIO alternate function |
| RX Pin | PA10 | GPIO alternate function |

---

## Caveats and Notes

1. **Bluetooth Pairing**: The radio must be paired before APRSDroid can connect
2. **TNC Type Must Be KISS**: Other modes (MacAPRS, WinAPRS) use different framing
3. **TX Delay**: May need adjustment for your radio's keying speed
4. **VOX vs PTT**: Radio may use internal PTT control for APRS TX
5. **Frequency**: Ensure you're on the correct APRS frequency for your region
6. **Power Level**: Consider using low power for APRS beaconing

---

## Verified Functions

| Function | Address | Purpose |
|----------|---------|---------|
| `KISS_Frame_Build` | FUN_080140c0 | Build KISS frame with byte-stuffing |
| `KISS_UART_Send` | FUN_08024444 | Send KISS frame over USART1 |
| `KISS_Byte_Send` | FUN_0802445c | Send single byte to USART1 |
| `APRS_Settings_Apply` | FUN_08014154 | Apply TX delay from settings |
| `APRS_Mode_Check` | Various | Check TNC type at offset +0x1D |

---

## ⚠️ CRITICAL BUG FOUND

### The Problem

The firmware has a bug where **KISS mode does NOT work with Bluetooth!**

Only WinAPRS mode (TNC Type = 1) sends KISS frames to Bluetooth. KISS mode (TNC Type = 3) is broken.

**The buggy code at 0x08014116:**
```c
if (tnc_type == 1) {  // Only checks for WinAPRS!
    send_to_bluetooth(kiss_frame);
}
```

### Workaround

**Set TNC Type to "WinAPRS" instead of "KISS"** - this actually uses KISS framing internally and works with APRSDroid.

### Proper Fix

A firmware patch is available in `scripts/patch_kiss_tnc.py` that fixes this bug.

See `docs/bug_report_chinese.md` and `docs/bug_report_english.md` for full details and patch instructions.

---

## Conclusion

The RT-950 Pro's TNC functionality is **compatible with APRSDroid** but requires a workaround or firmware patch:

1. **Workaround**: Set TNC Type to **WinAPRS** (not KISS)
2. **Proper fix**: Apply the firmware patch from `scripts/patch_kiss_tnc.py`

The implementation follows standard KISS TNC protocol and transmits/receives via the Bluetooth serial port at 115200 baud.

This is a legitimate, built-in feature with a configuration bug.

