# RT-950 Pro Firmware Bug Report and Fix Recommendations

**Version**: V0.24  
**Date**: December 20, 2024  
**Reporter**: Amateur Radio Community  

---

## Bug #1: TNC Type "KISS" Mode Does Not Send Data Over Bluetooth (Critical)

### Problem Description

When users set `TNC Type = KISS` in the menu, APRS packets are **NOT** sent over Bluetooth to APRSDroid or similar applications. Only setting `TNC Type = WinAPRS` makes Bluetooth work.

This prevents users from using the standard KISS protocol to connect APRSDroid.

### Root Cause Analysis

In function `FUN_080140c0` (address 0x080140c0), the code only checks if TNC type equals 1:

**Current Code (Buggy):**
```c
// Address: 0x08014745 (decompiled)
if (*(char *)(DAT_08014150 + 0x1d) == '\x01') {  // Only checks for type 1 (WinAPRS)
    FUN_08024444(local_214, uVar3 + 1 & 0xffff);  // Send to Bluetooth
}
```

**TNC Type Values:**
| Value | Type Name | Bluetooth Output |
|-------|-----------|------------------|
| 0 | MacAPRS | ❌ Not working |
| 1 | WinAPRS | ✅ Works |
| 2 | APRS | ❌ Not working |
| 3 | KISS | ❌ Not working (should work!) |

### Suggested Fix

**Option A: Also allow KISS mode to work (Recommended)**

```c
// Original code (FUN_080140c0, around address 0x08014745)
// Original:
if (*(char *)(DAT_08014150 + 0x1d) == '\x01') {
    FUN_08024444(local_214, uVar3 + 1 & 0xffff);
}

// Fixed:
uint8_t tnc_type = *(uint8_t *)(DAT_08014150 + 0x1d);
if (tnc_type == 1 || tnc_type == 3) {  // WinAPRS(1) or KISS(3)
    FUN_08024444(local_214, uVar3 + 1 & 0xffff);
}
```

**Option B: More flexible check (Best)**

```c
// Any non-zero TNC type sends to Bluetooth
uint8_t tnc_type = *(uint8_t *)(DAT_08014150 + 0x1d);
if (tnc_type > 0) {  // Any enabled TNC mode
    FUN_08024444(local_214, uVar3 + 1 & 0xffff);
}
```

### Assembly-Level Fix

**Original Instructions (Address 0x08014116):**
```asm
ram:08014114    407f            ldrb        r0,[r0,#0x1d]
ram:08014116    0128            cmp         r0,#0x1         ; Only compare to 1
ram:08014118    02d1            bne         LAB_08014120    ; Skip if not 1
```

**Fixed Instructions:**
```asm
ram:08014114    407f            ldrb        r0,[r0,#0x1d]
ram:08014116    0028            cmp         r0,#0x0         ; Compare to 0
ram:08014118    02d0            beq         LAB_08014120    ; Skip if 0 (any non-zero sends)
```

---

## Binary Patch for V0.24

### Patch Location

**File offset calculation:**
- Flash base: 0x08000000
- Code address: 0x08014116
- File offset: 0x14116

### Patch Bytes

| File Offset | Original | Patched | Description |
|-------------|----------|---------|-------------|
| 0x14116 | 01 28 | 00 28 | Change `cmp r0,#0x1` to `cmp r0,#0x0` |
| 0x14118 | 02 D1 | 02 D0 | Change `bne` to `beq` |

### Python Patch Script

```python
#!/usr/bin/env python3
"""
RT-950 Pro V0.24 Firmware Patch
Fixes: KISS TNC mode not sending to Bluetooth
"""

import sys

PATCH_OFFSET = 0x14116
ORIGINAL_BYTES = bytes([0x01, 0x28, 0x02, 0xD1])
PATCHED_BYTES = bytes([0x00, 0x28, 0x02, 0xD0])

def patch_firmware(input_file, output_file):
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())
    
    # Verify original bytes
    if data[PATCH_OFFSET:PATCH_OFFSET+4] != ORIGINAL_BYTES:
        print(f"ERROR: Original bytes at 0x{PATCH_OFFSET:X} don't match!")
        print(f"Expected: {ORIGINAL_BYTES.hex()}")
        print(f"Found: {data[PATCH_OFFSET:PATCH_OFFSET+4].hex()}")
        return False
    
    # Apply patch
    data[PATCH_OFFSET:PATCH_OFFSET+4] = PATCHED_BYTES
    
    with open(output_file, 'wb') as f:
        f.write(data)
    
    print(f"Patch applied successfully!")
    print(f"Output: {output_file}")
    return True

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.bin> <output.bin>")
        sys.exit(1)
    
    if not patch_firmware(sys.argv[1], sys.argv[2]):
        sys.exit(1)
```

---

## Additional Locations Requiring Same Fix

| Address | File Offset | Function |
|---------|-------------|----------|
| 0x08019650 | 0x19650 | GPIO control |
| 0x08021708 | 0x21708 | Settings load/save |
| 0x080263b0 | 0x263b0 | TNC function |

All these locations have the same `cmp r0,#0x1` check and need the same fix.

---

## Recommended Enhancements

### Enhancement #1: Add USB CDC TNC Output Option

Currently KISS frames only go to Bluetooth (USART1). Add option to output to USB CDC or accessory port (UART4).

### Enhancement #2: Bluetooth Connection Detection

Add check for Bluetooth connection status before sending KISS frames to avoid sending to disconnected port.

### Enhancement #3: Bidirectional KISS Support

Ensure KISS frames received from Bluetooth are properly parsed and transmitted over RF.

---

## Testing After Fix

1. Set TNC Type = KISS in radio menu
2. Pair Bluetooth with phone
3. Connect APRSDroid as KISS TNC at 115200 baud
4. Receive APRS signal on radio - verify APRSDroid displays it
5. Send position from APRSDroid - verify radio transmits

---

## Contact

For questions or feedback:
- GitHub: https://github.com/Dadud/radtel-950-pro
- Original project: https://github.com/nicsure/radtel-950-pro

