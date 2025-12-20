#!/usr/bin/env python3
"""
RT-950 Pro Firmware Patcher - KISS TNC Bluetooth Fix

This script patches the RT-950 Pro firmware to fix the bug where
KISS TNC mode does not send data over Bluetooth. Only WinAPRS mode
works in the original firmware.

Bug: In FUN_080140c0, the code checks if TNC type == 1 (WinAPRS)
     but KISS is type 3, so it never sends to Bluetooth.

Fix: Change the check from "type == 1" to "type != 0" so any
     enabled TNC mode will send to Bluetooth.

Usage:
    python patch_kiss_tnc.py input_firmware.bin output_firmware.bin

For V0.24 firmware. May work on other versions if code hasn't moved.

Author: RT-950 Pro Open Firmware Project
License: MIT
"""

import sys
import struct
from pathlib import Path

# Patch definitions for V0.24
PATCHES = [
    {
        'name': 'KISS TNC Bluetooth Output (Main)',
        'address': 0x08014116,
        'file_offset': 0x14116,
        'original': bytes([0x01, 0x28, 0x02, 0xD1]),  # cmp r0,#1; bne
        'patched': bytes([0x00, 0x28, 0x02, 0xD0]),   # cmp r0,#0; beq
        'description': 'Allow any non-zero TNC type to use Bluetooth output'
    },
    {
        'name': 'KISS TNC GPIO Control',
        'address': 0x08019650,
        'file_offset': 0x19650,
        'original': bytes([0x01, 0x28]),  # cmp r0,#1
        'patched': bytes([0x00, 0x28]),   # cmp r0,#0
        'description': 'Fix GPIO control for KISS mode',
        'optional': True  # May not exist in all versions
    },
    {
        'name': 'KISS TNC Settings',
        'address': 0x08021708,
        'file_offset': 0x21708,
        'original': bytes([0x01, 0x28]),  # cmp r0,#1
        'patched': bytes([0x00, 0x28]),   # cmp r0,#0
        'description': 'Fix settings handling for KISS mode',
        'optional': True
    },
]


def read_firmware(filepath):
    """Read firmware file into bytearray."""
    with open(filepath, 'rb') as f:
        return bytearray(f.read())


def write_firmware(filepath, data):
    """Write firmware data to file."""
    with open(filepath, 'wb') as f:
        f.write(data)


def verify_original(data, patch):
    """Verify original bytes match expected values."""
    offset = patch['file_offset']
    length = len(patch['original'])
    actual = data[offset:offset + length]
    return actual == patch['original']


def apply_patch(data, patch):
    """Apply a single patch to firmware data."""
    offset = patch['file_offset']
    length = len(patch['patched'])
    data[offset:offset + length] = patch['patched']


def calculate_checksum(data):
    """Calculate simple checksum for verification."""
    return sum(data) & 0xFFFFFFFF


def main():
    if len(sys.argv) < 3:
        print("RT-950 Pro Firmware Patcher - KISS TNC Fix")
        print()
        print(f"Usage: {sys.argv[0]} <input.bin> <output.bin> [--dry-run]")
        print()
        print("Options:")
        print("  --dry-run    Check patches without writing output")
        print()
        print("This patch fixes the bug where KISS TNC mode doesn't")
        print("send data over Bluetooth. After patching, both KISS")
        print("and WinAPRS modes will work with APRSDroid.")
        sys.exit(1)
    
    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])
    dry_run = '--dry-run' in sys.argv
    
    if not input_file.exists():
        print(f"ERROR: Input file not found: {input_file}")
        sys.exit(1)
    
    print(f"Reading firmware: {input_file}")
    data = read_firmware(input_file)
    print(f"Firmware size: {len(data)} bytes ({len(data)/1024:.1f} KB)")
    print(f"Original checksum: 0x{calculate_checksum(data):08X}")
    print()
    
    # Apply patches
    applied = 0
    skipped = 0
    failed = 0
    
    for patch in PATCHES:
        print(f"Patch: {patch['name']}")
        print(f"  Address: 0x{patch['address']:08X} (offset 0x{patch['file_offset']:05X})")
        print(f"  Original: {patch['original'].hex().upper()}")
        print(f"  Patched:  {patch['patched'].hex().upper()}")
        
        if patch['file_offset'] >= len(data):
            print(f"  Status: SKIPPED (offset beyond file size)")
            skipped += 1
            continue
        
        if verify_original(data, patch):
            print(f"  Status: MATCHED - applying patch")
            if not dry_run:
                apply_patch(data, patch)
            applied += 1
        else:
            actual = data[patch['file_offset']:patch['file_offset'] + len(patch['original'])]
            if actual == patch['patched']:
                print(f"  Status: ALREADY PATCHED")
                skipped += 1
            elif patch.get('optional'):
                print(f"  Status: SKIPPED (optional, bytes don't match)")
                print(f"  Found:  {actual.hex().upper()}")
                skipped += 1
            else:
                print(f"  Status: FAILED (bytes don't match)")
                print(f"  Found:  {actual.hex().upper()}")
                failed += 1
        print()
    
    # Summary
    print("=" * 50)
    print(f"Patches applied: {applied}")
    print(f"Patches skipped: {skipped}")
    print(f"Patches failed:  {failed}")
    print()
    
    if failed > 0:
        print("ERROR: Some required patches failed!")
        print("The firmware version may be different from expected (V0.24).")
        sys.exit(1)
    
    if applied == 0:
        print("No patches applied (already patched or wrong version).")
        sys.exit(0)
    
    if dry_run:
        print("Dry run complete - no file written.")
        sys.exit(0)
    
    # Write output
    print(f"Patched checksum: 0x{calculate_checksum(data):08X}")
    print(f"Writing patched firmware: {output_file}")
    write_firmware(output_file, data)
    print("Done!")
    print()
    print("IMPORTANT: After flashing, set TNC Type to KISS or WinAPRS")
    print("and pair Bluetooth with APRSDroid for APRS over Bluetooth.")


if __name__ == '__main__':
    main()

