#!/usr/bin/env python3
"""
Firmware Analysis Script
Analyzes RT-950 firmware binaries and extracts vector table information.
"""

import struct
import sys
import os
from pathlib import Path

def analyze_vector_table(data):
    """Extract ARM Cortex-M vector table information."""
    if len(data) < 16:
        return None
    
    vectors = {
        'stack_pointer': struct.unpack('<I', data[0:4])[0],
        'reset_handler': struct.unpack('<I', data[4:8])[0],
        'nmi_handler': struct.unpack('<I', data[8:12])[0] if len(data) >= 12 else 0,
        'hardfault_handler': struct.unpack('<I', data[12:16])[0] if len(data) >= 16 else 0,
        'memfault_handler': struct.unpack('<I', data[16:20])[0] if len(data) >= 20 else 0,
        'busfault_handler': struct.unpack('<I', data[20:24])[0] if len(data) >= 24 else 0,
        'usagefault_handler': struct.unpack('<I', data[24:28])[0] if len(data) >= 28 else 0,
    }
    return vectors

def analyze_file_header(data):
    """Analyze file header for encryption markers or special formats."""
    header_info = {
        'size': len(data),
        'is_encrypted': False,
        'format': 'unknown',
    }
    
    # Check for common encryption markers
    header_str = data[:16].hex()
    if b'BTF' in data[:16] or b'ENC' in data[:16] or b'CRY' in data[:16]:
        header_info['is_encrypted'] = True
    
    # Check if it looks like ARM vector table (stack pointer in RAM range)
    if len(data) >= 4:
        sp = struct.unpack('<I', data[0:4])[0]
        if 0x20000000 <= sp <= 0x20020000:  # RAM range for Cortex-M
            header_info['format'] = 'ARM_Cortex-M_VectorTable'
            header_info['is_encrypted'] = False
    
    return header_info

def find_code_patterns(data):
    """Find common code patterns that indicate function entry points."""
    patterns = {
        'push_lr': 0,  # PUSH {lr} or PUSH {r7, lr}
        'bx_lr': 0,    # BX LR
        'bl_instructions': [],
    }
    
    # Simple pattern matching (Thumb mode)
    for i in range(len(data) - 2):
        # PUSH {lr} - 0xB500 or variants
        if data[i] == 0x00 and data[i+1] == 0xB5:
            patterns['push_lr'] += 1
        # BX LR - 0x7047
        if data[i] == 0x47 and data[i+1] == 0x70:
            patterns['bx_lr'] += 1
        # BL instruction pattern (0xF7F0... or 0xF000...)
        if (data[i] & 0xF8) == 0xF0 and i + 1 < len(data):
            if len(patterns['bl_instructions']) < 100:  # Limit results
                patterns['bl_instructions'].append(i)
    
    return patterns

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_firmware.py <firmware_file>")
        sys.exit(1)
    
    firmware_path = Path(sys.argv[1])
    if not firmware_path.exists():
        print(f"Error: File not found: {firmware_path}")
        sys.exit(1)
    
    print(f"Analyzing: {firmware_path}")
    print("=" * 60)
    
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    # File header analysis
    header = analyze_file_header(data)
    print(f"\nFile Header:")
    print(f"  Size: {header['size']:,} bytes ({header['size'] / 1024:.1f} KB)")
    print(f"  Format: {header['format']}")
    print(f"  Encrypted: {header['is_encrypted']}")
    
    # Vector table analysis
    vectors = analyze_vector_table(data)
    if vectors:
        print(f"\nVector Table:")
        print(f"  Stack Pointer:     0x{vectors['stack_pointer']:08X}")
        print(f"  Reset Handler:     0x{vectors['reset_handler']:08X}")
        print(f"  NMI Handler:       0x{vectors['nmi_handler']:08X}")
        print(f"  Hard Fault:        0x{vectors['hardfault_handler']:08X}")
        print(f"  Mem Fault:         0x{vectors['memfault_handler']:08X}")
        print(f"  Bus Fault:         0x{vectors['busfault_handler']:08X}")
        print(f"  Usage Fault:       0x{vectors['usagefault_handler']:08X}")
        
        # Analyze stack pointer
        sp = vectors['stack_pointer']
        if 0x20000000 <= sp <= 0x20020000:
            ram_size = sp - 0x20000000
            print(f"\n  RAM Size (from SP): {ram_size / 1024:.1f} KB")
        
        # Analyze reset handler
        reset = vectors['reset_handler']
        if 0x08000000 <= reset <= 0x08100000:
            offset = reset - 0x08000000
            print(f"  Reset Handler Offset: 0x{offset:06X}")
    
    # Code patterns
    patterns = find_code_patterns(data)
    print(f"\nCode Patterns (approximate):")
    print(f"  PUSH {{lr}} patterns: {patterns['push_lr']}")
    print(f"  BX LR patterns: {patterns['bx_lr']}")
    print(f"  BL instructions found: {len(patterns['bl_instructions'])}")
    
    # First 64 bytes hex dump
    print(f"\nFirst 64 bytes (hex):")
    for i in range(0, min(64, len(data)), 16):
        hex_str = ' '.join(f'{b:02X}' for b in data[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"  {i:04X}: {hex_str:<48} {ascii_str}")
    
    print("\n" + "=" * 60)

if __name__ == '__main__':
    main()

