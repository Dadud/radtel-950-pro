#!/usr/bin/env python3
"""
Deep Binary Analysis Script
Extracts maximum information from firmware binary without requiring Ghidra.
"""

import struct
import sys
import json
from pathlib import Path
from collections import defaultdict

try:
    from capstone import *
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("Warning: capstone not installed. Install with: pip install capstone")
    print("Limited analysis will be performed.")

class FirmwareAnalyzer:
    def __init__(self, firmware_path):
        self.firmware_path = Path(firmware_path)
        with open(self.firmware_path, 'rb') as f:
            self.data = bytearray(f.read())
        self.results = {
            'file_info': {},
            'vector_table': {},
            'function_candidates': [],
            'string_table': [],
            'patterns': {},
            'memory_regions': [],
        }
    
    def analyze_vector_table(self):
        """Extract vector table information."""
        vectors = {}
        vector_names = [
            'stack_pointer', 'reset_handler', 'nmi_handler',
            'hardfault_handler', 'memfault_handler', 'busfault_handler',
            'usagefault_handler', 'svc_handler', 'debugmon_handler',
            'pendsv_handler', 'systick_handler'
        ]
        
        for i, name in enumerate(vector_names):
            offset = i * 4
            if offset + 4 <= len(self.data):
                addr = struct.unpack('<I', self.data[offset:offset+4])[0]
                vectors[name] = {
                    'address': f'0x{addr:08X}',
                    'offset': f'0x{offset:04X}',
                    'in_flash_range': 0x08000000 <= addr <= 0x08100000,
                    'in_ram_range': 0x20000000 <= addr <= 0x20020000,
                }
        
        self.results['vector_table'] = vectors
        
        # Analyze stack pointer
        if 'stack_pointer' in vectors:
            sp = int(vectors['stack_pointer']['address'], 16)
            if 0x20000000 <= sp <= 0x20020000:
                ram_size = sp - 0x20000000
                self.results['file_info']['ram_size_kb'] = ram_size / 1024
        
        # Analyze reset handler
        if 'reset_handler' in vectors:
            reset = int(vectors['reset_handler']['address'], 16)
            if 0x08000000 <= reset <= 0x08100000:
                code_offset = reset - 0x08000000
                self.results['file_info']['code_start_offset'] = f'0x{code_offset:06X}'
                self.results['file_info']['code_start_address'] = f'0x{reset:08X}'
    
    def find_function_patterns(self):
        """Find function prologue patterns (Thumb mode)."""
        candidates = []
        patterns = {
            'push_lr': (b'\x00\xB5', 2),  # PUSH {lr}
            'push_regs': (b'\x10\xB5', 2),  # PUSH {r4, lr}
            'push_multi': (b'\xF0\xB5', 2),  # PUSH {r4-r7, lr}
        }
        
        for pattern_bytes, pattern_len in patterns.values():
            offset = 0
            while True:
                idx = self.data.find(pattern_bytes, offset)
                if idx == -1:
                    break
                # Check if aligned (functions start at even addresses in Thumb)
                if idx % 2 == 0:
                    # Calculate address in flash
                    addr = 0x08000000 + idx
                    candidates.append({
                        'address': f'0x{addr:08X}',
                        'offset': f'0x{idx:06X}',
                        'pattern': pattern_bytes.hex(),
                        'confidence': 'medium'
                    })
                offset = idx + 2
        
        # Remove duplicates and sort
        seen = set()
        unique_candidates = []
        for cand in sorted(candidates, key=lambda x: int(x['address'], 16)):
            addr = cand['address']
            if addr not in seen:
                seen.add(addr)
                unique_candidates.append(cand)
        
        self.results['function_candidates'] = unique_candidates[:200]  # Limit
    
    def find_strings(self, min_length=4):
        """Extract ASCII strings from firmware."""
        strings = []
        current_string = b''
        current_start = 0
        
        for i, byte in enumerate(self.data):
            if 32 <= byte < 127:  # Printable ASCII
                if not current_string:
                    current_start = i
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    strings.append({
                        'offset': f'0x{current_start:06X}',
                        'address': f'0x{0x08000000 + current_start:08X}',
                        'string': current_string.decode('ascii', errors='ignore'),
                        'length': len(current_string)
                    })
                current_string = b''
        
        # Sort by offset
        self.results['string_table'] = sorted(strings, key=lambda x: int(x['offset'], 16))[:100]
    
    def find_register_accesses(self):
        """Find potential register addresses (0x400xxxxx or 0x200xxxxx)."""
        register_candidates = defaultdict(int)
        
        # Look for 32-bit values in register ranges
        for i in range(0, len(self.data) - 4, 2):
            val = struct.unpack('<I', self.data[i:i+4])[0]
            # GPIO base addresses
            if 0x40010000 <= val <= 0x40020000:
                register_candidates[f'0x{val:08X}'] += 1
            # SPI, UART, etc.
            elif 0x40000000 <= val <= 0x50000000:
                register_candidates[f'0x{val:08X}'] += 1
            # RAM addresses (possible pointers)
            elif 0x20000000 <= val <= 0x20020000:
                register_candidates[f'0x{val:08X}'] += 1
        
        # Sort by frequency
        sorted_regs = sorted(register_candidates.items(), key=lambda x: x[1], reverse=True)
        self.results['patterns']['register_addresses'] = [
            {'address': addr, 'frequency': freq}
            for addr, freq in sorted_regs[:50]
        ]
    
    def disassemble_entry_points(self):
        """Disassemble code at entry points."""
        if not HAS_CAPSTONE:
            return
        
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        
        disassembly = []
        if 'reset_handler' in self.results['vector_table']:
            reset_addr = int(self.results['vector_table']['reset_handler']['address'], 16)
            reset_offset = reset_addr - 0x08000000
            
            if 0 <= reset_offset < len(self.data) - 16:
                code = bytes(self.data[reset_offset:reset_offset + 64])
                for instr in md.disasm(code, reset_addr):
                    disassembly.append({
                        'address': f'0x{instr.address:08X}',
                        'mnemonic': instr.mnemonic,
                        'op_str': instr.op_str,
                        'bytes': instr.bytes.hex()
                    })
                    if len(disassembly) >= 20:
                        break
        
        self.results['patterns']['reset_handler_disassembly'] = disassembly
    
    def analyze_memory_layout(self):
        """Infer memory layout from addresses found in binary."""
        regions = []
        
        # Flash region
        regions.append({
            'name': 'FLASH',
            'start': '0x08000000',
            'end': f'0x{0x08000000 + len(self.data):08X}',
            'size_bytes': len(self.data),
            'type': 'code'
        })
        
        # RAM region (from stack pointer)
        if 'stack_pointer' in self.results['vector_table']:
            sp = int(self.results['vector_table']['stack_pointer']['address'], 16)
            if 0x20000000 <= sp <= 0x20020000:
                ram_size = sp - 0x20000000
                regions.append({
                    'name': 'RAM',
                    'start': '0x20000000',
                    'end': f'0x{sp:08X}',
                    'size_bytes': ram_size,
                    'type': 'data'
                })
        
        self.results['memory_regions'] = regions
    
    def analyze(self):
        """Run all analyses."""
        print("Analyzing firmware binary...")
        
        # File info
        self.results['file_info'] = {
            'filename': self.firmware_path.name,
            'size_bytes': len(self.data),
            'size_kb': len(self.data) / 1024,
            'sha256': self._calculate_sha256()
        }
        
        print("  - Analyzing vector table...")
        self.analyze_vector_table()
        
        print("  - Finding function candidates...")
        self.find_function_patterns()
        
        print("  - Extracting strings...")
        self.find_strings()
        
        print("  - Finding register accesses...")
        self.find_register_accesses()
        
        print("  - Analyzing memory layout...")
        self.analyze_memory_layout()
        
        if HAS_CAPSTONE:
            print("  - Disassembling entry points...")
            self.disassemble_entry_points()
        
        return self.results
    
    def _calculate_sha256(self):
        """Calculate SHA256 hash."""
        import hashlib
        return hashlib.sha256(self.data).hexdigest()
    
    def save_results(self, output_path):
        """Save results to JSON file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nResults saved to: {output_path}")
    
    def print_summary(self):
        """Print analysis summary."""
        info = self.results['file_info']
        vectors = self.results['vector_table']
        
        print("\n" + "=" * 60)
        print("FIRMWARE ANALYSIS SUMMARY")
        print("=" * 60)
        print(f"File: {info['filename']}")
        print(f"Size: {info['size_kb']:.1f} KB ({info['size_bytes']:,} bytes)")
        print(f"SHA256: {info['sha256']}")
        
        if 'code_start_address' in info:
            print(f"\nCode Start: {info['code_start_address']} (offset {info['code_start_offset']})")
        
        if 'ram_size_kb' in info:
            print(f"RAM Size: {info['ram_size_kb']:.1f} KB")
        
        print(f"\nVector Table:")
        for name, vec in vectors.items():
            print(f"  {name:20s}: {vec['address']}")
        
        print(f"\nFunction Candidates: {len(self.results['function_candidates'])}")
        print(f"Strings Found: {len(self.results['string_table'])}")
        print(f"Register Addresses: {len(self.results['patterns'].get('register_addresses', []))}")
        
        if 'reset_handler_disassembly' in self.results['patterns']:
            print(f"\nReset Handler Disassembly (first 10 instructions):")
            for instr in self.results['patterns']['reset_handler_disassembly'][:10]:
                print(f"  {instr['address']}: {instr['mnemonic']:8s} {instr['op_str']}")
        
        print("=" * 60)

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_binary_deep.py <firmware_file> [output_json]")
        sys.exit(1)
    
    firmware_path = sys.argv[1]
    output_json = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not Path(firmware_path).exists():
        print(f"Error: File not found: {firmware_path}")
        sys.exit(1)
    
    analyzer = FirmwareAnalyzer(firmware_path)
    results = analyzer.analyze()
    analyzer.print_summary()
    
    if output_json:
        analyzer.save_results(output_json)
    else:
        # Default output location
        firmware_dir = Path(firmware_path).parent
        output_file = firmware_dir / "analysis" / "binary_analysis.json"
        analyzer.save_results(output_file)

if __name__ == '__main__':
    main()

