#!/usr/bin/env python3
"""
Extract and format function information from binary analysis.
Converts analysis JSON into human-readable function list.
"""

import json
import sys
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        print("Usage: extract_functions_from_analysis.py <analysis_json>")
        sys.exit(1)
    
    analysis_file = Path(sys.argv[1])
    if not analysis_file.exists():
        print(f"Error: Analysis file not found: {analysis_file}")
        sys.exit(1)
    
    with open(analysis_file, 'r') as f:
        analysis = json.load(f)
    
    print("=" * 80)
    print("FUNCTION CANDIDATES")
    print("=" * 80)
    print(f"Found {len(analysis.get('function_candidates', []))} potential function entry points\n")
    
    for i, func in enumerate(analysis.get('function_candidates', []), 1):
        print(f"{i:3d}. {func['address']} (offset {func['offset']})")
        print(f"     Pattern: {func['pattern']}, Confidence: {func['confidence']}")
    
    print("\n" + "=" * 80)
    print("EXTRACTED STRINGS")
    print("=" * 80)
    print(f"Found {len(analysis.get('string_table', []))} strings\n")
    
    for i, string in enumerate(analysis.get('string_table', [])[:50], 1):
        print(f"{i:3d}. {string['address']}: \"{string['string']}\"")
    
    print("\n" + "=" * 80)
    print("REGISTER ADDRESSES (Most Frequent)")
    print("=" * 80)
    regs = analysis.get('patterns', {}).get('register_addresses', [])
    print(f"Found {len(regs)} unique register addresses\n")
    
    for i, reg in enumerate(regs[:30], 1):
        print(f"{i:3d}. {reg['address']} (appears {reg['frequency']} times)")
    
    # Generate function list for Ghidra import
    output_file = analysis_file.parent / "function_list.txt"
    with open(output_file, 'w') as f:
        f.write("# Function candidates for Ghidra\n")
        f.write("# Format: Address|Name|Confidence\n\n")
        for func in analysis.get('function_candidates', []):
            addr = func['address'].replace('0x', '')
            name = f"FUN_{addr}"
            f.write(f"{addr}|{name}|{func['confidence']}\n")
    
    print(f"\nFunction list exported to: {output_file}")

if __name__ == '__main__':
    main()

