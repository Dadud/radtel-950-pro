#!/usr/bin/env python3
"""
Compare RT-950 and RT-950 Pro firmware
Extracts and compares function addresses, memory layouts, and hardware differences.
"""

import json
import sys
from pathlib import Path

# RT-950 Pro known functions (from previous analysis)
RT950PRO_FUNCTIONS = {
    # System/Debug
    "reset_handler": "0x08000000",  # Typically at flash base or vector table offset
    "hardfault": "0x08013B0D",  # RT-950 has this at same address?
    
    # BK4829 Driver
    "bk4829_init": "FUN_08007f04",  # BK4829 initialization (50+ registers)
    
    # LCD Driver
    "lcd_write_cmd": "FUN_080271c0",  # LCD command write
    "lcd_write_data": "FUN_08027220",  # LCD data write
    "lcd_flush": "FUN_080037b0",  # LCD DMA flush
    
    # SPI Flash
    "flash_erase_4k": "FUN_080210c0",  # 4KB sector erase
    "flash_erase_32k": "FUN_08020f80",  # 32KB block erase
    "flash_erase_64k": "FUN_08020ff0",  # 64KB block erase
    "flash_read": "FUN_08021180",  # Read data
    
    # Encoder
    "encoder_handler": "FUN_0800e2e0",  # Rotary encoder quadrature decoder
    
    # Memory addresses
    "framebuffer": "0x20000BD0",  # LCD frame buffer
    "cmd_buffer": "0x2000A1D0",  # LCD command staging
}

def analyze_rt950_binary(firmware_path):
    """Analyze RT-950 binary analysis JSON."""
    analysis_file = Path(firmware_path).parent / "analysis" / "binary_analysis.json"
    
    if not analysis_file.exists():
        print(f"Error: Analysis file not found: {analysis_file}")
        print("Run: python scripts/analyze_binary_deep.py first")
        return None
    
    with open(analysis_file, 'r') as f:
        return json.load(f)

def compare_vector_tables(rt950_data, rt950pro_known):
    """Compare vector table entries."""
    comparison = {
        "rt950": {},
        "rt950pro_known": {},
        "differences": []
    }
    
    rt950_vectors = rt950_data.get("vector_table", {})
    
    # RT-950 vectors
    if "reset_handler" in rt950_vectors:
        comparison["rt950"]["reset_handler"] = rt950_vectors["reset_handler"]["address"]
    if "hardfault_handler" in rt950_vectors:
        comparison["rt950"]["hardfault"] = rt950_vectors["hardfault_handler"]["address"]
    
    # RT-950 Pro known
    comparison["rt950pro_known"]["hardfault"] = rt950pro_known.get("hardfault", "UNKNOWN")
    
    # Compare
    if comparison["rt950"].get("hardfault") == comparison["rt950pro_known"].get("hardfault"):
        comparison["differences"].append("Hard Fault handler at SAME address - possible shared code")
    else:
        comparison["differences"].append("Hard Fault handler at DIFFERENT address")
    
    return comparison

def compare_memory_layout(rt950_data, rt950pro_known):
    """Compare memory layout."""
    comparison = {
        "rt950": {},
        "rt950pro": {},
        "differences": []
    }
    
    # RT-950 RAM from stack pointer
    if "file_info" in rt950_data and "ram_size_kb" in rt950_data["file_info"]:
        comparison["rt950"]["ram_usage_kb"] = rt950_data["file_info"]["ram_size_kb"]
    
    # RT-950 Pro (known)
    comparison["rt950pro"]["framebuffer"] = rt950pro_known.get("framebuffer", "UNKNOWN")
    
    # File sizes
    if "file_info" in rt950_data:
        comparison["rt950"]["file_size_kb"] = rt950_data["file_info"].get("size_kb", 0)
    
    return comparison

def generate_comparison_report(rt950_data, output_file):
    """Generate detailed comparison report."""
    
    comparison = {
        "rt950_firmware": {
            "version": "V0.29",
            "file_size_kb": rt950_data["file_info"].get("size_kb", 0),
            "vector_table": rt950_data.get("vector_table", {}),
            "function_candidates": len(rt950_data.get("function_candidates", [])),
            "strings_found": len(rt950_data.get("string_table", [])),
        },
        "rt950pro_known": RT950PRO_FUNCTIONS,
        "comparisons": {
            "vector_table": compare_vector_tables(rt950_data, RT950PRO_FUNCTIONS),
            "memory_layout": compare_memory_layout(rt950_data, RT950PRO_FUNCTIONS),
        },
        "key_differences": [],
        "inferences": []
    }
    
    # Key differences
    rt950_size = rt950_data["file_info"].get("size_kb", 0)
    comparison["key_differences"].append({
        "category": "firmware_size",
        "rt950": f"{rt950_size:.1f} KB",
        "rt950pro": "UNKNOWN (need analysis)",
        "note": "Size difference may indicate feature differences"
    })
    
    # Inferences
    comparison["inferences"].append({
        "finding": "Reset handler offset",
        "rt950": rt950_data["file_info"].get("code_start_offset", "UNKNOWN"),
        "implication": "Code starts at different offset than Pro (if Pro starts at 0x08000000)"
    })
    
    # Write report
    with open(output_file, 'w') as f:
        json.dump(comparison, f, indent=2)
    
    return comparison

def main():
    firmware = "firmware/rt950/RT_950_V0.29_251104.BTF"
    if len(sys.argv) > 1:
        firmware = sys.argv[1]
    
    print("=" * 70)
    print("RT-950 vs RT-950 Pro Firmware Comparison")
    print("=" * 70)
    print()
    
    # Analyze RT-950
    rt950_data = analyze_rt950_binary(firmware)
    if not rt950_data:
        sys.exit(1)
    
    # Generate comparison
    output_file = Path(firmware).parent / "analysis" / "firmware_comparison.json"
    comparison = generate_comparison_report(rt950_data, output_file)
    
    # Print summary
    print("RT-950 Analysis:")
    print(f"  File size: {comparison['rt950_firmware']['file_size_kb']:.1f} KB")
    print(f"  Function candidates: {comparison['rt950_firmware']['function_candidates']}")
    print(f"  Strings found: {comparison['rt950_firmware']['strings_found']}")
    print()
    
    print("Key Differences:")
    for diff in comparison["key_differences"]:
        print(f"  {diff['category']}: {diff['rt950']} vs {diff['rt950pro']}")
    print()
    
    print(f"Full comparison report: {output_file}")
    print()
    print("Note: Detailed function comparison requires Ghidra analysis.")
    print("Run: python scripts/ghidra_analyze_direct.py to decompile firmware.")

if __name__ == '__main__':
    main()

