#!/usr/bin/env python3
"""
Extract comparison data from RT-950 firmware analysis
and compare with RT-950 Pro known functions.
"""

import json
import csv
import sys
from pathlib import Path
from collections import defaultdict

# Load RT-950 Pro function names
def load_rt950pro_functions():
    """Load RT-950 Pro function catalog."""
    csv_file = Path("docs/Function_Names.csv")
    functions = {}
    
    if csv_file.exists():
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                old_name = row.get('old function name', '')
                guessed_name = row.get('guessed function name & purpose', '')
                if old_name.startswith('FUN_'):
                    functions[old_name] = {
                        'guessed_name': guessed_name,
                        'notes': row.get('notes on parameter values/types and internal variables', '')
                    }
    
    return functions

# Known RT-950 Pro key functions with addresses
RT950PRO_KEY_FUNCTIONS = {
    "FUN_08007f04": {"name": "BK4829_Init", "address": "0x08007f04", "purpose": "BK4829 RF transceiver initialization (50+ registers)"},
    "FUN_080271c0": {"name": "LCD_WriteCommand", "address": "0x080271c0", "purpose": "LCD command write"},
    "FUN_08027220": {"name": "LCD_WriteData", "address": "0x08027220", "purpose": "LCD data write"},
    "FUN_080037b0": {"name": "Display_BufferFlush", "address": "0x080037b0", "purpose": "LCD DMA flush"},
    "FUN_080210c0": {"name": "SPIFlash_Erase4K", "address": "0x080210c0", "purpose": "4KB sector erase"},
    "FUN_08020f80": {"name": "SPIFlash_Erase32K", "address": "0x08020f80", "purpose": "32KB block erase"},
    "FUN_08020ff0": {"name": "SPIFlash_Erase64K", "address": "0x08020ff0", "purpose": "64KB block erase"},
    "FUN_08021180": {"name": "SPIFlash_Read", "address": "0x08021180", "purpose": "Read data"},
    "FUN_0800e2e0": {"name": "Encoder_HandleQuadrature", "address": "0x0800e2e0", "purpose": "Rotary encoder quadrature decoder"},
}

def analyze_rt950_functions(analysis_file):
    """Extract function candidates from RT-950 analysis."""
    with open(analysis_file, 'r') as f:
        data = json.load(f)
    
    functions = {}
    for func in data.get("function_candidates", []):
        addr = func["address"]
        offset = int(addr, 16) - 0x08000000
        functions[addr] = {
            "offset": f"0x{offset:06X}",
            "pattern": func["pattern"],
            "confidence": func["confidence"]
        }
    
    return functions

def compare_addresses(rt950_funcs, rt950pro_funcs):
    """Compare function addresses between RT-950 and RT-950 Pro."""
    matches = []
    differences = []
    
    # Check if RT-950 has functions at same addresses as Pro
    for pro_name, pro_info in RT950PRO_KEY_FUNCTIONS.items():
        pro_addr = pro_info["address"]
        if pro_addr in rt950_funcs:
            matches.append({
                "function": pro_info["name"],
                "address": pro_addr,
                "purpose": pro_info["purpose"],
                "status": "SAME_ADDRESS",
                "note": "Function appears at same address - likely shared code"
            })
        else:
            # Check if nearby (within reasonable range)
            pro_addr_val = int(pro_addr, 16)
            found_nearby = False
            for rt950_addr, rt950_info in rt950_funcs.items():
                rt950_addr_val = int(rt950_addr, 16)
                offset_diff = abs(rt950_addr_val - pro_addr_val)
                if offset_diff < 0x1000:  # Within 4KB
                    found_nearby = True
                    differences.append({
                        "function": pro_info["name"],
                        "rt950pro_address": pro_addr,
                        "rt950_address": rt950_addr,
                        "offset_difference": f"0x{offset_diff:04X}",
                        "status": "OFFSET_DIFFERENCE",
                        "purpose": pro_info["purpose"]
                    })
                    break
            
            if not found_nearby:
                differences.append({
                    "function": pro_info["name"],
                    "rt950pro_address": pro_addr,
                    "rt950_address": "NOT_FOUND",
                    "status": "MISSING_IN_RT950",
                    "purpose": pro_info["purpose"]
                })
    
    return matches, differences

def generate_comparison_report(rt950_analysis_data, output_file):
    """Generate detailed comparison report."""
    # Load RT-950 Pro functions
    rt950pro_all = load_rt950pro_functions()
    
    # Analyze RT-950 - need to write temp file or use data directly
    # Convert function candidates to dict format
    rt950_funcs = {}
    for func in rt950_analysis_data.get("function_candidates", []):
        addr = func["address"]
        rt950_funcs[addr] = {
            "offset": func["offset"],
            "pattern": func["pattern"],
            "confidence": func["confidence"]
        }
    
    # Compare
    matches, differences = compare_addresses(rt950_funcs, RT950PRO_KEY_FUNCTIONS)
    
    # Build report
    report = {
        "comparison_date": "2025-12-23",
        "rt950": {
            "firmware_version": "V0.29",
            "file_size_kb": rt950_analysis_data.get("file_info", {}).get("size_kb", 0),
            "function_candidates": len(rt950_funcs),
            "reset_handler": rt950_analysis_data.get("vector_table", {}).get("reset_handler", {}).get("address", "UNKNOWN"),
            "stack_pointer": rt950_analysis_data.get("vector_table", {}).get("stack_pointer", {}).get("address", "UNKNOWN"),
        },
        "rt950pro": {
            "known_functions": len(RT950PRO_KEY_FUNCTIONS),
            "total_cataloged_functions": len(rt950pro_all),
        },
        "address_comparison": {
            "matches": matches,
            "differences": differences,
            "summary": {
                "same_address": len([m for m in matches if m["status"] == "SAME_ADDRESS"]),
                "offset_difference": len([d for d in differences if d["status"] == "OFFSET_DIFFERENCE"]),
                "missing_in_rt950": len([d for d in differences if d["status"] == "MISSING_IN_RT950"]),
            }
        },
        "key_findings": [],
        "inferences": []
    }
    
    # Key findings
    if len(matches) > 0:
        report["key_findings"].append({
            "finding": "Shared Code",
            "description": f"{len(matches)} key functions at same addresses - indicates significant code reuse",
            "functions": [m["function"] for m in matches]
        })
    
    if any(d["status"] == "MISSING_IN_RT950" for d in differences):
        missing = [d["function"] for d in differences if d["status"] == "MISSING_IN_RT950"]
        report["key_findings"].append({
            "finding": "Missing Functions",
            "description": "Functions present in RT-950 Pro but not found in RT-950",
            "functions": missing,
            "possible_reasons": [
                "Different hardware configuration (single vs dual BK4829)",
                "Feature differences",
                "Different firmware structure"
            ]
        })
    
    # Inferences
    reset_rt950 = rt950_analysis_data.get("vector_table", {}).get("reset_handler", {}).get("address", "")
    if reset_rt950 == "0x08003191":
        report["inferences"].append({
            "observation": "Reset handler offset",
            "rt950": "0x08003191 (offset 0x003191)",
            "implication": "Code starts later than typical - may indicate bootloader or header space"
        })
    
    # Write report
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report

def main():
    rt950_analysis = Path("firmware/rt950/analysis/binary_analysis.json")
    if not rt950_analysis.exists():
        print(f"Error: RT-950 analysis file not found: {rt950_analysis}")
        print("Run: python scripts/analyze_binary_deep.py first")
        sys.exit(1)
    
    with open(rt950_analysis, 'r') as f:
        analysis_data = json.load(f)
    
    output_file = rt950_analysis.parent / "detailed_comparison.json"
    report = generate_comparison_report(analysis_data, output_file)
    
    # Print summary
    print("=" * 70)
    print("RT-950 vs RT-950 Pro Detailed Comparison")
    print("=" * 70)
    print()
    print("RT-950 Firmware:")
    print(f"  Version: V0.29")
    print(f"  Size: {report['rt950']['file_size_kb']:.1f} KB")
    print(f"  Function candidates: {report['rt950']['function_candidates']}")
    print(f"  Reset handler: {report['rt950']['reset_handler']}")
    print()
    
    print("Comparison Results:")
    summary = report["address_comparison"]["summary"]
    print(f"  Same address: {summary['same_address']}")
    print(f"  Offset difference: {summary['offset_difference']}")
    print(f"  Missing in RT-950: {summary['missing_in_rt950']}")
    print()
    
    if report["key_findings"]:
        print("Key Findings:")
        for finding in report["key_findings"]:
            print(f"  - {finding['finding']}: {finding['description']}")
        print()
    
    print(f"Full report: {output_file}")

if __name__ == '__main__':
    main()

