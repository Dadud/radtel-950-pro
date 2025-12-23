#!/usr/bin/env python3
"""
Compare RT-950 and RT-950 Pro firmware with actual data
Uses both firmware analysis files to generate comprehensive comparison.
"""

import json
import sys
from pathlib import Path

def load_analysis(firmware_name):
    """Load analysis JSON for a firmware."""
    if firmware_name == "RT950":
        analysis_file = Path("firmware/rt950/analysis/binary_analysis.json")
    elif firmware_name == "RT950PRO":
        analysis_file = Path("firmware/rt950pro/analysis/binary_analysis.json")
    else:
        return None
    
    if not analysis_file.exists():
        print(f"Warning: Analysis file not found: {analysis_file}")
        return None
    
    with open(analysis_file, 'r') as f:
        return json.load(f)

def compare_vector_tables(rt950, rt950pro):
    """Compare vector table entries."""
    comparison = {}
    
    rt950_vectors = rt950.get("vector_table", {})
    rt950pro_vectors = rt950pro.get("vector_table", {})
    
    vectors_to_compare = [
        "reset_handler", "nmi_handler", "hardfault_handler",
        "memfault_handler", "busfault_handler", "usagefault_handler"
    ]
    
    for vec_name in vectors_to_compare:
        rt950_addr = rt950_vectors.get(vec_name, {}).get("address", "UNKNOWN")
        rt950pro_addr = rt950pro_vectors.get(vec_name, {}).get("address", "UNKNOWN")
        
        rt950_val = int(rt950_addr, 16) if rt950_addr != "UNKNOWN" else 0
        rt950pro_val = int(rt950pro_addr, 16) if rt950pro_addr != "UNKNOWN" else 0
        
        offset_diff = abs(rt950pro_val - rt950_val) if rt950_val > 0 and rt950pro_val > 0 else 0
        
        comparison[vec_name] = {
            "rt950": rt950_addr,
            "rt950pro": rt950pro_addr,
            "offset_difference": f"0x{offset_diff:04X}" if offset_diff > 0 else "N/A",
            "same_address": rt950_addr == rt950pro_addr
        }
    
    return comparison

def generate_comparison_report(rt950_data, rt950pro_data, output_file):
    """Generate comprehensive comparison report."""
    
    report = {
        "comparison_date": "2025-12-23",
        "rt950": {
            "firmware_version": "V0.29",
            "release_date": "2025-11-04",
            "file_size_kb": rt950_data["file_info"].get("size_kb", 0),
            "file_size_bytes": rt950_data["file_info"].get("size_bytes", 0),
            "sha256": rt950_data["file_info"].get("sha256", ""),
            "stack_pointer": rt950_data["vector_table"].get("stack_pointer", {}).get("address", "UNKNOWN"),
            "reset_handler": rt950_data["vector_table"].get("reset_handler", {}).get("address", "UNKNOWN"),
            "ram_usage_kb": rt950_data["file_info"].get("ram_size_kb", 0),
            "function_candidates": len(rt950_data.get("function_candidates", [])),
            "strings_found": len(rt950_data.get("string_table", [])),
        },
        "rt950pro": {
            "firmware_version": "V0.24",
            "release_date": "2025-12-01",
            "file_size_kb": rt950pro_data["file_info"].get("size_kb", 0),
            "file_size_bytes": rt950pro_data["file_info"].get("size_bytes", 0),
            "sha256": rt950pro_data["file_info"].get("sha256", ""),
            "stack_pointer": rt950pro_data["vector_table"].get("stack_pointer", {}).get("address", "UNKNOWN"),
            "reset_handler": rt950pro_data["vector_table"].get("reset_handler", {}).get("address", "UNKNOWN"),
            "ram_usage_kb": rt950pro_data["file_info"].get("ram_size_kb", 0),
            "function_candidates": len(rt950pro_data.get("function_candidates", [])),
            "strings_found": len(rt950pro_data.get("string_table", [])),
        },
        "vector_table_comparison": compare_vector_tables(rt950_data, rt950pro_data),
        "size_comparison": {
            "size_difference_kb": rt950pro_data["file_info"].get("size_kb", 0) - rt950_data["file_info"].get("size_kb", 0),
            "size_difference_bytes": rt950pro_data["file_info"].get("size_bytes", 0) - rt950_data["file_info"].get("size_bytes", 0),
            "size_difference_percent": ((rt950pro_data["file_info"].get("size_kb", 0) - rt950_data["file_info"].get("size_kb", 0)) / rt950_data["file_info"].get("size_kb", 1)) * 100,
        },
        "memory_comparison": {
            "ram_usage_difference_kb": rt950pro_data["file_info"].get("ram_size_kb", 0) - rt950_data["file_info"].get("ram_size_kb", 0),
            "code_start_offset_rt950": rt950_data["file_info"].get("code_start_offset", "UNKNOWN"),
            "code_start_offset_rt950pro": rt950pro_data["file_info"].get("code_start_offset", "UNKNOWN"),
        },
        "key_findings": [],
        "inferences": []
    }
    
    # Key findings
    size_diff = report["size_comparison"]["size_difference_kb"]
    report["key_findings"].append({
        "finding": "Firmware Size Difference",
        "description": f"RT-950 Pro is {size_diff:.1f} KB ({report['size_comparison']['size_difference_percent']:.1f}%) larger than RT-950",
        "reason": "Additional code for dual-band operation, KISS TNC, and Pro-specific features"
    })
    
    # Vector table analysis
    reset_rt950 = int(rt950_data["vector_table"].get("reset_handler", {}).get("address", "0"), 16)
    reset_rt950pro = int(rt950pro_data["vector_table"].get("reset_handler", {}).get("address", "0"), 16)
    if reset_rt950 > 0 and reset_rt950pro > 0:
        offset_diff = abs(reset_rt950pro - reset_rt950)
        if offset_diff < 0x100:
            report["key_findings"].append({
                "finding": "Similar Code Organization",
                "description": f"Reset handlers very close (offset difference: 0x{offset_diff:04X})",
                "implication": "Similar firmware structure, likely shared codebase"
            })
    
    # Inferences
    report["inferences"].append({
        "observation": "Both firmwares have header space",
        "rt950": f"Code starts at {rt950_data['file_info'].get('code_start_offset', 'UNKNOWN')}",
        "rt950pro": f"Code starts at {rt950pro_data['file_info'].get('code_start_offset', 'UNKNOWN')}",
        "implication": "Both may share bootloader or use similar linker configuration"
    })
    
    # Write report
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report

def main():
    print("=" * 70)
    print("RT-950 vs RT-950 Pro Comprehensive Firmware Comparison")
    print("=" * 70)
    print()
    
    # Load analyses
    rt950_data = load_analysis("RT950")
    rt950pro_data = load_analysis("RT950PRO")
    
    if not rt950_data:
        print("Error: RT-950 analysis not found")
        print("Run: python scripts/analyze_binary_deep.py firmware/rt950/RT_950_V0.29_251104.BTF")
        sys.exit(1)
    
    if not rt950pro_data:
        print("Error: RT-950 Pro analysis not found")
        print("Run: python scripts/analyze_binary_deep.py firmware/rt950pro/RT_950Pro_V0.24_251201.BTF")
        sys.exit(1)
    
    # Generate comparison
    output_file = Path("docs/COMPARISON_FULL.json")
    output_file.parent.mkdir(exist_ok=True)
    
    report = generate_comparison_report(rt950_data, rt950pro_data, output_file)
    
    # Print summary
    print("Firmware Comparison Summary:")
    print()
    print("RT-950 (V0.29):")
    print(f"  Size: {report['rt950']['file_size_kb']:.1f} KB ({report['rt950']['file_size_bytes']:,} bytes)")
    print(f"  Reset Handler: {report['rt950']['reset_handler']}")
    print(f"  RAM Usage: {report['rt950']['ram_usage_kb']:.1f} KB")
    print(f"  Function Candidates: {report['rt950']['function_candidates']}")
    print()
    
    print("RT-950 Pro (V0.24):")
    print(f"  Size: {report['rt950pro']['file_size_kb']:.1f} KB ({report['rt950pro']['file_size_bytes']:,} bytes)")
    print(f"  Reset Handler: {report['rt950pro']['reset_handler']}")
    print(f"  RAM Usage: {report['rt950pro']['ram_usage_kb']:.1f} KB")
    print(f"  Function Candidates: {report['rt950pro']['function_candidates']}")
    print()
    
    print("Size Difference:")
    print(f"  RT-950 Pro is {report['size_comparison']['size_difference_kb']:.1f} KB larger")
    print(f"  ({report['size_comparison']['size_difference_percent']:.1f}% increase)")
    print()
    
    print("Vector Table Comparison:")
    for vec_name, vec_data in report["vector_table_comparison"].items():
        same = "[MATCH]" if vec_data["same_address"] else "[DIFF]"
        print(f"  {vec_name:20s}: {same:8s} RT-950: {vec_data['rt950']:10s} Pro: {vec_data['rt950pro']:10s} (offset: {vec_data['offset_difference']})")
    print()
    
    if report["key_findings"]:
        print("Key Findings:")
        for finding in report["key_findings"]:
            print(f"  - {finding['finding']}: {finding['description']}")
        print()
    
    print(f"Full comparison report: {output_file}")

if __name__ == '__main__':
    main()

