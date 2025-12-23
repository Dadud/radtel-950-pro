#!/usr/bin/env python3
"""
Extract analysis data from Ghidra project using Ghidra's headless analyzer.
This script runs a Ghidra script to export function lists and other data.
"""

import subprocess
import sys
import json
from pathlib import Path
import os

# Import the find_ghidra function from the other script
sys.path.insert(0, str(Path(__file__).parent))
from ghidra_analyze_direct import find_ghidra, GHIDRA_DIR_STR

def create_export_script(output_dir):
    """Create a Ghidra script to export analysis data."""
    script_content = f'''
# Ghidra export script
import json
from ghidra.program.model.symbol import SymbolTable
from ghidra.program.model.listing import FunctionManager

output_dir = r"{output_dir}"
program = getCurrentProgram()

results = {{
    "program_name": program.getName(),
    "image_base": str(program.getImageBase()),
    "language": program.getLanguage().toString(),
    "functions": [],
    "entry_points": [],
    "memory_blocks": [],
}}

# Export functions
function_manager = program.getFunctionManager()
functions = function_manager.getFunctions(True)

for func in functions:
    func_info = {{
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "body": str(func.getBody()),
        "calling_convention": func.getCallingConventionName() or "unknown",
        "signature": str(func.getSignature()),
    }}
    results["functions"].append(func_info)

# Export entry points
entry_points = program.getSymbolTable().getExternalEntryPointIterator()
for entry in entry_points:
    results["entry_points"].append({{
        "address": str(entry.getAddress()),
        "name": entry.getName()
    }})

# Export memory blocks
memory = program.getMemory()
for block in memory.getBlocks():
    results["memory_blocks"].append({{
        "name": block.getName(),
        "start": str(block.getStart()),
        "end": str(block.getEnd()),
        "size": block.getSize(),
    }})

# Write results
output_file = os.path.join(output_dir, "ghidra_export.json")
with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

print("Export complete: " + output_file)
'''
    return script_content

def run_export(firmware_path, output_dir):
    """Run Ghidra script to export data."""
    from ghidra_analyze_direct import ANALYZE_HEADLESS, GHIDRA_DIR_STR
    
    if ANALYZE_HEADLESS is None or not os.path.exists(ANALYZE_HEADLESS):
        print("Error: Ghidra not found. Run setup_ghidra.py first.")
        return False
    
    firmware_path = Path(firmware_path).resolve()
    project_dir = firmware_path.parent / "ghidra_project"
    project_name = "RT-950-Analysis"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create export script
    script_file = output_dir / "export_script.java"
    script_content = create_export_script(str(output_dir).replace('\\', '/'))
    with open(script_file, 'w') as f:
        f.write(script_content)
    
    # Run Ghidra with export script
    cmd = [
        ANALYZE_HEADLESS,
        str(project_dir),
        project_name,
        "-process",
        firmware_path.name,
        "-scriptPath", str(output_dir),
        "-postScript", "export_script.java",
    ]
    
    print(f"Exporting Ghidra analysis data...")
    print(f"Output: {output_dir}")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=str(firmware_path.parent),
            timeout=3600,
            text=True,
            capture_output=True
        )
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        return result.returncode == 0
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    firmware = "firmware/rt950/RT_950_V0.29_251104.BTF"
    output = "firmware/rt950/analysis"
    
    if len(sys.argv) > 1:
        firmware = sys.argv[1]
    if len(sys.argv) > 2:
        output = sys.argv[2]
    
    success = run_export(firmware, output)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

