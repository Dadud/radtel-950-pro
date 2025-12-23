#!/usr/bin/env python3
"""
Ghidra Headless Analysis Script
Automates firmware analysis using Ghidra's headless analyzer.
"""

import subprocess
import sys
import os
import json
from pathlib import Path
import time

# Ghidra paths (update these for your system)
GHIDRA_PATHS = [
    r"C:\Program Files\Ghidra\ghidraRun.bat",
    r"C:\ghidra\ghidraRun.bat",
    os.path.expanduser(r"~\ghidra\ghidraRun.bat"),
    "/usr/share/ghidra/ghidraRun",  # Linux
    "/opt/ghidra/ghidraRun",  # Linux
]

def find_ghidra():
    """Find Ghidra installation."""
    for path in GHIDRA_PATHS:
        if os.path.exists(path):
            # Get directory containing ghidraRun
            if path.endswith(".bat"):
                return os.path.dirname(path)
            else:
                return os.path.dirname(path)
    
    # Try to find in PATH
    try:
        result = subprocess.run(["ghidraRun", "--help"], 
                               capture_output=True, timeout=2)
        return "ghidraRun"  # Found in PATH
    except:
        pass
    
    return None

def create_analyze_script(firmware_path, output_dir):
    """Create Ghidra analysis script."""
    script = f"""
# Ghidra analysis script for {firmware_path}

import os
import json
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import ConsoleTaskMonitor

# Get current program
program = getCurrentProgram()
flat_api = FlatProgramAPI(program)
monitor = ConsoleTaskMonitor()

# Analysis results
results = {{
    "program_name": program.getName(),
    "language": program.getLanguage().toString(),
    "image_base": str(program.getImageBase()),
    "functions": [],
    "memory_map": [],
    "strings": [],
    "entry_points": []
}}

# Extract functions
function_manager = program.getFunctionManager()
functions = function_manager.getFunctions(True)

for func in functions:
    func_info = {{
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "body_address": str(func.getBody()),
        "calling_convention": func.getCallingConventionName(),
    }}
    results["functions"].append(func_info)

# Extract memory blocks
memory = program.getMemory()
for block in memory.getBlocks():
    block_info = {{
        "name": block.getName(),
        "start": str(block.getStart()),
        "end": str(block.getEnd()),
        "size": block.getSize(),
        "read": block.isRead(),
        "write": block.isWrite(),
        "execute": block.isExecute(),
    }}
    results["memory_map"].append(block_info)

# Extract entry points
listing = program.getListing()
entry_points = program.getSymbolTable().getExternalEntryPointIterator()
for entry in entry_points:
    results["entry_points"].append({{
        "address": str(entry.getAddress()),
        "name": entry.getName()
    }})

# Write results
output_file = os.path.join(r"{output_dir}", "analysis_results.json")
with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

print(f"Analysis complete. Results written to {{output_file}}")
"""
    return script

def run_ghidra_headless(ghidra_dir, firmware_path, project_dir, output_dir):
    """Run Ghidra headless analyzer."""
    project_name = "RT-950-Analysis"
    firmware_name = Path(firmware_path).stem
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(project_dir, exist_ok=True)
    
    # Create analysis script
    script_path = os.path.join(output_dir, "analyze_script.java")
    analyze_script = create_analyze_script(firmware_path, output_dir)
    
    # Determine if Windows or Unix
    is_windows = os.name == 'nt'
    
    if is_windows:
        ghidra_run = os.path.join(ghidra_dir, "support", "analyzeHeadless.bat")
        if not os.path.exists(ghidra_run):
            # Try alternative location
            ghidra_run = os.path.join(ghidra_dir, "ghidraRun.bat")
    else:
        ghidra_run = os.path.join(ghidra_dir, "support", "analyzeHeadless")
        if not os.path.exists(ghidra_run):
            ghidra_run = os.path.join(ghidra_dir, "ghidraRun")
    
    if not os.path.exists(ghidra_run):
        # Create analyze script file for Java
        with open(script_path, 'w') as f:
            f.write(analyze_script)
        
        # Try to find analyzeHeadless in common locations
        analyze_headless = None
        for base in [ghidra_dir] + [os.path.join(ghidra_dir, "support")]:
            for exe in ["analyzeHeadless.bat", "analyzeHeadless", "analyzeHeadless.sh"]:
                candidate = os.path.join(base, exe)
                if os.path.exists(candidate):
                    analyze_headless = candidate
                    break
            if analyze_headless:
                break
        
        if not analyze_headless:
            print("ERROR: Could not find analyzeHeadless executable")
            print(f"Looked in: {ghidra_dir}")
            print("\nPlease install Ghidra or specify path manually")
            return False
        
        ghidra_run = analyze_headless
    
    # Build command
    cmd = [
        ghidra_run,
        project_dir,  # Project directory
        project_name,  # Project name
        "-import", firmware_path,  # Import firmware
        "-processor", "ARM:LE:32:Cortex",  # ARM Cortex-M
        "-analysisTimeoutPerFile", "3600",  # 1 hour timeout
        "-deleteProject",  # Clean up after
        "-postScript", script_path,  # Run analysis script
    ]
    
    print(f"Running Ghidra headless analysis...")
    print(f"Command: {' '.join(cmd)}")
    print(f"Firmware: {firmware_path}")
    print(f"Output: {output_dir}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
        print(result.stdout)
        if result.stderr:
            print("Errors:", result.stderr)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("ERROR: Analysis timed out")
        return False
    except FileNotFoundError:
        print(f"ERROR: Could not find Ghidra at {ghidra_run}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: ghidra_analyze.py <firmware_file> [ghidra_path]")
        print("\nExample:")
        print("  python ghidra_analyze.py firmware/rt950/RT_950_V0.29_251104.BTF")
        sys.exit(1)
    
    firmware_path = Path(sys.argv[1])
    if not firmware_path.exists():
        print(f"Error: Firmware file not found: {firmware_path}")
        sys.exit(1)
    
    # Find or use provided Ghidra path
    if len(sys.argv) > 2:
        ghidra_dir = sys.argv[2]
    else:
        ghidra_dir = find_ghidra()
    
    if not ghidra_dir or not os.path.exists(ghidra_dir):
        print("ERROR: Ghidra not found!")
        print("\nPlease install Ghidra from: https://ghidra-sre.org/")
        print("Or specify path manually:")
        print(f"  python {sys.argv[0]} {firmware_path} <ghidra_path>")
        sys.exit(1)
    
    # Setup paths
    firmware_name = firmware_path.stem
    project_dir = firmware_path.parent / "ghidra_project"
    output_dir = firmware_path.parent / "analysis"
    
    # Run analysis
    success = run_ghidra_headless(ghidra_dir, str(firmware_path), 
                                  str(project_dir), str(output_dir))
    
    if success:
        results_file = output_dir / "analysis_results.json"
        if results_file.exists():
            print(f"\n✅ Analysis complete!")
            print(f"Results: {results_file}")
        else:
            print("\n⚠️ Analysis ran but results file not found")
    else:
        print("\n❌ Analysis failed")
        sys.exit(1)

if __name__ == '__main__':
    main()

