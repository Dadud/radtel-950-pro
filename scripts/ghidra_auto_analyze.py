#!/usr/bin/env python3
"""
Automated Ghidra Analysis Script
Uses Ghidra's headless analyzer to automatically analyze firmware.
"""

import subprocess
import sys
import os
from pathlib import Path
import time

GHIDRA_DIR = r"C:\Users\dadud\Downloads\ghidra_12.0_PUBLIC_20251205\ghidra_12.0_PUBLIC"

def find_analyze_headless():
    """Find analyzeHeadless executable."""
    possible_paths = [
        os.path.join(GHIDRA_DIR, "support", "analyzeHeadless.bat"),
        os.path.join(GHIDRA_DIR, "support", "analyzeHeadless"),
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    # Search recursively
    for root, dirs, files in os.walk(GHIDRA_DIR):
        for file in files:
            if "analyzeHeadless" in file.lower():
                return os.path.join(root, file)
    
    return None

def run_analysis(firmware_path, project_dir=None, project_name="RT-950-Analysis", delete_project=False):
    """Run Ghidra headless analysis."""
    firmware_path = Path(firmware_path).resolve()
    
    if not firmware_path.exists():
        raise FileNotFoundError(f"Firmware file not found: {firmware_path}")
    
    analyze_headless = find_analyze_headless()
    if not analyze_headless:
        raise FileNotFoundError(f"analyzeHeadless not found in {GHIDRA_DIR}")
    
    if project_dir is None:
        project_dir = firmware_path.parent / "ghidra_project"
    
    project_dir = Path(project_dir)
    project_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 60)
    print("Ghidra Headless Analysis")
    print("=" * 60)
    print(f"Ghidra: {GHIDRA_DIR}")
    print(f"Analyzer: {analyze_headless}")
    print(f"Firmware: {firmware_path}")
    print(f"Project: {project_dir / project_name}")
    print("=" * 60)
    print()
    print("Running analysis (this may take 5-15 minutes)...")
    print()
    
    cmd = [
        analyze_headless,
        str(project_dir),
        project_name,
        "-import", str(firmware_path),
        "-processor", "ARM:LE:32:Cortex",
        "-analysisTimeoutPerFile", "3600",
    ]
    
    if delete_project:
        cmd.append("-deleteProject")
    
    try:
        # Run with timeout (2 hours max)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=7200,
            cwd=str(firmware_path.parent)
        )
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("\n" + "=" * 60)
            print("✅ Analysis Complete!")
            print("=" * 60)
            print(f"Project location: {project_dir / project_name}")
            print("\nTo view results:")
            print("  1. Open Ghidra")
            print("  2. File → Open Project")
            print(f"  3. Navigate to: {project_dir}")
            print(f"  4. Select: {project_name}")
            return True
        else:
            print("\n" + "=" * 60)
            print(f"❌ Analysis failed with return code: {result.returncode}")
            print("=" * 60)
            return False
            
    except subprocess.TimeoutExpired:
        print("\n❌ Analysis timed out after 2 hours")
        return False
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        firmware = "firmware/rt950/RT_950_V0.29_251104.BTF"
        print(f"No firmware specified, using default: {firmware}")
    else:
        firmware = sys.argv[1]
    
    delete_project = "--delete" in sys.argv
    
    success = run_analysis(firmware, delete_project=delete_project)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

