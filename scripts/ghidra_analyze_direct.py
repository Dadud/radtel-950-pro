#!/usr/bin/env python3
"""
Direct Ghidra Headless Analysis
Runs Ghidra analysis without user interaction.
"""

import subprocess
import sys
from pathlib import Path
import os

GHIDRA_DIR = r"C:\Users\dadud\Downloads\ghidra_12.0_PUBLIC_20251205\ghidra_12.0_PUBLIC"
ANALYZE_HEADLESS = os.path.join(GHIDRA_DIR, "support", "analyzeHeadless.bat")

def main():
    firmware = "firmware/rt950/RT_950_V0.29_251104.BTF"
    if len(sys.argv) > 1:
        firmware = sys.argv[1]
    
    firmware_path = Path(firmware).resolve()
    if not firmware_path.exists():
        print(f"Error: Firmware not found: {firmware_path}")
        sys.exit(1)
    
    project_dir = firmware_path.parent / "ghidra_project"
    project_name = "RT-950-Analysis"
    
    project_dir.mkdir(exist_ok=True)
    
    if not os.path.exists(ANALYZE_HEADLESS):
        print(f"Error: analyzeHeadless.bat not found at: {ANALYZE_HEADLESS}")
        sys.exit(1)
    
    print("=" * 70)
    print("Ghidra Headless Analysis - RT-950 Firmware")
    print("=" * 70)
    print(f"Firmware: {firmware_path}")
    print(f"Project: {project_dir / project_name}")
    print(f"Analyzer: {ANALYZE_HEADLESS}")
    print()
    print("Starting analysis (this may take 5-15 minutes)...")
    print("=" * 70)
    print()
    
    cmd = [
        ANALYZE_HEADLESS,
        str(project_dir),
        project_name,
        "-import", str(firmware_path),
        "-processor", "ARM:LE:32:Cortex",
        "-analysisTimeoutPerFile", "3600",
    ]
    
    try:
        result = subprocess.run(
            cmd,
            cwd=str(firmware_path.parent),
            timeout=7200,  # 2 hour timeout
            text=True
        )
        
        if result.returncode == 0:
            print()
            print("=" * 70)
            print("✅ Analysis Complete!")
            print("=" * 70)
            print(f"Project location: {project_dir / project_name}")
            print()
            print("Next steps:")
            print("  1. Open Ghidra")
            print("  2. File → Open Project")
            print(f"  3. Navigate to: {project_dir}")
            print(f"  4. Select project: {project_name}")
            print()
            return True
        else:
            print()
            print("=" * 70)
            print(f"❌ Analysis failed with return code: {result.returncode}")
            print("=" * 70)
            return False
            
    except subprocess.TimeoutExpired:
        print()
        print("❌ Analysis timed out after 2 hours")
        return False
    except KeyboardInterrupt:
        print()
        print("❌ Analysis interrupted by user")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)

