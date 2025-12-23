#!/usr/bin/env python3
"""
Direct Ghidra Headless Analysis
Runs Ghidra analysis without user interaction.
"""

import subprocess
import sys
from pathlib import Path
import os
import platform

# Ghidra installation paths (checked in order)
def find_ghidra():
    """Find Ghidra installation automatically."""
    repo_root = Path(__file__).parent.parent
    possible_locations = [
        # Local repository folder (recommended)
        repo_root / "firmware" / "ghidra",
        # Original user location
        Path(r"C:\Users\dadud\Downloads\ghidra_12.0_PUBLIC_20251205\ghidra_12.0_PUBLIC"),
        # Common Windows locations
        Path("C:/Program Files/Ghidra"),
        Path(os.path.expanduser("~/Downloads/ghidra_*_PUBLIC")),
        # Environment variable
        os.environ.get("GHIDRA_INSTALL_DIR"),
    ]
    
    for base in possible_locations:
        if base is None:
            continue
        
        # Handle glob patterns
        if "*" in str(base):
            import glob
            matches = glob.glob(str(base))
            for match in matches:
                base = Path(match)
                break
        else:
            base = Path(base)
        
        # Check if directory exists
        if not base.exists():
            continue
        
        # Look for ghidra subdirectory or direct support folder
        if (base / "support" / "analyzeHeadless.bat").exists():
            return base
        if (base / "support" / "analyzeHeadless").exists():
            return base
        
            # Check subdirectories (for firmware/ghidra/ghidra_X.X_PUBLIC structure)
        for item in base.iterdir():
            if item.is_dir() and "ghidra" in item.name.lower():
                if (item / "support" / "analyzeHeadless.bat").exists():
                    return item
                if (item / "support" / "analyzeHeadless").exists():
                    return item
        
        # Check Downloads folder for ghidra (Windows)
        if platform.system() == "Windows":
            downloads = Path(os.path.expanduser("~/Downloads"))
            if downloads.exists():
                for item in downloads.iterdir():
                    if item.is_dir() and "ghidra" in item.name.lower():
                        # Check nested structure
                        for subdir in item.iterdir():
                            if subdir.is_dir() and "ghidra" in subdir.name.lower():
                                if (subdir / "support" / "analyzeHeadless.bat").exists():
                                    return subdir
                        # Check direct structure
                        if (item / "support" / "analyzeHeadless.bat").exists():
                            return item
    
    return None

GHIDRA_DIR = find_ghidra()

if GHIDRA_DIR is None:
    GHIDRA_DIR_STR = "NOT_FOUND"
    ANALYZE_HEADLESS = None
else:
    GHIDRA_DIR_STR = str(GHIDRA_DIR)
    if platform.system() == "Windows":
        ANALYZE_HEADLESS = os.path.join(GHIDRA_DIR_STR, "support", "analyzeHeadless.bat")
    else:
        ANALYZE_HEADLESS = os.path.join(GHIDRA_DIR_STR, "support", "analyzeHeadless")

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
    
    if ANALYZE_HEADLESS is None or not os.path.exists(ANALYZE_HEADLESS):
        print("=" * 70)
        print("❌ Ghidra not found!")
        print("=" * 70)
        print()
        print("Ghidra is required for firmware analysis.")
        print()
        print("Setup options:")
        print("  1. Download Ghidra from: https://ghidra-sre.org/Release.html")
        print("  2. Extract to: firmware/ghidra/ folder")
        print()
        print("Quick setup:")
        print("  python scripts/setup_ghidra.py  # Check status")
        print("  python scripts/setup_ghidra.py --extract <ghidra.zip>  # Extract")
        print()
        print("Or set environment variable:")
        print("  set GHIDRA_INSTALL_DIR=C:\\path\\to\\ghidra")
        print()
        sys.exit(1)
    
    print("=" * 70)
    print("Ghidra Headless Analysis - RT-950 Firmware")
    print("=" * 70)
    print(f"Ghidra: {GHIDRA_DIR_STR}")
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

