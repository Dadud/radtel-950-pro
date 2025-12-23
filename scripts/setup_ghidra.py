#!/usr/bin/env python3
"""
Ghidra Setup Script
Helps users set up Ghidra for firmware analysis.
"""

import os
import sys
import zipfile
from pathlib import Path
import platform

REPO_ROOT = Path(__file__).parent.parent
GHIDRA_DIR = REPO_ROOT / "firmware" / "ghidra"
GHIDRA_URL = "https://ghidra-sre.org/Release.html"

def find_ghidra_install():
    """Find existing Ghidra installation."""
    # Check local firmware/ghidra folder
    if GHIDRA_DIR.exists():
        for item in GHIDRA_DIR.iterdir():
            if item.is_dir() and "ghidra" in item.name.lower():
                analyze_headless = item / "support" / "analyzeHeadless.bat"
                if not analyze_headless.exists():
                    analyze_headless = item / "support" / "analyzeHeadless"
                if analyze_headless.exists():
                    return str(item)
    
    # Check common system locations (Windows)
    if platform.system() == "Windows":
        downloads = Path(os.path.expanduser("~/Downloads"))
        if downloads.exists():
            # Check for ghidra folders in Downloads
            for item in downloads.iterdir():
                if item.is_dir() and "ghidra" in item.name.lower():
                    # Check if it has the structure we need
                    for subdir in item.iterdir():
                        if subdir.is_dir() and "ghidra" in subdir.name.lower():
                            if (subdir / "support" / "analyzeHeadless.bat").exists():
                                return str(subdir)
                            if (subdir / "support" / "analyzeHeadless").exists():
                                return str(subdir)
                    # Or check direct structure
                    if (item / "support" / "analyzeHeadless.bat").exists():
                        return str(item)
        
        common_paths = [
            Path("C:/Program Files/Ghidra"),
        ]
    else:
        common_paths = [
            Path("/usr/share/ghidra"),
            Path("/opt/ghidra"),
            Path(os.path.expanduser("~/ghidra")),
        ]
    
    for base_path in common_paths:
        if "*" in str(base_path):
            # Handle glob patterns
            import glob
            matches = glob.glob(str(base_path))
            for match in matches:
                path = Path(match)
                if path.exists() and (path / "support" / "analyzeHeadless").exists():
                    return str(path)
        elif base_path.exists():
            for item in base_path.iterdir():
                if "ghidra" in item.name.lower():
                    analyze_headless = item / "support" / "analyzeHeadless"
                    if not analyze_headless.exists():
                        analyze_headless = item / "support" / "analyzeHeadless.bat"
                    if analyze_headless.exists():
                        return str(item)
    
    return None

def check_ghidra():
    """Check if Ghidra is set up."""
    print("=" * 70)
    print("Ghidra Setup Check")
    print("=" * 70)
    print()
    
    ghidra_path = find_ghidra_install()
    
    if ghidra_path:
        print(f"[OK] Ghidra found at: {ghidra_path}")
        print()
        
        # Check analyzeHeadless
        if platform.system() == "Windows":
            analyze = Path(ghidra_path) / "support" / "analyzeHeadless.bat"
        else:
            analyze = Path(ghidra_path) / "support" / "analyzeHeadless"
        
        if analyze.exists():
            print(f"[OK] analyzeHeadless found: {analyze}")
        else:
            print(f"[ERROR] analyzeHeadless not found at: {analyze}")
        
        return True
    else:
        print("[ERROR] Ghidra not found")
        print()
        print("To set up Ghidra:")
        print(f"  1. Download from: {GHIDRA_URL}")
        print(f"  2. Extract to: {GHIDRA_DIR}")
        print()
        print("Example:")
        print(f"  mkdir -p {GHIDRA_DIR}")
        print(f"  unzip ~/Downloads/ghidra_*.zip -d {GHIDRA_DIR}")
        print()
        print(f"Or extract to a custom location and update script paths.")
        return False

def extract_ghidra(zip_path):
    """Extract Ghidra from zip file."""
    zip_path = Path(zip_path)
    if not zip_path.exists():
        print(f"Error: Zip file not found: {zip_path}")
        return False
    
    print(f"Extracting Ghidra from: {zip_path}")
    print(f"To: {GHIDRA_DIR}")
    
    GHIDRA_DIR.mkdir(parents=True, exist_ok=True)
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(GHIDRA_DIR)
        print("[OK] Extraction complete!")
        return True
    except Exception as e:
        print(f"[ERROR] Extraction failed: {e}")
        return False

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--extract":
        if len(sys.argv) < 3:
            print("Usage: setup_ghidra.py --extract <ghidra.zip>")
            sys.exit(1)
        success = extract_ghidra(sys.argv[2])
        sys.exit(0 if success else 1)
    else:
        found = check_ghidra()
        sys.exit(0 if found else 1)

if __name__ == '__main__':
    main()

