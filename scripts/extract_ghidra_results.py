#!/usr/bin/env python3
"""
Extract analysis results from Ghidra project
Reads function list, symbols, and other analysis data from Ghidra project files.
"""

import sys
import json
from pathlib import Path

def main():
    project_dir = Path("firmware/rt950/ghidra_project/RT-950-Analysis")
    
    if not project_dir.exists():
        print(f"Error: Ghidra project not found at {project_dir}")
        print("\nTo run analysis:")
        print("  python scripts/ghidra_analyze_direct.py")
        sys.exit(1)
    
    print("=" * 70)
    print("Ghidra Project Analysis Results")
    print("=" * 70)
    print(f"Project: {project_dir}")
    print()
    
    # Check project files
    project_file = project_dir / "RT-950-Analysis.gpr"
    if project_file.exists():
        print("✅ Ghidra project file found")
        print(f"   {project_file}")
    else:
        print("❌ Project file not found")
    
    rep_dir = project_dir / "RT-950-Analysis.rep"
    if rep_dir.exists():
        print("✅ Project repository found")
        print(f"   {rep_dir}")
        
        # List repository contents
        files = list(rep_dir.rglob("*"))
        print(f"   Contains {len(files)} files")
    else:
        print("❌ Repository directory not found")
    
    print()
    print("=" * 70)
    print("To view detailed analysis results:")
    print("=" * 70)
    print("1. Open Ghidra")
    print("2. File → Open Project")
    print(f"3. Navigate to: {project_dir.parent}")
    print("4. Select: RT-950-Analysis")
    print()
    print("In Ghidra, you can:")
    print("  - View all functions in the Symbol Tree (Ctrl+Shift+E)")
    print("  - See disassembly in the Listing window")
    print("  - View decompiled C code (Window → Decompiler)")
    print("  - Export function list (File → Export Program → Function Start Addresses)")
    print()
    
    # Note: Ghidra stores analysis data in a proprietary format
    # Full extraction requires using Ghidra's API or exporting from GUI
    print("Note: Full function extraction requires Ghidra API or manual export.")
    print("The project is ready for interactive analysis in Ghidra.")

if __name__ == '__main__':
    main()

