#!/usr/bin/env python3
"""
RT-950 Pro Firmware Decompilation Script

Automatically decompiles firmware .bin files using Ghidra headless analyzer.
Can process single files or compare multiple firmware versions.

Usage:
    python decompile_firmware.py <firmware.bin> [output_dir]
    python decompile_firmware.py --compare <firmware1.bin> <firmware2.bin> [output_dir]
    python decompile_firmware.py --batch <dir_with_bins> [output_dir]
"""

import os
import sys
import subprocess
import argparse
import shutil
from pathlib import Path
from datetime import datetime

# Configuration - adjust these paths for your system
GHIDRA_PATH = r"C:\Users\dadud\Downloads\ghidra_12.0_PUBLIC_20251205\ghidra_12.0_PUBLIC"
JAVA_HOME = r"C:\Program Files\Eclipse Adoptium\jdk-21.0.9.10-hotspot"
BASE_ADDRESS = "0x08000000"
PROCESSOR = "ARM:LE:32:Cortex"

# Project settings
PROJECT_NAME_TEMPLATE = "firmware_{timestamp}"
SCRIPT_PATH = Path(__file__).parent
EXPORT_SCRIPT = SCRIPT_PATH / "export_all.java"


def find_ghidra():
    """Find Ghidra installation"""
    if os.path.exists(GHIDRA_PATH):
        return GHIDRA_PATH
    
    # Try common locations
    common_paths = [
        os.path.expanduser("~/Downloads/ghidra*"),
        "C:/ghidra*",
        "C:/Program Files/ghidra*",
    ]
    
    for pattern in common_paths:
        import glob
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    
    raise FileNotFoundError("Ghidra not found. Please set GHIDRA_PATH in the script.")


def find_java():
    """Find Java installation"""
    if os.path.exists(JAVA_HOME):
        return JAVA_HOME
    
    # Try to find Java in PATH
    try:
        result = subprocess.run(["java", "-version"], capture_output=True, text=True)
        return None  # Use system PATH
    except FileNotFoundError:
        pass
    
    # Try common locations
    common_paths = [
        "C:/Program Files/Eclipse Adoptium/jdk-*",
        "C:/Program Files/Java/jdk-*",
        os.path.expanduser("~/.jdks/jdk-*"),
    ]
    
    for pattern in common_paths:
        import glob
        matches = glob.glob(pattern)
        if matches:
            # Get latest version
            return sorted(matches, reverse=True)[0]
    
    raise FileNotFoundError("Java not found. Please set JAVA_HOME in the script or install Java.")


def decompile_firmware(firmware_path, output_dir=None, project_name=None):
    """
    Decompile a single firmware binary file
    
    Args:
        firmware_path: Path to firmware .bin file
        output_dir: Directory to save decompiled output (default: firmware_name_decompiled)
        project_name: Name for Ghidra project (default: auto-generated)
    
    Returns:
        Path to output directory
    """
    firmware_path = Path(firmware_path).resolve()
    
    if not firmware_path.exists():
        raise FileNotFoundError(f"Firmware file not found: {firmware_path}")
    
    # Setup paths
    ghidra_home = find_ghidra()
    java_home = find_java()
    analyze_headless = Path(ghidra_home) / "support" / "analyzeHeadless.bat"
    
    if not analyze_headless.exists():
        raise FileNotFoundError(f"analyzeHeadless.bat not found at: {analyze_headless}")
    
    # Create project directory (parent of firmware or temp location)
    project_parent = firmware_path.parent / "ghidra_projects"
    project_parent.mkdir(exist_ok=True)
    
    # Generate project name if not provided
    if project_name is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        project_name = f"{firmware_path.stem}_{timestamp}"
    
    # Setup output directory
    if output_dir is None:
        output_dir = firmware_path.parent / f"{firmware_path.stem}_decompiled"
    else:
        output_dir = Path(output_dir)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Prepare environment
    env = os.environ.copy()
    if java_home:
        env["JAVA_HOME"] = java_home
        env["PATH"] = f"{java_home}/bin;{env.get('PATH', '')}"
    
    print(f"\n{'='*70}")
    print(f"Decompiling: {firmware_path.name}")
    print(f"Project: {project_name}")
    print(f"Output: {output_dir}")
    print(f"{'='*70}\n")
    
    # Check if custom export script exists, otherwise create it
    custom_export_script = SCRIPT_PATH / "export_all_custom.java"
    create_custom_export_script(custom_export_script, output_dir)
    
    # Run Ghidra headless: import, analyze, and export in one go
    print("Step 1/2: Importing and analyzing firmware...")
    cmd = [
        str(analyze_headless),
        str(project_parent),
        project_name,
        "-import", str(firmware_path),
        "-processor", PROCESSOR,
        "-cspec", "default",
        "-loader", "BinaryLoader",
        "-loader-baseAddr", BASE_ADDRESS,
        "-scriptPath", str(SCRIPT_PATH),
        "-postScript", "export_all_custom.java",
        "-overwrite",  # Overwrite if project exists
    ]
    
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    
    if result.returncode != 0:
        # Check if it's just a project exists warning
        if "already exists" not in result.stderr.lower() and "Export complete" not in result.stdout:
            print(f"Error during import/analysis:\n{result.stderr}")
            # Don't fail completely - export might have still worked
            if "Export complete" not in result.stdout:
                raise RuntimeError(f"Ghidra processing failed: {result.stderr}")
    
    print("Step 2/2: Processing exported files...")
    
    # Files should already be in output_dir (export script writes directly there)
    # But check if they're in a temp location and move them
    temp_export = firmware_path.parent / "analysis_export"
    if temp_export.exists():
        for file in temp_export.glob("*"):
            dest = output_dir / file.name
            if file.is_file() and not dest.exists():
                shutil.move(str(file), str(dest))
                print(f"  Moved: {file.name}")
        try:
            temp_export.rmdir()
        except:
            pass
    
    # Check if files exist in output_dir
    c_file = output_dir / f"{firmware_path.stem}.c"
    lst_file = output_dir / f"{firmware_path.stem}.lst"
    
    if not c_file.exists() and not lst_file.exists():
        print("Warning: Expected output files not found. Check Ghidra logs.")
    else:
        print(f"  Found: {c_file.name if c_file.exists() else ''} {lst_file.name if lst_file.exists() else ''}")
    
    # Also copy original binary for reference (if not already there)
    dest_bin = output_dir / firmware_path.name
    if not dest_bin.exists():
        shutil.copy2(firmware_path, dest_bin)
    
    print(f"\nExport complete!")
    print(f"Output directory: {output_dir}")
    
    # Create summary file
    create_summary(output_dir, firmware_path, BASE_ADDRESS)
    
    return output_dir


def create_custom_export_script(script_path, output_dir):
    """Create a custom export script with fixed output directory"""
    # Convert Windows path to Java path format
    java_path = str(output_dir).replace('\\', '/')
    
    script_content = f'''//@category AT32/Export
//@name Export All Analysis (Custom)

import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.File;

public class export_all_custom extends GhidraScript {{
    
    @Override
    public void run() throws Exception {{
        String exportDir = "{java_path}";
        File exportFolder = new File(exportDir);
        exportFolder.mkdirs();
        
        println("Exporting to: " + exportDir);
        
        // Export C/C++ code
        println("Exporting C/C++ code...");
        CppExporter cppExporter = new CppExporter();
        File cppFile = new File(exportDir, currentProgram.getName() + ".c");
        cppExporter.export(cppFile, currentProgram, currentProgram.getMemory(), new ConsoleTaskMonitor());
        
        // Export ASCII listing
        println("Exporting ASCII listing...");
        AsciiExporter asciiExporter = new AsciiExporter();
        File asciiFile = new File(exportDir, currentProgram.getName() + ".lst");
        asciiExporter.export(asciiFile, currentProgram, currentProgram.getMemory(), new ConsoleTaskMonitor());
        
        println("Export complete! Files saved to: " + exportDir);
    }}
}}
'''
    script_path.write_text(script_content)
    print(f"Created custom export script: {script_path}")


def create_summary(output_dir, firmware_path, base_address):
    """Create a summary README file"""
    summary = f"""# Firmware Decompilation Summary

## Firmware Information

- **File**: {firmware_path.name}
- **Size**: {firmware_path.stat().st_size / 1024:.2f} KB
- **Base Address**: {base_address}
- **Processor**: {PROCESSOR}
- **Decompiled**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Files

- `{firmware_path.name}` - Original firmware binary
- `{firmware_path.stem}.c` - Decompiled C code
- `{firmware_path.stem}.lst` - Assembly listing

## Memory Map

- Flash: `{base_address}` - `0x080FFFFF` (1 MB)
- SRAM: `0x20000000` - `0x20017FFF` (96 KB)

## Notes

All function addresses use the correct format: `FUN_0800xxxx`

"""
    (output_dir / "README.md").write_text(summary)


def compare_firmware(firmware1_path, firmware2_path, output_dir=None):
    """
    Compare two firmware versions
    
    Args:
        firmware1_path: Path to first firmware
        firmware2_path: Path to second firmware
        output_dir: Directory for comparison results
    """
    firmware1_path = Path(firmware1_path).resolve()
    firmware2_path = Path(firmware2_path).resolve()
    
    if output_dir is None:
        output_dir = firmware1_path.parent / f"comparison_{firmware1_path.stem}_vs_{firmware2_path.stem}"
    else:
        output_dir = Path(output_dir)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*70}")
    print(f"Comparing Firmware Versions")
    print(f"{'='*70}")
    print(f"Version 1: {firmware1_path.name}")
    print(f"Version 2: {firmware2_path.name}")
    print(f"Output: {output_dir}")
    print(f"{'='*70}\n")
    
    # Decompile both
    print("Decompiling version 1...")
    decomp1_dir = decompile_firmware(firmware1_path, output_dir / "version1")
    
    print("\nDecompiling version 2...")
    decomp2_dir = decompile_firmware(firmware2_path, output_dir / "version2")
    
    # Use diff tools to compare (if available)
    print("\nGenerating comparison...")
    create_comparison_report(decomp1_dir, decomp2_dir, output_dir, 
                           firmware1_path, firmware2_path)
    
    print(f"\nComparison complete! Results in: {output_dir}")
    return output_dir


def create_comparison_report(dir1, dir2, output_dir, firmware1_path, firmware2_path):
    """Create a comparison report between two decompiled versions"""
    # Find C files
    c_file1 = next(Path(dir1).glob("*.c"), None)
    c_file2 = next(Path(dir2).glob("*.c"), None)
    
    if not c_file1 or not c_file2:
        print("Warning: Could not find C files for comparison")
        return
    
    firmware1_path = Path(firmware1_path)
    firmware2_path = Path(firmware2_path)
    
    # Create comparison report
    report = f"""# Firmware Comparison Report

## Versions Compared

- **Version 1**: {firmware1_path.name}
- **Version 2**: {firmware2_path.name}
- **Compared**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## File Sizes

- Version 1: {firmware1_path.stat().st_size / 1024:.2f} KB
- Version 2: {firmware2_path.stat().st_size / 1024:.2f} KB

## Comparison Instructions

### Manual Comparison

1. Use a diff tool to compare:
   - `version1/{c_file1.name}` vs `version2/{c_file2.name}`
   - `version1/{c_file1.stem}.lst` vs `version2/{c_file2.stem}.lst`

### Recommended Tools

- **Visual Studio Code**: Use built-in diff view
- **Beyond Compare**: Commercial diff tool
- **WinMerge**: Free Windows diff tool
- **Ghidra**: Open both projects and use version tracking

### Automated Diff (if available)

Run this command to generate a text diff:

```
diff -u version1/{c_file1.name} version2/{c_file2.name} > diff_report.txt
```

Or use Git:

```
git diff --no-index version1/{c_file1.name} version2/{c_file2.name} > diff_report.txt
```

## Key Areas to Check

1. **Function changes**: Look for modified function implementations
2. **New functions**: Functions present in version 2 but not version 1
3. **Removed functions**: Functions in version 1 but not version 2
4. **String changes**: Modified string literals
5. **Address changes**: If base addresses differ

"""
    
    # Try to create a basic diff if Python difflib is available
    try:
        import difflib
        with open(c_file1, 'r', encoding='utf-8', errors='ignore') as f1:
            lines1 = f1.readlines()
        with open(c_file2, 'r', encoding='utf-8', errors='ignore') as f2:
            lines2 = f2.readlines()
        
        diff = difflib.unified_diff(
            lines1, lines2,
            fromfile=f"version1/{c_file1.name}",
            tofile=f"version2/{c_file2.name}",
            lineterm=''
        )
        
        diff_content = '\n'.join(list(diff)[:1000])  # Limit to first 1000 lines
        if len(diff_content) > 1000:
            diff_content += "\n... (diff truncated, use full files for complete comparison)"
        
        (output_dir / "diff_summary.txt").write_text(diff_content)
        report += "\n## Quick Diff Summary\n\nSee `diff_summary.txt` for a sample of differences.\n"
    except Exception as e:
        report += f"\nNote: Automated diff generation failed: {e}\n"
    
    (output_dir / "COMPARISON_REPORT.md").write_text(report)
    print("  Created comparison report: COMPARISON_REPORT.md")


def batch_decompile(input_dir, output_dir=None):
    """Decompile all .bin files in a directory"""
    input_dir = Path(input_dir)
    
    if output_dir is None:
        output_dir = input_dir / "decompiled_all"
    else:
        output_dir = Path(output_dir)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    bin_files = list(input_dir.glob("*.bin"))
    
    if not bin_files:
        print(f"No .bin files found in {input_dir}")
        return
    
    print(f"\nFound {len(bin_files)} firmware file(s) to decompile\n")
    
    for i, bin_file in enumerate(bin_files, 1):
        print(f"\n[{i}/{len(bin_files)}] Processing: {bin_file.name}")
        try:
            decomp_dir = output_dir / bin_file.stem
            decompile_firmware(bin_file, decomp_dir)
        except Exception as e:
            print(f"Error processing {bin_file.name}: {e}")
            continue
    
    print(f"\n{'='*70}")
    print(f"Batch decompilation complete!")
    print(f"Results in: {output_dir}")
    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Decompile RT-950 Pro firmware binaries using Ghidra",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decompile a single firmware
  python decompile_firmware.py firmware.bin
  
  # Decompile to specific directory
  python decompile_firmware.py firmware.bin output/
  
  # Compare two firmware versions
  python decompile_firmware.py --compare v1.bin v2.bin
  
  # Batch decompile all .bin files in a directory
  python decompile_firmware.py --batch firmware_directory/
        """
    )
    
    parser.add_argument("input", nargs="?", help="Firmware .bin file or directory (for --batch)")
    parser.add_argument("output", nargs="?", help="Output directory (optional)")
    
    parser.add_argument("--compare", nargs=2, metavar=("FIRMWARE1", "FIRMWARE2"),
                       help="Compare two firmware versions")
    parser.add_argument("--batch", action="store_true",
                       help="Decompile all .bin files in input directory")
    
    args = parser.parse_args()
    
    try:
        if args.compare:
            compare_firmware(args.compare[0], args.compare[1], args.output)
        elif args.batch:
            if not args.input:
                parser.error("--batch requires input directory")
            batch_decompile(args.input, args.output)
        elif args.input:
            decompile_firmware(args.input, args.output)
        else:
            parser.print_help()
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

