#!/usr/bin/env python3
"""
RT-950 Pro Firmware Processing Script

Complete automated workflow for processing RT-950 Pro firmware:
1. Download/use BTF firmware file
2. Decrypt BTF to binary
3. Decompile using Ghidra
4. Organize output

Usage:
    # Process a BTF file you already have
    python process_firmware.py --btf path/to/firmware.BTF
    
    # Process latest firmware (downloads from URL)
    python process_firmware.py --latest
    
    # Specify output directory
    python process_firmware.py --btf firmware.BTF --output output_dir/
    
    # Compare with existing version
    python process_firmware.py --btf v0.24.BTF --compare-with v0.18.bin
"""

import os
import sys
import subprocess
import argparse
import shutil
from pathlib import Path
from datetime import datetime
import urllib.request
import urllib.parse

# Script configuration
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
FIRMWARE_DIR = PROJECT_ROOT / "firmware"
SCRIPTS_DIR = FIRMWARE_DIR / "scripts"
RE_DIR = FIRMWARE_DIR / "RE"

# URLs for firmware downloads (update these with actual URLs if available)
FIRMWARE_BASE_URL = "https://example.com/firmware/"  # Update with actual URL
LATEST_FIRMWARE_URL = None  # Set to actual download URL

# Default paths (auto-detected)
DECRYPT_SCRIPT = SCRIPTS_DIR / "fwcrypt_io.py"
DECOMPILE_SCRIPT = SCRIPTS_DIR / "decompile_firmware.py"


def find_firmware_downloads():
    """Find BTF files in Downloads directory"""
    downloads_paths = [
        Path.home() / "Downloads",
        Path("C:/Users") / os.getenv("USERNAME", "") / "Downloads",
    ]
    
    for dl_path in downloads_paths:
        if dl_path.exists():
            btf_files = list(dl_path.glob("**/*.BTF"))
            btf_files.extend(list(dl_path.glob("**/*.btf")))
            if btf_files:
                return sorted(btf_files, key=lambda p: p.stat().st_mtime, reverse=True)
    return []


def download_firmware(url, output_path):
    """Download firmware from URL"""
    print(f"Downloading firmware from {url}...")
    try:
        urllib.request.urlretrieve(url, output_path)
        print(f"Downloaded to: {output_path}")
        return True
    except Exception as e:
        print(f"Download failed: {e}")
        return False


def decrypt_btf(btf_path, output_path=None):
    """
    Decrypt BTF file to binary
    
    Args:
        btf_path: Path to BTF file
        output_path: Path for decrypted binary (default: same name with .bin extension)
    
    Returns:
        Path to decrypted binary, or None on error
    """
    btf_path = Path(btf_path).resolve()
    
    if not btf_path.exists():
        raise FileNotFoundError(f"BTF file not found: {btf_path}")
    
    if output_path is None:
        output_path = btf_path.parent / f"{btf_path.stem}_decrypted.bin"
    else:
        output_path = Path(output_path)
    
    print(f"\n{'='*70}")
    print(f"Step 1/3: Decrypting BTF file")
    print(f"{'='*70}")
    print(f"Input:  {btf_path.name}")
    print(f"Output: {output_path.name}")
    print()
    
    # Run decryption script
    cmd = [
        sys.executable,
        str(DECRYPT_SCRIPT),
        "--infile", str(btf_path),
        "--outfile", str(output_path),
        "--verbose"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Decryption failed:\n{result.stderr}")
        return None
    
    if output_path.exists():
        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"\n✓ Decryption successful!")
        print(f"  Decrypted binary: {output_path.name} ({size_mb:.2f} MB)")
        return output_path
    else:
        print("✗ Decryption failed: output file not created")
        return None


def decompile_binary(bin_path, output_dir=None, version_tag=None):
    """
    Decompile binary using Ghidra
    
    Args:
        bin_path: Path to decrypted binary
        output_dir: Output directory (default: RE/analysis_<version>)
        version_tag: Version tag for directory naming
    
    Returns:
        Path to output directory, or None on error
    """
    bin_path = Path(bin_path).resolve()
    
    if not bin_path.exists():
        raise FileNotFoundError(f"Binary file not found: {bin_path}")
    
    # Determine output directory
    if output_dir is None:
        if version_tag:
            output_dir = RE_DIR / f"analysis_v{version_tag}"
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = RE_DIR / f"analysis_{timestamp}"
    else:
        output_dir = Path(output_dir)
    
    print(f"\n{'='*70}")
    print(f"Step 2/3: Decompiling firmware")
    print(f"{'='*70}")
    print(f"Input:  {bin_path.name}")
    print(f"Output: {output_dir}")
    print()
    
    # Run decompile script
    cmd = [
        sys.executable,
        str(DECOMPILE_SCRIPT),
        str(bin_path),
        str(output_dir)
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Decompilation failed:\n{result.stderr}")
        # Check if it partially succeeded
        if output_dir.exists() and any(output_dir.glob("*.c")):
            print("Partial success - some files were created")
            return output_dir
        return None
    
    # Verify output files exist
    c_file = output_dir / f"{bin_path.stem}.c"
    if not c_file.exists():
        # Try alternative naming
        c_files = list(output_dir.glob("*.c"))
        if not c_files:
            print("Warning: C file not found in output")
            return output_dir
    
    print(f"\n✓ Decompilation successful!")
    print(f"  Output directory: {output_dir}")
    return output_dir


def extract_version_from_filename(filename):
    """Extract version number from filename"""
    import re
    # Look for patterns like V0.24, v0.24, 0.24, etc.
    match = re.search(r'[vV]?(\d+)\.(\d+)', str(filename))
    if match:
        return f"{match.group(1)}.{match.group(2)}"
    return None


def create_summary(output_dir, btf_path, bin_path, version_tag=None):
    """Create summary README in output directory"""
    btf_path = Path(btf_path)
    bin_path = Path(bin_path)
    
    # Find C and listing files
    c_file = next(output_dir.glob("*.c"), None)
    lst_file = next(output_dir.glob("*.lst"), None)
    
    summary = f"""# RT-950 Pro Firmware Analysis

## Firmware Information

- **Source BTF**: {btf_path.name}
- **Decrypted Binary**: {bin_path.name}
"""
    
    if version_tag:
        summary += f"- **Version**: {version_tag}\n"
    
    summary += f"""- **Size**: {bin_path.stat().st_size / 1024:.2f} KB
- **Base Address**: 0x08000000
- **Processor**: ARM:LE:32:Cortex (ARM Cortex-M4)
- **Processed**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Files

- `{bin_path.name}` - Decrypted firmware binary
"""
    
    if c_file:
        summary += f"- `{c_file.name}` - Decompiled C code ({c_file.stat().st_size / (1024*1024):.2f} MB)\n"
    if lst_file:
        summary += f"- `{lst_file.name}` - Assembly listing ({lst_file.stat().st_size / (1024*1024):.2f} MB)\n"
    
    summary += """- `README.md` - This file

## Memory Map

- Flash: `0x08000000` - `0x080FFFFF` (1 MB)
- SRAM: `0x20000000` - `0x20017FFF` (96 KB)

## Notes

- All function addresses use correct format: `FUN_0800xxxx`
- This firmware was processed using the automated workflow
- For comparison with other versions, see `firmware/RE/COMPARISON_GUIDE.md`

## Processing Workflow

This firmware was processed using:
1. BTF decryption (`fwcrypt_io.py`)
2. Ghidra decompilation (`decompile_firmware.py`)

To reprocess or update:
```bash
python firmware/scripts/process_firmware.py --btf path/to/firmware.BTF
```
"""
    
    (output_dir / "README.md").write_text(summary)
    print(f"  Created README.md")


def process_firmware(btf_path, output_dir=None, version_tag=None, keep_binary=True):
    """
    Complete firmware processing workflow
    
    Args:
        btf_path: Path to BTF file
        output_dir: Output directory for decompiled files
        version_tag: Version tag (extracted from filename if not provided)
        keep_binary: Keep decrypted binary in output directory
    
    Returns:
        Tuple of (decrypted_binary_path, output_directory_path)
    """
    btf_path = Path(btf_path).resolve()
    
    # Extract version if not provided
    if version_tag is None:
        version_tag = extract_version_from_filename(btf_path.name)
    
    # Ensure output directory exists
    if output_dir:
        output_dir = Path(output_dir)
    else:
        if version_tag:
            output_dir = RE_DIR / f"analysis_v{version_tag}"
        else:
            output_dir = RE_DIR / f"analysis_{datetime.now().strftime('%Y%m%d')}"
    
    RE_DIR.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*70}")
    print(f"RT-950 Pro Firmware Processing")
    print(f"{'='*70}")
    if version_tag:
        print(f"Version: {version_tag}")
    print(f"BTF File: {btf_path.name}")
    print(f"Output: {output_dir}")
    print(f"{'='*70}")
    
    # Step 1: Decrypt
    decrypted_bin = output_dir / f"{btf_path.stem}_decrypted.bin"
    decrypted_path = decrypt_btf(btf_path, decrypted_bin)
    
    if not decrypted_path:
        return None, None
    
    # Step 2: Decompile
    decompiled_dir = decompile_binary(decrypted_path, output_dir, version_tag)
    
    if not decompiled_dir:
        return decrypted_path, None
    
    # Step 3: Organize and create summary
    print(f"\n{'='*70}")
    print(f"Step 3/3: Organizing output")
    print(f"{'='*70}")
    
    # Move binary to output if it's not already there
    if decrypted_path.parent != decompiled_dir:
        dest_bin = decompiled_dir / decrypted_path.name
        if not dest_bin.exists() and keep_binary:
            shutil.copy2(decrypted_path, dest_bin)
            print(f"  Copied binary to output directory")
        # Clean up temp binary if requested
        if not keep_binary and decrypted_path.exists():
            decrypted_path.unlink()
    
    # Create summary
    create_summary(decompiled_dir, btf_path, decrypted_path, version_tag)
    
    print(f"\n{'='*70}")
    print(f"✓ Processing Complete!")
    print(f"{'='*70}")
    print(f"Output directory: {decompiled_dir}")
    print(f"\nNext steps:")
    print(f"  - Review decompiled code: {decompiled_dir}/*.c")
    print(f"  - Compare with other versions (see COMPARISON_GUIDE.md)")
    
    return decrypted_path, decompiled_dir


def compare_with_existing(new_btf_path, existing_bin_path, output_dir=None):
    """Process new firmware and compare with existing version"""
    # Process new firmware first
    new_decrypted, new_dir = process_firmware(new_btf_path, version_tag=extract_version_from_filename(new_btf_path.name))
    
    if not new_dir:
        print("Failed to process new firmware")
        return None
    
    # Use decompile script's compare function
    existing_bin_path = Path(existing_bin_path).resolve()
    
    if output_dir is None:
        existing_version = extract_version_from_filename(existing_bin_path.name) or "existing"
        new_version = extract_version_from_filename(new_btf_path.name) or "new"
        output_dir = RE_DIR / f"comparison_{existing_version}_vs_{new_version}"
    
    print(f"\n{'='*70}")
    print(f"Creating comparison...")
    print(f"{'='*70}")
    
    cmd = [
        sys.executable,
        str(DECOMPILE_SCRIPT),
        "--compare",
        str(existing_bin_path),
        str(new_decrypted),
        str(output_dir)
    ]
    
    subprocess.run(cmd)
    
    return output_dir


def main():
    parser = argparse.ArgumentParser(
        description="Complete RT-950 Pro firmware processing workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process a BTF file you downloaded
  python process_firmware.py --btf Downloads/RT_950Pro_V0.24_251201.BTF
  
  # Process and extract version automatically
  python process_firmware.py --btf firmware.BTF --output RE/v0.24
  
  # Process latest from Downloads folder
  python process_firmware.py --latest
  
  # Compare with existing version
  python process_firmware.py --btf v0.24.BTF --compare-with RE/analysis_v0.18/decrypted.bin
        """
    )
    
    parser.add_argument("--btf", type=str, help="Path to BTF firmware file")
    parser.add_argument("--latest", action="store_true", 
                       help="Process latest BTF file from Downloads folder")
    parser.add_argument("--output", "-o", type=str, 
                       help="Output directory for decompiled files")
    parser.add_argument("--version", "-v", type=str,
                       help="Version tag (auto-detected from filename if not provided)")
    parser.add_argument("--compare-with", type=str,
                       help="Compare with existing decompiled binary")
    parser.add_argument("--download-url", type=str,
                       help="URL to download latest firmware (if available)")
    parser.add_argument("--no-keep-binary", action="store_true",
                       help="Don't keep decrypted binary in output (saves space)")
    
    args = parser.parse_args()
    
    # Determine BTF file to process
    btf_path = None
    
    if args.btf:
        btf_path = Path(args.btf)
    elif args.latest:
        # Find latest BTF in Downloads
        btf_files = find_firmware_downloads()
        if btf_files:
            btf_path = btf_files[0]
            print(f"Found latest BTF: {btf_path.name}")
        else:
            print("No BTF files found in Downloads folder")
            print("Please specify --btf path/to/firmware.BTF")
            sys.exit(1)
    elif args.download_url:
        # Download firmware
        downloads_dir = Path.home() / "Downloads"
        filename = Path(urllib.parse.urlparse(args.download_url).path).name
        btf_path = downloads_dir / filename
        if not download_firmware(args.download_url, btf_path):
            sys.exit(1)
    else:
        parser.print_help()
        print("\nError: Must specify --btf, --latest, or --download-url")
        sys.exit(1)
    
    try:
        if args.compare_with:
            # Comparison mode
            compare_with_existing(btf_path, args.compare_with, args.output)
        else:
            # Normal processing mode
            process_firmware(
                btf_path, 
                output_dir=args.output,
                version_tag=args.version,
                keep_binary=not args.no_keep_binary
            )
            
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


