# RT-950 Pro Reverse Engineering

This folder contains reverse engineering artifacts for the Radtel RT-950 Pro firmware.

## Memory Map (AT32F403A)

The AT32F403ARGT7 MCU has the following memory layout:

| Region     | Start        | End          | Size   | Description              |
|------------|--------------|--------------|--------|--------------------------|
| Flash      | `0x08000000` | `0x080FFFFF` | 1 MB   | Internal flash memory    |
| SRAM       | `0x20000000` | `0x20017FFF` | 96 KB  | Internal SRAM            |
| Boot ROM   | `0x1FFFB000` | `0x1FFFEFFF` | 16 KB  | System memory (bootloader)|
| Peripherals| `0x40000000` | `0x50060BFF` | -      | APB1/APB2/AHB peripherals|

**IMPORTANT**: The firmware binary must be loaded at base address `0x08000000`, NOT `0x80000000`.

## Setting Up Ghidra Project (Correct Method)

### Step 1: Create New Project

1. Open Ghidra
2. **File → New Project** (or use existing non-shared project)
3. Name it something like `rt950pro-firmware`

### Step 2: Import Firmware Binary

1. **File → Import File**
2. Select `firmware/decrypted.bin`
3. In the Import dialog:
   - **Format**: `Raw Binary`
   - **Language**: `ARM:LE:32:Cortex` (ARM Cortex little-endian 32-bit)
   - Click **Options...**
   
4. In **Options** dialog:
   - **Base Address**: `0x08000000` ← **CRITICAL!**
   - **Block Name**: `FLASH`
   - Click **OK**

5. Click **OK** to import

### Step 3: Run Memory Map Setup Script

1. Open the imported program in the CodeBrowser
2. **Window → Script Manager** (or press the script icon)
3. Find and run `setup-artery-cortex-m-memory-map.py` from `firmware/scripts/`
   - Or: **File → Run Script** and navigate to it
4. The script will:
   - Create SRAM, peripheral, and other memory regions
   - Set the Reset_Handler entry point from the vector table
   - Configure proper read/write/execute permissions

### Step 4: Initial Analysis

1. **Analysis → Auto Analyze** (or press 'A')
2. Accept defaults and let Ghidra analyze
3. The vector table at `0x08000000` should now show proper function references

## Bootloader Import

For the bootloader binary (`firmware dumps/bootloader_dec.bin`):

1. Import as Raw Binary with language `ARM:LE:32:Cortex`
2. Base address: `0x08000000` (it runs from the same flash region)
3. The bootloader occupies roughly `0x08000000` - `0x08010000` (64KB)

## Key Addresses (Firmware)

| Address      | Description                           |
|--------------|---------------------------------------|
| `0x08000000` | Vector table (SP, Reset, NMI, etc.)   |
| `0x08000004` | Reset vector → entry point            |
| `0x0800B410` | CRC16-XMODEM function                 |
| `0x0800DF4C` | CDC TX frame builder                  |
| `0x0800E500` | CDC RX parser / frame assembler       |
| `0x0800EBBC` | Bootloader main loop/state machine    |
| `0x0801FDB8` | Flash chunk processing                |

## Directory Structure

```
RE/
├── README.md                    # This file
├── bootloader/
│   ├── bootloader_dump_dissassembled.c/.h  # Ghidra C export
│   └── bootloader_protocol_notes.md        # Protocol RE notes
├── decrypted-firmware/
│   └── firmware.gpr + firmware.rep/        # Ghidra project (needs reimport!)
└── firmware dumps/
    ├── bootloader_blob.bin      # Raw bootloader capture
    ├── bootloader_dec.bin       # Decrypted bootloader
    ├── firmware_app.bin         # Application firmware
    ├── fullflash_*.bin/txt      # Full flash dump captures
    ├── upgrade_*.bin/txt        # Upgrade packet captures
    └── usb_dump.pcapng          # USB traffic capture
```

## Common Issues

### Wrong Base Address (0x80000000 vs 0x08000000)

If you see function addresses like `FUN_800xxxxx` instead of `FUN_0800xxxx`, the binary was imported at the wrong base address. You need to:

1. Create a new Ghidra project
2. Reimport with base address `0x08000000`
3. DO NOT just change the memory block address - this breaks all analysis

### References Not Resolving

If cross-references to RAM (`0x2000xxxx`) or peripherals (`0x4000xxxx`) show as undefined:

1. Run the `setup-artery-cortex-m-memory-map.py` script
2. Re-run auto-analysis after the script completes

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/setup-artery-cortex-m-memory-map.py` | Ghidra script to configure AT32 memory regions |
| `scripts/fwcrypt_io.py` | Decrypt/encrypt BTF firmware files |
| `scripts/radtel_flash.py` | Flash firmware via USB CDC |

