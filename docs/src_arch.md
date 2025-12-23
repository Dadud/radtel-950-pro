# Architecture Layer Documentation (`src/arch/`)

**AI Reasoning:** This document explains why the AI structured the architecture layer code as it did.

> **⚠️ This is AI-generated content - verify against hardware before use**

---

## Files Overview

| File | Purpose | AI Reasoning |
|------|---------|--------------|
| `startup_at32f403a.s` | Vector table, reset handler | Standard ARM Cortex-M startup pattern |
| `system_at32f403a.c` | System clock and peripheral init | Based on Artery SDK structure |
| `AT32F403AxG_FLASH.ld` | Linker script, memory layout | Derived from OEM firmware memory map |

---

## `startup_at32f403a.s` - Startup Assembly

### Why This Structure?

**AI Reasoning:**
- Follows standard ARM Cortex-M4F startup sequence
- Vector table format is defined by ARM architecture (can't be guessed)
- Reset handler jumps to `SystemInit()` which sets up clocks
- Exception handlers are stubs (can be implemented later)

**Source of Information:**
- ARM Cortex-M4 documentation (public architecture spec)
- Artery AT32 SDK reference (vendor-provided)
- Memory addresses from OEM firmware analysis

**Potential Issues:**
- Exception handlers may need different implementations
- Stack pointer initialization value assumed from memory map

---

## `system_at32f403a.c` - System Initialization

### Clock Configuration

**AI Reasoning:**
- AT32F403A can run at 240MHz (confirmed from datasheet)
- PLL configuration calculated from crystal frequency
- Clock tree setup follows Artery SDK patterns

**Confidence:** **MEDIUM** - Based on datasheet but exact register values may differ

### Memory Configuration

**AI Reasoning:**
- Flash base: 0x08000000 (standard ARM Cortex-M)
- RAM base: 0x20000000 (standard ARM Cortex-M)
- SRAM size: 96KB (from AT32F403A datasheet)
- Stack size: Estimated from frame buffer location (0x20000BD0) and RAM size

**Confidence:** **HIGH** - These are standard ARM addresses and confirmed from datasheet

**Potential Issues:**
- Stack size may need adjustment based on actual usage
- Heap size is guessed (may need tuning)

---

## `AT32F403AxG_FLASH.ld` - Linker Script

### Memory Layout

**AI Reasoning:**
```
FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 1024K
RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 96K
```

- Flash address confirmed from OEM firmware binary analysis
- RAM address is standard ARM Cortex-M location
- Sizes from AT32F403A datasheet

**Section Placement:**

**AI Reasoning:**
- `.text` (code) goes in FLASH
- `.data` (initialized variables) copied from FLASH to RAM at startup
- `.bss` (uninitialized variables) zeroed in RAM
- Stack grows downward from top of RAM (0x20018000 estimated)
- Heap grows upward from end of `.bss`

**Confidence:** **MEDIUM** - Standard embedded linker script pattern, but stack/heap boundaries may need adjustment

**Potential Issues:**
- Stack/heap collision possible if sizes are wrong
- Frame buffer location (0x20000BD0) must be preserved (don't allocate heap there)

---

## Key AI Assumptions

1. **Clock Configuration**: Assumed typical PLL setup, but exact register values may differ
2. **Stack Size**: Estimated from available RAM, may need hardware testing
3. **Memory Layout**: Based on standard ARM patterns, but OEM firmware may use custom layout
4. **Startup Sequence**: Follows Artery SDK reference, but OEM may have custom initialization

---

## Verification Needed

- [ ] Verify clock configuration produces 240MHz actual clock
- [ ] Measure actual stack usage to confirm stack size
- [ ] Verify frame buffer location doesn't conflict with heap
- [ ] Test exception handlers actually work
- [ ] Confirm reset handler sequence matches OEM behavior

