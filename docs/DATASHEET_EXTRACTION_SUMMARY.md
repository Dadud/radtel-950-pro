# Datasheet Extraction Summary

## Files Processed

1. **BK4829-BEKEN.pdf** - BK4829 RF Transceiver Datasheet (DS-BK4829-E01 V1.0)
2. **RT950Pro.pdf** - RT-950 Pro Radio Schematic

## Key Updates Applied

### ✅ 1. Frequency Reference Correction

**Changed**: Crystal reference frequency from 12.8 MHz → **26 MHz**

- **File**: `src/drivers/bk4829.c`
- **Impact**: Frequency calculations now use correct 26 MHz reference
- **Source**: Confirmed in both datasheet and schematic (CY1 = 26 MHz crystal)

### ✅ 2. Documentation Updates

**Files Updated**:
- `src/drivers/bk4829.h` - Added confirmed specifications from datasheet
- `docs/pinout.md` - Updated with schematic findings (U11/U12, pin assignments)
- `docs/BK4829_DATASHEET_FINDINGS.md` - Created detailed findings document
- `docs/DATASHEET_UPDATES_APPLIED.md` - Created change log

### ✅ 3. Pin Assignments Confirmed

**From Schematic**:
- BK4829 U11: PE8 (SEN1), PE10 (SCK), PE11 (SDATA)
- BK4829 U12: PE15 (SEN2), PE10 (SCK shared), PE11 (SDATA shared)
- Signal names: RDA_SCK, RDA_SDA, RDA_SEN
- Crystal: CY1 = 26 MHz

## Important Findings

### Crystal Oscillator
- **26 MHz** (NOT 12.8 MHz as previously inferred)
- Parallel resonant mode
- ±2.5 ppm tolerance required

### Frequency Range
- **Band 1**: 18-580 MHz
- **Band 2**: 760-1160 MHz
- Channel spacing: 12.5/25/6.25/20 kHz

### SPI Interface
- 3-wire: SCK, SCN (CS), SDATA
- Max clock: 8 MHz
- Data latched on SCK rising edge
- Data output on SCK falling edge

### Power Specifications
- Supply: 3.0-3.6 V (3.3 V typical)
- RX current: 49 mA typical
- TX current: 43 mA typical
- TX power: -5 to +8 dBm (on-chip 7 dBm PA)
- RX sensitivity: -124 dBm typical

## Notes

### Code Discrepancy

There's a potential discrepancy in the code:
- **Code shows**: BK4829 #1 (VHF) uses hardware SPI1
- **Schematic shows**: Both chips use GPIOE (software SPI)

The current code structure supports both, but this should be verified with actual hardware. The schematic clearly shows both U11 and U12 using the same GPIOE SPI bus with separate chip selects.

### Frequency Formula

The datasheet provides these formulas:
- **RX mode**: f_locked = Ndiv × (fwanted - fIF)
- **TX mode**: f_locked = Ndiv × fwanted

The current implementation uses a simplified calculation. The exact register programming requires the full register map (not in public datasheet excerpt).

## Testing Recommendations

1. **Frequency Accuracy**: Verify frequency setting with corrected 26 MHz reference
2. **SPI Configuration**: Verify if both chips actually use software SPI (as schematic suggests) or if hardware SPI is used
3. **Register Values**: Compare initialization sequence with datasheet recommendations

## Files Created/Modified

**Created**:
- `docs/BK4829_DATASHEET_FINDINGS.md`
- `docs/DATASHEET_UPDATES_APPLIED.md`
- `docs/DATASHEET_EXTRACTION_SUMMARY.md` (this file)
- `docs/BK4829-BEKEN.txt` (extracted text)
- `docs/RT950Pro.txt` (extracted text)
- `scripts/extract_pdf_info.py` (PDF extraction tool)

**Modified**:
- `src/drivers/bk4829.c` (frequency reference updated)
- `src/drivers/bk4829.h` (documentation updated)
- `docs/pinout.md` (schematic findings applied)

---

**Status**: All major findings from datasheets have been extracted and applied to the codebase.

