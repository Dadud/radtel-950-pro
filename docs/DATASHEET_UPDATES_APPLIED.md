# Datasheet Updates Applied to Project

## Summary

Information extracted from `BK4829-BEKEN.pdf` and `RT950Pro.pdf` has been applied to the project codebase and documentation.

## Changes Made

### 1. Frequency Calculation Updated (`src/drivers/bk4829.c`)

**Before**: Assumed 12.8 MHz crystal reference
```c
uint32_t fref = 12800000;
```

**After**: Uses 26 MHz crystal reference (CONFIRMED from datasheet)
```c
uint32_t fref = 26000000;
```

**Impact**: Frequency calculations will now be accurate. The BK4829 uses a 26 MHz crystal oscillator, and all PLL calculations must use this reference frequency.

### 2. Header Documentation Updated (`src/drivers/bk4829.h`)

Added confirmed specifications from datasheet:
- Crystal reference: 26 MHz
- Frequency range: 18-580 MHz, 760-1160 MHz  
- SPI: 3-wire interface (SCK, SCN, SDATA), max 8 MHz
- TX power: -5 to +8 dBm (on-chip 7 dBm PA)
- RX sensitivity: -124 dBm typical

Added SPI interface details:
- SCK (Pin 25): Clock, max 8 MHz
- SCN (Pin 26): Chip select/enable
- SDATA (Pin 27): Bidirectional data
- Timing: Data latched on SCK rising edge, output on falling edge

### 3. Pinout Documentation Updated (`docs/pinout.md`)

Updated BK4829 entries with confirmed information from schematic:
- BK4829 #1 (U11): PE8 SEN1, PE10 SCK, PE11 SDATA
- BK4829 #2 (U12): PE15 SEN2, PE10 SCK (shared), PE11 SDATA (shared)
- Confirmed signal names: RDA_SCK, RDA_SDA, RDA_SEN
- Confirmed 26 MHz crystal usage

## Key Findings from Datasheets

### BK4829 Specifications (CONFIRMED)

1. **Crystal Oscillator**: 26 MHz (parallel resonant, ±2.5 ppm tolerance)
2. **Frequency Range**: 
   - Band 1: 18-580 MHz
   - Band 2: 760-1160 MHz
3. **Channel Spacing**: 12.5/25/6.25/20 kHz
4. **Power Supply**: 3.0-3.6 V (3.3 V typical)
5. **Current Consumption**:
   - RX: 49 mA typical
   - TX: 43 mA typical
   - Power down: 30 μA typical
6. **TX Power**: -5 to +8 dBm programmable (on-chip 7 dBm PA)
7. **RX Sensitivity**: -124 dBm typical
8. **SPI Interface**:
   - 3-wire (SCK, SCN, SDATA)
   - Max clock: 8 MHz
   - Data latched on SCK rising edge
   - Data output on SCK falling edge

### RT950Pro Schematic Findings (CONFIRMED)

1. **Two BK4829 Chips**: U11 and U12
2. **Shared SPI Bus**: Both chips share SCK (PE10) and SDATA (PE11)
3. **Separate Chip Selects**: 
   - U11: PE8 (SEN1)
   - U12: PE15 (SEN2)
4. **Crystal**: CY1 = 26 MHz (matches datasheet)
5. **Signal Names**: RDA_SCK, RDA_SDA, RDA_SEN (RDA = Radio)
6. **Power Rails**: 3V3_RDA, 3V3_RF, 5V, PA, BAT

## Remaining Work / Notes

### Frequency Formula

The datasheet provides these formulas:
- **RX mode**: f_locked = Ndiv × (fwanted - fIF)
- **TX mode**: f_locked = Ndiv × fwanted

The current implementation uses a simplified fractional-N calculation. The exact register programming for Ndiv and fIF values requires the full register map (not provided in public datasheet excerpt).

**TODO**: Verify frequency calculation accuracy with actual hardware testing.

### Register Map

The public datasheet excerpt does not include the full register map with bit field definitions. Current register usage is still inferred from OEM firmware analysis.

### SPI Implementation

Current code implementation should be verified against datasheet timing requirements:
- SCN setup to SCK↑: 20 ns minimum
- SDATA hold after SCK↑: 10 ns minimum
- SCK frequency: 0-8 MHz
- SCK high/low time: 25 ns minimum

## Files Modified

1. `src/drivers/bk4829.c` - Updated frequency reference to 26 MHz
2. `src/drivers/bk4829.h` - Added confirmed specifications and SPI details
3. `docs/pinout.md` - Updated with schematic findings
4. `docs/BK4829_DATASHEET_FINDINGS.md` - Created (detailed findings document)
5. `docs/DATASHEET_UPDATES_APPLIED.md` - This file

## Verification Status

✅ **Crystal frequency**: 26 MHz (confirmed from both datasheet and schematic)
✅ **SPI interface**: 3-wire confirmed (SCK, SCN, SDATA)
✅ **Chip count**: Two BK4829 chips confirmed (U11, U12)
✅ **CS pins**: PE8 and PE15 confirmed from schematic
✅ **Signal names**: RDA_SCK, RDA_SDA confirmed

⚠️ **Frequency formula**: Simplified implementation; full formula requires register map
⚠️ **Register definitions**: Still inferred from OEM firmware (register map not in public datasheet)

## Testing Recommendations

1. **Frequency Accuracy**: Test frequency setting with 26 MHz reference to verify calculations
2. **SPI Timing**: Verify SPI timing meets datasheet requirements (especially at higher clock rates)
3. **Register Values**: Compare current register initialization values with datasheet recommendations (if available)

