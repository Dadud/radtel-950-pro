# BK4829 Datasheet Findings

## Key Information Extracted from BK4829-BEKEN.pdf

### Crystal Oscillator
- **Reference Frequency**: 26 MHz (NOT 12.8 MHz as previously inferred)
- Crystal tolerance: ±2.5 ppm required
- Crystal connection: Parallel resonant mode
- Load capacitance matching required

### Frequency Range
- **Band 1**: 18 MHz ~ 580 MHz
- **Band 2**: 760 MHz ~ 1160 MHz
- Channel spacing: 12.5/25/6.25/20 kHz

### Frequency Synthesizer
- Uses fractional-N PLL
- In RX mode: locked frequency = Ndiv × (fwanted - fIF)
- In TX mode: locked frequency = Ndiv × fwanted
- Settling time: < 0.3 ms on channel change
- Reference: 26 MHz from crystal oscillator

### SPI Interface (3-Wire)
- **SCK** (Pin 25): SPI clock, max 8 MHz
- **SCN** (Pin 26): SPI enable/chip select
- **SDATA** (Pin 27): SPI data (bidirectional)
- Timing:
  - Data latched on SCK **rising edge**
  - Data output on SCK **falling edge**
  - SCN setup to SCK↑: 20 ns
  - SDATA hold after SCK↑: 10 ns

### Power Specifications
- Supply voltage: 3.0 V to 3.6 V (recommended: 3.3 V typical)
- RX current: 49 mA typical
- TX current: 43 mA typical
- Power down: 30 μA typical

### Transmitter
- Output power: -5 dBm to +8 dBm (programmable)
- On-chip 7 dBm RF PA
- FM modulation (constant envelope)
- Works in saturated mode for efficiency

### Receiver
- Low-IF image rejection architecture
- Sensitivity: -124 dBm typical (-123 dBm min)
- SINAD: 53 dB
- AGC: Automatic gain control for LNA and VGA

### Pin Assignments (QFN32 Package)
- Pin 25: SCK (SPI clock)
- Pin 26: SCN (SPI enable/CS)
- Pin 27: SDATA (SPI data)
- Pin 3, 11: VCC (Digital/Analog power)
- Pin 4: XO (Crystal output)
- Pin 5: XI (Crystal input)
- Pin 8: EARO (Earpiece output)
- Pin 13: MICN (Microphone input, negative)
- Pin 14: MICP (Microphone input, positive)
- Pin 15: LNAIN (LNA input)
- Pin 17: PAOUT (PA output)
- Pin 18: VRAMP (Programmable PA bias, 0-3.2V)
- Pins 28-32: GPIO0-4 (GPIO with internal pull-down)

---

## RT950Pro Schematic Findings

### BK4829 Connections
- **U11**: BK4829 #1 (likely VHF)
- **U12**: BK4829 #2 (likely UHF)
- Signal names:
  - `RDA_SCK` - SPI clock
  - `RDA_SDA` - SPI data  
  - `RDA_SEN2` - SPI enable/CS (note: schematic shows SEN2, may be SEN for one chip)

### Crystal
- **CY1**: 26 MHz crystal (confirmed matches datasheet)

### Power Rails
- `3V3_RDA` - 3.3V for BK4829 (RDA = Radio?)
- `3V3_RF` - 3.3V for RF section
- `5V` - 5V power rail
- `PA` - Power amplifier supply
- `BAT` - Battery voltage

### RF Path
- Extensive matching networks with inductors and capacitors
- External PA stages (Q14, Q16, Q20, Q21, etc.)
- RF switches (Q24, Q25, Q26 - UMC4N)
- Filters and matching components

---

## Impact on Code

### Required Updates

1. **Frequency Calculation**: Currently assumes 12.8 MHz reference, should use **26 MHz**
2. **SPI Timing**: Verify timing matches datasheet (latch on rising edge, output on falling edge)
3. **Crystal Value**: Update documentation to reflect 26 MHz crystal
4. **Register Definitions**: Can verify register usage against datasheet specifications

### Frequency Formula Correction

Current (incorrect) assumption:
```
Frequency = (N + F/65536) * 12800000
```

Should be (with 26 MHz reference):
```
Frequency = (N + F/65536) * 26000000
```

However, the actual formula from datasheet:
- RX: f_locked = Ndiv × (fwanted - fIF)
- TX: f_locked = Ndiv × fwanted

The exact register programming requires datasheet register map (not in public datasheet excerpt).

