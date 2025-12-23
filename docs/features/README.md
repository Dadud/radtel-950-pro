# Exotic Feature Research & Ideas

This directory contains research and documentation for exotic, unique, and advanced features that could be implemented in the RT-950/RT-950 Pro firmware. These features go beyond standard ham radio functionality and explore capabilities that few commercial radios offer.

## Overview

The RT-950/RT-950 Pro hardware platform provides several advantages for implementing advanced features:

- **Dual BK4829 Transceivers** (Pro): VHF and UHF bands with independent control
- **Powerful MCU**: AT32F403A Cortex-M4F @ 240MHz with DSP capabilities
- **Rich Peripherals**: DAC, ADC, DMA, multiple UARTs, SPI, timers
- **GPS Module**: Built-in GPS with NMEA output
- **Bluetooth**: Serial Bluetooth module for external connectivity
- **320×240 Color Display**: RGB565 TFT with DMA support
- **External SPI Flash**: 16MB for data storage

## Feature Categories

### [Digital Modes & Encoding](DIGITAL_MODES.md)
Advanced digital communication modes including M17, FreeDV, LoRa-like modes, packet radio, and WSPR beaconing.

### [Signal Processing](SIGNAL_PROCESSING.md)
Advanced signal analysis features: waterfall displays, SNR/BER estimation, noise reduction, auto-notch filters, and spectral analysis.

### [UI/UX Enhancements](UI_UX_FEATURES.md)
User interface improvements: themes, customizable dashboards, animated transitions, data visualization, and context-sensitive help.

### [Connectivity & Integration](CONNECTIVITY.md)
Bluetooth and GPS integration features: APRS iGate, remote control, OTA updates, settings sync, voice recording, and GPS tracking.

### [Automation & Macros](AUTOMATION.md)
Automated operations: smart scanning, scheduled operations, conditional logic, macro recording, adaptive squelch, and frequency hopping.

### [Exotic Operational Modes](EXOTIC_MODES.md)
Unique operational modes: enhanced dual-watch, cross-band bridging, repeater directory, activity heatmaps, direction finding, and calibration modes.

### [Feasibility Matrix](FEASIBILITY_MATRIX.md)
Comprehensive comparison of all features: hardware requirements, code complexity, memory usage, CPU load, and implementation risk.

### [OpenRTX Port Feasibility](OPENTX_PORT_FEASIBILITY.md)
Analysis of porting OpenRTX firmware to RT-950/RT-950 Pro, including hardware compatibility, porting complexity, and stock firmware recovery methods.

## Implementation Priority

Features are categorized by implementation difficulty and impact:

- **Quick Wins**: Easy to implement, high user impact
- **Medium Effort**: Moderate complexity, unique features
- **Long-Term Projects**: Complex but potentially groundbreaking

## Hardware Capabilities

### Confirmed Hardware
- AT32F403ARGT7 MCU (1MB Flash, 96KB RAM)
- BK4829 #1 (VHF): Hardware SPI1, PE8 CS
- BK4829 #2 (UHF, Pro only): Software SPI, PE15 CS
- SI4732 FM/AM receiver (I2C)
- GPS module (USART3, 9600 baud NMEA)
- Bluetooth module (USART1, 115200 baud)
- 320×240 TFT display (8080 parallel, RGB565)
- External SPI flash (16MB)
- DAC1 (PA4) for audio generation
- ADC2 (PA0, PA1) for sensing
- DMA2 for display and audio

### Hardware Limitations
- Limited RAM (96KB total, ~38KB used for frame buffer)
- Single-core MCU (no multi-threading)
- Fixed BK4829 modulation modes (FM/AM primarily)
- No hardware FFT accelerator
- Limited external connectivity (Bluetooth only)

## Research Methodology

Each feature document includes:

1. **Description**: What the feature does and why it's exotic/unique
2. **Hardware Requirements**: Which peripherals/components are needed
3. **Feasibility Assessment**: HIGH/MEDIUM/LOW with detailed reasoning
4. **Implementation Notes**: Key technical considerations and challenges
5. **Code Structure**: Suggested code organization and architecture
6. **Similar Features**: Comparison to features in other radios/projects
7. **References**: Links to protocols, standards, or example implementations

## Contributing

When researching new features:

1. Verify hardware capabilities against pinout and datasheets
2. Consider memory and CPU constraints
3. Assess implementation complexity realistically
4. Document any assumptions or unknowns
5. Provide references to protocols or standards
6. Note any regulatory considerations (FCC, etc.)

## References

- [OpenRTX Firmware](https://github.com/openrtx/openrtx) - Open-source radio firmware
- [Quansheng UV-K5 Firmware](https://github.com/Trafficcone/uv-k5-firmware) - Custom firmware features
- [M17 Protocol](https://github.com/M17-Project/M17_spec) - Digital voice protocol
- [FreeDV](https://freedv.org/) - Digital voice codec
- [Direwolf](https://github.com/wb2osz/direwolf) - APRS software
- [BK4829 Datasheet](../BK4829-BEKEN.pdf) - RF transceiver specifications
- [AT32F403A Datasheet](https://www.arterytek.com/) - MCU specifications

## Status

This research is ongoing. Features are documented as they are researched and evaluated. Implementation status is tracked in individual feature documents.

---

**Note**: All features documented here are research ideas. Implementation feasibility must be verified against actual hardware before development begins.

