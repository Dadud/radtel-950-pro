# Digital Modes & Encoding Features

Advanced digital communication modes that leverage the RT-950's hardware capabilities for exotic digital voice and data transmission.

## Overview

The RT-950 platform has several advantages for digital modes:
- **DAC Output** (PA4): Can generate arbitrary waveforms for modulation
- **ADC Input** (PA0, PA1): Can sample audio for demodulation
- **DMA Support**: Efficient audio streaming
- **Dual Transceivers** (Pro): Can implement diversity or dual-band modes
- **GPS**: Precise timing for synchronized protocols
- **Bluetooth**: External connectivity for TNC functionality

## Features

### 1. M17 Digital Voice Protocol

**Description**: M17 is an open-source digital voice protocol designed for amateur radio. It uses 4FSK modulation at 4800 baud and supports voice, data, and callsign encoding. Few commercial radios support M17 natively.

**Hardware Requirements**:
- DAC1 (PA4) for 4FSK modulation
- ADC2 (PA0) for demodulation
- BK4829 FM mode (M17 uses 4FSK over FM)
- GPS for timing synchronization (optional)

**Feasibility Assessment**: **MEDIUM**

**Reasoning**:
- ✅ DAC can generate 4FSK waveforms
- ✅ ADC can sample received audio
- ✅ MCU has sufficient processing power (240MHz Cortex-M4F)
- ⚠️ Codec 2 encoding/decoding requires significant CPU (but feasible)
- ⚠️ Real-time processing may require optimization
- ⚠️ Memory for codec buffers (~10-20KB)

**Implementation Notes**:
- Use DMA to stream audio samples to/from DAC/ADC
- Implement Codec 2 encoder/decoder (port from C library)
- 4FSK modulator: Map 2-bit symbols to 4 frequency offsets
- Demodulator: Use FFT or correlation to detect symbols
- Frame structure: Sync word + callsign + voice/data + CRC
- Integration: Add M17 mode to radio state machine

**Code Structure**:
```
src/digital_modes/
├── m17/
│   ├── m17_codec.c      # Codec 2 wrapper
│   ├── m17_modulator.c  # 4FSK modulation
│   ├── m17_demodulator.c # 4FSK demodulation
│   ├── m17_frame.c      # Frame encoding/decoding
│   └── m17.h
```

**Similar Features**:
- OpenRTX: M17 support in progress
- MMDVM: M17 hotspot implementation
- M17 reference implementation: C++ codebase

**References**:
- [M17 Specification](https://github.com/M17-Project/M17_spec)
- [M17 Reference Implementation](https://github.com/M17-Project/m17-cxx-demod)
- [Codec 2](https://github.com/drowe67/codec2)

---

### 2. FreeDV Integration

**Description**: FreeDV is an open-source digital voice mode using Codec 2. Unlike M17, FreeDV typically runs on a PC and uses audio I/O. RT-950 could integrate FreeDV by using Bluetooth audio input/output, making it a "FreeDV radio" without external PC.

**Hardware Requirements**:
- Bluetooth module (USART1) for audio streaming
- DAC1 (PA4) for audio output
- ADC2 (PA0) for audio input
- BK4829 FM mode

**Feasibility Assessment**: **MEDIUM**

**Reasoning**:
- ✅ Bluetooth can stream audio (if module supports A2DP)
- ✅ DAC/ADC available for audio processing
- ⚠️ Bluetooth module may not support A2DP (only serial)
- ⚠️ Would require external phone/PC for encoding (hybrid approach)
- ✅ Can implement "FreeDV TNC mode" via Bluetooth serial

**Implementation Notes**:
- **Hybrid Approach**: Phone app encodes FreeDV, radio transmits
- Bluetooth serial protocol: Send Codec 2 frames, receive audio
- Radio acts as "FreeDV modem" - handles RF, phone handles codec
- Alternative: Implement Codec 2 on radio (same as M17)
- Integration: Add FreeDV mode that uses Bluetooth for codec

**Code Structure**:
```
src/digital_modes/
├── freedv/
│   ├── freedv_tnc.c     # Bluetooth TNC protocol
│   ├── freedv_audio.c   # Audio I/O via Bluetooth
│   └── freedv.h
```

**Similar Features**:
- FreeDV on smartphones: Android/iOS apps
- FreeDV hardware: SM1000, SM2000 modems
- This would be unique: Integrated FreeDV in radio

**References**:
- [FreeDV Project](https://freedv.org/)
- [FreeDV Codec 2](https://github.com/drowe67/codec2)

---

### 3. LoRa-like Spread Spectrum Modes

**Description**: Implement LoRa-style chirp spread spectrum (CSS) or GFSK modulation using BK4829's frequency agility. While BK4829 doesn't support true LoRa, we can implement GFSK-based spread spectrum modes for improved range and interference rejection.

**Hardware Requirements**:
- BK4829 transceiver (frequency agility)
- DAC1 (PA4) for GFSK modulation
- ADC2 (PA0) for demodulation
- Fast frequency switching capability

**Feasibility Assessment**: **LOW-MEDIUM**

**Reasoning**:
- ✅ BK4829 supports frequency synthesis
- ⚠️ Frequency switching speed unknown (may be too slow for CSS)
- ✅ GFSK modulation feasible via DAC
- ⚠️ LoRa CSS requires very fast frequency sweeps (may not be possible)
- ✅ GFSK-based spread spectrum more feasible
- ⚠️ Requires significant signal processing

**Implementation Notes**:
- **GFSK Approach**: More feasible than true LoRa CSS
- Use DAC to generate GFSK waveform
- Implement frequency hopping pattern
- Demodulator: Correlate against known patterns
- Bandwidth: Use BK4829's wide bandwidth mode
- Integration: Add "Spread Spectrum" mode

**Code Structure**:
```
src/digital_modes/
├── spread_spectrum/
│   ├── gfsk_modulator.c  # GFSK modulation
│   ├── gfsk_demodulator.c # GFSK demodulation
│   ├── hopping_pattern.c # Frequency hopping
│   └── spread_spectrum.h
```

**Similar Features**:
- LoRa: Commercial spread spectrum
- This would be unique: LoRa-like on BK4829

**References**:
- [LoRa Specification](https://lora-alliance.org/)
- BK4829 datasheet frequency synthesis section

---

### 4. Advanced Morse Code (CW) Features

**Description**: Enhanced CW mode with auto-send/receive, waterfall integration, and advanced decoding. Most radios have basic CW, but few integrate it with waterfall displays and automatic decoding.

**Hardware Requirements**:
- DAC1 (PA4) for CW generation
- ADC2 (PA0) for audio sampling
- Display for waterfall
- Rotary encoder for speed control

**Feasibility Assessment**: **HIGH**

**Reasoning**:
- ✅ DAC can generate CW tones easily
- ✅ ADC can sample audio
- ✅ Waterfall display already planned
- ✅ MCU has sufficient processing
- ✅ Low memory requirements

**Implementation Notes**:
- Auto-send: Text-to-Morse conversion with timing
- Auto-receive: FFT-based tone detection + decoding
- Waterfall integration: Show CW signals on waterfall
- Speed detection: Auto-detect sending speed
- Integration: Enhance existing CW mode

**Code Structure**:
```
src/digital_modes/
├── cw/
│   ├── cw_encoder.c     # Text to Morse
│   ├── cw_decoder.c      # Morse to text
│   ├── cw_waterfall.c    # Waterfall integration
│   └── cw.h
```

**Similar Features**:
- FLDigi: Advanced CW decoding
- This would be unique: Integrated CW with waterfall

**References**:
- ITU-R M.1677-1: International Morse code
- FLDigi CW implementation

---

### 5. RTTY/Baudot Decoder

**Description**: Real-time RTTY (Radio Teletype) decoding with display on screen. RTTY uses FSK modulation (typically 170Hz shift). Few radios decode RTTY automatically.

**Hardware Requirements**:
- ADC2 (PA0) for audio sampling
- Display for text output
- FFT capability for tone detection

**Feasibility Assessment**: **HIGH**

**Reasoning**:
- ✅ ADC can sample audio
- ✅ FFT can detect tones (170Hz shift)
- ✅ MCU has DSP capabilities
- ✅ Low memory requirements
- ✅ Standard protocol (Baudot/ITA2)

**Implementation Notes**:
- Demodulator: Detect mark/space tones (2125Hz/2295Hz typical)
- Decoder: Baudot/ITA2 character set
- Display: Show decoded text on screen
- Integration: Add RTTY receive mode

**Code Structure**:
```
src/digital_modes/
├── rtty/
│   ├── rtty_demodulator.c # FSK demodulation
│   ├── rtty_decoder.c     # Baudot decoding
│   └── rtty.h
```

**Similar Features**:
- FLDigi: RTTY decoding
- This would be unique: Built-in RTTY decoder

**References**:
- ITA2 (Baudot) character set
- RTTY frequency standards

---

### 6. Packet Radio (AX.25) TNC

**Description**: Full AX.25 packet radio TNC functionality. Radio can send/receive AX.25 packets over FM. Bluetooth connection to phone/PC for higher-level protocols.

**Hardware Requirements**:
- DAC1 (PA4) for AFSK modulation (1200/2400 baud)
- ADC2 (PA0) for AFSK demodulation
- Bluetooth (USART1) for KISS protocol
- External SPI flash for packet storage

**Feasibility Assessment**: **MEDIUM**

**Reasoning**:
- ✅ DAC/ADC available
- ✅ AFSK modulation straightforward
- ✅ Bluetooth for KISS protocol
- ⚠️ AX.25 protocol implementation complex
- ✅ Can leverage existing KISS TNC code (from OEM firmware)

**Implementation Notes**:
- AFSK modulator: 1200Hz/2200Hz tones (Bell 202)
- AFSK demodulator: Tone detection + bit recovery
- AX.25: Frame encoding/decoding (HDLC)
- KISS protocol: Over Bluetooth serial
- Integration: Enhance existing KISS TNC mode

**Code Structure**:
```
src/digital_modes/
├── packet/
│   ├── afsk_modulator.c  # AFSK modulation
│   ├── afsk_demodulator.c # AFSK demodulation
│   ├── ax25_frame.c      # AX.25 protocol
│   ├── kiss_protocol.c   # KISS over Bluetooth
│   └── packet.h
```

**Similar Features**:
- Direwolf: Software TNC
- OEM firmware: Basic KISS TNC (buggy)
- This would fix: Full AX.25 implementation

**References**:
- [AX.25 Protocol](https://www.tapr.org/pdf/AX25.2.2.pdf)
- [KISS Protocol](https://www.ax25.net/kiss.aspx)
- Direwolf source code

---

### 7. WSPR Beacon Mode

**Description**: GPS-synchronized WSPR (Weak Signal Propagation Reporter) beacon transmission. WSPR uses precise timing and FSK modulation. Radio can act as automated WSPR beacon.

**Hardware Requirements**:
- GPS module for precise timing
- DAC1 (PA4) for FSK modulation
- BK4829 FM mode
- External SPI flash for logging

**Feasibility Assessment**: **HIGH**

**Reasoning**:
- ✅ GPS provides 1PPS timing
- ✅ DAC can generate FSK
- ✅ WSPR protocol well-documented
- ✅ Low bandwidth (1.46 Hz)
- ✅ Minimal processing required

**Implementation Notes**:
- GPS 1PPS: Use GPS for timing synchronization
- FSK modulator: 1.46 Hz shift, 1.46 baud
- Message encoding: Callsign + grid + power
- Transmission: Automated at specific times
- Integration: Add WSPR beacon mode

**Code Structure**:
```
src/digital_modes/
├── wspr/
│   ├── wspr_encoder.c   # WSPR message encoding
│   ├── wspr_modulator.c # FSK modulation
│   ├── wspr_scheduler.c # GPS timing
│   └── wspr.h
```

**Similar Features**:
- WSPR hardware: Various beacon kits
- This would be unique: Integrated WSPR in radio

**References**:
- [WSPR Protocol](https://wsprnet.org/)
- WSPR encoding algorithm

---

## Implementation Priority

1. **Quick Wins**: RTTY decoder, Advanced CW
2. **Medium Effort**: Packet Radio TNC, WSPR beacon
3. **Long-Term**: M17, FreeDV, LoRa-like modes

## Memory Requirements

- Codec 2 (M17/FreeDV): ~20KB RAM for buffers
- FFT processing: ~8KB RAM for FFT buffers
- Packet buffers: ~4KB RAM
- Total additional RAM: ~30-40KB (feasible with 96KB total)

## CPU Requirements

- Codec 2 encoding: ~20-30% CPU (240MHz MCU)
- FFT processing: ~10-15% CPU
- Demodulation: ~5-10% CPU
- Total: Manageable with proper optimization

---

**Status**: Research phase. Implementation feasibility verified against hardware capabilities.

