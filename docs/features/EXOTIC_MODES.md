# Exotic Operational Modes

Unique operational modes that leverage the RT-950's hardware in creative ways.

## Overview

The RT-950 platform provides:
- **Dual BK4829 Transceivers** (Pro): VHF and UHF bands
- **GPS Module**: Position and timing
- **Display**: 320×240 for visualization
- **External SPI Flash**: Data storage
- **Rich Peripherals**: ADC, DAC, DMA, timers

## Features

### 1. Enhanced Dual-Watch with Priority Switching

**Description**: Monitor multiple frequencies simultaneously with intelligent priority switching. RT-950 Pro can use both transceivers for true dual-watch.

**Hardware Requirements**:
- Dual BK4829 transceivers (Pro only)
- Priority logic
- Audio mixing/routing

**Feasibility Assessment**: **HIGH**

**Reasoning**:
- ✅ Dual transceivers available (Pro)
- ✅ Can monitor two frequencies simultaneously
- ✅ Priority logic straightforward
- ✅ Audio routing feasible
- ✅ Easy to implement

**Implementation Notes**:
- **Dual Monitoring**:
  - VHF transceiver: Frequency A
  - UHF transceiver: Frequency B
  - Both active simultaneously
- **Priority Switching**:
  - Define priority for each frequency
  - Switch audio to higher priority when signal detected
  - Visual indicator of active frequency
- **Audio Routing**:
  - Mix both audio streams
  - Or switch between them
- **Integration**: Enhance dual-watch mode

**Code Structure**:
```
src/radio/
├── dual_watch/
│   ├── dual_monitor.c         # Dual monitoring
│   ├── priority_handler.c     # Priority logic
│   └── dual_watch.h
```

**Similar Features**:
- Some radios: Dual-watch
- This would be unique: True dual-band dual-watch

**References**:
- Dual-watch implementations

---

### 2. Cross-Band Bridge/Repeater Mode

**Description**: RT-950 Pro can receive on one band (VHF) and retransmit on another (UHF), acting as a cross-band bridge. Useful for extending range or bridging different systems.

**Hardware Requirements**:
- Dual BK4829 transceivers (Pro only)
- Audio routing between transceivers
- TX/RX coordination

**Feasibility Assessment**: **MEDIUM**

**Reasoning**:
- ✅ Dual transceivers available (Pro)
- ✅ Audio routing feasible
- ⚠️ TX/RX coordination needed
- ⚠️ May need audio processing
- ✅ Feasible with proper design

**Implementation Notes**:
- **Bridge Logic**:
  - Receive on VHF transceiver
  - Detect signal (squelch open)
  - Transmit on UHF transceiver
  - Route audio between transceivers
- **Coordination**:
  - Prevent simultaneous TX on both bands
  - Handle timing delays
  - Manage audio levels
- **Integration**: Add bridge mode

**Code Structure**:
```
src/radio/
├── bridge/
│   ├── cross_band_bridge.c    # Bridge logic
│   ├── audio_router.c          # Audio routing
│   └── bridge.h
```

**Similar Features**:
- Some radios: Cross-band repeat
- This would be unique: Built-in bridge mode

**References**:
- Repeater/bridge implementations

---

### 3. Built-in Repeater Directory with GPS Lookup

**Description**: Repeater database stored in radio with GPS-based automatic lookup. Radio suggests nearest repeaters based on current position.

**Hardware Requirements**:
- GPS module (USART3)
- External SPI flash for database
- Repeater database format

**Feasibility Assessment**: **MEDIUM**

**Reasoning**:
- ✅ GPS available
- ✅ External flash available
- ⚠️ Database management needed
- ⚠️ Lookup algorithm design
- ✅ Feasible with proper design

**Implementation Notes**:
- **Database Format**:
  - Repeater entries: Frequency, offset, tone, coordinates, name
  - Store in external SPI flash
  - Update via Bluetooth/PC
- **GPS Lookup**:
  - Calculate distance to each repeater
  - Sort by distance
  - Display nearest repeaters
- **Integration**: Add repeater directory menu

**Code Structure**:
```
src/radio/
├── repeater/
│   ├── repeater_db.c         # Database management
│   ├── gps_lookup.c           # GPS-based lookup
│   └── repeater.h
```

**Similar Features**:
- Some radios: Repeater lists
- This would be unique: GPS-based auto-lookup

**References**:
- Repeater database formats

---

### 4. Band Activity Heatmap

**Description**: Visual heatmap showing frequency usage over time. Display shows which frequencies are busiest, helping identify active channels.

**Hardware Requirements**:
- BK4829 RSSI for signal detection
- Display (320×240) for visualization
- External SPI flash for history

**Feasibility Assessment**: **MEDIUM**

**Reasoning**:
- ✅ RSSI available
- ✅ Display available
- ✅ External flash for storage
- ⚠️ Visualization code needed
- ✅ Feasible with proper design

**Implementation Notes**:
- **Data Collection**:
  - Scan frequencies periodically
  - Record RSSI for each frequency
  - Store statistics over time
- **Visualization**:
  - Color-coded heatmap (frequency vs time)
  - Show activity intensity
  - Allow time range selection
- **Integration**: Add heatmap mode

**Code Structure**:
```
src/radio/
├── analysis/
│   ├── activity_heatmap.c    # Heatmap generation
│   ├── heatmap_display.c      # Visualization
│   └── analysis.h
```

**Similar Features**:
- SDR software: Activity displays
- This would be unique: On radio

**References**:
- Data visualization techniques

---

### 5. Signal Direction Finding (Mobile DF)

**Description**: Use GPS movement + signal strength measurements to estimate signal direction. Requires moving receiver.

**Hardware Requirements**:
- GPS module (USART3)
- BK4829 RSSI
- Movement tracking

**Feasibility Assessment**: **LOW-MEDIUM**

**Reasoning**:
- ✅ GPS available
- ✅ RSSI available
- ⚠️ Requires movement
- ⚠️ Limited accuracy with single antenna
- ⚠️ Complex algorithms
- ✅ Possible but limited

**Implementation Notes**:
- **Mobile DF**:
  - Record GPS position + RSSI over time
  - Calculate bearing from signal strength pattern
  - Display estimated direction
- **Limitations**:
  - Single antenna (limited accuracy)
  - Requires movement
  - Better for relative direction than absolute
- **Integration**: Add DF mode

**Code Structure**:
```
src/radio/
├── direction_finding/
│   ├── mobile_df.c            # Mobile DF algorithm
│   ├── df_display.c            # Direction display
│   └── direction_finding.h
```

**Similar Features**:
- DF equipment: Commercial DF systems
- This would be unique: Mobile DF on radio

**References**:
- Direction finding algorithms

---

### 6. Automatic Frequency Calibration

**Description**: Measure and correct crystal/oscillator drift automatically. Uses GPS timing or known frequency references.

**Hardware Requirements**:
- GPS module (USART3) for timing
- Frequency measurement capability
- Calibration storage

**Feasibility Assessment**: **MEDIUM**

**Reasoning**:
- ✅ GPS provides timing reference
- ⚠️ Frequency measurement method needed
- ✅ Calibration storage feasible
- ⚠️ May require known reference
- ✅ Feasible with proper method

**Implementation Notes**:
- **Calibration Method**:
  - Use GPS 1PPS for timing reference
  - Measure internal oscillator frequency
  - Calculate correction factor
  - Apply correction to frequency calculations
- **Storage**: Store calibration in settings
- **Integration**: Add calibration mode

**Code Structure**:
```
src/system/
├── calibration/
│   ├── freq_calibration.c    # Calibration logic
│   ├── calibration_storage.c   # Storage
│   └── calibration.h
```

**Similar Features**:
- Some radios: Manual calibration
- This would be unique: Automatic calibration

**References**:
- Frequency calibration methods

---

### 7. Diversity Reception Mode (Pro Only)

**Description**: Use both BK4829 transceivers to receive the same frequency simultaneously. Combine signals for improved reception (diversity combining).

**Hardware Requirements**:
- Dual BK4829 transceivers (Pro only)
- Signal combining logic
- Audio processing

**Feasibility Assessment**: **LOW-MEDIUM**

**Reasoning**:
- ✅ Dual transceivers available (Pro)
- ⚠️ Requires separate antennas (hardware mod)
- ⚠️ Signal combining complex
- ⚠️ May not provide benefit with single antenna
- ✅ Worth investigating

**Implementation Notes**:
- **Diversity Reception**:
  - Tune both transceivers to same frequency
  - Receive on both simultaneously
  - Combine signals (select best, or combine)
- **Challenges**:
  - Requires separate antennas for benefit
  - Signal combining algorithms
  - Audio synchronization
- **Integration**: Add diversity mode

**Code Structure**:
```
src/radio/
├── diversity/
│   ├── diversity_rx.c         # Diversity reception
│   ├── signal_combiner.c      # Signal combining
│   └── diversity.h
```

**Similar Features**:
- Some radios: Diversity reception
- This would be unique: On BK4829

**References**:
- Diversity reception techniques

---

### 8. Frequency Hopping Spread Spectrum Mode

**Description**: Rapid frequency switching to implement frequency-hopping spread spectrum. Can improve interference rejection.

**Hardware Requirements**:
- BK4829 frequency agility
- Fast frequency switching
- Hopping pattern

**Feasibility Assessment**: **LOW**

**Reasoning**:
- ✅ BK4829 supports frequency changes
- ⚠️ Switching speed likely too slow
- ⚠️ Requires precise timing
- ⚠️ May not be feasible
- ✅ Worth testing

**Implementation Notes**:
- **Hopping Pattern**:
  - Generate pseudo-random sequence
  - Synchronize with receiver (challenge)
- **Switching Speed**:
  - Measure BK4829 frequency change time
  - Determine feasibility
- **Integration**: Add hopping mode (if feasible)

**Code Structure**:
```
src/radio/
├── hopping/
│   ├── hop_pattern.c          # Pattern generation
│   ├── hop_controller.c        # Frequency control
│   └── hopping.h
```

**Similar Features**:
- Military radios: Frequency hopping
- This would be unique: On BK4829

**References**:
- Frequency hopping algorithms

---

## Implementation Priority

1. **High Priority**: Enhanced dual-watch, Repeater directory
2. **Medium Priority**: Cross-band bridge, Activity heatmap, Calibration
3. **Low Priority**: Direction finding, Diversity reception, Frequency hopping

## Memory Requirements

- Database buffers: ~2-4KB RAM
- Heatmap data: ~4-8KB RAM
- DF data: ~2-4KB RAM
- Total additional RAM: ~8-16KB

## CPU Requirements

- Bridge mode: ~5-10% CPU
- Heatmap processing: ~5-10% CPU
- DF calculation: ~2-5% CPU
- Total: ~12-25% CPU (manageable)

---

**Status**: Research phase. Implementation feasibility verified against hardware capabilities.

