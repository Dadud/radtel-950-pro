# HAL Layer Documentation (`src/hal/`)

**AI Reasoning:** This document explains the AI's reasoning for the Hardware Abstraction Layer implementation.

> **⚠️ This is AI-generated content - verify against hardware before use**

---

## HAL Layer Overview

The HAL provides low-level access to microcontroller peripherals. This layer abstracts register-level operations into function calls.

---

## GPIO (`hal/gpio.h`, `hal/gpio.c`)

### Why This API?

**AI Reasoning:**
- GPIO register addresses from AT32F403A datasheet (0x40010800 for GPIOA, etc.)
- API follows common embedded HAL patterns (similar to STM32 HAL)
- Pin configuration structure allows flexible setup

**Structure:**
```c
typedef enum {
    GPIO_PORT_A, GPIO_PORT_B, GPIO_PORT_C, ...
} GPIO_Port_t;

void HAL_GPIO_Config(GPIO_Port_t port, uint16_t pin, GPIO_Mode_t mode, ...);
```

**AI Reasoning:**
- Enum-based port selection is type-safe
- Pin mask allows setting multiple pins at once
- Mode enumeration covers common use cases (input/output/alternate/analog)

**Source:**
- AT32F403A register reference manual
- Observed GPIO register writes in OEM firmware (Ghidra analysis)
- Common HAL patterns from STM32/Artery SDK

**Confidence:** **HIGH** - Register addresses are from datasheet, API is straightforward

---

## SPI (`hal/spi.h`, `hal/spi.c`)

### Why Hardware + Software SPI?

**AI Reasoning:**
- OEM firmware uses hardware SPI1 for BK4829 #1 (observed in FUN_0802112c)
- OEM firmware uses software (bit-bang) SPI for BK4829 #2 (GPIO toggles observed)
- Need to support both patterns

**Hardware SPI:**
- SPI1 base: 0x40013000 (from AT32F403A datasheet)
- Configuration follows standard SPI patterns (CPOL, CPHA, clock divider)
- DMA support for bulk transfers (inferred from LCD driver usage)

**Software SPI:**
- GPIO bit-banging for secondary transceiver
- Allows flexibility when hardware SPI is unavailable
- Timing critical - must meet BK4829 SPI timing requirements (max 8 MHz)

**Confidence:** **MEDIUM** - Hardware SPI address confirmed, but software SPI timing may need tuning

**Potential Issues:**
- Software SPI delays may not meet timing requirements
- Clock polarity/phase may need adjustment for BK4829

---

## UART (`hal/uart.h`, `hal/uart.c`)

### Why This Structure?

**AI Reasoning:**
- Multiple UART instances needed (USART1 for Bluetooth, USART3 for GPS, UART4 for accessory)
- Standard UART configuration (baud rate, parity, stop bits)
- DMA support for efficient transfers

**Register Bases:**
- USART1: 0x40013800 (Bluetooth, confirmed from OEM firmware)
- USART3: 0x40004800 (GPS, confirmed from OEM firmware)
- UART4: 0x40004C00 (Accessory, inferred)

**Confidence:** **HIGH** - Register addresses from datasheet, standard UART operation

---

## ADC (`hal/adc.c`, `hal/adc.h`)

### Why This Implementation?

**AI Reasoning:**
- ADC2 used for battery monitoring (PA1, observed in OEM firmware)
- Single-shot conversion mode (typical for battery/voltage monitoring)
- 12-bit resolution (standard for AT32F403A)

**Configuration:**
- Channel 1 on PA1 for battery voltage
- Channel 0 on PA0 for VOX detection (inferred)
- Voltage divider ratio unknown (requires hardware measurement)

**Confidence:** **MEDIUM** - ADC setup is standard, but voltage scaling factors are guessed

**Potential Issues:**
- Battery voltage divider ratio unknown (may be 1:1, 2:1, or other)
- Reference voltage assumed to be 3.3V (may need calibration)

---

## DAC (`hal/dac.c`, `hal/dac.h`)

### Why This Approach?

**AI Reasoning:**
- DAC1 used for audio tone generation (CTCSS, AFSK, beep tones)
- DMA used to stream waveform data (observed in AudioDMA_Trigger function)
- Dual-channel DAC (PA4 and PA5) inferred from register analysis

**Audio Path:**
- DMA streams samples to DAC
- Waveform buffers in RAM
- Timer triggers DMA transfers for sample rate

**Confidence:** **MEDIUM** - DMA usage confirmed, but sample rates and buffer sizes are estimated

**Potential Issues:**
- Sample rate calculation may be incorrect
- Buffer sizes may cause audio glitches
- DAC output levels may need calibration

---

## DMA (`hal/dma.c`, `hal/dma.h`)

### Why This Structure?

**AI Reasoning:**
- DMA2 used for LCD frame buffer transfers (observed in OEM firmware)
- DMA also used for audio DAC streaming
- Channel configuration follows AT32F403A DMA architecture

**Usage:**
- LCD: DMA2 streams from frame buffer (0x20000BD0) to LCD data register
- Audio: DMA2 streams waveform buffers to DAC data register

**Confidence:** **HIGH** - DMA channel assignments confirmed from OEM firmware register writes

---

## Timer (`hal/timer.c`, `hal/timer.h`)

### Why This Implementation?

**AI Reasoning:**
- Multiple timers needed for different purposes:
  - SysTick: System timing (1ms ticks)
  - Timer2: PWM for backlight control (PC6)
  - Timer3+: Audio sample rate generation
  - General purpose timers for delays

**API Design:**
- Follows standard embedded timer patterns
- PWM configuration for backlight
- Interrupt-based timing for audio

**Confidence:** **MEDIUM** - Timer usage inferred from observed behavior, specific timer assignments may be wrong

---

## System (`hal/system.c`, `hal/system.h`)

### Why These Functions?

**AI Reasoning:**
- `HAL_GetTick()`: Standard embedded timing function (1ms resolution)
- `HAL_Delay()`: Simple blocking delay
- `HAL_DelayUs()`: Microsecond delays (for SPI timing)

**System Clock:**
- 240MHz confirmed from datasheet
- SysTick configured for 1ms interrupts (1000Hz)

**Confidence:** **HIGH** - Standard system functions, straightforward implementation

---

## Key AI Assumptions

1. **Register Addresses**: From AT32F403A datasheet (high confidence)
2. **API Patterns**: Based on common embedded HAL designs (STM32, Artery SDK)
3. **Peripheral Usage**: Inferred from OEM firmware register writes (medium confidence)
4. **Timing Parameters**: Estimated from typical values (may need hardware tuning)

---

## Verification Needed

- [ ] Verify GPIO pin configurations match OEM behavior
- [ ] Test SPI timing meets BK4829 requirements (max 8 MHz, timing margins)
- [ ] Measure actual UART baud rates
- [ ] Calibrate ADC voltage readings (battery monitoring)
- [ ] Test DAC output levels and audio quality
- [ ] Verify DMA transfers work correctly (LCD, audio)
- [ ] Confirm timer frequencies and PWM duty cycles

