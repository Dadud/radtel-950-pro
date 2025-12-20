/**
 * @file audio.h
 * @brief Audio Subsystem Driver
 * 
 * Handles audio generation for CTCSS tones, DTMF, and beeps.
 * Also manages audio path routing and volume control.
 * 
 * Hardware configuration (INFERRED from OEM firmware):
 *   - DAC1 (PA4): Tone output [CONFIRMED]
 *   - DAC2 (PA5): APC control [MEDIUM confidence]
 *   - DMA2: Audio sample streaming [CONFIRMED]
 *   - ADC2 CH0 (PA0): Battery/AGC sense [CONFIRMED]
 *   - ADC2 CH1 (PA1): Audio level/VOX [CONFIRMED]
 * 
 * CTCSS/DCS tone generation uses FUN_8000dca0 (AudioDMA_Trigger).
 * AFSK/APRS modulation uses the same DAC pathway.
 */

#ifndef DRIVERS_AUDIO_H
#define DRIVERS_AUDIO_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CTCSS TONE FREQUENCIES (Hz * 10)
 * ============================================================================
 * 
 * Standard CTCSS tones as defined by EIA/TIA-603.
 * Values are in tenths of Hz (e.g., 670 = 67.0 Hz).
 * INFERRED: Tone table at DAT_8000ca00 in OEM firmware.
 */

static const uint16_t CTCSS_TONES[] = {
    670, 693, 719, 744, 770, 797, 825, 854,     /* 67.0 - 85.4 */
    885, 915, 948, 974, 1000, 1035, 1072, 1109, /* 88.5 - 110.9 */
    1148, 1188, 1230, 1273, 1318, 1365, 1413, 1462, /* 114.8 - 146.2 */
    1514, 1567, 1598, 1622, 1655, 1679, 1713, 1738, /* 151.4 - 173.8 */
    1773, 1799, 1835, 1862, 1899, 1928, 1966, 1995, /* 177.3 - 199.5 */
    2035, 2065, 2107, 2181, 2257, 2336, 2418, 2503  /* 203.5 - 250.3 */
};

#define CTCSS_TONE_COUNT    (sizeof(CTCSS_TONES) / sizeof(CTCSS_TONES[0]))

/* ============================================================================
 * DTMF TONE DEFINITIONS
 * ============================================================================ */

typedef struct {
    uint16_t low_freq;      /* Low frequency in Hz */
    uint16_t high_freq;     /* High frequency in Hz */
} DTMFTone_t;

/* Standard DTMF frequencies */
#define DTMF_ROW_697    697
#define DTMF_ROW_770    770
#define DTMF_ROW_852    852
#define DTMF_ROW_941    941
#define DTMF_COL_1209   1209
#define DTMF_COL_1336   1336
#define DTMF_COL_1477   1477
#define DTMF_COL_1633   1633

/* ============================================================================
 * AUDIO PATH ENUMERATION
 * ============================================================================ */

typedef enum {
    AUDIO_PATH_NONE = 0,
    AUDIO_PATH_SPEAKER,         /* Internal speaker */
    AUDIO_PATH_HEADPHONE,       /* Headphone jack */
    AUDIO_PATH_EXTERNAL,        /* External speaker */
    AUDIO_PATH_BLUETOOTH        /* Bluetooth audio */
} AudioPath_t;

/* ============================================================================
 * BEEP TYPES
 * ============================================================================ */

typedef enum {
    BEEP_NONE = 0,
    BEEP_KEY,                   /* Short key beep */
    BEEP_ERROR,                 /* Error beep */
    BEEP_CONFIRM,               /* Confirmation beep */
    BEEP_POWER_ON,              /* Power on melody */
    BEEP_POWER_OFF,             /* Power off melody */
    BEEP_TX_START,              /* TX started */
    BEEP_TX_END,                /* TX ended */
    BEEP_SCAN_HIT,              /* Scan found signal */
    BEEP_ROGER                  /* Roger beep */
} BeepType_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize audio subsystem
 * 
 * Configures DAC, DMA, and audio routing.
 * INFERRED: Initialization from OEM firmware DAC_Channel_Enable etc.
 */
void Audio_Init(void);

/**
 * @brief Play a beep
 * @param type Type of beep to play
 */
void Audio_PlayBeep(BeepType_t type);

/**
 * @brief Start CTCSS tone generation
 * @param freq_tenths Frequency in 0.1 Hz units (e.g., 885 = 88.5 Hz)
 * 
 * INFERRED: Uses DAC + DMA pathway from FUN_8000dca0
 */
void Audio_StartCTCSS(uint16_t freq_tenths);

/**
 * @brief Stop CTCSS tone generation
 */
void Audio_StopCTCSS(void);

/**
 * @brief Start DCS code generation
 * @param code DCS code number
 * @param inverted true for inverted (N) codes
 */
void Audio_StartDCS(uint16_t code, bool inverted);

/**
 * @brief Stop DCS code generation
 */
void Audio_StopDCS(void);

/**
 * @brief Play DTMF tone
 * @param digit Character '0'-'9', 'A'-'D', '*', '#'
 * @param duration_ms Duration in milliseconds
 */
void Audio_PlayDTMF(char digit, uint32_t duration_ms);

/**
 * @brief Play DTMF string
 * @param digits Null-terminated string of DTMF digits
 * @param tone_ms Duration of each tone in ms
 * @param gap_ms Gap between tones in ms
 */
void Audio_PlayDTMFString(const char *digits, uint32_t tone_ms, uint32_t gap_ms);

/**
 * @brief Set audio volume
 * @param volume Volume level (0-31)
 */
void Audio_SetVolume(uint8_t volume);

/**
 * @brief Get current volume setting
 * @return Current volume (0-31)
 */
uint8_t Audio_GetVolume(void);

/**
 * @brief Mute/unmute audio
 * @param mute true to mute
 * 
 * INFERRED: Speaker mute on PE1
 */
void Audio_SetMute(bool mute);

/**
 * @brief Select audio output path
 * @param path Output destination
 */
void Audio_SetPath(AudioPath_t path);

/**
 * @brief Enable/disable microphone
 * @param enable true to enable
 * 
 * INFERRED: Microphone enable on PB8
 */
void Audio_SetMicEnabled(bool enable);

/**
 * @brief Get current audio level (for S-meter, VOX)
 * @return Audio level (0-255)
 * 
 * CONFIRMED: Uses ADC2 CH1 (PA1) from FUN_80013c98
 */
uint8_t Audio_GetLevel(void);

/**
 * @brief Check if audio is currently playing
 * @return true if audio generation is active
 */
bool Audio_IsPlaying(void);

/**
 * @brief Process audio tasks (call from main loop)
 * 
 * Handles queued tones and DMA completion.
 */
void Audio_Process(void);

#ifdef __cplusplus
}
#endif

#endif /* DRIVERS_AUDIO_H */


