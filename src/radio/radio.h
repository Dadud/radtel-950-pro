/**
 * @file radio.h
 * @brief Radio State Machine and Control
 * 
 * High-level radio control including VFO management, channel memory,
 * scanning, and transmit/receive control.
 * 
 * The RT-950 Pro is a dual-band radio with:
 *   - VHF: 136-174 MHz (BK4829 #1)
 *   - UHF: 400-520 MHz (BK4829 #2)
 *   - FM broadcast receiver: 64-108 MHz (SI4732)
 *   - GPS receiver
 * 
 * Operating modes (INFERRED from UI analysis):
 *   - VFO mode: Direct frequency entry
 *   - Memory mode: Channel selection
 *   - Scan mode: Frequency or memory scan
 *   - FM mode: Broadcast receiver
 */

#ifndef RADIO_RADIO_H
#define RADIO_RADIO_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * RADIO CONFIGURATION
 * ============================================================================ */

/* Frequency limits (INFERRED from OEM firmware) */
#define FREQ_VHF_MIN        136000000UL     /* 136 MHz */
#define FREQ_VHF_MAX        174000000UL     /* 174 MHz */
#define FREQ_UHF_MIN        400000000UL     /* 400 MHz */
#define FREQ_UHF_MAX        520000000UL     /* 520 MHz */
#define FREQ_FM_MIN         64000000UL      /* 64 MHz (FM broadcast) */
#define FREQ_FM_MAX         108000000UL     /* 108 MHz (FM broadcast) */

/* Step sizes in Hz (INFERRED) */
#define STEP_2K5            2500
#define STEP_5K             5000
#define STEP_6K25           6250
#define STEP_10K            10000
#define STEP_12K5           12500
#define STEP_25K            25000
#define STEP_50K            50000
#define STEP_100K           100000

/* Channel limits */
#define CHANNEL_MAX         999             /* Maximum channel number */
#define VFO_COUNT           2               /* A and B VFOs */

/* ============================================================================
 * RADIO STATE ENUMERATION
 * ============================================================================ */

typedef enum {
    RADIO_STATE_IDLE = 0,       /* Receiving, squelch closed */
    RADIO_STATE_RX,             /* Receiving, squelch open */
    RADIO_STATE_TX,             /* Transmitting */
    RADIO_STATE_SCAN,           /* Scanning */
    RADIO_STATE_FM,             /* FM broadcast mode */
    RADIO_STATE_MENU,           /* In menu */
    RADIO_STATE_ALARM,          /* Alarm/emergency mode */
    RADIO_STATE_POWER_SAVE      /* Power save mode */
} RadioState_t;

/* ============================================================================
 * RADIO MODE ENUMERATION
 * ============================================================================ */

typedef enum {
    RADIO_MODE_VFO = 0,         /* VFO mode */
    RADIO_MODE_MR,              /* Memory recall mode */
    RADIO_MODE_FM               /* FM broadcast mode */
} RadioMode_t;

/* ============================================================================
 * BAND ENUMERATION
 * ============================================================================ */

typedef enum {
    BAND_VHF = 0,               /* VHF band (136-174 MHz) */
    BAND_UHF,                   /* UHF band (400-520 MHz) */
    BAND_FM,                    /* FM broadcast (64-108 MHz) */
    BAND_COUNT
} Band_t;

/* ============================================================================
 * VFO SELECTION
 * ============================================================================ */

typedef enum {
    VFO_A = 0,
    VFO_B,
    VFO_COUNT_ENUM
} VFO_t;

/* ============================================================================
 * MODULATION MODE
 * ============================================================================ */

typedef enum {
    MOD_FM = 0,                 /* FM modulation */
    MOD_AM,                     /* AM modulation */
    MOD_USB,                    /* Upper sideband */
    MOD_LSB,                    /* Lower sideband */
    MOD_CW                      /* Continuous wave */
} Modulation_t;

/* ============================================================================
 * POWER LEVEL
 * ============================================================================ */

typedef enum {
    POWER_LOW = 0,              /* Low power (typically 1W) */
    POWER_MID,                  /* Medium power (typically 5W) */
    POWER_HIGH                  /* High power (typically 10-15W) */
} PowerLevel_t;

/* ============================================================================
 * SCAN TYPE
 * ============================================================================ */

typedef enum {
    SCAN_NONE = 0,
    SCAN_VFO_UP,                /* VFO scan up */
    SCAN_VFO_DOWN,              /* VFO scan down */
    SCAN_MEM,                   /* Memory scan */
    SCAN_PRIORITY,              /* Priority scan */
    SCAN_DUAL_WATCH             /* Dual watch */
} ScanType_t;

/* ============================================================================
 * VFO CONFIGURATION STRUCTURE
 * ============================================================================ */

typedef struct {
    uint32_t frequency;         /* Frequency in Hz */
    uint32_t tx_offset;         /* TX offset in Hz (for repeaters) */
    int8_t tx_offset_dir;       /* -1 = minus, 0 = simplex, +1 = plus */
    uint32_t step;              /* Step size in Hz */
    Modulation_t modulation;    /* Modulation mode */
    PowerLevel_t power;         /* TX power level */
    bool wide_bandwidth;        /* true = 25kHz, false = 12.5kHz */
    uint16_t rx_ctcss;          /* RX CTCSS (0 = none) */
    uint16_t tx_ctcss;          /* TX CTCSS (0 = none) */
    uint16_t rx_dcs;            /* RX DCS code (0 = none) */
    uint16_t tx_dcs;            /* TX DCS code (0 = none) */
    bool rx_dcs_inverted;       /* RX DCS polarity */
    bool tx_dcs_inverted;       /* TX DCS polarity */
    uint8_t squelch_level;      /* Squelch level (0-9) */
    bool busy_lock;             /* Busy channel lockout */
    bool ptt_id;                /* PTT ID enabled */
} VFOConfig_t;

/* ============================================================================
 * RADIO STATUS STRUCTURE
 * ============================================================================ */

typedef struct {
    RadioState_t state;         /* Current radio state */
    RadioMode_t mode;           /* Current operating mode */
    VFO_t current_vfo;          /* Currently selected VFO */
    uint16_t current_channel;   /* Current memory channel (if in MR mode) */
    Band_t active_band;         /* Currently active band */
    VFOConfig_t vfo[VFO_COUNT]; /* VFO configurations */
    ScanType_t scan_type;       /* Current scan type */
    bool squelch_open;          /* Is squelch open? */
    bool ptt_pressed;           /* Is PTT pressed? */
    int16_t rssi;               /* Current RSSI in dBm */
    uint8_t s_meter;            /* S-meter reading (0-9, 9+10, 9+20...) */
    uint8_t tx_power_level;     /* Actual TX power for display */
    bool gps_locked;            /* GPS has fix */
    bool bluetooth_connected;   /* Bluetooth is connected */
} RadioStatus_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize radio subsystem
 * 
 * Loads saved VFO settings and prepares radio for operation.
 */
void Radio_Init(void);

/**
 * @brief Process radio state machine (call from main loop)
 * 
 * Handles receive monitoring, PTT, scanning, etc.
 */
void Radio_Process(void);

/**
 * @brief Get current radio status
 * @return Pointer to status structure (read-only)
 */
const RadioStatus_t *Radio_GetStatus(void);

/**
 * @brief Set operating frequency
 * @param frequency Frequency in Hz
 * @return true if frequency is valid and was set
 */
bool Radio_SetFrequency(uint32_t frequency);

/**
 * @brief Get current frequency
 * @return Current frequency in Hz
 */
uint32_t Radio_GetFrequency(void);

/**
 * @brief Select VFO
 * @param vfo VFO_A or VFO_B
 */
void Radio_SelectVFO(VFO_t vfo);

/**
 * @brief Toggle between VFO A and B
 */
void Radio_ToggleVFO(void);

/**
 * @brief Set operating mode
 * @param mode VFO, Memory, or FM
 */
void Radio_SetMode(RadioMode_t mode);

/**
 * @brief Select memory channel
 * @param channel Channel number (0-999)
 * @return true if channel is valid and was selected
 */
bool Radio_SelectChannel(uint16_t channel);

/**
 * @brief Tune up by one step
 */
void Radio_TuneUp(void);

/**
 * @brief Tune down by one step
 */
void Radio_TuneDown(void);

/**
 * @brief Set frequency step size
 * @param step Step in Hz
 */
void Radio_SetStep(uint32_t step);

/**
 * @brief Start PTT (begin transmitting)
 * 
 * @warning This will key the transmitter! Ensure frequency is legal
 *          and antenna is connected!
 */
void Radio_StartTX(void);

/**
 * @brief Stop PTT (stop transmitting)
 */
void Radio_StopTX(void);

/**
 * @brief Check if transmitting
 * @return true if currently transmitting
 */
bool Radio_IsTX(void);

/**
 * @brief Start scanning
 * @param type Type of scan to perform
 */
void Radio_StartScan(ScanType_t type);

/**
 * @brief Stop scanning
 */
void Radio_StopScan(void);

/**
 * @brief Check if scanning
 * @return true if scan is active
 */
bool Radio_IsScanning(void);

/**
 * @brief Set TX power level
 * @param power Power level
 */
void Radio_SetPower(PowerLevel_t power);

/**
 * @brief Set squelch level
 * @param level Squelch level (0-9)
 */
void Radio_SetSquelch(uint8_t level);

/**
 * @brief Set CTCSS/DCS tones
 * @param rx_tone RX tone in 0.1Hz (0 = none)
 * @param tx_tone TX tone in 0.1Hz (0 = none)
 */
void Radio_SetCTCSS(uint16_t rx_tone, uint16_t tx_tone);

/**
 * @brief Set DCS codes
 * @param rx_code RX DCS code (0 = none)
 * @param tx_code TX DCS code (0 = none)
 * @param rx_inv RX code inverted
 * @param tx_inv TX code inverted
 */
void Radio_SetDCS(uint16_t rx_code, uint16_t tx_code, bool rx_inv, bool tx_inv);

/**
 * @brief Get current RSSI
 * @return RSSI in dBm
 */
int16_t Radio_GetRSSI(void);

/**
 * @brief Check if squelch is open
 * @return true if receiving signal
 */
bool Radio_IsSquelchOpen(void);

/**
 * @brief Set modulation mode
 * @param mod Modulation type
 */
void Radio_SetModulation(Modulation_t mod);

/**
 * @brief Set bandwidth
 * @param wide true for 25kHz, false for 12.5kHz
 */
void Radio_SetBandwidth(bool wide);

/**
 * @brief Set repeater offset
 * @param offset Offset in Hz
 * @param direction -1, 0, or +1
 */
void Radio_SetOffset(uint32_t offset, int8_t direction);

#ifdef __cplusplus
}
#endif

#endif /* RADIO_RADIO_H */



