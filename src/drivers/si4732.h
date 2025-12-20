/**
 * @file si4732.h
 * @brief SI4732 FM/AM/SW Broadcast Receiver Driver
 * 
 * Driver for the Silicon Labs SI4732 broadcast receiver IC.
 * This chip provides FM broadcast reception (76-108 MHz).
 * 
 * Hardware connection (INFERRED from OEM firmware):
 *   - I2C SCL: PB6 [HIGH confidence]
 *   - I2C SDA: PB7 [HIGH confidence]
 *   - Reset: PA6 [MEDIUM confidence]
 *   - Enable: PA7 [MEDIUM confidence]
 * 
 * Communication uses I2C at standard 100kHz or fast 400kHz mode.
 */

#ifndef DRIVERS_SI4732_H
#define DRIVERS_SI4732_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * SI4732 CONFIGURATION
 * ============================================================================ */

#define SI4732_I2C_ADDR         0x11    /* Default I2C address (can be 0x63) */
#define SI4732_I2C_ADDR_ALT     0x63    /* Alternate address */

/* Frequency ranges (in kHz) */
#define SI4732_FM_MIN_KHZ       64000   /* 64 MHz (extended range) */
#define SI4732_FM_MAX_KHZ       108000  /* 108 MHz */
#define SI4732_AM_MIN_KHZ       520     /* 520 kHz */
#define SI4732_AM_MAX_KHZ       1710    /* 1710 kHz */
#define SI4732_SW_MIN_KHZ       1711    /* 1.711 MHz */
#define SI4732_SW_MAX_KHZ       30000   /* 30 MHz */

/* ============================================================================
 * SI4732 COMMANDS
 * ============================================================================ */

#define SI4732_CMD_POWER_UP         0x01
#define SI4732_CMD_GET_REV          0x10
#define SI4732_CMD_POWER_DOWN       0x11
#define SI4732_CMD_SET_PROPERTY     0x12
#define SI4732_CMD_GET_PROPERTY     0x13
#define SI4732_CMD_GET_INT_STATUS   0x14
#define SI4732_CMD_FM_TUNE_FREQ     0x20
#define SI4732_CMD_FM_SEEK_START    0x21
#define SI4732_CMD_FM_TUNE_STATUS   0x22
#define SI4732_CMD_FM_RSQ_STATUS    0x23
#define SI4732_CMD_FM_RDS_STATUS    0x24
#define SI4732_CMD_AM_TUNE_FREQ     0x40
#define SI4732_CMD_AM_SEEK_START    0x41
#define SI4732_CMD_AM_TUNE_STATUS   0x42
#define SI4732_CMD_AM_RSQ_STATUS    0x43
#define SI4732_CMD_GPIO_CTL         0x80
#define SI4732_CMD_GPIO_SET         0x81

/* ============================================================================
 * SI4732 PROPERTIES
 * ============================================================================ */

#define SI4732_PROP_FM_DEEMPHASIS       0x1100
#define SI4732_PROP_FM_CHANNEL_FILTER   0x1102
#define SI4732_PROP_FM_BLEND_RSSI       0x1105
#define SI4732_PROP_FM_SNR_INT_LEVEL    0x1200
#define SI4732_PROP_FM_RSQ_INT_SOURCE   0x1203
#define SI4732_PROP_FM_SOFTMUTE_RATE    0x1300
#define SI4732_PROP_FM_SOFTMUTE_SNR     0x1303
#define SI4732_PROP_FM_SEEK_FREQ_SPACING 0x1400
#define SI4732_PROP_RX_VOLUME           0x4000
#define SI4732_PROP_RX_HARD_MUTE        0x4001

/* ============================================================================
 * SI4732 STATUS FLAGS
 * ============================================================================ */

#define SI4732_STATUS_CTS           0x80    /* Clear to send */
#define SI4732_STATUS_ERR           0x40    /* Error */
#define SI4732_STATUS_RSQINT        0x08    /* RSQ interrupt */
#define SI4732_STATUS_RDSINT        0x04    /* RDS interrupt */
#define SI4732_STATUS_STCINT        0x01    /* Seek/tune complete */

/* ============================================================================
 * SI4732 MODE ENUMERATION
 * ============================================================================ */

typedef enum {
    SI4732_MODE_FM = 0,         /* FM broadcast */
    SI4732_MODE_AM,             /* AM/MW broadcast */
    SI4732_MODE_SW              /* Shortwave */
} SI4732_Mode_t;

/* ============================================================================
 * SI4732 STATUS STRUCTURE
 * ============================================================================ */

typedef struct {
    uint32_t frequency;         /* Current frequency in Hz */
    int16_t rssi;               /* RSSI in dBuV */
    uint8_t snr;                /* SNR in dB */
    bool stereo;                /* Stereo detected */
    bool valid;                 /* Valid channel */
    bool rds_ready;             /* RDS data available */
} SI4732_Status_t;

/* ============================================================================
 * RDS DATA STRUCTURE
 * ============================================================================ */

typedef struct {
    char program_service[9];    /* PS name (8 chars + null) */
    char radio_text[65];        /* Radio text (64 chars + null) */
    uint16_t program_id;        /* PI code */
    uint8_t program_type;       /* PTY code */
    bool ta;                    /* Traffic announcement */
    bool tp;                    /* Traffic program */
    bool valid;                 /* RDS data is valid */
} SI4732_RDS_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize SI4732
 * 
 * Performs hardware reset and configures for FM mode.
 */
void SI4732_Init(void);

/**
 * @brief Power up SI4732
 * @param mode Operating mode (FM, AM, or SW)
 */
void SI4732_PowerUp(SI4732_Mode_t mode);

/**
 * @brief Power down SI4732
 */
void SI4732_PowerDown(void);

/**
 * @brief Check if SI4732 is powered
 * @return true if powered on
 */
bool SI4732_IsPowered(void);

/**
 * @brief Set frequency
 * @param frequency_hz Frequency in Hz
 * @return true if frequency is valid and was set
 */
bool SI4732_SetFrequency(uint32_t frequency_hz);

/**
 * @brief Get current frequency
 * @return Frequency in Hz
 */
uint32_t SI4732_GetFrequency(void);

/**
 * @brief Seek up to next station
 * @return true if station found
 */
bool SI4732_SeekUp(void);

/**
 * @brief Seek down to next station
 * @return true if station found
 */
bool SI4732_SeekDown(void);

/**
 * @brief Stop seek operation
 */
void SI4732_SeekStop(void);

/**
 * @brief Get receiver status
 * @param status Pointer to status structure
 */
void SI4732_GetStatus(SI4732_Status_t *status);

/**
 * @brief Get RDS data
 * @param rds Pointer to RDS structure
 * @return true if RDS data is available
 */
bool SI4732_GetRDS(SI4732_RDS_t *rds);

/**
 * @brief Set volume
 * @param volume Volume level (0-63)
 */
void SI4732_SetVolume(uint8_t volume);

/**
 * @brief Mute/unmute audio
 * @param mute true to mute
 */
void SI4732_SetMute(bool mute);

/**
 * @brief Enable/disable stereo
 * @param enable true to enable stereo (FM only)
 */
void SI4732_SetStereo(bool enable);

/**
 * @brief Set operating mode
 * @param mode FM, AM, or SW
 */
void SI4732_SetMode(SI4732_Mode_t mode);

/**
 * @brief Process SI4732 tasks (call from main loop)
 * 
 * Updates status, processes RDS, etc.
 */
void SI4732_Process(void);

/**
 * @brief Write command to SI4732
 * @param cmd Command buffer
 * @param len Command length
 */
void SI4732_WriteCommand(const uint8_t *cmd, uint8_t len);

/**
 * @brief Read response from SI4732
 * @param resp Response buffer
 * @param len Response length
 */
void SI4732_ReadResponse(uint8_t *resp, uint8_t len);

/**
 * @brief Set property
 * @param property Property ID
 * @param value Property value
 */
void SI4732_SetProperty(uint16_t property, uint16_t value);

/**
 * @brief Get property
 * @param property Property ID
 * @return Property value
 */
uint16_t SI4732_GetProperty(uint16_t property);

#ifdef __cplusplus
}
#endif

#endif /* DRIVERS_SI4732_H */


