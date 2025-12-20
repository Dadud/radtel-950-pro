/**
 * @file settings.h
 * @brief Settings Storage and EEPROM Management
 * 
 * Manages persistent storage of radio settings in external SPI flash.
 * 
 * Flash layout (INFERRED from OEM firmware analysis):
 *   0x00000 - 0x00FFF: Bootloader reserved
 *   0x01000 - 0x10FFF: Channel memory (1000 channels)
 *   0x11000 - 0x11FFF: VFO settings
 *   0x12000 - 0x12FFF: Radio settings
 *   0x13000 - 0x13FFF: Calibration data
 *   0x14000 - 0x1FFFF: Reserved
 *   0x20000 - 0x3FFFF: Additional storage (contacts, etc.)
 * 
 * Flash operations use 4K/32K/64K sector erase as seen in:
 *   - Software_SPI_FlashErase4K (FUN_800210c0)
 *   - Software_SPI_FlashErase32KBlock (FUN_80020f80)
 *   - Software_SPI_FlashErase64KBlock (FUN_80020ff0)
 */

#ifndef CONFIG_SETTINGS_H
#define CONFIG_SETTINGS_H

#include <stdint.h>
#include <stdbool.h>
#include "radio/radio.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * FLASH LAYOUT CONSTANTS (INFERRED from OEM firmware)
 * ============================================================================ */

#define FLASH_ADDR_BOOTLOADER   0x00000
#define FLASH_ADDR_CHANNELS     0x01000
#define FLASH_ADDR_VFO          0x11000
#define FLASH_ADDR_SETTINGS     0x12000
#define FLASH_ADDR_CALIBRATION  0x13000
#define FLASH_ADDR_CONTACTS     0x20000

/* Channel entry size (INFERRED: each channel is 24 bytes) */
#define CHANNEL_ENTRY_SIZE      24
#define CHANNEL_BANK_SIZE       (CHANNEL_ENTRY_SIZE * 100)

/* Zone/Channel limits - CONFIRMED from v0.24 changelog */
#define NUM_ZONES               10      /* v0.24: Changed to 10 zones */
#define CHANNELS_PER_ZONE       99      /* v0.24: Changed to 99 channels per zone */
#define MAX_CHANNELS            (NUM_ZONES * CHANNELS_PER_ZONE)  /* 990 total */

/* ============================================================================
 * SETTINGS VERSION
 * ============================================================================ */

#define SETTINGS_VERSION        0x0001
#define SETTINGS_MAGIC          0x950A      /* RT-950 settings marker */

/* ============================================================================
 * CHANNEL MEMORY STRUCTURE
 * ============================================================================
 * 
 * INFERRED from OEM firmware Channel_Load_Config (FUN_80009110)
 */

typedef struct __attribute__((packed)) {
    uint32_t rx_frequency;      /* RX frequency in Hz */
    uint32_t tx_frequency;      /* TX frequency in Hz (or offset) */
    uint16_t rx_ctcss;          /* RX CTCSS in 0.1Hz */
    uint16_t tx_ctcss;          /* TX CTCSS in 0.1Hz */
    uint8_t rx_dcs;             /* RX DCS code */
    uint8_t tx_dcs;             /* TX DCS code */
    uint8_t flags;              /* Bit flags (bandwidth, power, etc.) */
    uint8_t name[8];            /* Channel name (ASCII, null-padded) */
    uint8_t reserved[1];        /* Reserved/padding */
} ChannelEntry_t;

/* Channel flags */
#define CHANNEL_FLAG_VALID      0x01
#define CHANNEL_FLAG_WIDE       0x02
#define CHANNEL_FLAG_HIGH_POWER 0x04
#define CHANNEL_FLAG_SCAN_ADD   0x08
#define CHANNEL_FLAG_RX_DCS_INV 0x10
#define CHANNEL_FLAG_TX_DCS_INV 0x20

/* ============================================================================
 * RADIO SETTINGS STRUCTURE
 * ============================================================================
 * 
 * INFERRED from OEM firmware settings handling
 */

typedef struct __attribute__((packed)) {
    uint16_t magic;             /* Settings magic number */
    uint16_t version;           /* Settings version */
    
    /* Display settings */
    uint8_t lcd_brightness;     /* LCD brightness (0-100) */
    uint8_t lcd_timeout;        /* LCD timeout in seconds (0 = always on) */
    uint8_t keypad_brightness;  /* Keypad backlight (0-100) */
    uint8_t keypad_timeout;     /* Keypad backlight timeout */
    
    /* Audio settings */
    uint8_t volume;             /* Master volume (0-31) */
    uint8_t beep_volume;        /* Beep volume (0-31) */
    bool beep_enabled;          /* Enable keypad beep */
    bool roger_beep;            /* Enable roger beep */
    
    /* Radio settings */
    uint8_t squelch_level;      /* Default squelch (0-9) */
    uint8_t vox_level;          /* VOX sensitivity (0-9, 0=off) */
    uint8_t vox_delay;          /* VOX delay in 100ms units */
    uint8_t tot;                /* TX timeout in minutes (0=off) */
    bool busy_lockout;          /* Busy channel lockout */
    
    /* Scan settings */
    uint8_t scan_resume_mode;   /* Scan resume mode */
    uint8_t scan_delay;         /* Scan resume delay */
    
    /* Power settings */
    uint8_t auto_power_off;     /* Auto power off in minutes (0=off) */
    uint8_t battery_save;       /* Battery save ratio */
    
    /* Interface settings */
    bool dual_watch;            /* Dual watch enabled */
    bool cross_band;            /* Cross-band repeat enabled */
    bool ptt_id;                /* PTT ID enabled */
    uint8_t mdc_id[4];          /* MDC1200 ID */
    
    /* VFO states */
    VFOConfig_t vfo_a;          /* VFO A configuration */
    VFOConfig_t vfo_b;          /* VFO B configuration */
    uint8_t current_vfo;        /* Currently selected VFO */
    uint8_t current_mode;       /* VFO/MR mode */
    uint16_t current_channel;   /* Current memory channel */
    
    /* FM radio */
    uint32_t fm_frequency;      /* FM broadcast frequency */
    uint8_t fm_presets[16];     /* FM preset stations */
    
    /* GPS settings */
    bool gps_enabled;           /* GPS enabled */
    uint8_t gps_format;         /* Coordinate format */
    int16_t utc_offset;         /* UTC offset in minutes */
    
    /* Bluetooth settings */
    bool bt_enabled;            /* Bluetooth enabled */
    char bt_name[16];           /* Bluetooth device name */
    
    /* CRC for data integrity */
    uint16_t crc16;             /* CRC-16 of settings */
    
} RadioSettings_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Load settings from flash
 * @return true if settings were loaded successfully
 */
bool Settings_Load(void);

/**
 * @brief Save settings to flash
 * @return true if settings were saved successfully
 */
bool Settings_Save(void);

/**
 * @brief Reset settings to factory defaults
 */
void Settings_Reset(void);

/**
 * @brief Get pointer to current settings
 * @return Pointer to settings structure
 */
RadioSettings_t *Settings_Get(void);

/**
 * @brief Load a channel from memory
 * @param channel Channel number (0-999)
 * @param entry Pointer to entry structure to fill
 * @return true if channel is valid
 */
bool Settings_LoadChannel(uint16_t channel, ChannelEntry_t *entry);

/**
 * @brief Save a channel to memory
 * @param channel Channel number (0-999)
 * @param entry Pointer to entry structure to save
 * @return true if save was successful
 */
bool Settings_SaveChannel(uint16_t channel, const ChannelEntry_t *entry);

/**
 * @brief Delete a channel from memory
 * @param channel Channel number (0-999)
 * @return true if delete was successful
 */
bool Settings_DeleteChannel(uint16_t channel);

/**
 * @brief Check if a channel is programmed
 * @param channel Channel number (0-999)
 * @return true if channel contains valid data
 */
bool Settings_IsChannelValid(uint16_t channel);

/**
 * @brief Calculate CRC-16 for settings validation
 * @param data Pointer to data
 * @param length Data length
 * @return CRC-16 value
 */
uint16_t Settings_CalculateCRC(const void *data, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_SETTINGS_H */


