/**
 * @file bk4829.h
 * @brief BK4829/BK4829 RF Transceiver Driver
 * 
 * Driver for the Beken BK4829/BK4829 RF transceiver chips used in the
 * Radtel RT-950 Pro. This radio uses TWO BK4829 chips:
 *   - BK4829 #1: VHF band, connected via hardware SPI1 [CONFIRMED]
 *   - BK4829 #2: UHF band, connected via software SPI on GPIOE [CONFIRMED]
 * 
 * Register definitions and initialization sequences are INFERRED from
 * OEM firmware analysis and BK4829 datasheet information.
 * 
 * CONFIRMED from datasheet (DS-BK4829-E01 V1.0):
 *   - Crystal reference: 26 MHz
 *   - Frequency range: 18-580 MHz, 760-1160 MHz
 *   - SPI: 3-wire interface (SCK, SCN, SDATA), max 8 MHz
 *   - TX power: -5 to +8 dBm (on-chip 7 dBm PA)
 *   - RX sensitivity: -124 dBm typical
 * 
 * @note The BK4829 is register-compatible with BK1080/BK4802/BK1088.
 */

#ifndef DRIVERS_BK4829_H
#define DRIVERS_BK4829_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * BK4829 INSTANCE ENUMERATION
 * ============================================================================ */

typedef enum {
    BK4829_INSTANCE_VHF = 0,    /* Primary VHF transceiver (hardware SPI) */
    BK4829_INSTANCE_UHF,        /* Secondary UHF transceiver (software SPI) */
    BK4829_INSTANCE_COUNT
} BK4829_Instance_t;

/* ============================================================================
 * BK4829 REGISTER ADDRESSES (INFERRED from OEM firmware + datasheet)
 * ============================================================================
 * 
 * The BK4829 uses a 7-bit register address space.
 * Registers are 16 bits wide.
 * 
 * SPI Interface (CONFIRMED from datasheet):
 *   - SCK (Pin 25): Clock, max 8 MHz
 *   - SCN (Pin 26): Chip select/enable
 *   - SDATA (Pin 27): Bidirectional data
 *   - Data latched on SCK rising edge, output on falling edge
 */

/* Basic control registers */
#define BK4829_REG_00       0x00    /* Device ID / status */
#define BK4829_REG_02       0x02    /* GPIO / interrupt status */
#define BK4829_REG_07       0x07    /* Frequency control */
#define BK4829_REG_08       0x08    /* Frequency control (continued) */
#define BK4829_REG_0B       0x0B    /* DAC gain control */
#define BK4829_REG_0D       0x0D    /* AFC control */

/* Modulation control */
#define BK4829_REG_30       0x30    /* Device enable control */
#define BK4829_REG_31       0x31    /* VOX control */
#define BK4829_REG_32       0x32    /* VOX settings */
#define BK4829_REG_33       0x33    /* VOX threshold */
#define BK4829_REG_34       0x34    /* VOX delay */

/* RF control */
#define BK4829_REG_36       0x36    /* PA bias */
#define BK4829_REG_37       0x37    /* RF filter bandwidth */
#define BK4829_REG_38       0x38    /* Frequency synthesizer */
#define BK4829_REG_39       0x39    /* Frequency synthesizer */
#define BK4829_REG_3A       0x3A    /* LNA gain */
#define BK4829_REG_3B       0x3B    /* MIC gain */
#define BK4829_REG_3C       0x3C    /* TX power control */
#define BK4829_REG_3D       0x3D    /* RX squelch control */
#define BK4829_REG_3E       0x3E    /* Reserved */
#define BK4829_REG_3F       0x3F    /* BK4829 enable (PA, VCO, etc.) */

/* Audio processing */
#define BK4829_REG_47       0x47    /* AF gain */
#define BK4829_REG_48       0x48    /* AF filter */
#define BK4829_REG_49       0x49    /* Audio settings */
#define BK4829_REG_4D       0x4D    /* TX deviation */
#define BK4829_REG_4E       0x4E    /* Audio DAC control */

/* CTCSS/DCS */
#define BK4829_REG_51       0x51    /* TX CTCSS frequency */
#define BK4829_REG_52       0x52    /* CTCSS settings */
#define BK4829_REG_67       0x67    /* DCS settings */
#define BK4829_REG_68       0x68    /* DCS code word */
#define BK4829_REG_69       0x69    /* DCS detection */

/* RSSI and status */
#define BK4829_REG_65       0x65    /* RSSI value */
#define BK4829_REG_67       0x67    /* RSSI threshold */

/* Device ID */
#define BK4829_REG_70       0x70    /* Chip ID register */
#define BK4829_REG_71       0x71    /* Version register */

/* ============================================================================
 * BK4829 MODULATION MODES
 * ============================================================================ */

typedef enum {
    BK4829_MOD_FM = 0,          /* FM modulation */
    BK4829_MOD_AM,              /* AM modulation */
    BK4829_MOD_USB,             /* Upper sideband (if supported) */
    BK4829_MOD_LSB,             /* Lower sideband (if supported) */
    BK4829_MOD_CW               /* Continuous wave */
} BK4829_Modulation_t;

/* ============================================================================
 * BK4829 BANDWIDTH SETTINGS
 * ============================================================================ */

typedef enum {
    BK4829_BW_WIDE = 0,         /* 25 kHz (wide) */
    BK4829_BW_NARROW,           /* 12.5 kHz (narrow) */
    BK4829_BW_NARROWER          /* 6.25 kHz (narrowest) */
} BK4829_Bandwidth_t;

/* ============================================================================
 * BK4829 TX POWER LEVELS
 * ============================================================================ */

typedef enum {
    BK4829_POWER_LOW = 0,
    BK4829_POWER_MID,
    BK4829_POWER_HIGH
} BK4829_Power_t;

/* ============================================================================
 * BK4829 SQUELCH MODES
 * ============================================================================ */

typedef enum {
    BK4829_SQUELCH_CARRIER = 0, /* Carrier squelch */
    BK4829_SQUELCH_CTCSS,       /* CTCSS tone squelch */
    BK4829_SQUELCH_DCS,         /* DCS code squelch */
    BK4829_SQUELCH_BOTH         /* CTCSS/DCS + carrier */
} BK4829_SquelchMode_t;

/* ============================================================================
 * BK4829 CONFIGURATION STRUCTURES
 * ============================================================================ */

typedef struct {
    uint32_t frequency_hz;      /* Frequency in Hz */
    BK4829_Modulation_t modulation;
    BK4829_Bandwidth_t bandwidth;
    BK4829_Power_t tx_power;
    BK4829_SquelchMode_t squelch_mode;
    uint8_t squelch_level;      /* 0-9 */
    uint16_t ctcss_freq;        /* CTCSS frequency in 0.1 Hz units */
    uint32_t dcs_code;          /* DCS code */
    bool rx_enabled;
    bool tx_enabled;
} BK4829_Config_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize BK4829 transceiver
 * @param instance Which BK4829 to initialize
 * 
 * Performs power-on reset and loads default register values.
 * INFERRED: Initialization sequence from OEM firmware FUN_80007f04
 */
void BK4829_Init(BK4829_Instance_t instance);

/**
 * @brief Read a BK4829 register
 * @param instance Which BK4829 to access
 * @param reg Register address (0-127)
 * @return 16-bit register value
 */
uint16_t BK4829_ReadReg(BK4829_Instance_t instance, uint8_t reg);

/**
 * @brief Write a BK4829 register
 * @param instance Which BK4829 to access
 * @param reg Register address (0-127)
 * @param value 16-bit value to write
 */
void BK4829_WriteReg(BK4829_Instance_t instance, uint8_t reg, uint16_t value);

/**
 * @brief Set operating frequency
 * @param instance Which BK4829 to configure
 * @param frequency_hz Frequency in Hz
 * 
 * INFERRED: Frequency calculation from FUN_8000b62c
 * The frequency is programmed via registers 0x38, 0x39, 0x07, 0x08
 */
void BK4829_SetFrequency(BK4829_Instance_t instance, uint32_t frequency_hz);

/**
 * @brief Get current RSSI value
 * @param instance Which BK4829 to read
 * @return RSSI in dBm (approximately)
 */
int16_t BK4829_GetRSSI(BK4829_Instance_t instance);

/**
 * @brief Check if carrier is detected (squelch open)
 * @param instance Which BK4829 to check
 * @return true if squelch is open
 */
bool BK4829_IsSquelchOpen(BK4829_Instance_t instance);

/**
 * @brief Enable/disable receiver
 * @param instance Which BK4829 to control
 * @param enable true to enable RX
 */
void BK4829_EnableRX(BK4829_Instance_t instance, bool enable);

/**
 * @brief Enable/disable transmitter
 * @param instance Which BK4829 to control
 * @param enable true to enable TX
 * 
 * @warning TX should only be enabled when PTT is pressed and
 *          frequency is within legal amateur bands!
 */
void BK4829_EnableTX(BK4829_Instance_t instance, bool enable);

/**
 * @brief Set TX power level
 * @param instance Which BK4829 to control
 * @param power Power level
 */
void BK4829_SetTXPower(BK4829_Instance_t instance, BK4829_Power_t power);

/**
 * @brief Set modulation mode
 * @param instance Which BK4829 to control
 * @param modulation Modulation type
 */
void BK4829_SetModulation(BK4829_Instance_t instance, BK4829_Modulation_t modulation);

/**
 * @brief Set channel bandwidth
 * @param instance Which BK4829 to control
 * @param bandwidth Bandwidth setting
 */
void BK4829_SetBandwidth(BK4829_Instance_t instance, BK4829_Bandwidth_t bandwidth);

/**
 * @brief Configure squelch
 * @param instance Which BK4829 to control
 * @param mode Squelch mode
 * @param level Squelch level (0-9)
 */
void BK4829_SetSquelch(BK4829_Instance_t instance, BK4829_SquelchMode_t mode, 
                       uint8_t level);

/**
 * @brief Set CTCSS tone frequency
 * @param instance Which BK4829 to control
 * @param freq_tenths Frequency in 0.1 Hz units (e.g., 885 = 88.5 Hz)
 */
void BK4829_SetCTCSS(BK4829_Instance_t instance, uint16_t freq_tenths);

/**
 * @brief Set DCS code
 * @param instance Which BK4829 to control
 * @param code DCS code (e.g., 023, 754)
 * @param inverted true for inverted (N) codes
 */
void BK4829_SetDCS(BK4829_Instance_t instance, uint16_t code, bool inverted);

/**
 * @brief Enable CTCSS/DCS detection
 * @param instance Which BK4829 to control
 * @param enable true to enable detection
 */
void BK4829_EnableToneDetection(BK4829_Instance_t instance, bool enable);

/**
 * @brief Check if CTCSS/DCS tone is detected
 * @param instance Which BK4829 to check
 * @return true if tone/code is detected
 */
bool BK4829_IsToneDetected(BK4829_Instance_t instance);

/**
 * @brief Apply full configuration
 * @param instance Which BK4829 to configure
 * @param config Configuration structure
 */
void BK4829_Configure(BK4829_Instance_t instance, const BK4829_Config_t *config);

/**
 * @brief Get chip ID
 * @param instance Which BK4829 to read
 * @return Chip ID value
 */
uint16_t BK4829_GetChipID(BK4829_Instance_t instance);

#ifdef __cplusplus
}
#endif

#endif /* DRIVERS_BK4829_H */



