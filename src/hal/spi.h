/**
 * @file spi.h
 * @brief SPI Hardware Abstraction Layer
 * 
 * Provides both hardware SPI and bit-banged software SPI support.
 * 
 * Hardware SPI1 is used for:
 *   - BK4829 #1 (VHF transceiver) [CONFIRMED]
 * 
 * Software SPI is used for:
 *   - BK4829 #2 (UHF transceiver) via GPIOE [CONFIRMED]
 *   - External SPI Flash via GPIOB [CONFIRMED]
 */

#ifndef HAL_SPI_H
#define HAL_SPI_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * SPI PERIPHERAL BASE ADDRESSES (CONFIRMED from datasheet)
 * ============================================================================ */

#define SPI1_BASE           0x40013000UL
#define SPI2_BASE           0x40003800UL
#define SPI3_BASE           0x40003C00UL
#define SPI4_BASE           0x40013400UL

/* SPI register structure */
typedef struct {
    volatile uint32_t CTRL1;    /* 0x00: Control register 1 */
    volatile uint32_t CTRL2;    /* 0x04: Control register 2 */
    volatile uint32_t STS;      /* 0x08: Status register */
    volatile uint32_t DT;       /* 0x0C: Data register */
    volatile uint32_t CPOLY;    /* 0x10: CRC polynomial */
    volatile uint32_t RCRC;     /* 0x14: RX CRC */
    volatile uint32_t TCRC;     /* 0x18: TX CRC */
    volatile uint32_t I2SCTRL;  /* 0x1C: I2S control */
    volatile uint32_t I2SCLK;   /* 0x20: I2S clock */
} SPI_TypeDef;

#define SPI1                ((SPI_TypeDef *)SPI1_BASE)
#define SPI2                ((SPI_TypeDef *)SPI2_BASE)
#define SPI3                ((SPI_TypeDef *)SPI3_BASE)
#define SPI4                ((SPI_TypeDef *)SPI4_BASE)

/* ============================================================================
 * SPI STATUS REGISTER BITS
 * ============================================================================ */

#define SPI_STS_RDBF        (1 << 0)    /* Receive data buffer full */
#define SPI_STS_TDBE        (1 << 1)    /* Transmit data buffer empty */
#define SPI_STS_ACS         (1 << 2)    /* Audio channel side */
#define SPI_STS_TUERR       (1 << 3)    /* Transmit underrun error */
#define SPI_STS_CCERR       (1 << 4)    /* CRC calculation error */
#define SPI_STS_MMERR       (1 << 5)    /* Master mode error */
#define SPI_STS_ROERR       (1 << 6)    /* Receive overrun error */
#define SPI_STS_BF          (1 << 7)    /* Busy flag */

/* ============================================================================
 * SPI INSTANCE ENUMERATION
 * ============================================================================ */

typedef enum {
    SPI_INSTANCE_HW1 = 0,       /* Hardware SPI1 */
    SPI_INSTANCE_HW2,           /* Hardware SPI2 */
    SPI_INSTANCE_HW3,           /* Hardware SPI3 */
    SPI_INSTANCE_HW4,           /* Hardware SPI4 */
    SPI_INSTANCE_SW_BK4829,     /* Software SPI for BK4829 #2 */
    SPI_INSTANCE_SW_FLASH,      /* Software SPI for external flash */
    SPI_INSTANCE_COUNT
} SPI_Instance_t;

/* ============================================================================
 * SPI CONFIGURATION
 * ============================================================================ */

typedef enum {
    SPI_MODE_0 = 0,             /* CPOL=0, CPHA=0 */
    SPI_MODE_1,                 /* CPOL=0, CPHA=1 */
    SPI_MODE_2,                 /* CPOL=1, CPHA=0 */
    SPI_MODE_3                  /* CPOL=1, CPHA=1 */
} SPI_Mode_t;

typedef enum {
    SPI_DIV_2 = 0,
    SPI_DIV_4,
    SPI_DIV_8,
    SPI_DIV_16,
    SPI_DIV_32,
    SPI_DIV_64,
    SPI_DIV_128,
    SPI_DIV_256
} SPI_ClockDiv_t;

typedef struct {
    SPI_Mode_t mode;
    SPI_ClockDiv_t clock_div;
    bool msb_first;
    bool is_master;
} SPI_Config_t;

/* ============================================================================
 * SOFTWARE SPI PIN DEFINITIONS (INFERRED from OEM firmware)
 * ============================================================================ */

/**
 * Software SPI for BK4829 #2 (GPIOE)
 * INFERRED: Second RF transceiver uses bit-banged SPI
 * 
 * PE15: Chip Select (SEN2)
 * PE10: Clock (SCK)
 * PE11: Data (MOSI/MISO - bidirectional)
 */

/**
 * Software SPI for external flash (GPIOB)
 * CONFIRMED: Flash storage for settings/channels
 * 
 * PB12: Chip Select (CS)
 * PB13: Clock (SCK)
 * PB14: MISO
 * PB15: MOSI
 */

/* ============================================================================
 * FUNCTION PROTOTYPES - HARDWARE SPI
 * ============================================================================ */

/**
 * @brief Initialize hardware SPI peripheral
 * @param instance SPI instance (SPI1-4)
 * @param config Configuration parameters
 */
void HAL_SPI_Init(SPI_Instance_t instance, const SPI_Config_t *config);

/**
 * @brief Transfer a single byte over SPI
 * @param instance SPI instance
 * @param tx_data Byte to transmit
 * @return Byte received
 */
uint8_t HAL_SPI_TransferByte(SPI_Instance_t instance, uint8_t tx_data);

/**
 * @brief Transfer a 16-bit word over SPI
 * @param instance SPI instance
 * @param tx_data Word to transmit
 * @return Word received
 */
uint16_t HAL_SPI_TransferWord(SPI_Instance_t instance, uint16_t tx_data);

/**
 * @brief Transfer a buffer over SPI
 * @param instance SPI instance
 * @param tx_buf Transmit buffer (can be NULL for read-only)
 * @param rx_buf Receive buffer (can be NULL for write-only)
 * @param len Number of bytes to transfer
 */
void HAL_SPI_Transfer(SPI_Instance_t instance, const uint8_t *tx_buf, 
                      uint8_t *rx_buf, uint32_t len);

/* ============================================================================
 * FUNCTION PROTOTYPES - SOFTWARE SPI
 * ============================================================================ */

/**
 * @brief Initialize software SPI GPIO pins
 * @param instance Software SPI instance
 */
void HAL_SPI_SW_Init(SPI_Instance_t instance);

/**
 * @brief Assert chip select (drive low)
 * @param instance Software SPI instance
 */
void HAL_SPI_SW_CSLow(SPI_Instance_t instance);

/**
 * @brief Deassert chip select (drive high)
 * @param instance Software SPI instance
 */
void HAL_SPI_SW_CSHigh(SPI_Instance_t instance);

/**
 * @brief Transfer a byte using software SPI
 * @param instance Software SPI instance
 * @param tx_data Byte to transmit
 * @return Byte received
 * 
 * @note This is a bit-banged implementation that toggles GPIO pins.
 *       INFERRED clock polarity and phase from OEM firmware timing.
 */
uint8_t HAL_SPI_SW_TransferByte(SPI_Instance_t instance, uint8_t tx_data);

/**
 * @brief Read multiple bytes using software SPI
 * @param instance Software SPI instance
 * @param rx_buf Receive buffer
 * @param len Number of bytes to read
 */
void HAL_SPI_SW_Read(SPI_Instance_t instance, uint8_t *rx_buf, uint32_t len);

/**
 * @brief Write multiple bytes using software SPI
 * @param instance Software SPI instance
 * @param tx_buf Transmit buffer
 * @param len Number of bytes to write
 */
void HAL_SPI_SW_Write(SPI_Instance_t instance, const uint8_t *tx_buf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* HAL_SPI_H */



