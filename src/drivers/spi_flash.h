/**
 * @file spi_flash.h
 * @brief External SPI Flash Driver
 * 
 * Driver for the external SPI NOR flash used to store settings,
 * channel memory, and other persistent data.
 * 
 * Hardware connection (CONFIRMED from OEM firmware):
 *   - CS: PB12 [CONFIRMED]
 *   - SCK: PB13 [CONFIRMED]
 *   - MISO: PB14 [CONFIRMED]
 *   - MOSI: PB15 [CONFIRMED]
 * 
 * The flash uses standard SPI NOR commands. Operations are implemented
 * based on Software_SPI_* functions from the OEM firmware.
 * 
 * @note The SPI bus is shared with BK4819 #2 - chip select discipline
 *       is critical to avoid conflicts.
 */

#ifndef DRIVERS_SPI_FLASH_H
#define DRIVERS_SPI_FLASH_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * FLASH CONFIGURATION
 * ============================================================================ */

/* Flash size (INFERRED - typical for this application) */
#define SPIFLASH_SIZE           (2 * 1024 * 1024)   /* 2MB = 16Mbit */
#define SPIFLASH_PAGE_SIZE      256
#define SPIFLASH_SECTOR_SIZE    4096                /* 4KB sector */
#define SPIFLASH_BLOCK_32K      (32 * 1024)         /* 32KB block */
#define SPIFLASH_BLOCK_64K      (64 * 1024)         /* 64KB block */

/* ============================================================================
 * SPI FLASH COMMANDS (Standard NOR Flash)
 * ============================================================================ */

#define SPIFLASH_CMD_WRITE_ENABLE   0x06
#define SPIFLASH_CMD_WRITE_DISABLE  0x04
#define SPIFLASH_CMD_READ_STATUS    0x05
#define SPIFLASH_CMD_WRITE_STATUS   0x01
#define SPIFLASH_CMD_READ_DATA      0x03    /* CONFIRMED from FUN_80021180 */
#define SPIFLASH_CMD_FAST_READ      0x0B
#define SPIFLASH_CMD_PAGE_PROGRAM   0x02
#define SPIFLASH_CMD_SECTOR_ERASE   0x20    /* CONFIRMED: 4KB erase */
#define SPIFLASH_CMD_BLOCK_ERASE_32 0x52    /* CONFIRMED: 32KB erase */
#define SPIFLASH_CMD_BLOCK_ERASE_64 0xD8    /* CONFIRMED: 64KB erase */
#define SPIFLASH_CMD_CHIP_ERASE     0xC7
#define SPIFLASH_CMD_POWER_DOWN     0xB9
#define SPIFLASH_CMD_RELEASE_PD     0xAB
#define SPIFLASH_CMD_DEVICE_ID      0x90
#define SPIFLASH_CMD_JEDEC_ID       0x9F

/* Status register bits */
#define SPIFLASH_STATUS_WIP         0x01    /* Write in progress */
#define SPIFLASH_STATUS_WEL         0x02    /* Write enable latch */
#define SPIFLASH_STATUS_BP          0x3C    /* Block protect bits */
#define SPIFLASH_STATUS_SRP         0x80    /* Status register protect */

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize SPI flash interface
 * 
 * Configures GPIO pins for SPI communication and verifies flash ID.
 */
void SPIFlash_Init(void);

/**
 * @brief Read flash memory
 * @param address Start address
 * @param buffer Buffer to store data
 * @param length Number of bytes to read
 * @return true if read was successful
 * 
 * CONFIRMED: Implementation based on FUN_80021180
 */
bool SPIFlash_Read(uint32_t address, uint8_t *buffer, uint32_t length);

/**
 * @brief Write flash memory (page program)
 * @param address Start address (must be page-aligned for best performance)
 * @param buffer Data to write
 * @param length Number of bytes to write
 * @return true if write was successful
 * 
 * @note Will handle crossing page boundaries automatically.
 */
bool SPIFlash_Write(uint32_t address, const uint8_t *buffer, uint32_t length);

/**
 * @brief Erase a 4KB sector
 * @param address Any address within the sector to erase
 * @return true if erase was successful
 * 
 * CONFIRMED: Implementation based on Software_SPI_FlashErase4K (FUN_800210c0)
 */
bool SPIFlash_EraseSector(uint32_t address);

/**
 * @brief Erase a 32KB block
 * @param address Any address within the block to erase
 * @return true if erase was successful
 * 
 * CONFIRMED: Implementation based on Software_SPI_FlashErase32KBlock (FUN_80020f80)
 */
bool SPIFlash_EraseBlock32K(uint32_t address);

/**
 * @brief Erase a 64KB block
 * @param address Any address within the block to erase
 * @return true if erase was successful
 * 
 * CONFIRMED: Implementation based on Software_SPI_FlashErase64KBlock (FUN_80020ff0)
 */
bool SPIFlash_EraseBlock64K(uint32_t address);

/**
 * @brief Erase entire flash chip
 * @return true if erase was successful
 * 
 * @warning This operation takes several seconds!
 */
bool SPIFlash_EraseChip(void);

/**
 * @brief Read flash status register
 * @return Status register value
 */
uint8_t SPIFlash_ReadStatus(void);

/**
 * @brief Check if flash is busy (write/erase in progress)
 * @return true if flash is busy
 * 
 * CONFIRMED: Polls status register WIP bit as in FUN_80020f6c
 */
bool SPIFlash_IsBusy(void);

/**
 * @brief Wait for flash operation to complete
 * @param timeout_ms Maximum wait time in milliseconds
 * @return true if operation completed, false if timeout
 */
bool SPIFlash_WaitReady(uint32_t timeout_ms);

/**
 * @brief Read flash JEDEC ID
 * @param manufacturer Pointer to store manufacturer ID
 * @param device Pointer to store device ID
 */
void SPIFlash_ReadID(uint8_t *manufacturer, uint16_t *device);

/**
 * @brief Power down flash for low-power mode
 */
void SPIFlash_PowerDown(void);

/**
 * @brief Wake flash from power-down mode
 */
void SPIFlash_PowerUp(void);

/**
 * @brief Read data with CRC-16 calculation
 * @param address Start address
 * @param buffer Buffer to store data
 * @param length Number of bytes to read
 * @return CRC-16 of read data
 * 
 * CONFIRMED: Based on FUN_8000956c (SPI_Read_And_CRC16)
 */
uint16_t SPIFlash_ReadWithCRC(uint32_t address, uint8_t *buffer, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif /* DRIVERS_SPI_FLASH_H */


