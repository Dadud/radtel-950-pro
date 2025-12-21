/**
 * @file spi_flash.c
 * @brief External SPI Flash Driver Implementation
 * 
 * CONFIRMED: Implementation based on Ghidra analysis of OEM firmware.
 * Key functions analyzed:
 *   - FUN_080210c0: 4KB sector erase (command 0x20)
 *   - FUN_08020f80: 32KB block erase (command 0x52)
 *   - FUN_08020ff0: 64KB block erase (command 0xD8)
 *   - FUN_08021064: Chip erase (command 0xC7)
 *   - FUN_08021180: Read data (command 0x03)
 *   - FUN_08021314: Page program
 *   - FUN_0802137c: Write enable
 *   - FUN_08020f6c: Check busy status
 */

#include "drivers/spi_flash.h"
#include "hal/gpio.h"
#include "hal/spi.h"
#include "hal/system.h"

/* GPIO pins for SPI flash (CONFIRMED from OEM pinout) */
#define FLASH_CS_PORT       GPIOB
#define FLASH_CS_PIN        GPIO_PIN_12
#define FLASH_SCK_PORT      GPIOB
#define FLASH_SCK_PIN       GPIO_PIN_13
#define FLASH_MISO_PORT     GPIOB
#define FLASH_MISO_PIN      GPIO_PIN_14
#define FLASH_MOSI_PORT     GPIOB
#define FLASH_MOSI_PIN      GPIO_PIN_15

/* CS control macros */
#define FLASH_CS_LOW()      (FLASH_CS_PORT->CLR = FLASH_CS_PIN)
#define FLASH_CS_HIGH()     (FLASH_CS_PORT->SCR = FLASH_CS_PIN)

/* CONFIRMED: Timeout value from OEM firmware (-0x15A0 = ~5536 iterations) */
#define ERASE_TIMEOUT_LOOPS     5536
#define ERASE_POLL_DELAY_US     500

/**
 * @brief Send one byte over SPI and receive response
 */
static uint8_t spi_transfer_byte(uint8_t data)
{
    return HAL_SPI_SW_TransferByte(SPI_INSTANCE_SW_FLASH, data);
}

/**
 * @brief Write enable command
 * 
 * CONFIRMED: Part of FUN_0802137c sequence
 */
static void flash_write_enable(void)
{
    FLASH_CS_LOW();
    HAL_DelayUs(1);
    spi_transfer_byte(SPIFLASH_CMD_WRITE_ENABLE);  /* 0x06 */
    HAL_DelayUs(1);
    FLASH_CS_HIGH();
    HAL_DelayUs(1);
}

/**
 * @brief Initialize SPI flash interface
 */
void SPIFlash_Init(void)
{
    /* Configure CS pin as output, high (deselected) */
    HAL_GPIO_Config(GPIO_PORT_B, FLASH_CS_PIN, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_50MHZ);
    FLASH_CS_HIGH();
    
    /* Configure SPI pins */
    HAL_GPIO_Config(GPIO_PORT_B, FLASH_SCK_PIN | FLASH_MOSI_PIN, 
                    GPIO_MODE_OUTPUT_PP, GPIO_SPEED_50MHZ);
    HAL_GPIO_Config(GPIO_PORT_B, FLASH_MISO_PIN, GPIO_MODE_INPUT, GPIO_SPEED_50MHZ);
    
    /* Initialize software SPI */
    HAL_SPI_SW_Init(SPI_INSTANCE_SW_FLASH);
    
    /* Wake from power-down if needed */
    SPIFlash_PowerUp();
    HAL_Delay(1);
    
    /* Verify communication by reading ID */
    uint8_t mfg;
    uint16_t dev;
    SPIFlash_ReadID(&mfg, &dev);
    /* TODO: Verify expected flash ID */
}

/**
 * @brief Read flash memory
 * 
 * CONFIRMED: Based on FUN_08021180
 * Sequence: CS low, cmd 0x03, 24-bit address, read N bytes, CS high
 */
bool SPIFlash_Read(uint32_t address, uint8_t *buffer, uint32_t length)
{
    if (buffer == NULL || length == 0) return false;
    
    FLASH_CS_LOW();
    HAL_DelayUs(1);
    
    /* Send read command (0x03) */
    spi_transfer_byte(SPIFLASH_CMD_READ_DATA);
    
    /* Send 24-bit address, MSB first */
    spi_transfer_byte((address >> 16) & 0xFF);
    spi_transfer_byte((address >> 8) & 0xFF);
    spi_transfer_byte(address & 0xFF);
    
    /* Read data bytes */
    for (uint32_t i = 0; i < length; i++) {
        buffer[i] = spi_transfer_byte(0xFF);
    }
    
    HAL_DelayUs(1);
    FLASH_CS_HIGH();
    
    return true;
}

/**
 * @brief Write flash memory (page program)
 * 
 * CONFIRMED: Based on FUN_08021314
 */
bool SPIFlash_Write(uint32_t address, const uint8_t *buffer, uint32_t length)
{
    if (buffer == NULL || length == 0) return false;
    
    while (length > 0) {
        /* Calculate bytes remaining in current page */
        uint32_t page_offset = address & (SPIFLASH_PAGE_SIZE - 1);
        uint32_t bytes_to_write = SPIFLASH_PAGE_SIZE - page_offset;
        if (bytes_to_write > length) {
            bytes_to_write = length;
        }
        
        /* Write enable */
        flash_write_enable();
        
        FLASH_CS_LOW();
        HAL_DelayUs(1);
        
        /* Page program command (0x02) */
        spi_transfer_byte(SPIFLASH_CMD_PAGE_PROGRAM);
        
        /* Send 24-bit address */
        spi_transfer_byte((address >> 16) & 0xFF);
        spi_transfer_byte((address >> 8) & 0xFF);
        spi_transfer_byte(address & 0xFF);
        
        /* Write data */
        for (uint32_t i = 0; i < bytes_to_write; i++) {
            spi_transfer_byte(buffer[i]);
        }
        
        HAL_DelayUs(1);
        FLASH_CS_HIGH();
        
        /* Wait for program to complete */
        if (!SPIFlash_WaitReady(100)) {
            return false;
        }
        
        /* Update pointers */
        address += bytes_to_write;
        buffer += bytes_to_write;
        length -= bytes_to_write;
    }
    
    return true;
}

/**
 * @brief Erase a 4KB sector
 * 
 * CONFIRMED: Based on FUN_080210c0
 * OEM uses command 0x20, then polls status with ~500us delays
 */
bool SPIFlash_EraseSector(uint32_t address)
{
    /* Write enable */
    flash_write_enable();
    
    FLASH_CS_LOW();
    HAL_DelayUs(1);
    
    /* Sector erase command (0x20) */
    spi_transfer_byte(SPIFLASH_CMD_SECTOR_ERASE);
    
    /* Send 24-bit address */
    spi_transfer_byte((address >> 16) & 0xFF);
    spi_transfer_byte((address >> 8) & 0xFF);
    spi_transfer_byte(address & 0xFF);
    
    HAL_DelayUs(1);
    FLASH_CS_HIGH();
    
    /* Wait for erase to complete (OEM polls with 500us delays) */
    for (int i = 0; i < ERASE_TIMEOUT_LOOPS; i++) {
        HAL_DelayUs(ERASE_POLL_DELAY_US);
        if (!SPIFlash_IsBusy()) {
            return true;
        }
    }
    
    return false;  /* Timeout */
}

/**
 * @brief Erase a 32KB block
 * 
 * CONFIRMED: Based on FUN_08020f80
 * OEM uses command 0x52
 */
bool SPIFlash_EraseBlock32K(uint32_t address)
{
    /* Write enable */
    flash_write_enable();
    
    FLASH_CS_LOW();
    HAL_DelayUs(1);
    
    /* 32KB block erase command (0x52) */
    spi_transfer_byte(SPIFLASH_CMD_BLOCK_ERASE_32);
    
    /* Send 24-bit address */
    spi_transfer_byte((address >> 16) & 0xFF);
    spi_transfer_byte((address >> 8) & 0xFF);
    spi_transfer_byte(address & 0xFF);
    
    HAL_DelayUs(1);
    FLASH_CS_HIGH();
    
    /* Wait for erase to complete */
    for (int i = 0; i < ERASE_TIMEOUT_LOOPS; i++) {
        HAL_DelayUs(ERASE_POLL_DELAY_US);
        if (!SPIFlash_IsBusy()) {
            return true;
        }
    }
    
    return false;
}

/**
 * @brief Erase a 64KB block
 * 
 * CONFIRMED: Based on FUN_08020ff0
 * OEM uses command 0xD8, adds 5ms delay before polling
 */
bool SPIFlash_EraseBlock64K(uint32_t address)
{
    /* Write enable */
    flash_write_enable();
    
    FLASH_CS_LOW();
    HAL_DelayUs(1);
    
    /* 64KB block erase command (0xD8) */
    spi_transfer_byte(SPIFLASH_CMD_BLOCK_ERASE_64);
    
    /* Send 24-bit address */
    spi_transfer_byte((address >> 16) & 0xFF);
    spi_transfer_byte((address >> 8) & 0xFF);
    spi_transfer_byte(address & 0xFF);
    
    HAL_DelayUs(1);
    FLASH_CS_HIGH();
    
    /* OEM adds initial 5ms delay for 64KB erase (FUN_0800b7a6(5)) */
    HAL_Delay(5);
    
    /* Wait for erase to complete */
    for (int i = 0; i < ERASE_TIMEOUT_LOOPS; i++) {
        HAL_DelayUs(ERASE_POLL_DELAY_US);
        if (!SPIFlash_IsBusy()) {
            return true;
        }
    }
    
    return false;
}

/**
 * @brief Erase entire flash chip
 * 
 * CONFIRMED: Based on FUN_08021064
 * OEM uses command 0xC7 (199 decimal), 100ms initial delay
 */
bool SPIFlash_EraseChip(void)
{
    /* Write enable */
    flash_write_enable();
    
    FLASH_CS_LOW();
    HAL_DelayUs(1);
    
    /* Chip erase command (0xC7 = 199) */
    spi_transfer_byte(SPIFLASH_CMD_CHIP_ERASE);
    
    HAL_DelayUs(1);
    FLASH_CS_HIGH();
    
    /* OEM adds initial 100ms delay for chip erase */
    HAL_Delay(100);
    
    /* Wait for erase to complete - chip erase takes several seconds */
    for (int i = 0; i < 60000; i++) {  /* Up to 30 seconds */
        HAL_DelayUs(ERASE_POLL_DELAY_US);
        if (!SPIFlash_IsBusy()) {
            return true;
        }
    }
    
    return false;
}

/**
 * @brief Read flash status register
 */
uint8_t SPIFlash_ReadStatus(void)
{
    FLASH_CS_LOW();
    HAL_DelayUs(1);
    
    spi_transfer_byte(SPIFLASH_CMD_READ_STATUS);
    uint8_t status = spi_transfer_byte(0xFF);
    
    HAL_DelayUs(1);
    FLASH_CS_HIGH();
    
    return status;
}

/**
 * @brief Check if flash is busy
 * 
 * CONFIRMED: Based on FUN_08020f6c
 */
bool SPIFlash_IsBusy(void)
{
    return (SPIFlash_ReadStatus() & SPIFLASH_STATUS_WIP) != 0;
}

/**
 * @brief Wait for flash operation to complete
 */
bool SPIFlash_WaitReady(uint32_t timeout_ms)
{
    uint32_t start = HAL_GetTick();
    
    while (SPIFlash_IsBusy()) {
        if ((HAL_GetTick() - start) >= timeout_ms) {
            return false;
        }
        HAL_DelayUs(100);
    }
    
    return true;
}

/**
 * @brief Read flash JEDEC ID
 */
void SPIFlash_ReadID(uint8_t *manufacturer, uint16_t *device)
{
    FLASH_CS_LOW();
    HAL_DelayUs(1);
    
    spi_transfer_byte(SPIFLASH_CMD_JEDEC_ID);
    
    *manufacturer = spi_transfer_byte(0xFF);
    *device = spi_transfer_byte(0xFF) << 8;
    *device |= spi_transfer_byte(0xFF);
    
    HAL_DelayUs(1);
    FLASH_CS_HIGH();
}

/**
 * @brief Power down flash for low-power mode
 */
void SPIFlash_PowerDown(void)
{
    FLASH_CS_LOW();
    HAL_DelayUs(1);
    spi_transfer_byte(SPIFLASH_CMD_POWER_DOWN);
    HAL_DelayUs(1);
    FLASH_CS_HIGH();
}

/**
 * @brief Wake flash from power-down mode
 */
void SPIFlash_PowerUp(void)
{
    FLASH_CS_LOW();
    HAL_DelayUs(1);
    spi_transfer_byte(SPIFLASH_CMD_RELEASE_PD);
    HAL_DelayUs(1);
    FLASH_CS_HIGH();
}

/**
 * @brief Read data with CRC-16 calculation
 * 
 * CONFIRMED: Based on FUN_8000956c
 */
uint16_t SPIFlash_ReadWithCRC(uint32_t address, uint8_t *buffer, uint32_t length)
{
    /* Read data */
    SPIFlash_Read(address, buffer, length);
    
    /* Calculate CRC-16/XMODEM */
    uint16_t crc = 0;
    for (uint32_t i = 0; i < length; i++) {
        crc ^= (uint16_t)buffer[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    
    return crc;
}


