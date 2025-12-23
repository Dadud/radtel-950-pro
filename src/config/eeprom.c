/**
 * @file eeprom.c
 * @brief EEPROM/Flash Storage Implementation
 * 
 * Provides persistent storage for settings and calibration data.
 * Uses internal flash or external SPI flash.
 */

#include "config/eeprom.h"
#include "drivers/spi_flash.h"
#include "hal/system.h"

#include <string.h>

/* Storage configuration */
#define EEPROM_BASE_ADDR        0x00000     /* Start of EEPROM area in flash */
#define EEPROM_SIZE             0x1000      /* 4KB EEPROM area */
#define EEPROM_PAGE_SIZE        256

/* EEPROM state */
static struct {
    bool initialized;
    bool use_external_flash;
} g_eeprom;

void EEPROM_Init(void)
{
    /* Try to initialize external SPI flash first */
    SPIFlash_Init();
    
    if (SPIFlash_ReadID() != 0 && SPIFlash_ReadID() != 0xFFFFFF) {
        g_eeprom.use_external_flash = true;
    } else {
        /* Fall back to internal flash */
        g_eeprom.use_external_flash = false;
    }
    
    g_eeprom.initialized = true;
}

void EEPROM_DeInit(void)
{
    g_eeprom.initialized = false;
}

bool EEPROM_Read(uint32_t address, uint8_t *data, uint32_t length)
{
    if (!g_eeprom.initialized || data == NULL) {
        return false;
    }
    
    if (address + length > EEPROM_SIZE) {
        return false;
    }
    
    if (g_eeprom.use_external_flash) {
        SPIFlash_Read(EEPROM_BASE_ADDR + address, data, length);
    } else {
        /* Read from internal flash */
        uint8_t *flash_ptr = (uint8_t*)(0x080FF000 + address);  /* Last 4KB of 1MB flash */
        memcpy(data, flash_ptr, length);
    }
    
    return true;
}

bool EEPROM_Write(uint32_t address, const uint8_t *data, uint32_t length)
{
    if (!g_eeprom.initialized || data == NULL) {
        return false;
    }
    
    if (address + length > EEPROM_SIZE) {
        return false;
    }
    
    if (g_eeprom.use_external_flash) {
        /* External flash needs erase before write */
        /* For simplicity, erase entire sector if writing */
        if (address == 0) {
            SPIFlash_EraseSector(EEPROM_BASE_ADDR);
        }
        SPIFlash_Write(EEPROM_BASE_ADDR + address, data, length);
    } else {
        /* Internal flash write */
        /* This would require flash unlock, erase, program sequence */
        /* Simplified implementation - needs proper flash driver */
        EEPROM_WriteInternalFlash(0x080FF000 + address, data, length);
    }
    
    return true;
}

bool EEPROM_Erase(void)
{
    if (!g_eeprom.initialized) {
        return false;
    }
    
    if (g_eeprom.use_external_flash) {
        SPIFlash_EraseSector(EEPROM_BASE_ADDR);
    } else {
        /* Erase internal flash sector */
        EEPROM_EraseInternalFlash(0x080FF000);
    }
    
    return true;
}

bool EEPROM_ReadByte(uint32_t address, uint8_t *data)
{
    return EEPROM_Read(address, data, 1);
}

bool EEPROM_WriteByte(uint32_t address, uint8_t data)
{
    return EEPROM_Write(address, &data, 1);
}

bool EEPROM_ReadWord(uint32_t address, uint32_t *data)
{
    return EEPROM_Read(address, (uint8_t*)data, 4);
}

bool EEPROM_WriteWord(uint32_t address, uint32_t data)
{
    return EEPROM_Write(address, (uint8_t*)&data, 4);
}

/* Internal flash operations */

#define FLASH_BASE_ADDR     0x40022000UL
#define FLASH_KEY1          0x45670123
#define FLASH_KEY2          0xCDEF89AB

typedef struct {
    volatile uint32_t PSR;      /* 0x00: Performance select */
    volatile uint32_t UNLOCK;   /* 0x04: Unlock register */
    volatile uint32_t USD_UNLOCK; /* 0x08: USD unlock */
    volatile uint32_t STS;      /* 0x0C: Status register */
    volatile uint32_t CTRL;     /* 0x10: Control register */
    volatile uint32_t ADDR;     /* 0x14: Address register */
    volatile uint32_t RESERVED;
    volatile uint32_t USD;      /* 0x1C: User system data */
    volatile uint32_t EPPS;     /* 0x20: Erase/program protection */
} FLASH_TypeDef;

#define FLASH           ((FLASH_TypeDef *)FLASH_BASE_ADDR)

#define FLASH_STS_OBF       (1 << 0)    /* Operate busy flag */
#define FLASH_STS_PRGMERR   (1 << 2)    /* Program error */
#define FLASH_STS_EPPERR    (1 << 4)    /* Erase/program protection error */
#define FLASH_STS_ODF       (1 << 5)    /* Operate done flag */

#define FLASH_CTRL_FPRGM    (1 << 0)    /* Flash program */
#define FLASH_CTRL_SECERS   (1 << 1)    /* Sector erase */
#define FLASH_CTRL_BANKERS  (1 << 2)    /* Bank erase */
#define FLASH_CTRL_USDPRGM  (1 << 4)    /* USD program */
#define FLASH_CTRL_USDERS   (1 << 5)    /* USD erase */
#define FLASH_CTRL_ERSTR    (1 << 6)    /* Erase start */
#define FLASH_CTRL_OPLK     (1 << 7)    /* Operation lock */

static void flash_unlock(void)
{
    if (FLASH->CTRL & FLASH_CTRL_OPLK) {
        FLASH->UNLOCK = FLASH_KEY1;
        FLASH->UNLOCK = FLASH_KEY2;
    }
}

static void flash_lock(void)
{
    FLASH->CTRL |= FLASH_CTRL_OPLK;
}

static void flash_wait_complete(void)
{
    while (FLASH->STS & FLASH_STS_OBF);
}

bool EEPROM_WriteInternalFlash(uint32_t address, const uint8_t *data, uint32_t length)
{
    flash_unlock();
    
    /* Write data as halfwords (16-bit) */
    for (uint32_t i = 0; i < length; i += 2) {
        FLASH->CTRL |= FLASH_CTRL_FPRGM;
        
        uint16_t halfword = data[i];
        if (i + 1 < length) {
            halfword |= (data[i + 1] << 8);
        } else {
            halfword |= 0xFF00;
        }
        
        *(volatile uint16_t*)(address + i) = halfword;
        
        flash_wait_complete();
        
        FLASH->CTRL &= ~FLASH_CTRL_FPRGM;
    }
    
    flash_lock();
    
    return true;
}

bool EEPROM_EraseInternalFlash(uint32_t address)
{
    flash_unlock();
    
    FLASH->CTRL |= FLASH_CTRL_SECERS;
    FLASH->ADDR = address;
    FLASH->CTRL |= FLASH_CTRL_ERSTR;
    
    flash_wait_complete();
    
    FLASH->CTRL &= ~FLASH_CTRL_SECERS;
    
    flash_lock();
    
    return true;
}

