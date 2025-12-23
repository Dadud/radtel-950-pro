/**
 * @file spi.c
 * @brief SPI Hardware Abstraction Layer Implementation
 * 
 * Provides both hardware SPI and bit-banged software SPI support.
 */

#include "hal/spi.h"
#include "hal/gpio.h"
#include "hal/system.h"

/* ============================================================================
 * SOFTWARE SPI PIN CONFIGURATION
 * ============================================================================ */

/* BK4829 #2 software SPI (GPIOE) */
#define BK4829_SW_CS_PORT   GPIOE
#define BK4829_SW_CS_PIN    GPIO_PIN_15
#define BK4829_SW_SCK_PORT  GPIOE
#define BK4829_SW_SCK_PIN   GPIO_PIN_10
#define BK4829_SW_SDA_PORT  GPIOE
#define BK4829_SW_SDA_PIN   GPIO_PIN_11

/* External flash software SPI (GPIOB) */
#define FLASH_SW_CS_PORT    GPIOB
#define FLASH_SW_CS_PIN     GPIO_PIN_12
#define FLASH_SW_SCK_PORT   GPIOB
#define FLASH_SW_SCK_PIN    GPIO_PIN_13
#define FLASH_SW_MISO_PORT  GPIOB
#define FLASH_SW_MISO_PIN   GPIO_PIN_14
#define FLASH_SW_MOSI_PORT  GPIOB
#define FLASH_SW_MOSI_PIN   GPIO_PIN_15

/* ============================================================================
 * HARDWARE SPI FUNCTIONS
 * ============================================================================ */

void HAL_SPI_Init(SPI_Instance_t instance, const SPI_Config_t *config)
{
    SPI_TypeDef *spi = NULL;
    
    switch (instance) {
        case SPI_INSTANCE_HW1:
            spi = SPI1;
            /* Enable SPI1 clock */
            CRM_APB2EN |= (1 << 12);
            break;
        case SPI_INSTANCE_HW2:
            spi = SPI2;
            CRM_APB1EN |= (1 << 14);
            break;
        case SPI_INSTANCE_HW3:
            spi = SPI3;
            CRM_APB1EN |= (1 << 15);
            break;
        case SPI_INSTANCE_HW4:
            spi = SPI4;
            CRM_APB2EN |= (1 << 15);
            break;
        default:
            /* Software SPI - use SW init */
            HAL_SPI_SW_Init(instance);
            return;
    }
    
    if (spi == NULL) return;
    
    /* Configure SPI */
    uint32_t ctrl1 = 0;
    
    /* Clock polarity and phase */
    if (config->mode == SPI_MODE_1 || config->mode == SPI_MODE_3) {
        ctrl1 |= (1 << 0);  /* CPHA */
    }
    if (config->mode == SPI_MODE_2 || config->mode == SPI_MODE_3) {
        ctrl1 |= (1 << 1);  /* CPOL */
    }
    
    /* Master mode */
    if (config->is_master) {
        ctrl1 |= (1 << 2);  /* MSTEN */
    }
    
    /* Clock divider */
    ctrl1 |= ((config->clock_div & 0x07) << 3);
    
    /* MSB first */
    if (!config->msb_first) {
        ctrl1 |= (1 << 7);  /* LTF (LSB first) */
    }
    
    /* 8-bit data frame */
    /* ctrl1 |= 0; DFF bit = 0 for 8-bit */
    
    /* Software slave management */
    ctrl1 |= (1 << 9);   /* SWCSEN */
    ctrl1 |= (1 << 8);   /* SWCSIL - internal select high */
    
    spi->CTRL1 = ctrl1;
    
    /* Enable SPI */
    spi->CTRL1 |= (1 << 6);  /* SPIEN */
}

uint8_t HAL_SPI_TransferByte(SPI_Instance_t instance, uint8_t tx_data)
{
    SPI_TypeDef *spi = NULL;
    
    switch (instance) {
        case SPI_INSTANCE_HW1: spi = SPI1; break;
        case SPI_INSTANCE_HW2: spi = SPI2; break;
        case SPI_INSTANCE_HW3: spi = SPI3; break;
        case SPI_INSTANCE_HW4: spi = SPI4; break;
        default:
            return HAL_SPI_SW_TransferByte(instance, tx_data);
    }
    
    if (spi == NULL) return 0;
    
    /* Wait for TX buffer empty */
    while (!(spi->STS & SPI_STS_TDBE));
    
    /* Send data */
    spi->DT = tx_data;
    
    /* Wait for RX buffer full */
    while (!(spi->STS & SPI_STS_RDBF));
    
    /* Return received data */
    return (uint8_t)spi->DT;
}

uint16_t HAL_SPI_TransferWord(SPI_Instance_t instance, uint16_t tx_data)
{
    uint16_t result;
    result = HAL_SPI_TransferByte(instance, tx_data >> 8) << 8;
    result |= HAL_SPI_TransferByte(instance, tx_data & 0xFF);
    return result;
}

void HAL_SPI_Transfer(SPI_Instance_t instance, const uint8_t *tx_buf, 
                      uint8_t *rx_buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        uint8_t tx = tx_buf ? tx_buf[i] : 0xFF;
        uint8_t rx = HAL_SPI_TransferByte(instance, tx);
        if (rx_buf) {
            rx_buf[i] = rx;
        }
    }
}

/* ============================================================================
 * SOFTWARE SPI FUNCTIONS
 * ============================================================================ */

void HAL_SPI_SW_Init(SPI_Instance_t instance)
{
    if (instance == SPI_INSTANCE_SW_BK4829) {
        /* Configure BK4829 #2 software SPI pins */
        HAL_GPIO_Config(GPIO_PORT_E, GPIO_PIN_15, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_50MHZ);  /* CS */
        HAL_GPIO_Config(GPIO_PORT_E, GPIO_PIN_10, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_50MHZ);  /* SCK */
        HAL_GPIO_Config(GPIO_PORT_E, GPIO_PIN_11, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_50MHZ);  /* SDA (bidirectional) */
        
        /* Default states */
        HAL_GPIO_SetHigh(GPIO_PORT_E, GPIO_PIN_15);  /* CS high */
        HAL_GPIO_SetLow(GPIO_PORT_E, GPIO_PIN_10);   /* SCK low */
    }
    else if (instance == SPI_INSTANCE_SW_FLASH) {
        /* Configure flash software SPI pins */
        HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_12, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_50MHZ);  /* CS */
        HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_13, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_50MHZ);  /* SCK */
        HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_14, GPIO_MODE_INPUT_PULLUP, GPIO_SPEED_50MHZ);  /* MISO */
        HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_15, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_50MHZ);  /* MOSI */
        
        /* Default states */
        HAL_GPIO_SetHigh(GPIO_PORT_B, GPIO_PIN_12);  /* CS high */
        HAL_GPIO_SetLow(GPIO_PORT_B, GPIO_PIN_13);   /* SCK low */
    }
}

void HAL_SPI_SW_CSLow(SPI_Instance_t instance)
{
    if (instance == SPI_INSTANCE_SW_BK4829) {
        BK4829_SW_CS_PORT->CLR = BK4829_SW_CS_PIN;
    }
    else if (instance == SPI_INSTANCE_SW_FLASH) {
        FLASH_SW_CS_PORT->CLR = FLASH_SW_CS_PIN;
    }
}

void HAL_SPI_SW_CSHigh(SPI_Instance_t instance)
{
    if (instance == SPI_INSTANCE_SW_BK4829) {
        BK4829_SW_CS_PORT->SCR = BK4829_SW_CS_PIN;
    }
    else if (instance == SPI_INSTANCE_SW_FLASH) {
        FLASH_SW_CS_PORT->SCR = FLASH_SW_CS_PIN;
    }
}

uint8_t HAL_SPI_SW_TransferByte(SPI_Instance_t instance, uint8_t tx_data)
{
    uint8_t rx_data = 0;
    
    if (instance == SPI_INSTANCE_SW_BK4829) {
        /* BK4829 uses bidirectional SDA line */
        /* Set SDA as output for TX phase */
        GPIOE->CFGHR = (GPIOE->CFGHR & ~(0x0F << 12)) | (0x03 << 12);  /* PE11 output */
        
        for (int i = 7; i >= 0; i--) {
            /* Set data bit */
            if (tx_data & (1 << i)) {
                BK4829_SW_SDA_PORT->SCR = BK4829_SW_SDA_PIN;
            } else {
                BK4829_SW_SDA_PORT->CLR = BK4829_SW_SDA_PIN;
            }
            
            /* Clock high */
            BK4829_SW_SCK_PORT->SCR = BK4829_SW_SCK_PIN;
            __asm volatile ("nop\nnop\nnop\nnop");
            
            /* Read data on falling edge */
            /* For read operations, data comes from BK4829 */
            
            /* Clock low */
            BK4829_SW_SCK_PORT->CLR = BK4829_SW_SCK_PIN;
            __asm volatile ("nop\nnop\nnop\nnop");
        }
    }
    else if (instance == SPI_INSTANCE_SW_FLASH) {
        /* Flash uses separate MOSI/MISO lines */
        for (int i = 7; i >= 0; i--) {
            /* Set MOSI */
            if (tx_data & (1 << i)) {
                FLASH_SW_MOSI_PORT->SCR = FLASH_SW_MOSI_PIN;
            } else {
                FLASH_SW_MOSI_PORT->CLR = FLASH_SW_MOSI_PIN;
            }
            
            /* Clock high */
            FLASH_SW_SCK_PORT->SCR = FLASH_SW_SCK_PIN;
            __asm volatile ("nop\nnop\nnop\nnop");
            
            /* Read MISO */
            rx_data <<= 1;
            if (FLASH_SW_MISO_PORT->IDT & FLASH_SW_MISO_PIN) {
                rx_data |= 1;
            }
            
            /* Clock low */
            FLASH_SW_SCK_PORT->CLR = FLASH_SW_SCK_PIN;
            __asm volatile ("nop\nnop\nnop\nnop");
        }
    }
    
    return rx_data;
}

void HAL_SPI_SW_Read(SPI_Instance_t instance, uint8_t *rx_buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        rx_buf[i] = HAL_SPI_SW_TransferByte(instance, 0xFF);
    }
}

void HAL_SPI_SW_Write(SPI_Instance_t instance, const uint8_t *tx_buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        HAL_SPI_SW_TransferByte(instance, tx_buf[i]);
    }
}

