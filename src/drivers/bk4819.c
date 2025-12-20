/**
 * @file bk4819.c
 * @brief BK4819 RF Transceiver Driver Implementation
 * 
 * Implements control for the dual BK4819 transceivers.
 * Register sequences are INFERRED from OEM firmware analysis.
 */

#include "drivers/bk4819.h"
#include "hal/gpio.h"
#include "hal/spi.h"
#include "hal/system.h"

/* Instance configuration */
typedef struct {
    SPI_Instance_t spi;
    GPIO_TypeDef *cs_port;
    uint16_t cs_pin;
    bool initialized;
} BK4819_Instance_Config_t;

static BK4819_Instance_Config_t g_instances[BK4819_INSTANCE_COUNT] = {
    [BK4819_INSTANCE_VHF] = {
        .spi = SPI_INSTANCE_HW1,
        .cs_port = GPIOE,
        .cs_pin = GPIO_PIN_8,
        .initialized = false
    },
    [BK4819_INSTANCE_UHF] = {
        .spi = SPI_INSTANCE_SW_BK4819,
        .cs_port = GPIOE,
        .cs_pin = GPIO_PIN_15,
        .initialized = false
    }
};

/* Chip select control */
static void bk4819_cs_low(BK4819_Instance_t instance)
{
    g_instances[instance].cs_port->CLR = g_instances[instance].cs_pin;
}

static void bk4819_cs_high(BK4819_Instance_t instance)
{
    g_instances[instance].cs_port->SCR = g_instances[instance].cs_pin;
}

/**
 * @brief Write a register to BK4819
 * 
 * Protocol:
 *   - CS low
 *   - Send: [7-bit address | 0] (write bit = 0)
 *   - Send: 16-bit value (MSB first)
 *   - CS high
 */
void BK4819_WriteReg(BK4819_Instance_t instance, uint8_t reg, uint16_t value)
{
    if (instance >= BK4819_INSTANCE_COUNT) return;
    
    SPI_Instance_t spi = g_instances[instance].spi;
    
    bk4819_cs_low(instance);
    HAL_DelayUs(1);
    
    /* Send register address with write bit (bit 7 = 0) */
    HAL_SPI_SW_TransferByte(spi, (reg & 0x7F) << 1);
    
    /* Send 16-bit value, MSB first */
    HAL_SPI_SW_TransferByte(spi, value >> 8);
    HAL_SPI_SW_TransferByte(spi, value & 0xFF);
    
    HAL_DelayUs(1);
    bk4819_cs_high(instance);
}

/**
 * @brief Read a register from BK4819
 * 
 * Protocol:
 *   - CS low
 *   - Send: [7-bit address | 1] (read bit = 1)
 *   - Read: 16-bit value (MSB first)
 *   - CS high
 */
uint16_t BK4819_ReadReg(BK4819_Instance_t instance, uint8_t reg)
{
    if (instance >= BK4819_INSTANCE_COUNT) return 0;
    
    SPI_Instance_t spi = g_instances[instance].spi;
    uint16_t value;
    
    bk4819_cs_low(instance);
    HAL_DelayUs(1);
    
    /* Send register address with read bit (bit 7 = 1) */
    HAL_SPI_SW_TransferByte(spi, ((reg & 0x7F) << 1) | 0x01);
    
    /* Read 16-bit value, MSB first */
    value = HAL_SPI_SW_TransferByte(spi, 0xFF) << 8;
    value |= HAL_SPI_SW_TransferByte(spi, 0xFF);
    
    HAL_DelayUs(1);
    bk4819_cs_high(instance);
    
    return value;
}

/**
 * @brief Initialize BK4819 transceiver
 * 
 * INFERRED: Initialization sequence from FUN_80007f04
 */
void BK4819_Init(BK4819_Instance_t instance)
{
    if (instance >= BK4819_INSTANCE_COUNT) return;
    
    BK4819_Instance_Config_t *cfg = &g_instances[instance];
    
    /* Configure CS pin as output */
    HAL_GPIO_Config(
        (cfg->cs_port == GPIOE) ? GPIO_PORT_E : GPIO_PORT_B,
        cfg->cs_pin,
        GPIO_MODE_OUTPUT_PP,
        GPIO_SPEED_50MHZ
    );
    bk4819_cs_high(instance);
    
    /* Initialize SPI */
    if (instance == BK4819_INSTANCE_VHF) {
        /* Hardware SPI1 initialization */
        SPI_Config_t spi_cfg = {
            .mode = SPI_MODE_0,
            .clock_div = SPI_DIV_8,
            .msb_first = true,
            .is_master = true
        };
        HAL_SPI_Init(SPI_INSTANCE_HW1, &spi_cfg);
    } else {
        /* Software SPI for secondary transceiver */
        HAL_SPI_SW_Init(SPI_INSTANCE_SW_BK4819);
    }
    
    /* Wait for BK4819 to be ready after power-up */
    HAL_Delay(100);
    
    /* Read chip ID to verify communication */
    uint16_t chip_id = BK4819_ReadReg(instance, BK4819_REG_00);
    (void)chip_id;  /* TODO: Verify expected ID */
    
    /* Soft reset - write 0 to register 0 */
    BK4819_WriteReg(instance, BK4819_REG_00, 0x0000);
    HAL_Delay(10);
    
    /* INFERRED: Basic initialization sequence */
    /* TODO: Verify these values against actual OEM init */
    
    /* Power control - enable basic blocks */
    BK4819_WriteReg(instance, BK4819_REG_30, 0x0200);
    
    /* AFC enable */
    BK4819_WriteReg(instance, BK4819_REG_0D, 0x0200);
    
    /* Audio filter settings */
    BK4819_WriteReg(instance, BK4819_REG_48, 0xB3A8);
    
    /* Default squelch settings */
    BK4819_WriteReg(instance, BK4819_REG_3D, 0x2400);
    
    /* Default bandwidth (wide) */
    BK4819_WriteReg(instance, BK4819_REG_37, 0x1F0F);
    
    /* Enable receiver */
    BK4819_WriteReg(instance, BK4819_REG_3F, 0x8000);
    
    cfg->initialized = true;
}

/**
 * @brief Set operating frequency
 * 
 * INFERRED: Frequency calculation from FUN_8000b62c
 */
void BK4819_SetFrequency(BK4819_Instance_t instance, uint32_t frequency_hz)
{
    if (instance >= BK4819_INSTANCE_COUNT) return;
    
    /* BK4819 frequency register format:
     * The frequency synthesizer uses a fractional-N PLL.
     * Register 0x38/0x39 contain the frequency word.
     * 
     * INFERRED: Frequency = (N + F/65536) * Fref
     * where Fref is typically 12.8 MHz or 26 MHz
     * 
     * TODO: Verify exact formula from captured register values
     */
    
    /* Approximate calculation assuming 12.8 MHz reference */
    uint32_t fref = 12800000;
    uint32_t div = frequency_hz / fref;
    uint32_t frac = ((frequency_hz % fref) * 65536) / fref;
    
    uint16_t reg38 = (div << 8) | ((frac >> 8) & 0xFF);
    uint16_t reg39 = (frac & 0xFF) << 8;
    
    /* Disable synthesizer during frequency change */
    BK4819_WriteReg(instance, BK4819_REG_3F, 
                    BK4819_ReadReg(instance, BK4819_REG_3F) & ~0x0100);
    
    /* Write frequency registers */
    BK4819_WriteReg(instance, BK4819_REG_38, reg38);
    BK4819_WriteReg(instance, BK4819_REG_39, reg39);
    
    /* Re-enable synthesizer */
    BK4819_WriteReg(instance, BK4819_REG_3F, 
                    BK4819_ReadReg(instance, BK4819_REG_3F) | 0x0100);
    
    /* Wait for PLL lock */
    HAL_Delay(10);
}

/**
 * @brief Get RSSI value
 */
int16_t BK4819_GetRSSI(BK4819_Instance_t instance)
{
    if (instance >= BK4819_INSTANCE_COUNT) return -127;
    
    uint16_t raw = BK4819_ReadReg(instance, BK4819_REG_65);
    
    /* Convert to dBm (INFERRED formula) */
    int16_t rssi = (int16_t)(raw & 0x01FF) - 220;
    
    return rssi;
}

/**
 * @brief Check if squelch is open
 */
bool BK4819_IsSquelchOpen(BK4819_Instance_t instance)
{
    if (instance >= BK4819_INSTANCE_COUNT) return false;
    
    uint16_t status = BK4819_ReadReg(instance, BK4819_REG_02);
    
    /* INFERRED: Bit 0 indicates squelch state */
    return (status & 0x0001) != 0;
}

/**
 * @brief Enable/disable receiver
 */
void BK4819_EnableRX(BK4819_Instance_t instance, bool enable)
{
    if (instance >= BK4819_INSTANCE_COUNT) return;
    
    uint16_t reg3f = BK4819_ReadReg(instance, BK4819_REG_3F);
    
    if (enable) {
        reg3f |= 0x8000;    /* Enable RX */
        reg3f &= ~0x4000;   /* Disable TX */
    } else {
        reg3f &= ~0x8000;
    }
    
    BK4819_WriteReg(instance, BK4819_REG_3F, reg3f);
}

/**
 * @brief Enable/disable transmitter
 */
void BK4819_EnableTX(BK4819_Instance_t instance, bool enable)
{
    if (instance >= BK4819_INSTANCE_COUNT) return;
    
    uint16_t reg3f = BK4819_ReadReg(instance, BK4819_REG_3F);
    
    if (enable) {
        reg3f |= 0x4000;    /* Enable TX */
        reg3f &= ~0x8000;   /* Disable RX */
    } else {
        reg3f &= ~0x4000;
    }
    
    BK4819_WriteReg(instance, BK4819_REG_3F, reg3f);
}

/**
 * @brief Set TX power level
 */
void BK4819_SetTXPower(BK4819_Instance_t instance, BK4819_Power_t power)
{
    if (instance >= BK4819_INSTANCE_COUNT) return;
    
    uint16_t pa_bias;
    
    switch (power) {
        case BK4819_POWER_LOW:
            pa_bias = 0x10;
            break;
        case BK4819_POWER_MID:
            pa_bias = 0x40;
            break;
        case BK4819_POWER_HIGH:
        default:
            pa_bias = 0x80;
            break;
    }
    
    BK4819_WriteReg(instance, BK4819_REG_36, pa_bias);
}

/**
 * @brief Set channel bandwidth
 */
void BK4819_SetBandwidth(BK4819_Instance_t instance, BK4819_Bandwidth_t bandwidth)
{
    if (instance >= BK4819_INSTANCE_COUNT) return;
    
    uint16_t filter;
    
    switch (bandwidth) {
        case BK4819_BW_WIDE:
            filter = 0x1F0F;    /* 25 kHz */
            break;
        case BK4819_BW_NARROW:
            filter = 0x0F0F;    /* 12.5 kHz */
            break;
        case BK4819_BW_NARROWER:
        default:
            filter = 0x070F;    /* 6.25 kHz */
            break;
    }
    
    BK4819_WriteReg(instance, BK4819_REG_37, filter);
}

/**
 * @brief Set CTCSS tone frequency
 */
void BK4819_SetCTCSS(BK4819_Instance_t instance, uint16_t freq_tenths)
{
    if (instance >= BK4819_INSTANCE_COUNT) return;
    
    if (freq_tenths == 0) {
        /* Disable CTCSS */
        BK4819_WriteReg(instance, BK4819_REG_51, 0x0000);
    } else {
        /* Set CTCSS frequency
         * INFERRED: Register value = frequency * 20.64
         */
        uint16_t reg_value = (freq_tenths * 206) / 100;
        BK4819_WriteReg(instance, BK4819_REG_51, reg_value);
    }
}

/**
 * @brief Get chip ID
 */
uint16_t BK4819_GetChipID(BK4819_Instance_t instance)
{
    return BK4819_ReadReg(instance, BK4819_REG_00);
}


