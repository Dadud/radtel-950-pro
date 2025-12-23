/**
 * @file bk4829.c
 * @brief BK4829 RF Transceiver Driver Implementation
 * 
 * Implements control for the dual BK4829 transceivers.
 * Register sequences are INFERRED from OEM firmware analysis.
 */

#include "drivers/bk4829.h"
#include "config/radio_model.h"
#include "hal/gpio.h"
#include "hal/spi.h"
#include "hal/system.h"

/* Instance configuration */
typedef struct {
    SPI_Instance_t spi;
    GPIO_TypeDef *cs_port;
    uint16_t cs_pin;
    bool initialized;
} BK4829_Instance_Config_t;

static BK4829_Instance_Config_t g_instances[BK4829_INSTANCE_COUNT] = {
    [BK4829_INSTANCE_VHF] = {
        .spi = SPI_INSTANCE_HW1,
        .cs_port = GPIOE,
        .cs_pin = GPIO_PIN_8,
        .initialized = false
    },
#if BK4829_INSTANCE_COUNT > 1
    [BK4829_INSTANCE_UHF] = {
        .spi = SPI_INSTANCE_SW_BK4829,
        .cs_port = GPIOE,
        .cs_pin = GPIO_PIN_15,
        .initialized = false
    },
#endif
};

/* Chip select control */
static void bk4829_cs_low(BK4829_Instance_t instance)
{
    g_instances[instance].cs_port->CLR = g_instances[instance].cs_pin;
}

static void bk4829_cs_high(BK4829_Instance_t instance)
{
    g_instances[instance].cs_port->SCR = g_instances[instance].cs_pin;
}

/**
 * @brief Write a register to BK4829
 * 
 * Protocol:
 *   - CS low
 *   - Send: [7-bit address | 0] (write bit = 0)
 *   - Send: 16-bit value (MSB first)
 *   - CS high
 */
void BK4829_WriteReg(BK4829_Instance_t instance, uint8_t reg, uint16_t value)
{
    if (instance >= BK4829_INSTANCE_COUNT) return;
    
    SPI_Instance_t spi = g_instances[instance].spi;
    
    bk4829_cs_low(instance);
    HAL_DelayUs(1);
    
    /* Send register address with write bit (bit 7 = 0) */
    HAL_SPI_SW_TransferByte(spi, (reg & 0x7F) << 1);
    
    /* Send 16-bit value, MSB first */
    HAL_SPI_SW_TransferByte(spi, value >> 8);
    HAL_SPI_SW_TransferByte(spi, value & 0xFF);
    
    HAL_DelayUs(1);
    bk4829_cs_high(instance);
}

/**
 * @brief Read a register from BK4829
 * 
 * Protocol:
 *   - CS low
 *   - Send: [7-bit address | 1] (read bit = 1)
 *   - Read: 16-bit value (MSB first)
 *   - CS high
 */
uint16_t BK4829_ReadReg(BK4829_Instance_t instance, uint8_t reg)
{
    if (instance >= BK4829_INSTANCE_COUNT) return 0;
    
    SPI_Instance_t spi = g_instances[instance].spi;
    uint16_t value;
    
    bk4829_cs_low(instance);
    HAL_DelayUs(1);
    
    /* Send register address with read bit (bit 7 = 1) */
    HAL_SPI_SW_TransferByte(spi, ((reg & 0x7F) << 1) | 0x01);
    
    /* Read 16-bit value, MSB first */
    value = HAL_SPI_SW_TransferByte(spi, 0xFF) << 8;
    value |= HAL_SPI_SW_TransferByte(spi, 0xFF);
    
    HAL_DelayUs(1);
    bk4829_cs_high(instance);
    
    return value;
}

/**
 * @brief Initialize BK4829 transceiver
 * 
 * CONFIRMED: Initialization sequence from FUN_08007f04 (Ghidra analysis)
 * These register values are extracted directly from OEM firmware.
 */
void BK4829_Init(BK4829_Instance_t instance)
{
    if (instance >= BK4829_INSTANCE_COUNT) return;
    
    BK4829_Instance_Config_t *cfg = &g_instances[instance];
    
    /* Configure CS pin as output */
    HAL_GPIO_Config(
        (cfg->cs_port == GPIOE) ? GPIO_PORT_E : GPIO_PORT_B,
        cfg->cs_pin,
        GPIO_MODE_OUTPUT_PP,
        GPIO_SPEED_50MHZ
    );
    bk4829_cs_high(instance);
    
    /* Initialize SPI */
    if (instance == BK4829_INSTANCE_VHF) {
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
        HAL_SPI_SW_Init(SPI_INSTANCE_SW_BK4829);
    }
    
    /* Wait for BK4829 to be ready after power-up */
    HAL_Delay(100);
    
    /* Soft reset - write 0x8000 to register 0 (CONFIRMED from OEM) */
    BK4829_WriteReg(instance, 0x00, 0x8000);
    BK4829_WriteReg(instance, 0x00, 0x0000);
    HAL_Delay(10);
    
    /* =========================================================================
     * CONFIRMED: OEM initialization sequence from FUN_08007f04
     * All values below are extracted from decompiled firmware
     * ========================================================================= */
    
    /* Register 0x37: RF filter / bandwidth control */
    BK4829_WriteReg(instance, 0x37, 0x9D1F);
    
    /* Registers 0x10-0x14: AGC / gain settings */
    BK4829_WriteReg(instance, 0x13, 0x03DF);
    BK4829_WriteReg(instance, 0x12, 0x03DB);
    BK4829_WriteReg(instance, 0x11, 0x033A);
    BK4829_WriteReg(instance, 0x10, 0x0318);
    BK4829_WriteReg(instance, 0x14, 0x0210);
    
    /* Register 0x49: Audio settings */
    BK4829_WriteReg(instance, 0x49, 0x2AB2);
    
    /* Register 0x7B: Unknown / calibration */
    BK4829_WriteReg(instance, 0x7B, 0x73DC);
    
    /* Registers 0x1C-0x1F: DTMF / tone settings */
    BK4829_WriteReg(instance, 0x1C, 0x07C0);
    BK4829_WriteReg(instance, 0x1D, 0xE555);
    BK4829_WriteReg(instance, 0x1E, 0x4C58);
    BK4829_WriteReg(instance, 0x1F, 0x865A);
    
    /* Registers 0x3E-0x3F: Enable controls */
    BK4829_WriteReg(instance, 0x3E, 0x94C6);
    BK4829_WriteReg(instance, 0x3F, 0x07FE);
    
    /* Register 0x25: Unknown */
    BK4829_WriteReg(instance, 0x25, 0xC1BA);
    
    /* Register 0x3A: LNA settings */
    BK4829_WriteReg(instance, 0x3A, 0x9A7C);
    
    /* Register 0x19: Unknown */
    BK4829_WriteReg(instance, 0x19, 0x1041);
    
    /* Registers 0x28-0x2F: Squelch / noise settings */
    BK4829_WriteReg(instance, 0x28, 0x0B40);
    BK4829_WriteReg(instance, 0x29, 0xAA00);
    BK4829_WriteReg(instance, 0x2A, 0x6600);
    BK4829_WriteReg(instance, 0x2C, 0x0022);
    BK4829_WriteReg(instance, 0x2F, 0x9890);
    
    /* Register 0x53: TX deviation */
    BK4829_WriteReg(instance, 0x53, 0x2028);
    
    /* Register 0x7E: Unknown */
    BK4829_WriteReg(instance, 0x7E, 0x303E);
    
    /* Registers 0x46-0x4F: Audio filter chain */
    BK4829_WriteReg(instance, 0x46, 0x6050);
    BK4829_WriteReg(instance, 0x4A, 0x5430);
    BK4829_WriteReg(instance, 0x48, 0xB3BF);
    BK4829_WriteReg(instance, 0x49, 0x2AB2);  /* Written again */
    BK4829_WriteReg(instance, 0x4A, 0x5430);  /* Written again */
    BK4829_WriteReg(instance, 0x4D, 0xA004);
    BK4829_WriteReg(instance, 0x4E, 0x3815);
    BK4829_WriteReg(instance, 0x4F, 0x3F3B);
    
    /* Register 0x77: Unknown */
    BK4829_WriteReg(instance, 0x77, 0xCCEF);
    
    /* Register 0x7E: Written again */
    BK4829_WriteReg(instance, 0x7E, 0x303E);
    
    /* Register 0x40: Modify existing value (preserve upper nibble) */
    uint16_t reg40 = BK4829_ReadReg(instance, 0x40);
    BK4829_WriteReg(instance, 0x40, (reg40 & 0xF000) | 0x04D2);
    
    /* Register 0x7D: Unknown */
    BK4829_WriteReg(instance, 0x7D, 0xE912);
    
    /* Register 0x48: Final audio filter value */
    BK4829_WriteReg(instance, 0x48, 0xB3FF);
    
    /* Register 0x09: AGC gain table (16 entries) */
    BK4829_WriteReg(instance, 0x09, 0x006F);
    BK4829_WriteReg(instance, 0x09, 0x106B);
    BK4829_WriteReg(instance, 0x09, 0x2067);
    BK4829_WriteReg(instance, 0x09, 0x3062);
    BK4829_WriteReg(instance, 0x09, 0x4050);
    BK4829_WriteReg(instance, 0x09, 0x5047);
    BK4829_WriteReg(instance, 0x09, 0x603A);
    BK4829_WriteReg(instance, 0x09, 0x702C);
    BK4829_WriteReg(instance, 0x09, 0x8041);
    BK4829_WriteReg(instance, 0x09, 0x9037);
    BK4829_WriteReg(instance, 0x09, 0xA025);
    BK4829_WriteReg(instance, 0x09, 0xB017);
    BK4829_WriteReg(instance, 0x09, 0xC0E4);
    BK4829_WriteReg(instance, 0x09, 0xD0CB);
    BK4829_WriteReg(instance, 0x09, 0xE0B5);
    BK4829_WriteReg(instance, 0x09, 0xF09F);
    
    /* Registers 0x74-0x75: Unknown / calibration */
    BK4829_WriteReg(instance, 0x74, 0xE61C);
    BK4829_WriteReg(instance, 0x44, 0x8F88);
    BK4829_WriteReg(instance, 0x45, 0x3201);
    BK4829_WriteReg(instance, 0x75, 0xE61C);
    
    /* Registers 0x54-0x55: TX settings */
    BK4829_WriteReg(instance, 0x54, 0x91C1);
    BK4829_WriteReg(instance, 0x55, 0x3040);
    
    cfg->initialized = true;
}

/**
 * @brief Set operating frequency
 * 
 * INFERRED: Frequency calculation from FUN_8000b62c
 */
void BK4829_SetFrequency(BK4829_Instance_t instance, uint32_t frequency_hz)
{
    if (instance >= BK4829_INSTANCE_COUNT) return;
    
    /* BK4829 frequency register format:
     * The frequency synthesizer uses a fractional-N PLL.
     * Register 0x38/0x39 contain the frequency word.
     * 
     * CONFIRMED from datasheet: Crystal reference is 26 MHz
     * 
     * Datasheet formula:
     *   RX mode: f_locked = Ndiv × (fwanted - fIF)
     *   TX mode: f_locked = Ndiv × fwanted
     * 
     * The simplified calculation below approximates:
     *   Frequency ≈ (N + F/65536) × 26000000
     * 
     * TODO: Verify exact register programming with Ndiv and fIF
     */
    
    /* Use 26 MHz reference (CONFIRMED from BK4829 datasheet) */
    uint32_t fref = 26000000;
    uint32_t div = frequency_hz / fref;
    uint32_t frac = ((frequency_hz % fref) * 65536) / fref;
    
    uint16_t reg38 = (div << 8) | ((frac >> 8) & 0xFF);
    uint16_t reg39 = (frac & 0xFF) << 8;
    
    /* Disable synthesizer during frequency change */
    BK4829_WriteReg(instance, BK4829_REG_3F, 
                    BK4829_ReadReg(instance, BK4829_REG_3F) & ~0x0100);
    
    /* Write frequency registers */
    BK4829_WriteReg(instance, BK4829_REG_38, reg38);
    BK4829_WriteReg(instance, BK4829_REG_39, reg39);
    
    /* Re-enable synthesizer */
    BK4829_WriteReg(instance, BK4829_REG_3F, 
                    BK4829_ReadReg(instance, BK4829_REG_3F) | 0x0100);
    
    /* Wait for PLL lock */
    HAL_Delay(10);
}

/**
 * @brief Get RSSI value
 */
int16_t BK4829_GetRSSI(BK4829_Instance_t instance)
{
    if (instance >= BK4829_INSTANCE_COUNT) return -127;
    
    uint16_t raw = BK4829_ReadReg(instance, BK4829_REG_65);
    
    /* Convert to dBm (INFERRED formula) */
    int16_t rssi = (int16_t)(raw & 0x01FF) - 220;
    
    return rssi;
}

/**
 * @brief Check if squelch is open
 */
bool BK4829_IsSquelchOpen(BK4829_Instance_t instance)
{
    if (instance >= BK4829_INSTANCE_COUNT) return false;
    
    uint16_t status = BK4829_ReadReg(instance, BK4829_REG_02);
    
    /* INFERRED: Bit 0 indicates squelch state */
    return (status & 0x0001) != 0;
}

/**
 * @brief Enable/disable receiver
 */
void BK4829_EnableRX(BK4829_Instance_t instance, bool enable)
{
    if (instance >= BK4829_INSTANCE_COUNT) return;
    
    uint16_t reg3f = BK4829_ReadReg(instance, BK4829_REG_3F);
    
    if (enable) {
        reg3f |= 0x8000;    /* Enable RX */
        reg3f &= ~0x4000;   /* Disable TX */
    } else {
        reg3f &= ~0x8000;
    }
    
    BK4829_WriteReg(instance, BK4829_REG_3F, reg3f);
}

/**
 * @brief Enable/disable transmitter
 */
void BK4829_EnableTX(BK4829_Instance_t instance, bool enable)
{
    if (instance >= BK4829_INSTANCE_COUNT) return;
    
    uint16_t reg3f = BK4829_ReadReg(instance, BK4829_REG_3F);
    
    if (enable) {
        reg3f |= 0x4000;    /* Enable TX */
        reg3f &= ~0x8000;   /* Disable RX */
    } else {
        reg3f &= ~0x4000;
    }
    
    BK4829_WriteReg(instance, BK4829_REG_3F, reg3f);
}

/**
 * @brief Set TX power level
 */
void BK4829_SetTXPower(BK4829_Instance_t instance, BK4829_Power_t power)
{
    if (instance >= BK4829_INSTANCE_COUNT) return;
    
    uint16_t pa_bias;
    
    switch (power) {
        case BK4829_POWER_LOW:
            pa_bias = 0x10;
            break;
        case BK4829_POWER_MID:
            pa_bias = 0x40;
            break;
        case BK4829_POWER_HIGH:
        default:
            pa_bias = 0x80;
            break;
    }
    
    BK4829_WriteReg(instance, BK4829_REG_36, pa_bias);
}

/**
 * @brief Set channel bandwidth
 */
void BK4829_SetBandwidth(BK4829_Instance_t instance, BK4829_Bandwidth_t bandwidth)
{
    if (instance >= BK4829_INSTANCE_COUNT) return;
    
    uint16_t filter;
    
    switch (bandwidth) {
        case BK4829_BW_WIDE:
            filter = 0x1F0F;    /* 25 kHz */
            break;
        case BK4829_BW_NARROW:
            filter = 0x0F0F;    /* 12.5 kHz */
            break;
        case BK4829_BW_NARROWER:
        default:
            filter = 0x070F;    /* 6.25 kHz */
            break;
    }
    
    BK4829_WriteReg(instance, BK4829_REG_37, filter);
}

/**
 * @brief Set CTCSS tone frequency
 */
void BK4829_SetCTCSS(BK4829_Instance_t instance, uint16_t freq_tenths)
{
    if (instance >= BK4829_INSTANCE_COUNT) return;
    
    if (freq_tenths == 0) {
        /* Disable CTCSS */
        BK4829_WriteReg(instance, BK4829_REG_51, 0x0000);
    } else {
        /* Set CTCSS frequency
         * INFERRED: Register value = frequency * 20.64
         */
        uint16_t reg_value = (freq_tenths * 206) / 100;
        BK4829_WriteReg(instance, BK4829_REG_51, reg_value);
    }
}

/**
 * @brief Get chip ID
 */
uint16_t BK4829_GetChipID(BK4829_Instance_t instance)
{
    return BK4829_ReadReg(instance, BK4829_REG_00);
}


