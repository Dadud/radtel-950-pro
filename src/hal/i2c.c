/**
 * @file i2c.c
 * @brief I2C Hardware Abstraction Layer Implementation
 */

#include "hal/i2c.h"
#include "hal/gpio.h"
#include "hal/system.h"

/* Software I2C pins (for SI4732) */
#define I2C_SW_SCL_PORT     GPIOB
#define I2C_SW_SCL_PIN      GPIO_PIN_6
#define I2C_SW_SDA_PORT     GPIOB
#define I2C_SW_SDA_PIN      GPIO_PIN_7

/* I2C status register bits */
#define I2C_STS1_STARTF     (1 << 0)    /* Start flag */
#define I2C_STS1_ADDR7F     (1 << 1)    /* Address sent */
#define I2C_STS1_TDC        (1 << 2)    /* Transfer done */
#define I2C_STS1_ADDRHF     (1 << 3)    /* Address header match */
#define I2C_STS1_STOPF      (1 << 4)    /* Stop flag */
#define I2C_STS1_RDBF       (1 << 6)    /* Receive data buffer full */
#define I2C_STS1_TDBE       (1 << 7)    /* Transmit data buffer empty */
#define I2C_STS1_BUSERR     (1 << 8)    /* Bus error */
#define I2C_STS1_ARLOST     (1 << 9)    /* Arbitration lost */
#define I2C_STS1_ACKFAIL    (1 << 10)   /* Acknowledge failure */
#define I2C_STS1_OUF        (1 << 11)   /* Overload/underflow */
#define I2C_STS1_PECERR     (1 << 12)   /* PEC error */

#define I2C_STS2_TRMODE     (1 << 0)    /* Transmit mode */
#define I2C_STS2_BUSYF      (1 << 1)    /* Busy flag */
#define I2C_STS2_DIRF       (1 << 2)    /* Direction flag */

/* I2C control register bits */
#define I2C_CTRL1_I2CEN     (1 << 0)    /* I2C enable */
#define I2C_CTRL1_PERMODE   (1 << 1)    /* Peripheral mode */
#define I2C_CTRL1_SMBMODE   (1 << 3)    /* SMBus mode */
#define I2C_CTRL1_ARPEN     (1 << 4)    /* ARP enable */
#define I2C_CTRL1_PECEN     (1 << 5)    /* PEC enable */
#define I2C_CTRL1_GCAEN     (1 << 6)    /* General call enable */
#define I2C_CTRL1_STRETCH   (1 << 7)    /* Clock stretch disable */
#define I2C_CTRL1_GENSTART  (1 << 8)    /* Generate start */
#define I2C_CTRL1_GENSTOP   (1 << 9)    /* Generate stop */
#define I2C_CTRL1_ACKEN     (1 << 10)   /* Acknowledge enable */
#define I2C_CTRL1_MACKCTRL  (1 << 11)   /* ACK control for next byte */
#define I2C_CTRL1_PECTRA    (1 << 12)   /* PEC transfer */
#define I2C_CTRL1_RESET     (1 << 15)   /* I2C reset */

/* Get I2C peripheral */
static I2C_TypeDef* get_i2c(I2C_Instance_t instance)
{
    switch (instance) {
        case I2C_INSTANCE_1: return I2C1;
        case I2C_INSTANCE_2: return I2C2;
        default: return NULL;
    }
}

void HAL_I2C_Init(I2C_Instance_t instance, const I2C_Config_t *config)
{
    if (instance == I2C_INSTANCE_SW) {
        HAL_I2C_SW_Init();
        return;
    }
    
    I2C_TypeDef *i2c = get_i2c(instance);
    if (i2c == NULL || config == NULL) return;
    
    /* Enable clock */
    if (instance == I2C_INSTANCE_1) {
        CRM_APB1EN |= (1 << 21);
    } else if (instance == I2C_INSTANCE_2) {
        CRM_APB1EN |= (1 << 22);
    }
    
    /* Reset I2C */
    i2c->CTRL1 = I2C_CTRL1_RESET;
    i2c->CTRL1 = 0;
    
    /* Configure clock */
    uint32_t pclk = HAL_System_GetAPB1ClockHz();
    uint32_t freq = pclk / 1000000;  /* MHz */
    
    i2c->CTRL2 = freq & 0x3F;
    
    /* Configure clock control for desired speed */
    uint32_t ccr;
    if (config->speed == I2C_SPEED_FAST) {
        /* Fast mode: 400 kHz */
        ccr = pclk / (400000 * 3);  /* Tlow/Thigh = 2:1 */
        ccr |= (1 << 15);  /* Fast mode */
    } else {
        /* Standard mode: 100 kHz */
        ccr = pclk / (100000 * 2);  /* Tlow = Thigh */
    }
    i2c->CLKCTRL = ccr;
    
    /* Configure rise time */
    if (config->speed == I2C_SPEED_FAST) {
        i2c->TMRISE = (freq * 300 / 1000) + 1;  /* 300ns max */
    } else {
        i2c->TMRISE = freq + 1;  /* 1000ns max */
    }
    
    /* Enable I2C */
    i2c->CTRL1 = I2C_CTRL1_I2CEN;
}

void HAL_I2C_DeInit(I2C_Instance_t instance)
{
    I2C_TypeDef *i2c = get_i2c(instance);
    if (i2c == NULL) return;
    
    i2c->CTRL1 = 0;
}

/* Wait for flag with timeout */
static bool i2c_wait_flag(I2C_TypeDef *i2c, uint32_t flag, bool set, uint32_t timeout_ms)
{
    uint32_t start = HAL_GetTick();
    
    while (1) {
        bool state = (i2c->STS1 & flag) != 0;
        if (state == set) return true;
        
        if ((HAL_GetTick() - start) >= timeout_ms) return false;
    }
}

bool HAL_I2C_Write(I2C_Instance_t instance, uint8_t dev_addr,
                   const uint8_t *data, uint32_t len)
{
    if (instance == I2C_INSTANCE_SW) {
        HAL_I2C_SW_Start();
        if (!HAL_I2C_SW_WriteByte(dev_addr << 1)) {
            HAL_I2C_SW_Stop();
            return false;
        }
        for (uint32_t i = 0; i < len; i++) {
            if (!HAL_I2C_SW_WriteByte(data[i])) {
                HAL_I2C_SW_Stop();
                return false;
            }
        }
        HAL_I2C_SW_Stop();
        return true;
    }
    
    I2C_TypeDef *i2c = get_i2c(instance);
    if (i2c == NULL || data == NULL) return false;
    
    /* Generate start */
    i2c->CTRL1 |= I2C_CTRL1_GENSTART;
    if (!i2c_wait_flag(i2c, I2C_STS1_STARTF, true, 100)) return false;
    
    /* Send address */
    i2c->DT = dev_addr << 1;  /* Write mode */
    if (!i2c_wait_flag(i2c, I2C_STS1_ADDR7F, true, 100)) {
        i2c->CTRL1 |= I2C_CTRL1_GENSTOP;
        return false;
    }
    
    /* Clear ADDR flag by reading STS2 */
    (void)i2c->STS2;
    
    /* Send data */
    for (uint32_t i = 0; i < len; i++) {
        if (!i2c_wait_flag(i2c, I2C_STS1_TDBE, true, 100)) {
            i2c->CTRL1 |= I2C_CTRL1_GENSTOP;
            return false;
        }
        i2c->DT = data[i];
    }
    
    /* Wait for transfer complete */
    if (!i2c_wait_flag(i2c, I2C_STS1_TDC, true, 100)) {
        i2c->CTRL1 |= I2C_CTRL1_GENSTOP;
        return false;
    }
    
    /* Generate stop */
    i2c->CTRL1 |= I2C_CTRL1_GENSTOP;
    
    return true;
}

bool HAL_I2C_Read(I2C_Instance_t instance, uint8_t dev_addr,
                  uint8_t *data, uint32_t len)
{
    if (instance == I2C_INSTANCE_SW) {
        HAL_I2C_SW_Start();
        if (!HAL_I2C_SW_WriteByte((dev_addr << 1) | 1)) {
            HAL_I2C_SW_Stop();
            return false;
        }
        for (uint32_t i = 0; i < len; i++) {
            data[i] = HAL_I2C_SW_ReadByte(i < len - 1);
        }
        HAL_I2C_SW_Stop();
        return true;
    }
    
    I2C_TypeDef *i2c = get_i2c(instance);
    if (i2c == NULL || data == NULL) return false;
    
    /* Enable ACK */
    i2c->CTRL1 |= I2C_CTRL1_ACKEN;
    
    /* Generate start */
    i2c->CTRL1 |= I2C_CTRL1_GENSTART;
    if (!i2c_wait_flag(i2c, I2C_STS1_STARTF, true, 100)) return false;
    
    /* Send address */
    i2c->DT = (dev_addr << 1) | 1;  /* Read mode */
    if (!i2c_wait_flag(i2c, I2C_STS1_ADDR7F, true, 100)) {
        i2c->CTRL1 |= I2C_CTRL1_GENSTOP;
        return false;
    }
    
    /* Clear ADDR flag */
    (void)i2c->STS2;
    
    /* Read data */
    for (uint32_t i = 0; i < len; i++) {
        if (i == len - 1) {
            /* Disable ACK for last byte */
            i2c->CTRL1 &= ~I2C_CTRL1_ACKEN;
            i2c->CTRL1 |= I2C_CTRL1_GENSTOP;
        }
        
        if (!i2c_wait_flag(i2c, I2C_STS1_RDBF, true, 100)) return false;
        data[i] = (uint8_t)i2c->DT;
    }
    
    return true;
}

bool HAL_I2C_WriteReg(I2C_Instance_t instance, uint8_t dev_addr,
                      uint8_t reg_addr, const uint8_t *data, uint32_t len)
{
    if (instance == I2C_INSTANCE_SW) {
        HAL_I2C_SW_Start();
        if (!HAL_I2C_SW_WriteByte(dev_addr << 1)) {
            HAL_I2C_SW_Stop();
            return false;
        }
        if (!HAL_I2C_SW_WriteByte(reg_addr)) {
            HAL_I2C_SW_Stop();
            return false;
        }
        for (uint32_t i = 0; i < len; i++) {
            if (!HAL_I2C_SW_WriteByte(data[i])) {
                HAL_I2C_SW_Stop();
                return false;
            }
        }
        HAL_I2C_SW_Stop();
        return true;
    }
    
    /* For hardware I2C, combine register address and data */
    uint8_t buf[17];  /* Max 16 bytes + reg addr */
    if (len > 16) return false;
    
    buf[0] = reg_addr;
    for (uint32_t i = 0; i < len; i++) {
        buf[i + 1] = data[i];
    }
    
    return HAL_I2C_Write(instance, dev_addr, buf, len + 1);
}

bool HAL_I2C_ReadReg(I2C_Instance_t instance, uint8_t dev_addr,
                     uint8_t reg_addr, uint8_t *data, uint32_t len)
{
    /* Write register address first */
    if (!HAL_I2C_Write(instance, dev_addr, &reg_addr, 1)) return false;
    
    /* Then read data */
    return HAL_I2C_Read(instance, dev_addr, data, len);
}

bool HAL_I2C_IsDeviceReady(I2C_Instance_t instance, uint8_t dev_addr)
{
    if (instance == I2C_INSTANCE_SW) {
        HAL_I2C_SW_Start();
        bool ack = HAL_I2C_SW_WriteByte(dev_addr << 1);
        HAL_I2C_SW_Stop();
        return ack;
    }
    
    I2C_TypeDef *i2c = get_i2c(instance);
    if (i2c == NULL) return false;
    
    /* Generate start */
    i2c->CTRL1 |= I2C_CTRL1_GENSTART;
    if (!i2c_wait_flag(i2c, I2C_STS1_STARTF, true, 10)) return false;
    
    /* Send address */
    i2c->DT = dev_addr << 1;
    
    /* Wait for ACK or NACK */
    uint32_t start = HAL_GetTick();
    while (!(i2c->STS1 & (I2C_STS1_ADDR7F | I2C_STS1_ACKFAIL))) {
        if ((HAL_GetTick() - start) >= 10) {
            i2c->CTRL1 |= I2C_CTRL1_GENSTOP;
            return false;
        }
    }
    
    bool ready = (i2c->STS1 & I2C_STS1_ADDR7F) != 0;
    
    /* Clear flags */
    (void)i2c->STS2;
    i2c->STS1 = 0;
    
    /* Generate stop */
    i2c->CTRL1 |= I2C_CTRL1_GENSTOP;
    
    return ready;
}

/* ============================================================================
 * SOFTWARE I2C IMPLEMENTATION
 * ============================================================================ */

static inline void i2c_delay(void)
{
    /* ~2.5us delay for 400kHz */
    for (volatile int i = 0; i < 100; i++);
}

static inline void sda_high(void)
{
    /* Set as input (open-drain high) */
    HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_7, GPIO_MODE_INPUT_PULLUP, GPIO_SPEED_50MHZ);
}

static inline void sda_low(void)
{
    HAL_GPIO_SetLow(GPIO_PORT_B, GPIO_PIN_7);
    HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_7, GPIO_MODE_OUTPUT_OD, GPIO_SPEED_50MHZ);
}

static inline bool sda_read(void)
{
    sda_high();
    return HAL_GPIO_Read(GPIO_PORT_B, GPIO_PIN_7);
}

static inline void scl_high(void)
{
    HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_6, GPIO_MODE_INPUT_PULLUP, GPIO_SPEED_50MHZ);
}

static inline void scl_low(void)
{
    HAL_GPIO_SetLow(GPIO_PORT_B, GPIO_PIN_6);
    HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_6, GPIO_MODE_OUTPUT_OD, GPIO_SPEED_50MHZ);
}

void HAL_I2C_SW_Init(void)
{
    /* Configure pins as open-drain with pull-up */
    HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_6, GPIO_MODE_OUTPUT_OD, GPIO_SPEED_50MHZ);
    HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_7, GPIO_MODE_OUTPUT_OD, GPIO_SPEED_50MHZ);
    
    /* Start with both lines high */
    scl_high();
    sda_high();
    i2c_delay();
}

void HAL_I2C_SW_Start(void)
{
    sda_high();
    scl_high();
    i2c_delay();
    sda_low();
    i2c_delay();
    scl_low();
    i2c_delay();
}

void HAL_I2C_SW_Stop(void)
{
    sda_low();
    i2c_delay();
    scl_high();
    i2c_delay();
    sda_high();
    i2c_delay();
}

bool HAL_I2C_SW_WriteByte(uint8_t byte)
{
    for (int i = 7; i >= 0; i--) {
        if (byte & (1 << i)) {
            sda_high();
        } else {
            sda_low();
        }
        i2c_delay();
        scl_high();
        i2c_delay();
        scl_low();
    }
    
    /* Read ACK */
    sda_high();
    i2c_delay();
    scl_high();
    i2c_delay();
    bool ack = !sda_read();  /* ACK = SDA low */
    scl_low();
    i2c_delay();
    
    return ack;
}

uint8_t HAL_I2C_SW_ReadByte(bool ack)
{
    uint8_t byte = 0;
    
    sda_high();
    
    for (int i = 7; i >= 0; i--) {
        scl_high();
        i2c_delay();
        if (sda_read()) {
            byte |= (1 << i);
        }
        scl_low();
        i2c_delay();
    }
    
    /* Send ACK/NACK */
    if (ack) {
        sda_low();
    } else {
        sda_high();
    }
    i2c_delay();
    scl_high();
    i2c_delay();
    scl_low();
    sda_high();
    i2c_delay();
    
    return byte;
}

