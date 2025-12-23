/**
 * @file i2c.h
 * @brief I2C Hardware Abstraction Layer
 * 
 * Provides I2C functionality for:
 *   - SI4732 FM/AM receiver (PB6/PB7) [HIGH confidence]
 */

#ifndef HAL_I2C_H
#define HAL_I2C_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * I2C PERIPHERAL BASE ADDRESSES
 * ============================================================================ */

#define I2C1_BASE           0x40005400UL
#define I2C2_BASE           0x40005800UL

/* I2C register structure */
typedef struct {
    volatile uint32_t CTRL1;    /* 0x00: Control register 1 */
    volatile uint32_t CTRL2;    /* 0x04: Control register 2 */
    volatile uint32_t OADDR1;   /* 0x08: Own address 1 */
    volatile uint32_t OADDR2;   /* 0x0C: Own address 2 */
    volatile uint32_t DT;       /* 0x10: Data register */
    volatile uint32_t STS1;     /* 0x14: Status register 1 */
    volatile uint32_t STS2;     /* 0x18: Status register 2 */
    volatile uint32_t CLKCTRL;  /* 0x1C: Clock control */
    volatile uint32_t TMRISE;   /* 0x20: Rise time */
} I2C_TypeDef;

#define I2C1                ((I2C_TypeDef *)I2C1_BASE)
#define I2C2                ((I2C_TypeDef *)I2C2_BASE)

/* ============================================================================
 * I2C CONFIGURATION
 * ============================================================================ */

typedef enum {
    I2C_INSTANCE_1 = 0,
    I2C_INSTANCE_2,
    I2C_INSTANCE_SW,        /* Software I2C */
    I2C_INSTANCE_COUNT
} I2C_Instance_t;

typedef enum {
    I2C_SPEED_STANDARD = 0,     /* 100 kHz */
    I2C_SPEED_FAST              /* 400 kHz */
} I2C_Speed_t;

typedef struct {
    I2C_Speed_t speed;
    uint8_t own_address;        /* Own address (for slave mode) */
} I2C_Config_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize I2C peripheral
 * @param instance I2C instance
 * @param config Configuration parameters
 */
void HAL_I2C_Init(I2C_Instance_t instance, const I2C_Config_t *config);

/**
 * @brief Deinitialize I2C peripheral
 * @param instance I2C instance
 */
void HAL_I2C_DeInit(I2C_Instance_t instance);

/**
 * @brief Write data to I2C device
 * @param instance I2C instance
 * @param dev_addr 7-bit device address
 * @param data Data buffer
 * @param len Number of bytes
 * @return true if successful
 */
bool HAL_I2C_Write(I2C_Instance_t instance, uint8_t dev_addr, 
                   const uint8_t *data, uint32_t len);

/**
 * @brief Read data from I2C device
 * @param instance I2C instance
 * @param dev_addr 7-bit device address
 * @param data Buffer for received data
 * @param len Number of bytes to read
 * @return true if successful
 */
bool HAL_I2C_Read(I2C_Instance_t instance, uint8_t dev_addr,
                  uint8_t *data, uint32_t len);

/**
 * @brief Write to register on I2C device
 * @param instance I2C instance
 * @param dev_addr 7-bit device address
 * @param reg_addr Register address
 * @param data Data buffer
 * @param len Number of bytes
 * @return true if successful
 */
bool HAL_I2C_WriteReg(I2C_Instance_t instance, uint8_t dev_addr,
                      uint8_t reg_addr, const uint8_t *data, uint32_t len);

/**
 * @brief Read from register on I2C device
 * @param instance I2C instance
 * @param dev_addr 7-bit device address
 * @param reg_addr Register address
 * @param data Buffer for received data
 * @param len Number of bytes to read
 * @return true if successful
 */
bool HAL_I2C_ReadReg(I2C_Instance_t instance, uint8_t dev_addr,
                     uint8_t reg_addr, uint8_t *data, uint32_t len);

/**
 * @brief Check if device is present on bus
 * @param instance I2C instance
 * @param dev_addr 7-bit device address
 * @return true if device responds
 */
bool HAL_I2C_IsDeviceReady(I2C_Instance_t instance, uint8_t dev_addr);

/* ============================================================================
 * SOFTWARE I2C (for SI4732 on PB6/PB7)
 * ============================================================================ */

/**
 * @brief Initialize software I2C
 */
void HAL_I2C_SW_Init(void);

/**
 * @brief Software I2C start condition
 */
void HAL_I2C_SW_Start(void);

/**
 * @brief Software I2C stop condition
 */
void HAL_I2C_SW_Stop(void);

/**
 * @brief Software I2C write byte
 * @param byte Data byte
 * @return true if ACK received
 */
bool HAL_I2C_SW_WriteByte(uint8_t byte);

/**
 * @brief Software I2C read byte
 * @param ack Send ACK if true, NACK if false
 * @return Received byte
 */
uint8_t HAL_I2C_SW_ReadByte(bool ack);

#ifdef __cplusplus
}
#endif

#endif /* HAL_I2C_H */

