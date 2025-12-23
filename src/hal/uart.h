/**
 * @file uart.h
 * @brief UART Hardware Abstraction Layer
 * 
 * Provides UART communication for:
 *   - USART1: Bluetooth module (115200 baud) [CONFIRMED]
 *   - USART3: GPS module (9600 baud) [CONFIRMED]
 */

#ifndef HAL_UART_H
#define HAL_UART_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * UART PERIPHERAL BASE ADDRESSES
 * ============================================================================ */

#define USART1_BASE         0x40013800UL
#define USART2_BASE         0x40004400UL
#define USART3_BASE         0x40004800UL
#define UART4_BASE          0x40004C00UL
#define UART5_BASE          0x40005000UL

/* UART register structure */
typedef struct {
    volatile uint32_t STS;      /* 0x00: Status register */
    volatile uint32_t DT;       /* 0x04: Data register */
    volatile uint32_t BAUDR;    /* 0x08: Baud rate register */
    volatile uint32_t CTRL1;    /* 0x0C: Control register 1 */
    volatile uint32_t CTRL2;    /* 0x10: Control register 2 */
    volatile uint32_t CTRL3;    /* 0x14: Control register 3 */
    volatile uint32_t GDIV;     /* 0x18: Guard time and divider */
} USART_TypeDef;

#define USART1              ((USART_TypeDef *)USART1_BASE)
#define USART2              ((USART_TypeDef *)USART2_BASE)
#define USART3              ((USART_TypeDef *)USART3_BASE)
#define UART4               ((USART_TypeDef *)UART4_BASE)
#define UART5               ((USART_TypeDef *)UART5_BASE)

/* ============================================================================
 * UART STATUS REGISTER BITS
 * ============================================================================ */

#define USART_STS_PERR      (1 << 0)    /* Parity error */
#define USART_STS_FERR      (1 << 1)    /* Framing error */
#define USART_STS_NERR      (1 << 2)    /* Noise error */
#define USART_STS_ROERR     (1 << 3)    /* Receiver overflow error */
#define USART_STS_IDLEF     (1 << 4)    /* Idle flag */
#define USART_STS_RDBF      (1 << 5)    /* Receive data buffer full */
#define USART_STS_TDC       (1 << 6)    /* Transmit data complete */
#define USART_STS_TDBE      (1 << 7)    /* Transmit data buffer empty */
#define USART_STS_BFF       (1 << 8)    /* Break frame flag */
#define USART_STS_CTSCF     (1 << 9)    /* CTS change flag */

/* ============================================================================
 * UART INSTANCE ENUMERATION
 * ============================================================================ */

typedef enum {
    UART_INSTANCE_1 = 0,    /* USART1 - Bluetooth */
    UART_INSTANCE_2,        /* USART2 */
    UART_INSTANCE_3,        /* USART3 - GPS */
    UART_INSTANCE_4,        /* UART4 */
    UART_INSTANCE_5,        /* UART5 */
    UART_INSTANCE_COUNT
} UART_Instance_t;

/* ============================================================================
 * UART CONFIGURATION
 * ============================================================================ */

typedef enum {
    UART_WORDLEN_8 = 0,
    UART_WORDLEN_9
} UART_WordLength_t;

typedef enum {
    UART_STOPBITS_1 = 0,
    UART_STOPBITS_0_5,
    UART_STOPBITS_2,
    UART_STOPBITS_1_5
} UART_StopBits_t;

typedef enum {
    UART_PARITY_NONE = 0,
    UART_PARITY_EVEN,
    UART_PARITY_ODD
} UART_Parity_t;

typedef struct {
    uint32_t baudrate;
    UART_WordLength_t word_length;
    UART_StopBits_t stop_bits;
    UART_Parity_t parity;
    bool enable_rx;
    bool enable_tx;
} UART_Config_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize UART peripheral
 * @param instance UART instance
 * @param config Configuration parameters
 */
void HAL_UART_Init(UART_Instance_t instance, const UART_Config_t *config);

/**
 * @brief Deinitialize UART peripheral
 * @param instance UART instance
 */
void HAL_UART_DeInit(UART_Instance_t instance);

/**
 * @brief Transmit a single byte (blocking)
 * @param instance UART instance
 * @param data Byte to transmit
 */
void HAL_UART_TransmitByte(UART_Instance_t instance, uint8_t data);

/**
 * @brief Transmit a buffer (blocking)
 * @param instance UART instance
 * @param data Buffer to transmit
 * @param len Number of bytes
 */
void HAL_UART_Transmit(UART_Instance_t instance, const uint8_t *data, uint32_t len);

/**
 * @brief Transmit a null-terminated string
 * @param instance UART instance
 * @param str String to transmit
 */
void HAL_UART_TransmitString(UART_Instance_t instance, const char *str);

/**
 * @brief Check if receive data is available
 * @param instance UART instance
 * @return true if data available
 */
bool HAL_UART_IsRxReady(UART_Instance_t instance);

/**
 * @brief Receive a single byte (blocking)
 * @param instance UART instance
 * @return Received byte
 */
uint8_t HAL_UART_ReceiveByte(UART_Instance_t instance);

/**
 * @brief Receive a byte with timeout
 * @param instance UART instance
 * @param data Pointer to store received byte
 * @param timeout_ms Timeout in milliseconds
 * @return true if byte received, false if timeout
 */
bool HAL_UART_ReceiveByteTimeout(UART_Instance_t instance, uint8_t *data, uint32_t timeout_ms);

/**
 * @brief Receive a buffer (blocking)
 * @param instance UART instance
 * @param data Buffer for received data
 * @param len Number of bytes to receive
 */
void HAL_UART_Receive(UART_Instance_t instance, uint8_t *data, uint32_t len);

/**
 * @brief Enable UART RX interrupt
 * @param instance UART instance
 */
void HAL_UART_EnableRxInterrupt(UART_Instance_t instance);

/**
 * @brief Disable UART RX interrupt
 * @param instance UART instance
 */
void HAL_UART_DisableRxInterrupt(UART_Instance_t instance);

#ifdef __cplusplus
}
#endif

#endif /* HAL_UART_H */

