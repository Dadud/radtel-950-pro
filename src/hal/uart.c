/**
 * @file uart.c
 * @brief UART Hardware Abstraction Layer Implementation
 */

#include "hal/uart.h"
#include "hal/system.h"
#include "hal/gpio.h"

/* Get USART peripheral pointer */
static USART_TypeDef* get_uart(UART_Instance_t instance)
{
    switch (instance) {
        case UART_INSTANCE_1: return USART1;
        case UART_INSTANCE_2: return USART2;
        case UART_INSTANCE_3: return USART3;
        case UART_INSTANCE_4: return UART4;
        case UART_INSTANCE_5: return UART5;
        default: return NULL;
    }
}

void HAL_UART_Init(UART_Instance_t instance, const UART_Config_t *config)
{
    USART_TypeDef *uart = get_uart(instance);
    if (uart == NULL || config == NULL) return;
    
    /* Enable clock */
    switch (instance) {
        case UART_INSTANCE_1:
            CRM_APB2EN |= (1 << 14);  /* USART1 on APB2 */
            /* Configure GPIO: PA9 TX, PA10 RX */
            HAL_GPIO_Config(GPIO_PORT_A, GPIO_PIN_9, GPIO_MODE_AF_PP, GPIO_SPEED_50MHZ);
            HAL_GPIO_Config(GPIO_PORT_A, GPIO_PIN_10, GPIO_MODE_INPUT_PULLUP, GPIO_SPEED_50MHZ);
            break;
        case UART_INSTANCE_2:
            CRM_APB1EN |= (1 << 17);
            break;
        case UART_INSTANCE_3:
            CRM_APB1EN |= (1 << 18);
            /* Configure GPIO: PB10 TX, PB11 RX */
            HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_10, GPIO_MODE_AF_PP, GPIO_SPEED_50MHZ);
            HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_11, GPIO_MODE_INPUT_PULLUP, GPIO_SPEED_50MHZ);
            break;
        case UART_INSTANCE_4:
            CRM_APB1EN |= (1 << 19);
            break;
        case UART_INSTANCE_5:
            CRM_APB1EN |= (1 << 20);
            break;
        default:
            return;
    }
    
    /* Calculate baud rate divider */
    uint32_t pclk;
    if (instance == UART_INSTANCE_1) {
        pclk = HAL_System_GetAPB2ClockHz();
    } else {
        pclk = HAL_System_GetAPB1ClockHz();
    }
    
    /* BAUDR = PCLK / (16 * baudrate) */
    uint32_t div = (pclk + config->baudrate / 2) / config->baudrate;
    uart->BAUDR = div;
    
    /* Configure CTRL1 */
    uint32_t ctrl1 = 0;
    
    /* Word length */
    if (config->word_length == UART_WORDLEN_9) {
        ctrl1 |= (1 << 12);  /* DBN */
    }
    
    /* Parity */
    if (config->parity != UART_PARITY_NONE) {
        ctrl1 |= (1 << 10);  /* PEN */
        if (config->parity == UART_PARITY_ODD) {
            ctrl1 |= (1 << 9);  /* PSEL */
        }
    }
    
    /* Enable TX/RX */
    if (config->enable_tx) {
        ctrl1 |= (1 << 3);  /* TEN */
    }
    if (config->enable_rx) {
        ctrl1 |= (1 << 2);  /* REN */
    }
    
    uart->CTRL1 = ctrl1;
    
    /* Configure CTRL2 - stop bits */
    uart->CTRL2 = (config->stop_bits & 0x03) << 12;
    
    /* Enable USART */
    uart->CTRL1 |= (1 << 13);  /* UEN */
}

void HAL_UART_DeInit(UART_Instance_t instance)
{
    USART_TypeDef *uart = get_uart(instance);
    if (uart == NULL) return;
    
    uart->CTRL1 = 0;
    uart->CTRL2 = 0;
    uart->CTRL3 = 0;
}

void HAL_UART_TransmitByte(UART_Instance_t instance, uint8_t data)
{
    USART_TypeDef *uart = get_uart(instance);
    if (uart == NULL) return;
    
    /* Wait for TX buffer empty */
    while (!(uart->STS & USART_STS_TDBE));
    
    /* Send byte */
    uart->DT = data;
    
    /* Wait for transmission complete */
    while (!(uart->STS & USART_STS_TDC));
}

void HAL_UART_Transmit(UART_Instance_t instance, const uint8_t *data, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        HAL_UART_TransmitByte(instance, data[i]);
    }
}

void HAL_UART_TransmitString(UART_Instance_t instance, const char *str)
{
    while (*str) {
        HAL_UART_TransmitByte(instance, *str++);
    }
}

bool HAL_UART_IsRxReady(UART_Instance_t instance)
{
    USART_TypeDef *uart = get_uart(instance);
    if (uart == NULL) return false;
    
    return (uart->STS & USART_STS_RDBF) != 0;
}

uint8_t HAL_UART_ReceiveByte(UART_Instance_t instance)
{
    USART_TypeDef *uart = get_uart(instance);
    if (uart == NULL) return 0;
    
    /* Wait for data */
    while (!(uart->STS & USART_STS_RDBF));
    
    return (uint8_t)uart->DT;
}

bool HAL_UART_ReceiveByteTimeout(UART_Instance_t instance, uint8_t *data, uint32_t timeout_ms)
{
    USART_TypeDef *uart = get_uart(instance);
    if (uart == NULL || data == NULL) return false;
    
    uint32_t start = HAL_GetTick();
    
    while (!(uart->STS & USART_STS_RDBF)) {
        if ((HAL_GetTick() - start) >= timeout_ms) {
            return false;
        }
    }
    
    *data = (uint8_t)uart->DT;
    return true;
}

void HAL_UART_Receive(UART_Instance_t instance, uint8_t *data, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        data[i] = HAL_UART_ReceiveByte(instance);
    }
}

void HAL_UART_EnableRxInterrupt(UART_Instance_t instance)
{
    USART_TypeDef *uart = get_uart(instance);
    if (uart == NULL) return;
    
    uart->CTRL1 |= (1 << 5);  /* RDBFIEN */
}

void HAL_UART_DisableRxInterrupt(UART_Instance_t instance)
{
    USART_TypeDef *uart = get_uart(instance);
    if (uart == NULL) return;
    
    uart->CTRL1 &= ~(1 << 5);
}

