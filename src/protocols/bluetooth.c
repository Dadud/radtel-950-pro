/**
 * @file bluetooth.c
 * @brief Bluetooth Module Driver Implementation
 * 
 * Handles Bluetooth communication for audio, serial, and TNC.
 */

#include "protocols/bluetooth.h"
#include "hal/uart.h"
#include "hal/gpio.h"
#include "hal/system.h"

#include <string.h>

/* Bluetooth state */
static struct {
    bool initialized;
    bool connected;
    BT_Mode_t mode;
    char device_name[32];
    
    /* RX buffer */
    uint8_t rx_buffer[BT_BUFFER_SIZE];
    uint16_t rx_head;
    uint16_t rx_tail;
    
    BT_Callback_t callback;
} g_bt;

#define BT_BUFFER_SIZE      256
#define BT_UART_INSTANCE    UART_INSTANCE_1
#define BT_BAUDRATE         115200

void BT_Init(void)
{
    /* Configure UART for Bluetooth module */
    UART_Config_t uart_config = {
        .baudrate = BT_BAUDRATE,
        .word_length = UART_WORDLEN_8,
        .stop_bits = UART_STOPBITS_1,
        .parity = UART_PARITY_NONE,
        .enable_rx = true,
        .enable_tx = true
    };
    
    HAL_UART_Init(BT_UART_INSTANCE, &uart_config);
    HAL_UART_EnableRxInterrupt(BT_UART_INSTANCE);
    
    g_bt.initialized = true;
    g_bt.connected = false;
    g_bt.mode = BT_MODE_SERIAL;
    strcpy(g_bt.device_name, "RT-950");
    g_bt.rx_head = 0;
    g_bt.rx_tail = 0;
    g_bt.callback = NULL;
}

void BT_DeInit(void)
{
    HAL_UART_DeInit(BT_UART_INSTANCE);
    g_bt.initialized = false;
    g_bt.connected = false;
}

bool BT_IsConnected(void)
{
    return g_bt.connected;
}

void BT_SetMode(BT_Mode_t mode)
{
    g_bt.mode = mode;
}

BT_Mode_t BT_GetMode(void)
{
    return g_bt.mode;
}

void BT_SetDeviceName(const char *name)
{
    strncpy(g_bt.device_name, name, sizeof(g_bt.device_name) - 1);
    g_bt.device_name[sizeof(g_bt.device_name) - 1] = '\0';
    
    /* Send AT command to set device name */
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "AT+NAME=%s\r\n", g_bt.device_name);
    BT_SendString(cmd);
}

const char *BT_GetDeviceName(void)
{
    return g_bt.device_name;
}

uint16_t BT_Available(void)
{
    if (g_bt.rx_head >= g_bt.rx_tail) {
        return g_bt.rx_head - g_bt.rx_tail;
    }
    return BT_BUFFER_SIZE - g_bt.rx_tail + g_bt.rx_head;
}

int16_t BT_Read(void)
{
    if (g_bt.rx_head == g_bt.rx_tail) {
        return -1;
    }
    
    uint8_t data = g_bt.rx_buffer[g_bt.rx_tail];
    g_bt.rx_tail = (g_bt.rx_tail + 1) % BT_BUFFER_SIZE;
    
    return data;
}

uint16_t BT_ReadBuffer(uint8_t *buffer, uint16_t max_len)
{
    uint16_t count = 0;
    
    while (count < max_len && g_bt.rx_head != g_bt.rx_tail) {
        buffer[count++] = g_bt.rx_buffer[g_bt.rx_tail];
        g_bt.rx_tail = (g_bt.rx_tail + 1) % BT_BUFFER_SIZE;
    }
    
    return count;
}

void BT_Send(uint8_t data)
{
    HAL_UART_TransmitByte(BT_UART_INSTANCE, data);
}

void BT_SendBuffer(const uint8_t *buffer, uint16_t len)
{
    HAL_UART_Transmit(BT_UART_INSTANCE, buffer, len);
}

void BT_SendString(const char *str)
{
    HAL_UART_TransmitString(BT_UART_INSTANCE, str);
}

void BT_SetCallback(BT_Callback_t callback)
{
    g_bt.callback = callback;
}

void BT_Process(void)
{
    if (!g_bt.initialized) return;
    
    /* Process received data */
    while (HAL_UART_IsRxReady(BT_UART_INSTANCE)) {
        uint8_t data = HAL_UART_ReceiveByte(BT_UART_INSTANCE);
        
        uint16_t next = (g_bt.rx_head + 1) % BT_BUFFER_SIZE;
        if (next != g_bt.rx_tail) {
            g_bt.rx_buffer[g_bt.rx_head] = data;
            g_bt.rx_head = next;
        }
    }
    
    /* Call callback if data available */
    if (g_bt.callback && BT_Available() > 0) {
        g_bt.callback();
    }
}

/* USART1 RX interrupt handler */
void USART1_IRQHandler(void)
{
    if (HAL_UART_IsRxReady(BT_UART_INSTANCE)) {
        uint8_t data = HAL_UART_ReceiveByte(BT_UART_INSTANCE);
        
        uint16_t next = (g_bt.rx_head + 1) % BT_BUFFER_SIZE;
        if (next != g_bt.rx_tail) {
            g_bt.rx_buffer[g_bt.rx_head] = data;
            g_bt.rx_head = next;
        }
    }
}

