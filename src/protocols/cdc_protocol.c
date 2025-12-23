/**
 * @file cdc_protocol.c
 * @brief USB CDC Protocol Implementation
 * 
 * Handles USB CDC communication for programming and firmware updates.
 */

#include "protocols/cdc_protocol.h"
#include "config/settings.h"
#include "hal/system.h"

#include <string.h>

/* CDC state */
static struct {
    bool initialized;
    bool connected;
    CDC_Mode_t mode;
    
    /* Buffer */
    uint8_t rx_buffer[CDC_RX_BUFFER_SIZE];
    uint16_t rx_head;
    uint16_t rx_tail;
    
    uint8_t tx_buffer[CDC_TX_BUFFER_SIZE];
    uint16_t tx_head;
    uint16_t tx_tail;
    
    CDC_Callback_t callback;
} g_cdc;

#define CDC_RX_BUFFER_SIZE  512
#define CDC_TX_BUFFER_SIZE  512

void CDC_Init(void)
{
    /* Initialize USB CDC peripheral */
    /* This would involve USB peripheral setup for AT32F403A */
    
    g_cdc.initialized = true;
    g_cdc.connected = false;
    g_cdc.mode = CDC_MODE_SERIAL;
    g_cdc.rx_head = 0;
    g_cdc.rx_tail = 0;
    g_cdc.tx_head = 0;
    g_cdc.tx_tail = 0;
    g_cdc.callback = NULL;
}

void CDC_DeInit(void)
{
    g_cdc.initialized = false;
    g_cdc.connected = false;
}

bool CDC_IsConnected(void)
{
    return g_cdc.connected;
}

void CDC_SetMode(CDC_Mode_t mode)
{
    g_cdc.mode = mode;
}

CDC_Mode_t CDC_GetMode(void)
{
    return g_cdc.mode;
}

uint16_t CDC_Available(void)
{
    if (g_cdc.rx_head >= g_cdc.rx_tail) {
        return g_cdc.rx_head - g_cdc.rx_tail;
    }
    return CDC_RX_BUFFER_SIZE - g_cdc.rx_tail + g_cdc.rx_head;
}

int16_t CDC_Read(void)
{
    if (g_cdc.rx_head == g_cdc.rx_tail) {
        return -1;
    }
    
    uint8_t data = g_cdc.rx_buffer[g_cdc.rx_tail];
    g_cdc.rx_tail = (g_cdc.rx_tail + 1) % CDC_RX_BUFFER_SIZE;
    
    return data;
}

uint16_t CDC_ReadBuffer(uint8_t *buffer, uint16_t max_len)
{
    uint16_t count = 0;
    
    while (count < max_len && g_cdc.rx_head != g_cdc.rx_tail) {
        buffer[count++] = g_cdc.rx_buffer[g_cdc.rx_tail];
        g_cdc.rx_tail = (g_cdc.rx_tail + 1) % CDC_RX_BUFFER_SIZE;
    }
    
    return count;
}

bool CDC_Write(uint8_t data)
{
    uint16_t next = (g_cdc.tx_head + 1) % CDC_TX_BUFFER_SIZE;
    
    if (next == g_cdc.tx_tail) {
        return false;  /* Buffer full */
    }
    
    g_cdc.tx_buffer[g_cdc.tx_head] = data;
    g_cdc.tx_head = next;
    
    return true;
}

uint16_t CDC_WriteBuffer(const uint8_t *buffer, uint16_t len)
{
    uint16_t count = 0;
    
    while (count < len) {
        if (!CDC_Write(buffer[count])) {
            break;
        }
        count++;
    }
    
    return count;
}

void CDC_WriteString(const char *str)
{
    while (*str) {
        CDC_Write(*str++);
    }
}

void CDC_Flush(void)
{
    /* Flush TX buffer to USB */
    /* This would trigger USB transmission */
}

void CDC_SetCallback(CDC_Callback_t callback)
{
    g_cdc.callback = callback;
}

void CDC_Process(void)
{
    if (!g_cdc.initialized) return;
    
    /* Process USB events */
    /* Handle received data based on mode */
    
    if (g_cdc.mode == CDC_MODE_PROGRAMMING) {
        /* Handle programming protocol */
        CDC_ProcessProgramming();
    }
}

void CDC_ProcessProgramming(void)
{
    /* Programming protocol handler */
    /* This would handle chirp/programming software commands */
}

/* USB interrupt handlers would go here */
void USB_IRQHandler(void)
{
    /* Handle USB interrupts */
}

