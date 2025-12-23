/**
 * @file cdc_protocol.h
 * @brief USB CDC Protocol
 */

#ifndef PROTOCOLS_CDC_PROTOCOL_H
#define PROTOCOLS_CDC_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CDC_RX_BUFFER_SIZE  512
#define CDC_TX_BUFFER_SIZE  512

typedef enum {
    CDC_MODE_SERIAL = 0,
    CDC_MODE_PROGRAMMING,
    CDC_MODE_DEBUG
} CDC_Mode_t;

typedef void (*CDC_Callback_t)(uint8_t *data, uint16_t len);

void CDC_Init(void);
void CDC_DeInit(void);
bool CDC_IsConnected(void);
void CDC_SetMode(CDC_Mode_t mode);
CDC_Mode_t CDC_GetMode(void);
uint16_t CDC_Available(void);
int16_t CDC_Read(void);
uint16_t CDC_ReadBuffer(uint8_t *buffer, uint16_t max_len);
bool CDC_Write(uint8_t data);
uint16_t CDC_WriteBuffer(const uint8_t *buffer, uint16_t len);
void CDC_WriteString(const char *str);
void CDC_Flush(void);
void CDC_SetCallback(CDC_Callback_t callback);
void CDC_Process(void);
void CDC_ProcessProgramming(void);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOLS_CDC_PROTOCOL_H */
