/**
 * @file bluetooth.h
 * @brief Bluetooth Module Driver
 */

#ifndef PROTOCOLS_BLUETOOTH_H
#define PROTOCOLS_BLUETOOTH_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BT_BUFFER_SIZE      256

typedef enum {
    BT_MODE_SERIAL = 0,
    BT_MODE_AUDIO,
    BT_MODE_TNC
} BT_Mode_t;

typedef void (*BT_Callback_t)(void);

void BT_Init(void);
void BT_DeInit(void);
bool BT_IsConnected(void);
void BT_SetMode(BT_Mode_t mode);
BT_Mode_t BT_GetMode(void);
void BT_SetDeviceName(const char *name);
const char *BT_GetDeviceName(void);
uint16_t BT_Available(void);
int16_t BT_Read(void);
uint16_t BT_ReadBuffer(uint8_t *buffer, uint16_t max_len);
void BT_Send(uint8_t data);
void BT_SendBuffer(const uint8_t *buffer, uint16_t len);
void BT_SendString(const char *str);
void BT_SetCallback(BT_Callback_t callback);
void BT_Process(void);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOLS_BLUETOOTH_H */
