/**
 * @file scan.h
 * @brief Scanning Functionality
 */

#ifndef RADIO_SCAN_H
#define RADIO_SCAN_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SCAN_MODE_VFO = 0,
    SCAN_MODE_CHANNEL,
    SCAN_MODE_PRIORITY
} ScanMode_t;

typedef enum {
    SCAN_DIR_UP = 0,
    SCAN_DIR_DOWN
} ScanDirection_t;

typedef enum {
    SCAN_EVENT_START = 0,
    SCAN_EVENT_STOP,
    SCAN_EVENT_HIT,
    SCAN_EVENT_RESUME
} ScanEvent_t;

typedef void (*Scan_Callback_t)(ScanEvent_t event);

void Scan_Init(void);
void Scan_Start(ScanMode_t mode);
void Scan_Stop(void);
bool Scan_IsActive(void);
void Scan_SetDirection(ScanDirection_t direction);
ScanDirection_t Scan_GetDirection(void);
void Scan_SetSpeed(uint32_t ms_per_step);
void Scan_SetHoldTime(uint32_t ms);
void Scan_SetCallback(Scan_Callback_t callback);
void Scan_Process(void);
void Scan_Skip(void);
void Scan_Reverse(void);

#ifdef __cplusplus
}
#endif

#endif /* RADIO_SCAN_H */

