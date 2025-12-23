/**
 * @file gps.h
 * @brief GPS Module Driver
 */

#ifndef PROTOCOLS_GPS_H
#define PROTOCOLS_GPS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    double latitude;
    double longitude;
    float altitude;
    float speed_knots;
    float course;
    uint8_t satellites;
    float hdop;
    bool valid;
} GPS_Position_t;

typedef struct {
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t day;
    uint8_t month;
    uint16_t year;
} GPS_Time_t;

typedef void (*GPS_Callback_t)(void);

void GPS_Init(void);
void GPS_DeInit(void);
void GPS_Enable(void);
void GPS_Disable(void);
bool GPS_IsEnabled(void);
bool GPS_HasFix(void);
void GPS_GetPosition(GPS_Position_t *pos);
void GPS_GetTime(GPS_Time_t *time);
void GPS_SetCallback(GPS_Callback_t callback);
void GPS_Process(void);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOLS_GPS_H */
