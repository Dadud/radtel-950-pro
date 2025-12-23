/**
 * @file gps.c
 * @brief GPS Module Driver Implementation
 * 
 * Handles GPS NMEA parsing and position reporting.
 */

#include "protocols/gps.h"
#include "hal/uart.h"
#include "hal/gpio.h"
#include "hal/system.h"

#include <string.h>
#include <stdlib.h>

/* GPS state */
static struct {
    bool initialized;
    bool enabled;
    bool fix_valid;
    
    /* Position */
    double latitude;
    double longitude;
    float altitude;
    float speed_knots;
    float course;
    uint8_t satellites;
    float hdop;
    
    /* Time */
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t day;
    uint8_t month;
    uint16_t year;
    
    /* NMEA parsing */
    char nmea_buffer[128];
    uint8_t nmea_index;
    
    GPS_Callback_t callback;
} g_gps;

#define GPS_UART_INSTANCE   UART_INSTANCE_3
#define GPS_BAUDRATE        9600
#define GPS_ENABLE_PORT     GPIOA
#define GPS_ENABLE_PIN      GPIO_PIN_8

static double nmea_to_degrees(const char *nmea, char dir)
{
    double raw = atof(nmea);
    int deg = (int)(raw / 100);
    double min = raw - (deg * 100);
    double result = deg + (min / 60.0);
    
    if (dir == 'S' || dir == 'W') {
        result = -result;
    }
    
    return result;
}

static void gps_parse_gga(char *sentence)
{
    char *token;
    int field = 0;
    
    token = strtok(sentence, ",");
    while (token != NULL) {
        switch (field) {
            case 1: /* Time */
                if (strlen(token) >= 6) {
                    g_gps.hour = (token[0] - '0') * 10 + (token[1] - '0');
                    g_gps.minute = (token[2] - '0') * 10 + (token[3] - '0');
                    g_gps.second = (token[4] - '0') * 10 + (token[5] - '0');
                }
                break;
            case 2: /* Latitude */
                g_gps.latitude = atof(token);
                break;
            case 3: /* N/S */
                if (*token == 'S') g_gps.latitude = -g_gps.latitude;
                g_gps.latitude = nmea_to_degrees(token - 1, *token);
                break;
            case 4: /* Longitude */
                g_gps.longitude = atof(token);
                break;
            case 5: /* E/W */
                if (*token == 'W') g_gps.longitude = -g_gps.longitude;
                g_gps.longitude = nmea_to_degrees(token - 1, *token);
                break;
            case 6: /* Fix quality */
                g_gps.fix_valid = (atoi(token) > 0);
                break;
            case 7: /* Satellites */
                g_gps.satellites = atoi(token);
                break;
            case 8: /* HDOP */
                g_gps.hdop = atof(token);
                break;
            case 9: /* Altitude */
                g_gps.altitude = atof(token);
                break;
        }
        field++;
        token = strtok(NULL, ",");
    }
}

static void gps_parse_rmc(char *sentence)
{
    char *token;
    int field = 0;
    
    token = strtok(sentence, ",");
    while (token != NULL) {
        switch (field) {
            case 1: /* Time */
                if (strlen(token) >= 6) {
                    g_gps.hour = (token[0] - '0') * 10 + (token[1] - '0');
                    g_gps.minute = (token[2] - '0') * 10 + (token[3] - '0');
                    g_gps.second = (token[4] - '0') * 10 + (token[5] - '0');
                }
                break;
            case 2: /* Status */
                g_gps.fix_valid = (*token == 'A');
                break;
            case 7: /* Speed */
                g_gps.speed_knots = atof(token);
                break;
            case 8: /* Course */
                g_gps.course = atof(token);
                break;
            case 9: /* Date */
                if (strlen(token) >= 6) {
                    g_gps.day = (token[0] - '0') * 10 + (token[1] - '0');
                    g_gps.month = (token[2] - '0') * 10 + (token[3] - '0');
                    g_gps.year = 2000 + (token[4] - '0') * 10 + (token[5] - '0');
                }
                break;
        }
        field++;
        token = strtok(NULL, ",");
    }
}

static void gps_process_sentence(void)
{
    if (g_gps.nmea_index < 6) return;
    
    /* Check for valid NMEA sentence */
    if (strncmp(g_gps.nmea_buffer, "$GPGGA", 6) == 0 ||
        strncmp(g_gps.nmea_buffer, "$GNGGA", 6) == 0) {
        gps_parse_gga(g_gps.nmea_buffer);
    }
    else if (strncmp(g_gps.nmea_buffer, "$GPRMC", 6) == 0 ||
             strncmp(g_gps.nmea_buffer, "$GNRMC", 6) == 0) {
        gps_parse_rmc(g_gps.nmea_buffer);
    }
    
    /* Notify callback */
    if (g_gps.callback) {
        g_gps.callback();
    }
}

void GPS_Init(void)
{
    /* Configure enable pin */
    HAL_GPIO_Config(GPIO_PORT_A, GPIO_PIN_8, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_10MHZ);
    GPS_ENABLE_PORT->CLR = GPS_ENABLE_PIN;  /* Off by default */
    
    /* Configure UART */
    UART_Config_t uart_config = {
        .baudrate = GPS_BAUDRATE,
        .word_length = UART_WORDLEN_8,
        .stop_bits = UART_STOPBITS_1,
        .parity = UART_PARITY_NONE,
        .enable_rx = true,
        .enable_tx = true
    };
    
    HAL_UART_Init(GPS_UART_INSTANCE, &uart_config);
    
    g_gps.initialized = true;
    g_gps.enabled = false;
    g_gps.fix_valid = false;
    g_gps.nmea_index = 0;
    g_gps.callback = NULL;
}

void GPS_DeInit(void)
{
    GPS_Disable();
    HAL_UART_DeInit(GPS_UART_INSTANCE);
    g_gps.initialized = false;
}

void GPS_Enable(void)
{
    GPS_ENABLE_PORT->SCR = GPS_ENABLE_PIN;
    g_gps.enabled = true;
    HAL_UART_EnableRxInterrupt(GPS_UART_INSTANCE);
}

void GPS_Disable(void)
{
    GPS_ENABLE_PORT->CLR = GPS_ENABLE_PIN;
    g_gps.enabled = false;
    HAL_UART_DisableRxInterrupt(GPS_UART_INSTANCE);
}

bool GPS_IsEnabled(void)
{
    return g_gps.enabled;
}

bool GPS_HasFix(void)
{
    return g_gps.fix_valid;
}

void GPS_GetPosition(GPS_Position_t *pos)
{
    if (pos == NULL) return;
    
    pos->latitude = g_gps.latitude;
    pos->longitude = g_gps.longitude;
    pos->altitude = g_gps.altitude;
    pos->speed_knots = g_gps.speed_knots;
    pos->course = g_gps.course;
    pos->satellites = g_gps.satellites;
    pos->hdop = g_gps.hdop;
    pos->valid = g_gps.fix_valid;
}

void GPS_GetTime(GPS_Time_t *time)
{
    if (time == NULL) return;
    
    time->hour = g_gps.hour;
    time->minute = g_gps.minute;
    time->second = g_gps.second;
    time->day = g_gps.day;
    time->month = g_gps.month;
    time->year = g_gps.year;
}

void GPS_SetCallback(GPS_Callback_t callback)
{
    g_gps.callback = callback;
}

void GPS_Process(void)
{
    if (!g_gps.initialized || !g_gps.enabled) return;
    
    /* Read available data from UART */
    while (HAL_UART_IsRxReady(GPS_UART_INSTANCE)) {
        uint8_t c = HAL_UART_ReceiveByte(GPS_UART_INSTANCE);
        
        if (c == '$') {
            /* Start of new sentence */
            g_gps.nmea_index = 0;
        }
        
        if (g_gps.nmea_index < sizeof(g_gps.nmea_buffer) - 1) {
            g_gps.nmea_buffer[g_gps.nmea_index++] = c;
        }
        
        if (c == '\n') {
            /* End of sentence */
            g_gps.nmea_buffer[g_gps.nmea_index] = '\0';
            gps_process_sentence();
            g_gps.nmea_index = 0;
        }
    }
}

