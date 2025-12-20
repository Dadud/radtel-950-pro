/**
 * @file gps.h
 * @brief GPS Receiver Interface
 * 
 * Handles NMEA data from the GPS module connected via UART.
 * 
 * Hardware connection (CONFIRMED from OEM firmware):
 *   - USART3 or UART on PB10/PB11 (or PC10/PC11)
 *   - 9600 baud [CONFIRMED from GPS_USART3_Init]
 *   - GPS power enable on PA8 [HIGH confidence]
 * 
 * NMEA parsing from FUN_8000ac7c (GPS_Parse_NMEA_Coordinate)
 */

#ifndef PROTOCOLS_GPS_H
#define PROTOCOLS_GPS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * GPS CONFIGURATION
 * ============================================================================ */

#define GPS_UART_BAUD           9600
#define GPS_BUFFER_SIZE         256
#define GPS_MAX_SATELLITES      12

/* ============================================================================
 * GPS DATA STRUCTURES
 * ============================================================================ */

/**
 * @brief GPS fix type
 */
typedef enum {
    GPS_FIX_NONE = 0,           /* No fix */
    GPS_FIX_2D,                 /* 2D fix (lat/lon only) */
    GPS_FIX_3D                  /* 3D fix (lat/lon/alt) */
} GPS_FixType_t;

/**
 * @brief GPS position data
 * 
 * INFERRED: Structure layout from GPS_Parse_NMEA_Coordinate analysis.
 * Coordinates are stored as degrees * 10^7 for precision without floats.
 */
typedef struct {
    int32_t latitude;           /* Latitude in degrees * 10^7 */
    int32_t longitude;          /* Longitude in degrees * 10^7 */
    int32_t altitude;           /* Altitude in centimeters */
    uint16_t speed;             /* Speed in 0.1 knots */
    uint16_t heading;           /* Heading in 0.1 degrees */
    uint8_t satellites;         /* Number of satellites in use */
    GPS_FixType_t fix_type;     /* Fix type */
    bool valid;                 /* Data is valid */
} GPS_Position_t;

/**
 * @brief GPS time/date
 */
typedef struct {
    uint8_t hour;               /* Hour (0-23) */
    uint8_t minute;             /* Minute (0-59) */
    uint8_t second;             /* Second (0-59) */
    uint8_t day;                /* Day (1-31) */
    uint8_t month;              /* Month (1-12) */
    uint16_t year;              /* Year (e.g., 2024) */
    bool valid;                 /* Time is valid */
} GPS_Time_t;

/**
 * @brief Complete GPS data
 */
typedef struct {
    GPS_Position_t position;    /* Position data */
    GPS_Time_t time;            /* Time/date data */
    uint8_t hdop;               /* Horizontal dilution * 10 */
    uint8_t vdop;               /* Vertical dilution * 10 */
    uint32_t last_update;       /* System tick of last valid fix */
} GPS_Data_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize GPS interface
 * 
 * Configures UART and enables GPS module power.
 * CONFIRMED: UART configuration from GPS_USART3_Init (FUN_80013f90)
 */
void GPS_Init(void);

/**
 * @brief Process GPS data (call from main loop)
 * 
 * Reads UART buffer and parses NMEA sentences.
 */
void GPS_Process(void);

/**
 * @brief Get current GPS data
 * @return Pointer to GPS data structure (read-only)
 */
const GPS_Data_t *GPS_GetData(void);

/**
 * @brief Check if GPS has a valid fix
 * @return true if GPS has a valid position fix
 */
bool GPS_HasFix(void);

/**
 * @brief Check if GPS time is valid
 * @return true if GPS time is synchronized
 */
bool GPS_HasTime(void);

/**
 * @brief Power on GPS module
 */
void GPS_PowerOn(void);

/**
 * @brief Power off GPS module
 */
void GPS_PowerOff(void);

/**
 * @brief Check if GPS is powered on
 * @return true if GPS is powered
 */
bool GPS_IsPowered(void);

/**
 * @brief Format position as string
 * @param buffer Output buffer
 * @param size Buffer size
 * @param format 0=decimal degrees, 1=degrees minutes, 2=degrees minutes seconds
 * @return Number of characters written
 */
int GPS_FormatPosition(char *buffer, uint32_t size, uint8_t format);

/**
 * @brief Format time as string
 * @param buffer Output buffer
 * @param size Buffer size
 * @param utc_offset UTC offset in minutes
 * @return Number of characters written
 */
int GPS_FormatTime(char *buffer, uint32_t size, int16_t utc_offset);

/**
 * @brief Calculate distance between two points
 * @param lat1 Latitude 1 (degrees * 10^7)
 * @param lon1 Longitude 1 (degrees * 10^7)
 * @param lat2 Latitude 2 (degrees * 10^7)
 * @param lon2 Longitude 2 (degrees * 10^7)
 * @return Distance in meters
 */
uint32_t GPS_CalculateDistance(int32_t lat1, int32_t lon1, 
                                int32_t lat2, int32_t lon2);

/**
 * @brief Calculate bearing between two points
 * @param lat1 Latitude 1 (degrees * 10^7)
 * @param lon1 Longitude 1 (degrees * 10^7)
 * @param lat2 Latitude 2 (degrees * 10^7)
 * @param lon2 Longitude 2 (degrees * 10^7)
 * @return Bearing in 0.1 degrees (0-3599)
 */
uint16_t GPS_CalculateBearing(int32_t lat1, int32_t lon1, 
                               int32_t lat2, int32_t lon2);

/**
 * @brief Get Maidenhead grid locator
 * @param buffer Output buffer (minimum 7 bytes)
 * @param precision 3, 4, or 5 for 6, 8, or 10 character locator
 */
void GPS_GetGridLocator(char *buffer, uint8_t precision);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOLS_GPS_H */


