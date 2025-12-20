/**
 * @file bluetooth.h
 * @brief Bluetooth Module Interface
 * 
 * Handles communication with the on-board Bluetooth module.
 * Used for remote programming and audio (headset).
 * 
 * Hardware connection (CONFIRMED from OEM firmware):
 *   - USART1: PA9 (TX), PA10 (RX) [CONFIRMED]
 *   - Baud rate: 115200 [CONFIRMED from Bluetooth_UART1_Init]
 * 
 * The Bluetooth module appears to use AT command set for control.
 * Audio is routed through a separate analog path.
 */

#ifndef PROTOCOLS_BLUETOOTH_H
#define PROTOCOLS_BLUETOOTH_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * BLUETOOTH CONFIGURATION
 * ============================================================================ */

#define BT_UART_BAUD            115200
#define BT_MAX_NAME_LEN         32
#define BT_MAX_COMMAND_LEN      64

/* ============================================================================
 * BLUETOOTH STATE ENUMERATION
 * ============================================================================ */

typedef enum {
    BT_STATE_OFF = 0,           /* Bluetooth disabled */
    BT_STATE_INIT,              /* Initializing */
    BT_STATE_IDLE,              /* Powered, not connected */
    BT_STATE_PAIRING,           /* Pairing mode */
    BT_STATE_CONNECTING,        /* Connection in progress */
    BT_STATE_CONNECTED,         /* Connected to device */
    BT_STATE_CALL,              /* Call active (headset mode) */
    BT_STATE_AUDIO,             /* Audio streaming */
    BT_STATE_ERROR              /* Error state */
} BT_State_t;

/* ============================================================================
 * BLUETOOTH PROFILE ENUMERATION
 * ============================================================================ */

typedef enum {
    BT_PROFILE_SPP = 0,         /* Serial Port Profile */
    BT_PROFILE_HFP,             /* Hands-Free Profile */
    BT_PROFILE_A2DP             /* Audio streaming */
} BT_Profile_t;

/* ============================================================================
 * BLUETOOTH STATUS STRUCTURE
 * ============================================================================ */

typedef struct {
    BT_State_t state;           /* Current state */
    bool connected;             /* Device is connected */
    bool audio_active;          /* Audio stream active */
    int8_t rssi;                /* Connection RSSI */
    char device_name[BT_MAX_NAME_LEN];  /* Connected device name */
    uint8_t battery;            /* Remote device battery (if available) */
} BT_Status_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize Bluetooth interface
 * 
 * Configures UART and powers up Bluetooth module.
 * CONFIRMED: UART configuration from Bluetooth_UART1_Init (FUN_8000834c)
 */
void Bluetooth_Init(void);

/**
 * @brief Process Bluetooth communication (call from main loop)
 * 
 * Handles AT command responses and state machine.
 */
void Bluetooth_Process(void);

/**
 * @brief Get Bluetooth status
 * @return Pointer to status structure
 */
const BT_Status_t *Bluetooth_GetStatus(void);

/**
 * @brief Check if Bluetooth is connected
 * @return true if connected
 */
bool Bluetooth_IsConnected(void);

/**
 * @brief Enable Bluetooth
 */
void Bluetooth_Enable(void);

/**
 * @brief Disable Bluetooth
 */
void Bluetooth_Disable(void);

/**
 * @brief Enter pairing mode
 */
void Bluetooth_StartPairing(void);

/**
 * @brief Stop pairing mode
 */
void Bluetooth_StopPairing(void);

/**
 * @brief Disconnect current device
 */
void Bluetooth_Disconnect(void);

/**
 * @brief Set Bluetooth device name
 * @param name Device name (max 32 chars)
 */
void Bluetooth_SetName(const char *name);

/**
 * @brief Get Bluetooth device name
 * @return Pointer to device name string
 */
const char *Bluetooth_GetName(void);

/**
 * @brief Send data over Bluetooth SPP
 * @param data Data buffer
 * @param length Data length
 * @return Number of bytes sent
 */
uint32_t Bluetooth_Send(const uint8_t *data, uint32_t length);

/**
 * @brief Check if data is available to read
 * @return Number of bytes available
 */
uint32_t Bluetooth_Available(void);

/**
 * @brief Read data from Bluetooth SPP
 * @param buffer Buffer to store data
 * @param max_length Maximum bytes to read
 * @return Number of bytes read
 */
uint32_t Bluetooth_Read(uint8_t *buffer, uint32_t max_length);

/**
 * @brief Enable audio routing to Bluetooth
 * @param enable true to route audio to Bluetooth
 */
void Bluetooth_EnableAudio(bool enable);

/**
 * @brief Set volume for Bluetooth audio
 * @param volume Volume level (0-15)
 */
void Bluetooth_SetVolume(uint8_t volume);

/**
 * @brief Send AT command to Bluetooth module
 * @param command AT command string
 * @param response Buffer for response (can be NULL)
 * @param max_len Maximum response length
 * @param timeout_ms Timeout in milliseconds
 * @return true if command succeeded
 */
bool Bluetooth_SendCommand(const char *command, char *response, 
                           uint32_t max_len, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOLS_BLUETOOTH_H */


