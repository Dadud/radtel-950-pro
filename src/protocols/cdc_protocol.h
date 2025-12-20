/**
 * @file cdc_protocol.h
 * @brief USB CDC Protocol for PC Programming
 * 
 * Implements the USB CDC/ACM protocol used for firmware updates and
 * radio programming. Protocol details are CONFIRMED from USB captures
 * and OEM updater reverse engineering.
 * 
 * Protocol Overview:
 *   - USB CDC/ACM class device
 *   - Binary protocol with 0xAA start, 0x55 end framing
 *   - CRC-16 XMODEM for packet validation
 *   - Commands for firmware update and memory read/write
 * 
 * Captured protocol details are in:
 *   firmware/RE/bootloader/bootloader_protocol_notes.md
 */

#ifndef PROTOCOLS_CDC_PROTOCOL_H
#define PROTOCOLS_CDC_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * PROTOCOL CONSTANTS (CONFIRMED from USB captures)
 * ============================================================================ */

#define CDC_PACKET_START        0xAA
#define CDC_PACKET_END          0x55
#define CDC_SUCCESS_CODE        0x0006
#define CDC_ERROR_CODE          0x0015

#define CDC_MAX_PAYLOAD         1024
#define CDC_CHUNK_SIZE          1024

/* ============================================================================
 * COMMAND CODES (CONFIRMED from bootloader analysis)
 * ============================================================================ */

typedef enum {
    CDC_CMD_ENTER_BINARY    = 0x42,     /* Enter binary/update mode */
    CDC_CMD_BOOT_VERSION    = 0x0A,     /* Send bootloader version */
    CDC_CMD_METADATA        = 0x02,     /* Send model metadata */
    CDC_CMD_CONFIG          = 0x04,     /* Send config blob */
    CDC_CMD_DATA            = 0x03,     /* Data chunk */
    CDC_CMD_FINALISE        = 0x45,     /* Finalize and reboot */
    
    /* Programming commands (INFERRED) */
    CDC_CMD_READ_MEM        = 0x52,     /* Read memory */
    CDC_CMD_WRITE_MEM       = 0x57,     /* Write memory */
    CDC_CMD_ERASE           = 0x45,     /* Erase sector */
    CDC_CMD_GET_STATUS      = 0x53,     /* Get status */
    CDC_CMD_RESET           = 0x52,     /* Reset device */
} CDC_Command_t;

/* ============================================================================
 * PACKET STRUCTURE
 * ============================================================================
 * 
 * Packet format (CONFIRMED):
 * +------+-----+--------+--------+---------+-------+-----+
 * | 0xAA | CMD | PARAM1 | PARAM2 | PAYLOAD | CRC16 | 0x55|
 * +------+-----+--------+--------+---------+-------+-----+
 * | 1    | 1   | 2 (BE) | 2 (BE) | 0-1024  | 2 (BE)| 1   |
 * +------+-----+--------+--------+---------+-------+-----+
 * 
 * CRC covers: CMD + PARAM1 + PARAM2 + PAYLOAD
 */

typedef struct __attribute__((packed)) {
    uint8_t start;              /* Always 0xAA */
    uint8_t cmd;                /* Command code */
    uint16_t param1;            /* Parameter 1 (big-endian) */
    uint16_t param2;            /* Parameter 2 / payload length */
    uint8_t payload[CDC_MAX_PAYLOAD];
    uint16_t crc;               /* CRC-16 XMODEM */
    uint8_t end;                /* Always 0x55 */
} CDC_Packet_t;

/* ============================================================================
 * PROTOCOL STATE
 * ============================================================================ */

typedef enum {
    CDC_STATE_IDLE = 0,         /* Waiting for connection */
    CDC_STATE_HANDSHAKE,        /* ASCII handshake phase */
    CDC_STATE_BINARY,           /* Binary protocol active */
    CDC_STATE_UPDATE,           /* Firmware update in progress */
    CDC_STATE_PROGRAM,          /* Memory programming mode */
    CDC_STATE_ERROR             /* Error state */
} CDC_State_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize CDC protocol handler
 */
void CDC_Init(void);

/**
 * @brief Process CDC communication (call from main loop)
 */
void CDC_Process(void);

/**
 * @brief Check if CDC is connected
 * @return true if USB host is connected
 */
bool CDC_IsConnected(void);

/**
 * @brief Get current protocol state
 * @return Current state
 */
CDC_State_t CDC_GetState(void);

/**
 * @brief Send a response packet
 * @param cmd Command code (echo back)
 * @param param1 Parameter 1 (usually status)
 * @param payload Response payload (can be NULL)
 * @param payload_len Payload length
 */
void CDC_SendResponse(uint8_t cmd, uint16_t param1, 
                      const uint8_t *payload, uint16_t payload_len);

/**
 * @brief Send success acknowledgment
 * @param cmd Command being acknowledged
 */
void CDC_SendAck(uint8_t cmd);

/**
 * @brief Send error response
 * @param cmd Command that failed
 * @param error_code Error code
 */
void CDC_SendError(uint8_t cmd, uint16_t error_code);

/**
 * @brief Calculate CRC-16 XMODEM
 * @param data Data buffer
 * @param length Data length
 * @return CRC-16 value
 * 
 * CONFIRMED: Uses polynomial 0x1021, init 0x0000
 */
uint16_t CDC_CalculateCRC(const uint8_t *data, uint32_t length);

/**
 * @brief Handle received packet
 * @param packet Pointer to received packet
 * 
 * Called internally when a complete valid packet is received.
 */
void CDC_HandlePacket(const CDC_Packet_t *packet);

/**
 * @brief Enter firmware update mode
 * 
 * Prepares system for firmware update. Called when CMD_ENTER_BINARY
 * is received.
 */
void CDC_EnterUpdateMode(void);

/**
 * @brief Exit firmware update mode
 * 
 * Returns to normal operation.
 */
void CDC_ExitUpdateMode(void);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOLS_CDC_PROTOCOL_H */


