/**
 * @file channel.h
 * @brief Channel Memory Management
 */

#ifndef RADIO_CHANNEL_H
#define RADIO_CHANNEL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Channel data structure */
typedef struct {
    uint32_t rx_freq;           /* RX frequency in Hz */
    uint32_t tx_freq;           /* TX frequency in Hz */
    uint16_t rx_ctcss;          /* RX CTCSS (0.1 Hz units) */
    uint16_t tx_ctcss;          /* TX CTCSS (0.1 Hz units) */
    uint16_t rx_dcs;            /* RX DCS code */
    uint16_t tx_dcs;            /* TX DCS code */
    uint8_t tx_power;           /* TX power level */
    uint8_t modulation;         /* Modulation type */
    uint8_t bandwidth;          /* Bandwidth */
    uint8_t flags;              /* Channel flags */
    char name[17];              /* Channel name */
    bool is_valid;              /* True if channel is programmed */
} Channel_t;

void Channel_Init(void);
bool Channel_Load(uint8_t zone, uint16_t channel, Channel_t *ch);
bool Channel_Save(uint8_t zone, uint16_t channel, const Channel_t *ch);
bool Channel_Delete(uint8_t zone, uint16_t channel);
bool Channel_Select(uint8_t zone, uint16_t channel);
void Channel_GetCurrent(uint8_t *zone, uint16_t *channel);
const Channel_t *Channel_GetCurrentData(void);
bool Channel_Next(void);
bool Channel_Prev(void);
uint16_t Channel_GetCount(uint8_t zone);
uint8_t Channel_GetZoneCount(void);

#ifdef __cplusplus
}
#endif

#endif /* RADIO_CHANNEL_H */

