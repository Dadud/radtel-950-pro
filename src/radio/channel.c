/**
 * @file channel.c
 * @brief Channel Memory Management Implementation
 * 
 * Manages channel storage, loading, and saving.
 */

#include "radio/channel.h"
#include "drivers/spi_flash.h"
#include "config/settings.h"

#include <string.h>

/* Channel storage configuration */
#define CHANNEL_FLASH_BASE      0x01000     /* Start address in flash */
#define CHANNEL_SIZE            64          /* Bytes per channel */
#define MAX_CHANNELS            990         /* 10 zones x 99 channels */
#define MAX_ZONES               10

/* Channel cache */
static struct {
    bool initialized;
    uint16_t current_channel;
    uint8_t current_zone;
    Channel_t cached_channel;
    bool cache_valid;
} g_channel;

/* Calculate flash address for channel */
static uint32_t channel_get_address(uint8_t zone, uint16_t channel)
{
    uint32_t index = zone * 99 + channel;
    return CHANNEL_FLASH_BASE + (index * CHANNEL_SIZE);
}

void Channel_Init(void)
{
    g_channel.initialized = true;
    g_channel.current_channel = 0;
    g_channel.current_zone = 0;
    g_channel.cache_valid = false;
}

bool Channel_Load(uint8_t zone, uint16_t channel, Channel_t *ch)
{
    if (!g_channel.initialized || ch == NULL) return false;
    if (zone >= MAX_ZONES || channel >= 99) return false;
    
    uint32_t addr = channel_get_address(zone, channel);
    
    /* Read from flash */
    uint8_t buffer[CHANNEL_SIZE];
    SPIFlash_Read(addr, buffer, CHANNEL_SIZE);
    
    /* Check if channel is programmed (first byte != 0xFF) */
    if (buffer[0] == 0xFF) {
        return false;
    }
    
    /* Parse channel data - format is INFERRED from OEM firmware */
    ch->rx_freq = ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
                  ((uint32_t)buffer[2] << 8) | buffer[3];
    ch->tx_freq = ((uint32_t)buffer[4] << 24) | ((uint32_t)buffer[5] << 16) |
                  ((uint32_t)buffer[6] << 8) | buffer[7];
    
    ch->rx_ctcss = ((uint16_t)buffer[8] << 8) | buffer[9];
    ch->tx_ctcss = ((uint16_t)buffer[10] << 8) | buffer[11];
    ch->rx_dcs = ((uint16_t)buffer[12] << 8) | buffer[13];
    ch->tx_dcs = ((uint16_t)buffer[14] << 8) | buffer[15];
    
    ch->tx_power = buffer[16];
    ch->modulation = buffer[17];
    ch->bandwidth = buffer[18];
    ch->flags = buffer[19];
    
    /* Channel name (up to 16 characters) */
    memcpy(ch->name, &buffer[20], 16);
    ch->name[16] = '\0';
    
    ch->is_valid = true;
    
    /* Update cache */
    memcpy(&g_channel.cached_channel, ch, sizeof(Channel_t));
    g_channel.cache_valid = true;
    
    return true;
}

bool Channel_Save(uint8_t zone, uint16_t channel, const Channel_t *ch)
{
    if (!g_channel.initialized || ch == NULL) return false;
    if (zone >= MAX_ZONES || channel >= 99) return false;
    
    uint32_t addr = channel_get_address(zone, channel);
    
    /* Prepare buffer */
    uint8_t buffer[CHANNEL_SIZE];
    memset(buffer, 0xFF, CHANNEL_SIZE);
    
    buffer[0] = (ch->rx_freq >> 24) & 0xFF;
    buffer[1] = (ch->rx_freq >> 16) & 0xFF;
    buffer[2] = (ch->rx_freq >> 8) & 0xFF;
    buffer[3] = ch->rx_freq & 0xFF;
    
    buffer[4] = (ch->tx_freq >> 24) & 0xFF;
    buffer[5] = (ch->tx_freq >> 16) & 0xFF;
    buffer[6] = (ch->tx_freq >> 8) & 0xFF;
    buffer[7] = ch->tx_freq & 0xFF;
    
    buffer[8] = (ch->rx_ctcss >> 8) & 0xFF;
    buffer[9] = ch->rx_ctcss & 0xFF;
    buffer[10] = (ch->tx_ctcss >> 8) & 0xFF;
    buffer[11] = ch->tx_ctcss & 0xFF;
    buffer[12] = (ch->rx_dcs >> 8) & 0xFF;
    buffer[13] = ch->rx_dcs & 0xFF;
    buffer[14] = (ch->tx_dcs >> 8) & 0xFF;
    buffer[15] = ch->tx_dcs & 0xFF;
    
    buffer[16] = ch->tx_power;
    buffer[17] = ch->modulation;
    buffer[18] = ch->bandwidth;
    buffer[19] = ch->flags;
    
    /* Copy name */
    size_t name_len = strlen(ch->name);
    if (name_len > 16) name_len = 16;
    memcpy(&buffer[20], ch->name, name_len);
    
    /* Write to flash */
    SPIFlash_Write(addr, buffer, CHANNEL_SIZE);
    
    /* Invalidate cache */
    g_channel.cache_valid = false;
    
    return true;
}

bool Channel_Delete(uint8_t zone, uint16_t channel)
{
    if (zone >= MAX_ZONES || channel >= 99) return false;
    
    uint32_t addr = channel_get_address(zone, channel);
    
    /* Write 0xFF to first byte to mark as deleted */
    uint8_t marker = 0xFF;
    SPIFlash_Write(addr, &marker, 1);
    
    g_channel.cache_valid = false;
    
    return true;
}

bool Channel_Select(uint8_t zone, uint16_t channel)
{
    if (zone >= MAX_ZONES || channel >= 99) return false;
    
    g_channel.current_zone = zone;
    g_channel.current_channel = channel;
    g_channel.cache_valid = false;
    
    return Channel_Load(zone, channel, &g_channel.cached_channel);
}

void Channel_GetCurrent(uint8_t *zone, uint16_t *channel)
{
    if (zone) *zone = g_channel.current_zone;
    if (channel) *channel = g_channel.current_channel;
}

const Channel_t *Channel_GetCurrentData(void)
{
    if (!g_channel.cache_valid) {
        Channel_Load(g_channel.current_zone, g_channel.current_channel, 
                     &g_channel.cached_channel);
    }
    
    return &g_channel.cached_channel;
}

bool Channel_Next(void)
{
    uint16_t next_channel = g_channel.current_channel + 1;
    
    if (next_channel >= 99) {
        next_channel = 0;
    }
    
    /* Find next valid channel */
    Channel_t temp;
    uint16_t start = next_channel;
    
    do {
        if (Channel_Load(g_channel.current_zone, next_channel, &temp)) {
            g_channel.current_channel = next_channel;
            g_channel.cached_channel = temp;
            g_channel.cache_valid = true;
            return true;
        }
        
        next_channel++;
        if (next_channel >= 99) next_channel = 0;
        
    } while (next_channel != start);
    
    return false;
}

bool Channel_Prev(void)
{
    int16_t prev_channel = g_channel.current_channel - 1;
    
    if (prev_channel < 0) {
        prev_channel = 98;
    }
    
    /* Find previous valid channel */
    Channel_t temp;
    int16_t start = prev_channel;
    
    do {
        if (Channel_Load(g_channel.current_zone, prev_channel, &temp)) {
            g_channel.current_channel = prev_channel;
            g_channel.cached_channel = temp;
            g_channel.cache_valid = true;
            return true;
        }
        
        prev_channel--;
        if (prev_channel < 0) prev_channel = 98;
        
    } while (prev_channel != start);
    
    return false;
}

uint16_t Channel_GetCount(uint8_t zone)
{
    if (zone >= MAX_ZONES) return 0;
    
    uint16_t count = 0;
    Channel_t temp;
    
    for (uint16_t i = 0; i < 99; i++) {
        if (Channel_Load(zone, i, &temp)) {
            count++;
        }
    }
    
    return count;
}

uint8_t Channel_GetZoneCount(void)
{
    return MAX_ZONES;
}

