/**
 * @file vfo.c
 * @brief VFO Management Implementation
 * 
 * Manages VFO A/B state and frequency settings.
 */

#include "radio/vfo.h"
#include "config/radio_model.h"
#include "radio/radio.h"
#include "config/settings.h"

#include <string.h>

/* VFO state */
static struct {
    bool initialized;
    VFO_t vfo_a;
    VFO_t vfo_b;
    bool vfo_a_active;
} g_vfo;

/* Band limits */
static const struct {
    uint32_t min_freq;
    uint32_t max_freq;
} g_band_limits[] = {
    { 136000000, 174000000 },   /* VHF */
#if DUAL_BAND_ENABLED
    { 400000000, 520000000 },   /* UHF - Pro only */
#endif
    { 76000000, 108000000 },    /* FM broadcast */
};

void VFO_Init(void)
{
    /* Default VFO A settings */
    g_vfo.vfo_a.frequency = 146520000;
    g_vfo.vfo_a.tx_offset = 0;
    g_vfo.vfo_a.offset_direction = VFO_OFFSET_NONE;
    g_vfo.vfo_a.tx_ctcss = 0;
    g_vfo.vfo_a.rx_ctcss = 0;
    g_vfo.vfo_a.tx_dcs = 0;
    g_vfo.vfo_a.rx_dcs = 0;
    g_vfo.vfo_a.modulation = VFO_MOD_FM;
    g_vfo.vfo_a.bandwidth = VFO_BW_WIDE;
    g_vfo.vfo_a.tx_power = VFO_POWER_HIGH;
    g_vfo.vfo_a.step = 25000;  /* 25 kHz step */
    
    /* Default VFO B settings */
    g_vfo.vfo_b.frequency = 446000000;
    g_vfo.vfo_b.tx_offset = 0;
    g_vfo.vfo_b.offset_direction = VFO_OFFSET_NONE;
    g_vfo.vfo_b.tx_ctcss = 0;
    g_vfo.vfo_b.rx_ctcss = 0;
    g_vfo.vfo_b.tx_dcs = 0;
    g_vfo.vfo_b.rx_dcs = 0;
    g_vfo.vfo_b.modulation = VFO_MOD_FM;
    g_vfo.vfo_b.bandwidth = VFO_BW_WIDE;
    g_vfo.vfo_b.tx_power = VFO_POWER_HIGH;
    g_vfo.vfo_b.step = 25000;
    
    g_vfo.vfo_a_active = true;
    g_vfo.initialized = true;
}

VFO_t *VFO_GetActive(void)
{
    return g_vfo.vfo_a_active ? &g_vfo.vfo_a : &g_vfo.vfo_b;
}

VFO_t *VFO_GetA(void)
{
    return &g_vfo.vfo_a;
}

VFO_t *VFO_GetB(void)
{
    return &g_vfo.vfo_b;
}

bool VFO_IsAActive(void)
{
    return g_vfo.vfo_a_active;
}

void VFO_SetActive(bool use_a)
{
    g_vfo.vfo_a_active = use_a;
}

void VFO_Toggle(void)
{
    g_vfo.vfo_a_active = !g_vfo.vfo_a_active;
}

bool VFO_SetFrequency(uint32_t freq)
{
    VFO_t *vfo = VFO_GetActive();
    
    /* Check band limits */
    bool valid = false;
    for (size_t i = 0; i < sizeof(g_band_limits) / sizeof(g_band_limits[0]); i++) {
        if (freq >= g_band_limits[i].min_freq && freq <= g_band_limits[i].max_freq) {
            valid = true;
            break;
        }
    }
    
    if (!valid) return false;
    
    vfo->frequency = freq;
    return true;
}

uint32_t VFO_GetFrequency(void)
{
    return VFO_GetActive()->frequency;
}

uint32_t VFO_GetTXFrequency(void)
{
    VFO_t *vfo = VFO_GetActive();
    
    switch (vfo->offset_direction) {
        case VFO_OFFSET_PLUS:
            return vfo->frequency + vfo->tx_offset;
        case VFO_OFFSET_MINUS:
            return vfo->frequency - vfo->tx_offset;
        default:
            return vfo->frequency;
    }
}

void VFO_StepUp(void)
{
    VFO_t *vfo = VFO_GetActive();
    VFO_SetFrequency(vfo->frequency + vfo->step);
}

void VFO_StepDown(void)
{
    VFO_t *vfo = VFO_GetActive();
    VFO_SetFrequency(vfo->frequency - vfo->step);
}

void VFO_SetStep(uint32_t step_hz)
{
    VFO_GetActive()->step = step_hz;
}

uint32_t VFO_GetStep(void)
{
    return VFO_GetActive()->step;
}

void VFO_SetOffset(int32_t offset_hz)
{
    VFO_t *vfo = VFO_GetActive();
    
    if (offset_hz > 0) {
        vfo->offset_direction = VFO_OFFSET_PLUS;
        vfo->tx_offset = offset_hz;
    } else if (offset_hz < 0) {
        vfo->offset_direction = VFO_OFFSET_MINUS;
        vfo->tx_offset = -offset_hz;
    } else {
        vfo->offset_direction = VFO_OFFSET_NONE;
        vfo->tx_offset = 0;
    }
}

int32_t VFO_GetOffset(void)
{
    VFO_t *vfo = VFO_GetActive();
    
    switch (vfo->offset_direction) {
        case VFO_OFFSET_PLUS:
            return vfo->tx_offset;
        case VFO_OFFSET_MINUS:
            return -(int32_t)vfo->tx_offset;
        default:
            return 0;
    }
}

void VFO_CopyAtoB(void)
{
    memcpy(&g_vfo.vfo_b, &g_vfo.vfo_a, sizeof(VFO_t));
}

void VFO_CopyBtoA(void)
{
    memcpy(&g_vfo.vfo_a, &g_vfo.vfo_b, sizeof(VFO_t));
}

void VFO_Swap(void)
{
    VFO_t temp;
    memcpy(&temp, &g_vfo.vfo_a, sizeof(VFO_t));
    memcpy(&g_vfo.vfo_a, &g_vfo.vfo_b, sizeof(VFO_t));
    memcpy(&g_vfo.vfo_b, &temp, sizeof(VFO_t));
}

