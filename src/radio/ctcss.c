/**
 * @file ctcss.c
 * @brief CTCSS/DCS Encoding and Decoding Implementation
 */

#include "radio/ctcss.h"
#include "drivers/audio.h"
#include "hal/system.h"

#include <string.h>

/* Standard CTCSS tones (frequency in 0.1 Hz) */
static const uint16_t g_ctcss_tones[] = {
    670, 693, 719, 744, 770, 797, 825, 854,
    885, 915, 948, 974, 1000, 1035, 1072, 1109,
    1148, 1188, 1230, 1273, 1318, 1365, 1413, 1462,
    1514, 1567, 1598, 1622, 1655, 1679, 1713, 1738,
    1773, 1799, 1835, 1862, 1899, 1928, 1966, 1995,
    2035, 2065, 2107, 2181, 2257, 2336, 2418, 2503
};

#define CTCSS_TONE_COUNT    (sizeof(g_ctcss_tones) / sizeof(g_ctcss_tones[0]))

/* Standard DCS codes */
static const uint16_t g_dcs_codes[] = {
    23, 25, 26, 31, 32, 36, 43, 47, 51, 53, 54, 65, 71, 72, 73, 74,
    114, 115, 116, 122, 125, 131, 132, 134, 143, 145, 152, 155, 156, 162, 165, 172,
    174, 205, 212, 223, 225, 226, 243, 244, 245, 246, 251, 252, 255, 261, 263, 265,
    266, 271, 274, 306, 311, 315, 325, 331, 332, 343, 346, 351, 356, 364, 365, 371,
    411, 412, 413, 423, 431, 432, 445, 446, 452, 454, 455, 462, 464, 465, 466, 503,
    506, 516, 523, 526, 532, 546, 565, 606, 612, 624, 627, 631, 632, 654, 662, 664,
    703, 712, 723, 731, 732, 734, 743, 754
};

#define DCS_CODE_COUNT      (sizeof(g_dcs_codes) / sizeof(g_dcs_codes[0]))

/* CTCSS state */
static struct {
    bool tx_active;
    bool rx_active;
    uint16_t tx_tone;
    uint16_t rx_tone;
    uint16_t detected_tone;
    bool tone_detected;
} g_ctcss;

/* DCS state */
static struct {
    bool tx_active;
    bool rx_active;
    uint16_t tx_code;
    uint16_t rx_code;
    bool tx_inverted;
    bool rx_inverted;
    uint16_t detected_code;
    bool code_detected;
} g_dcs;

void CTCSS_Init(void)
{
    memset(&g_ctcss, 0, sizeof(g_ctcss));
    memset(&g_dcs, 0, sizeof(g_dcs));
}

uint8_t CTCSS_GetToneCount(void)
{
    return CTCSS_TONE_COUNT;
}

uint16_t CTCSS_GetToneFreq(uint8_t index)
{
    if (index >= CTCSS_TONE_COUNT) return 0;
    return g_ctcss_tones[index];
}

int8_t CTCSS_FindTone(uint16_t freq_tenths)
{
    for (uint8_t i = 0; i < CTCSS_TONE_COUNT; i++) {
        if (g_ctcss_tones[i] == freq_tenths) {
            return i;
        }
    }
    return -1;
}

void CTCSS_SetTX(uint16_t freq_tenths)
{
    g_ctcss.tx_tone = freq_tenths;
}

void CTCSS_SetRX(uint16_t freq_tenths)
{
    g_ctcss.rx_tone = freq_tenths;
}

void CTCSS_StartTX(void)
{
    if (g_ctcss.tx_tone == 0) return;
    
    Audio_StartCTCSS(g_ctcss.tx_tone);
    g_ctcss.tx_active = true;
}

void CTCSS_StopTX(void)
{
    Audio_StopCTCSS();
    g_ctcss.tx_active = false;
}

void CTCSS_StartRX(void)
{
    if (g_ctcss.rx_tone == 0) return;
    
    g_ctcss.rx_active = true;
    g_ctcss.tone_detected = false;
}

void CTCSS_StopRX(void)
{
    g_ctcss.rx_active = false;
}

bool CTCSS_IsDetected(void)
{
    return g_ctcss.tone_detected;
}

uint16_t CTCSS_GetDetected(void)
{
    return g_ctcss.detected_tone;
}

void CTCSS_Process(void)
{
    if (!g_ctcss.rx_active) return;
    
    /* TODO: Implement CTCSS detection using Goertzel algorithm */
    /* This requires audio input sampling and frequency detection */
    /* For now, just a placeholder */
}

/* DCS Functions */

uint8_t DCS_GetCodeCount(void)
{
    return DCS_CODE_COUNT;
}

uint16_t DCS_GetCode(uint8_t index)
{
    if (index >= DCS_CODE_COUNT) return 0;
    return g_dcs_codes[index];
}

int8_t DCS_FindCode(uint16_t code)
{
    for (uint8_t i = 0; i < DCS_CODE_COUNT; i++) {
        if (g_dcs_codes[i] == code) {
            return i;
        }
    }
    return -1;
}

void DCS_SetTX(uint16_t code, bool inverted)
{
    g_dcs.tx_code = code;
    g_dcs.tx_inverted = inverted;
}

void DCS_SetRX(uint16_t code, bool inverted)
{
    g_dcs.rx_code = code;
    g_dcs.rx_inverted = inverted;
}

void DCS_StartTX(void)
{
    if (g_dcs.tx_code == 0) return;
    
    Audio_StartDCS(g_dcs.tx_code, g_dcs.tx_inverted);
    g_dcs.tx_active = true;
}

void DCS_StopTX(void)
{
    Audio_StopDCS();
    g_dcs.tx_active = false;
}

void DCS_StartRX(void)
{
    if (g_dcs.rx_code == 0) return;
    
    g_dcs.rx_active = true;
    g_dcs.code_detected = false;
}

void DCS_StopRX(void)
{
    g_dcs.rx_active = false;
}

bool DCS_IsDetected(void)
{
    return g_dcs.code_detected;
}

uint16_t DCS_GetDetected(void)
{
    return g_dcs.detected_code;
}

void DCS_Process(void)
{
    if (!g_dcs.rx_active) return;
    
    /* TODO: Implement DCS detection */
    /* This requires FSK demodulation of the 134.4 Hz subaudible signal */
}

