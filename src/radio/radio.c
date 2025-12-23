/**
 * @file radio.c
 * @brief Radio Core State Machine Implementation
 * 
 * Manages the core radio functionality including TX/RX switching,
 * frequency control, and squelch handling.
 */

#include "radio/radio.h"
#include "drivers/bk4829.h"
#include "drivers/audio.h"
#include "drivers/power.h"
#include "hal/gpio.h"
#include "hal/system.h"

#include <string.h>

/* Radio status */
static RadioStatus_t g_status;
static bool g_initialized = false;

/* Timing */
static uint32_t g_tx_start_time = 0;
static uint32_t g_tx_timeout_ms = 180000;  /* 3 minute TOT */

/* PTT pin control */
#define PTT_PORT            GPIOE
#define PTT_PIN             GPIO_PIN_3
#define PA_ENABLE_PORT      GPIOE
#define PA_ENABLE_PIN       GPIO_PIN_4

static void radio_set_ptt(bool enable)
{
    if (enable) {
        PTT_PORT->SCR = PTT_PIN;
    } else {
        PTT_PORT->CLR = PTT_PIN;
    }
}

static void radio_set_pa(bool enable)
{
    if (enable) {
        PA_ENABLE_PORT->SCR = PA_ENABLE_PIN;
    } else {
        PA_ENABLE_PORT->CLR = PA_ENABLE_PIN;
    }
}

static Band_t freq_to_band(uint32_t freq)
{
    if (freq >= FREQ_VHF_MIN && freq <= FREQ_VHF_MAX) {
        return BAND_VHF;
#if DUAL_BAND_ENABLED
    } else if (freq >= FREQ_UHF_MIN && freq <= FREQ_UHF_MAX) {
        return BAND_UHF;
#endif
    } else if (freq >= FREQ_FM_MIN && freq <= FREQ_FM_MAX) {
        return BAND_FM;
    }
    return BAND_VHF;  /* Default */
}

void Radio_Init(void)
{
    /* Configure PTT and PA pins */
    HAL_GPIO_Config(GPIO_PORT_E, GPIO_PIN_3, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_10MHZ);
    HAL_GPIO_Config(GPIO_PORT_E, GPIO_PIN_4, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_10MHZ);
    
    /* Start with PTT and PA off */
    radio_set_ptt(false);
    radio_set_pa(false);
    
    /* Initialize BK4829 transceivers */
    BK4829_Init(BK4829_INSTANCE_VHF);
#if BK4829_INSTANCE_COUNT > 1
    BK4829_Init(BK4829_INSTANCE_UHF);
#endif
    
    /* Initialize status */
    memset(&g_status, 0, sizeof(g_status));
    g_status.state = RADIO_STATE_IDLE;
    g_status.mode = RADIO_MODE_VFO;
    g_status.current_vfo = VFO_A;
    g_status.active_band = BAND_VHF;
    
    /* Default VFO A settings */
    g_status.vfo[VFO_A].frequency = 146520000;
    g_status.vfo[VFO_A].step = STEP_25K;
    g_status.vfo[VFO_A].modulation = MOD_FM;
    g_status.vfo[VFO_A].power = POWER_HIGH;
    g_status.vfo[VFO_A].wide_bandwidth = true;
    g_status.vfo[VFO_A].squelch_level = 5;
    
    /* Default VFO B settings */
    g_status.vfo[VFO_B].frequency = 446000000;
    g_status.vfo[VFO_B].step = STEP_25K;
    g_status.vfo[VFO_B].modulation = MOD_FM;
    g_status.vfo[VFO_B].power = POWER_HIGH;
    g_status.vfo[VFO_B].wide_bandwidth = true;
    g_status.vfo[VFO_B].squelch_level = 5;
    
    g_initialized = true;
}

void Radio_Process(void)
{
    if (!g_initialized) return;
    
    /* Check TX timeout */
    if (g_status.state == RADIO_STATE_TX && g_tx_timeout_ms > 0) {
        if ((HAL_GetTick() - g_tx_start_time) >= g_tx_timeout_ms) {
            Radio_StopTX();
            Audio_PlayBeep(BEEP_ERROR);
        }
    }
    
    /* Update RSSI and squelch status when receiving */
    if (g_status.state == RADIO_STATE_IDLE || g_status.state == RADIO_STATE_RX) {
        BK4829_Instance_t instance = BK4829_INSTANCE_VHF;
#if DUAL_BAND_ENABLED
        if (g_status.active_band == BAND_UHF) {
            instance = BK4829_INSTANCE_UHF;
        }
#endif
        
        g_status.rssi = BK4829_GetRSSI(instance);
        
        /* Simple threshold-based squelch */
        VFO_t vfo = g_status.current_vfo;
        int16_t threshold = -130 + (g_status.vfo[vfo].squelch_level * 5);
        bool was_open = g_status.squelch_open;
        g_status.squelch_open = (g_status.rssi > threshold);
        
        /* State transitions */
        if (g_status.squelch_open && !was_open) {
            g_status.state = RADIO_STATE_RX;
            Audio_EnableSpeaker(true);
        }
        else if (!g_status.squelch_open && was_open) {
            g_status.state = RADIO_STATE_IDLE;
            Audio_EnableSpeaker(false);
        }
        
        /* Calculate S-meter */
        int16_t s = (g_status.rssi + 127) / 6;
        if (s < 0) s = 0;
        if (s > 9) s = 9;
        g_status.s_meter = s;
    }
}

const RadioStatus_t *Radio_GetStatus(void)
{
    return &g_status;
}

bool Radio_SetFrequency(uint32_t frequency)
{
    /* Check band limits */
    Band_t band = freq_to_band(frequency);
    if (band == BAND_FM) {
        /* FM broadcast is receive-only */
    }
    
#if !DUAL_BAND_ENABLED
    /* Single-band mode: force VHF if not FM */
    if (band != BAND_FM) {
        band = BAND_VHF;
    }
#endif
    
    /* Set on appropriate BK4829 */
    BK4829_Instance_t instance = BK4829_INSTANCE_VHF;
#if DUAL_BAND_ENABLED
    if (band == BAND_UHF) {
        instance = BK4829_INSTANCE_UHF;
    }
#endif
    
    BK4829_SetFrequency(instance, frequency);
    
    g_status.vfo[g_status.current_vfo].frequency = frequency;
    g_status.active_band = band;
    
    return true;
}

uint32_t Radio_GetFrequency(void)
{
    return g_status.vfo[g_status.current_vfo].frequency;
}

void Radio_SelectVFO(VFO_t vfo)
{
    if (vfo < VFO_COUNT_ENUM) {
        g_status.current_vfo = vfo;
        Radio_SetFrequency(g_status.vfo[vfo].frequency);
    }
}

void Radio_ToggleVFO(void)
{
    Radio_SelectVFO(g_status.current_vfo == VFO_A ? VFO_B : VFO_A);
}

void Radio_SetMode(RadioMode_t mode)
{
    g_status.mode = mode;
    
    if (mode == RADIO_MODE_FM) {
        g_status.state = RADIO_STATE_FM;
    } else {
        g_status.state = RADIO_STATE_IDLE;
    }
}

bool Radio_SelectChannel(uint16_t channel)
{
    if (channel > CHANNEL_MAX) return false;
    
    g_status.current_channel = channel;
    /* Load channel data and set frequency */
    /* TODO: Implement channel loading */
    
    return true;
}

void Radio_TuneUp(void)
{
    VFO_t vfo = g_status.current_vfo;
    uint32_t new_freq = g_status.vfo[vfo].frequency + g_status.vfo[vfo].step;
    Radio_SetFrequency(new_freq);
}

void Radio_TuneDown(void)
{
    VFO_t vfo = g_status.current_vfo;
    uint32_t new_freq = g_status.vfo[vfo].frequency - g_status.vfo[vfo].step;
    Radio_SetFrequency(new_freq);
}

void Radio_SetStep(uint32_t step)
{
    g_status.vfo[g_status.current_vfo].step = step;
}

void Radio_StartTX(void)
{
    if (!g_initialized) return;
    if (g_status.state == RADIO_STATE_TX) return;
    
    VFO_t vfo = g_status.current_vfo;
    uint32_t tx_freq = g_status.vfo[vfo].frequency;
    
    /* Apply TX offset */
    if (g_status.vfo[vfo].tx_offset_dir > 0) {
        tx_freq += g_status.vfo[vfo].tx_offset;
    } else if (g_status.vfo[vfo].tx_offset_dir < 0) {
        tx_freq -= g_status.vfo[vfo].tx_offset;
    }
    
    /* Band check */
    Band_t band = freq_to_band(tx_freq);
    if (band == BAND_FM) return;  /* Can't TX on FM broadcast */
    
#if !DUAL_BAND_ENABLED
    /* Single-band mode: force VHF */
    band = BAND_VHF;
#endif
    
    BK4829_Instance_t instance = BK4829_INSTANCE_VHF;
#if DUAL_BAND_ENABLED
    if (band == BAND_UHF) {
        instance = BK4829_INSTANCE_UHF;
    }
#endif
    
    /* Set TX frequency and enable TX */
    BK4829_SetFrequency(instance, tx_freq);
    BK4829_EnableTX(instance, true);
    
    /* Start TX CTCSS if configured */
    if (g_status.vfo[vfo].tx_ctcss > 0) {
        Audio_StartCTCSS(g_status.vfo[vfo].tx_ctcss);
    }
    
    /* Enable PA */
    radio_set_pa(true);
    radio_set_ptt(true);
    
    /* Enable microphone */
    Audio_SetMicEnabled(true);
    
    g_status.state = RADIO_STATE_TX;
    g_status.ptt_pressed = true;
    g_tx_start_time = HAL_GetTick();
    
    Audio_PlayBeep(BEEP_TX_START);
}

void Radio_StopTX(void)
{
    if (g_status.state != RADIO_STATE_TX) return;
    
    VFO_t vfo = g_status.current_vfo;
    
    /* Stop CTCSS */
    Audio_StopCTCSS();
    
    /* Disable microphone */
    Audio_SetMicEnabled(false);
    
    /* Disable PA and PTT */
    radio_set_ptt(false);
    radio_set_pa(false);
    
    /* Disable TX on BK4829 */
    Band_t band = g_status.active_band;
    BK4829_Instance_t instance = BK4829_INSTANCE_VHF;
#if DUAL_BAND_ENABLED
    if (band == BAND_UHF) {
        instance = BK4829_INSTANCE_UHF;
    }
#endif
    BK4829_EnableTX(instance, false);
    
    /* Restore RX frequency */
    BK4829_SetFrequency(instance, g_status.vfo[vfo].frequency);
    
    g_status.state = RADIO_STATE_IDLE;
    g_status.ptt_pressed = false;
    
    Audio_PlayBeep(BEEP_TX_END);
}

bool Radio_IsTX(void)
{
    return g_status.state == RADIO_STATE_TX;
}

void Radio_StartScan(ScanType_t type)
{
    g_status.scan_type = type;
    g_status.state = RADIO_STATE_SCAN;
}

void Radio_StopScan(void)
{
    g_status.scan_type = SCAN_NONE;
    g_status.state = RADIO_STATE_IDLE;
}

bool Radio_IsScanning(void)
{
    return g_status.scan_type != SCAN_NONE;
}

void Radio_SetPower(PowerLevel_t power)
{
    g_status.vfo[g_status.current_vfo].power = power;
    
    /* Update BK4829 power register */
    uint16_t power_reg;
    switch (power) {
        case POWER_LOW:
            power_reg = 0x0000;
            break;
        case POWER_MID:
            power_reg = 0x0800;
            break;
        case POWER_HIGH:
        default:
            power_reg = 0x1000;
            break;
    }
    
    BK4829_WriteReg(BK4829_INSTANCE_VHF, 0x36, power_reg);
#if BK4829_INSTANCE_COUNT > 1
    BK4829_WriteReg(BK4829_INSTANCE_UHF, 0x36, power_reg);
#endif
}

void Radio_SetSquelch(uint8_t level)
{
    if (level > 9) level = 9;
    g_status.vfo[g_status.current_vfo].squelch_level = level;
    
    /* Configure squelch threshold on BK4829 */
    uint16_t sq_reg = 0x5400 | (level << 8);
    BK4829_WriteReg(BK4829_INSTANCE_VHF, 0x78, sq_reg);
#if BK4829_INSTANCE_COUNT > 1
    BK4829_WriteReg(BK4829_INSTANCE_UHF, 0x78, sq_reg);
#endif
}

void Radio_SetCTCSS(uint16_t rx_tone, uint16_t tx_tone)
{
    VFO_t vfo = g_status.current_vfo;
    g_status.vfo[vfo].rx_ctcss = rx_tone;
    g_status.vfo[vfo].tx_ctcss = tx_tone;
}

void Radio_SetDCS(uint16_t rx_code, uint16_t tx_code, bool rx_inv, bool tx_inv)
{
    VFO_t vfo = g_status.current_vfo;
    g_status.vfo[vfo].rx_dcs = rx_code;
    g_status.vfo[vfo].tx_dcs = tx_code;
    g_status.vfo[vfo].rx_dcs_inverted = rx_inv;
    g_status.vfo[vfo].tx_dcs_inverted = tx_inv;
}

int16_t Radio_GetRSSI(void)
{
    return g_status.rssi;
}

bool Radio_IsSquelchOpen(void)
{
    return g_status.squelch_open;
}

void Radio_SetModulation(Modulation_t mod)
{
    g_status.vfo[g_status.current_vfo].modulation = mod;
}

void Radio_SetBandwidth(bool wide)
{
    g_status.vfo[g_status.current_vfo].wide_bandwidth = wide;
}

void Radio_SetOffset(uint32_t offset, int8_t direction)
{
    VFO_t vfo = g_status.current_vfo;
    g_status.vfo[vfo].tx_offset = offset;
    g_status.vfo[vfo].tx_offset_dir = direction;
}
