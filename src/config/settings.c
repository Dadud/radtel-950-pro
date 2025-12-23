/**
 * @file settings.c
 * @brief Settings Management Implementation
 * 
 * Handles loading, saving, and managing user settings.
 */

#include "config/settings.h"
#include "config/eeprom.h"
#include "hal/system.h"

#include <string.h>

/* Settings magic number for validation */
#define SETTINGS_MAGIC      0x5254393530    /* "RT950" */
#define SETTINGS_VERSION    1

/* Current settings */
static Settings_t g_settings;
static bool g_settings_modified = false;
static bool g_settings_loaded = false;

/* Default settings */
static const Settings_t g_default_settings = {
    .magic = SETTINGS_MAGIC,
    .version = SETTINGS_VERSION,
    
    /* Display */
    .display = {
        .brightness = 50,
        .contrast = 50,
        .timeout_sec = 30,
        .color_scheme = 0,
        .show_battery = true,
        .show_clock = true
    },
    
    /* Audio */
    .audio = {
        .volume = 20,
        .beep_enabled = true,
        .beep_volume = 15,
        .vox_enabled = false,
        .vox_level = 5,
        .vox_delay_ms = 500
    },
    
    /* Radio */
    .radio = {
        .squelch = 5,
        .tx_power = 2,          /* High */
        .tot_minutes = 3,       /* 3 minute timeout */
        .vfo_a_freq = 146520000,
        .vfo_b_freq = 446000000,
        .step_hz = 25000,
        .offset_hz = 600000
    },
    
    /* System */
    .system = {
        .auto_off_minutes = 0,  /* Disabled */
        .key_lock = false,
        .gps_enabled = false,
        .bluetooth_enabled = true,
        .language = 0           /* English */
    },
    
    /* Calibration */
    .calibration = {
        .vhf_tx_gain = 50,
#if DUAL_BAND_ENABLED
        .uhf_tx_gain = 50,
#endif
        .battery_offset = 0
    }
};

void Settings_Init(void)
{
    EEPROM_Init();
    
    if (!Settings_Load()) {
        Settings_Reset();
    }
}

bool Settings_Load(void)
{
    /* Read settings from EEPROM/Flash */
    if (!EEPROM_Read(0, (uint8_t*)&g_settings, sizeof(Settings_t))) {
        return false;
    }
    
    /* Validate magic number */
    if (g_settings.magic != SETTINGS_MAGIC) {
        return false;
    }
    
    /* Check version compatibility */
    if (g_settings.version != SETTINGS_VERSION) {
        /* Could do migration here */
        return false;
    }
    
    g_settings_loaded = true;
    g_settings_modified = false;
    
    return true;
}

bool Settings_Save(void)
{
    if (!g_settings_modified) {
        return true;
    }
    
    /* Update magic and version */
    g_settings.magic = SETTINGS_MAGIC;
    g_settings.version = SETTINGS_VERSION;
    
    /* Write to EEPROM/Flash */
    if (!EEPROM_Write(0, (uint8_t*)&g_settings, sizeof(Settings_t))) {
        return false;
    }
    
    g_settings_modified = false;
    
    return true;
}

void Settings_Reset(void)
{
    memcpy(&g_settings, &g_default_settings, sizeof(Settings_t));
    g_settings_loaded = true;
    g_settings_modified = true;
}

const Settings_t *Settings_Get(void)
{
    return &g_settings;
}

void Settings_Set(const Settings_t *settings)
{
    if (settings == NULL) return;
    
    memcpy(&g_settings, settings, sizeof(Settings_t));
    g_settings_modified = true;
}

bool Settings_IsModified(void)
{
    return g_settings_modified;
}

/* Individual setting getters/setters */

uint8_t Settings_GetVolume(void)
{
    return g_settings.audio.volume;
}

void Settings_SetVolume(uint8_t volume)
{
    if (volume > 31) volume = 31;
    g_settings.audio.volume = volume;
    g_settings_modified = true;
}

uint8_t Settings_GetSquelch(void)
{
    return g_settings.radio.squelch;
}

void Settings_SetSquelch(uint8_t squelch)
{
    if (squelch > 9) squelch = 9;
    g_settings.radio.squelch = squelch;
    g_settings_modified = true;
}

uint8_t Settings_GetBrightness(void)
{
    return g_settings.display.brightness;
}

void Settings_SetBrightness(uint8_t brightness)
{
    if (brightness > 100) brightness = 100;
    g_settings.display.brightness = brightness;
    g_settings_modified = true;
}

uint8_t Settings_GetTXPower(void)
{
    return g_settings.radio.tx_power;
}

void Settings_SetTXPower(uint8_t power)
{
    if (power > 2) power = 2;
    g_settings.radio.tx_power = power;
    g_settings_modified = true;
}

bool Settings_GetBeepEnabled(void)
{
    return g_settings.audio.beep_enabled;
}

void Settings_SetBeepEnabled(bool enabled)
{
    g_settings.audio.beep_enabled = enabled;
    g_settings_modified = true;
}

uint32_t Settings_GetVFOAFreq(void)
{
    return g_settings.radio.vfo_a_freq;
}

void Settings_SetVFOAFreq(uint32_t freq)
{
    g_settings.radio.vfo_a_freq = freq;
    g_settings_modified = true;
}

uint32_t Settings_GetVFOBFreq(void)
{
    return g_settings.radio.vfo_b_freq;
}

void Settings_SetVFOBFreq(uint32_t freq)
{
    g_settings.radio.vfo_b_freq = freq;
    g_settings_modified = true;
}

uint32_t Settings_GetStep(void)
{
    return g_settings.radio.step_hz;
}

void Settings_SetStep(uint32_t step)
{
    g_settings.radio.step_hz = step;
    g_settings_modified = true;
}

bool Settings_GetGPSEnabled(void)
{
    return g_settings.system.gps_enabled;
}

void Settings_SetGPSEnabled(bool enabled)
{
    g_settings.system.gps_enabled = enabled;
    g_settings_modified = true;
}

bool Settings_GetBluetoothEnabled(void)
{
    return g_settings.system.bluetooth_enabled;
}

void Settings_SetBluetoothEnabled(bool enabled)
{
    g_settings.system.bluetooth_enabled = enabled;
    g_settings_modified = true;
}

