/**
 * @file settings.h
 * @brief Settings Management
 */

#ifndef CONFIG_SETTINGS_H
#define CONFIG_SETTINGS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Display settings */
typedef struct {
    uint8_t brightness;
    uint8_t contrast;
    uint8_t timeout_sec;
    uint8_t color_scheme;
    bool show_battery;
    bool show_clock;
} DisplaySettings_t;

/* Audio settings */
typedef struct {
    uint8_t volume;
    bool beep_enabled;
    uint8_t beep_volume;
    bool vox_enabled;
    uint8_t vox_level;
    uint16_t vox_delay_ms;
} AudioSettings_t;

/* Radio settings */
typedef struct {
    uint8_t squelch;
    uint8_t tx_power;
    uint8_t tot_minutes;
    uint32_t vfo_a_freq;
    uint32_t vfo_b_freq;
    uint32_t step_hz;
    int32_t offset_hz;
} RadioSettings_t;

/* System settings */
typedef struct {
    uint8_t auto_off_minutes;
    bool key_lock;
    bool gps_enabled;
    bool bluetooth_enabled;
    uint8_t language;
} SystemSettings_t;

/* Calibration data */
typedef struct {
    uint8_t vhf_tx_gain;
    uint8_t uhf_tx_gain;
    int16_t battery_offset;
} CalibrationSettings_t;

/* Complete settings structure */
typedef struct {
    uint32_t magic;
    uint8_t version;
    DisplaySettings_t display;
    AudioSettings_t audio;
    RadioSettings_t radio;
    SystemSettings_t system;
    CalibrationSettings_t calibration;
} Settings_t;

void Settings_Init(void);
bool Settings_Load(void);
bool Settings_Save(void);
void Settings_Reset(void);
const Settings_t *Settings_Get(void);
void Settings_Set(const Settings_t *settings);
bool Settings_IsModified(void);

/* Individual setting accessors */
uint8_t Settings_GetVolume(void);
void Settings_SetVolume(uint8_t volume);
uint8_t Settings_GetSquelch(void);
void Settings_SetSquelch(uint8_t squelch);
uint8_t Settings_GetBrightness(void);
void Settings_SetBrightness(uint8_t brightness);
uint8_t Settings_GetTXPower(void);
void Settings_SetTXPower(uint8_t power);
bool Settings_GetBeepEnabled(void);
void Settings_SetBeepEnabled(bool enabled);
uint32_t Settings_GetVFOAFreq(void);
void Settings_SetVFOAFreq(uint32_t freq);
uint32_t Settings_GetVFOBFreq(void);
void Settings_SetVFOBFreq(uint32_t freq);
uint32_t Settings_GetStep(void);
void Settings_SetStep(uint32_t step);
bool Settings_GetGPSEnabled(void);
void Settings_SetGPSEnabled(bool enabled);
bool Settings_GetBluetoothEnabled(void);
void Settings_SetBluetoothEnabled(bool enabled);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_SETTINGS_H */
