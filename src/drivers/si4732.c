/**
 * @file si4732.c
 * @brief SI4732 FM/AM/SW Receiver Driver Implementation
 * 
 * Driver for the SI4732 broadcast receiver chip.
 * Connected via I2C on PB6 (SCL) and PB7 (SDA).
 */

#include "drivers/si4732.h"
#include "hal/i2c.h"
#include "hal/gpio.h"
#include "hal/system.h"

/* Reset pin - INFERRED: PA6 */
#define SI4732_RESET_PORT   GPIOA
#define SI4732_RESET_PIN    GPIO_PIN_6

/* Driver state */
static struct {
    bool initialized;
    bool powered_on;
    SI4732_Mode_t current_mode;
    uint32_t current_freq_hz;
    uint8_t volume;
    bool muted;
    bool stereo_enabled;
    SI4732_Status_t status;
    SI4732_RDS_t rds;
} g_si4732;

static bool si4732_wait_cts(uint32_t timeout_ms)
{
    uint32_t start = HAL_GetTick();
    uint8_t status;
    
    while ((HAL_GetTick() - start) < timeout_ms) {
        if (HAL_I2C_Read(I2C_INSTANCE_SW, SI4732_I2C_ADDR, &status, 1)) {
            if (status & SI4732_STATUS_CTS) {
                return true;
            }
        }
        HAL_Delay(1);
    }
    
    return false;
}

void SI4732_WriteCommand(const uint8_t *cmd, uint8_t len)
{
    HAL_I2C_Write(I2C_INSTANCE_SW, SI4732_I2C_ADDR, cmd, len);
}

void SI4732_ReadResponse(uint8_t *resp, uint8_t len)
{
    HAL_I2C_Read(I2C_INSTANCE_SW, SI4732_I2C_ADDR, resp, len);
}

void SI4732_SetProperty(uint16_t property, uint16_t value)
{
    uint8_t cmd[6] = {
        SI4732_CMD_SET_PROPERTY,
        0x00,
        (uint8_t)(property >> 8),
        (uint8_t)(property & 0xFF),
        (uint8_t)(value >> 8),
        (uint8_t)(value & 0xFF)
    };
    
    SI4732_WriteCommand(cmd, 6);
    si4732_wait_cts(100);
}

uint16_t SI4732_GetProperty(uint16_t property)
{
    uint8_t cmd[4] = {
        SI4732_CMD_GET_PROPERTY,
        0x00,
        (uint8_t)(property >> 8),
        (uint8_t)(property & 0xFF)
    };
    
    SI4732_WriteCommand(cmd, 4);
    if (!si4732_wait_cts(100)) return 0;
    
    uint8_t resp[4];
    SI4732_ReadResponse(resp, 4);
    
    return ((uint16_t)resp[2] << 8) | resp[3];
}

void SI4732_Init(void)
{
    /* Initialize I2C */
    HAL_I2C_SW_Init();
    
    /* Configure reset pin */
    HAL_GPIO_Config(GPIO_PORT_A, GPIO_PIN_6, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_10MHZ);
    
    /* Reset sequence */
    SI4732_RESET_PORT->CLR = SI4732_RESET_PIN;
    HAL_Delay(10);
    SI4732_RESET_PORT->SCR = SI4732_RESET_PIN;
    HAL_Delay(10);
    
    /* Initialize state */
    g_si4732.initialized = true;
    g_si4732.powered_on = false;
    g_si4732.current_mode = SI4732_MODE_FM;
    g_si4732.current_freq_hz = 87500000;  /* 87.5 MHz default */
    g_si4732.volume = 50;
    g_si4732.muted = false;
    g_si4732.stereo_enabled = true;
    
    /* Clear RDS data */
    for (int i = 0; i < 9; i++) g_si4732.rds.program_service[i] = 0;
    for (int i = 0; i < 65; i++) g_si4732.rds.radio_text[i] = 0;
    g_si4732.rds.valid = false;
}

void SI4732_PowerUp(SI4732_Mode_t mode)
{
    if (!g_si4732.initialized) return;
    
    uint8_t cmd[3];
    
    cmd[0] = SI4732_CMD_POWER_UP;
    
    switch (mode) {
        case SI4732_MODE_FM:
            cmd[1] = 0x00;  /* FM receive */
            break;
        case SI4732_MODE_AM:
        case SI4732_MODE_SW:
            cmd[1] = 0x01;  /* AM receive */
            break;
        default:
            return;
    }
    
    cmd[2] = 0x05;  /* Analog audio output */
    
    SI4732_WriteCommand(cmd, 3);
    if (!si4732_wait_cts(500)) return;
    
    g_si4732.powered_on = true;
    g_si4732.current_mode = mode;
    
    /* Set default properties */
    SI4732_SetProperty(SI4732_PROP_RX_VOLUME, g_si4732.volume);
    
    if (mode == SI4732_MODE_FM) {
        /* 50us de-emphasis for most regions */
        SI4732_SetProperty(SI4732_PROP_FM_DEEMPHASIS, 1);
    }
}

void SI4732_PowerDown(void)
{
    if (!g_si4732.powered_on) return;
    
    uint8_t cmd = SI4732_CMD_POWER_DOWN;
    SI4732_WriteCommand(&cmd, 1);
    si4732_wait_cts(100);
    
    g_si4732.powered_on = false;
}

bool SI4732_IsPowered(void)
{
    return g_si4732.powered_on;
}

bool SI4732_SetFrequency(uint32_t frequency_hz)
{
    if (!g_si4732.powered_on) return false;
    
    uint8_t cmd[5];
    uint32_t freq_unit;
    
    switch (g_si4732.current_mode) {
        case SI4732_MODE_FM:
            /* FM frequency in 10kHz units */
            freq_unit = frequency_hz / 10000;
            cmd[0] = SI4732_CMD_FM_TUNE_FREQ;
            cmd[1] = 0x00;
            cmd[2] = (uint8_t)(freq_unit >> 8);
            cmd[3] = (uint8_t)(freq_unit & 0xFF);
            cmd[4] = 0x00;
            break;
            
        case SI4732_MODE_AM:
        case SI4732_MODE_SW:
            /* AM frequency in 1kHz units */
            freq_unit = frequency_hz / 1000;
            cmd[0] = SI4732_CMD_AM_TUNE_FREQ;
            cmd[1] = 0x00;
            cmd[2] = (uint8_t)(freq_unit >> 8);
            cmd[3] = (uint8_t)(freq_unit & 0xFF);
            cmd[4] = 0x00;
            break;
            
        default:
            return false;
    }
    
    SI4732_WriteCommand(cmd, 5);
    if (!si4732_wait_cts(500)) return false;
    
    g_si4732.current_freq_hz = frequency_hz;
    return true;
}

uint32_t SI4732_GetFrequency(void)
{
    return g_si4732.current_freq_hz;
}

bool SI4732_SeekUp(void)
{
    if (!g_si4732.powered_on) return false;
    
    uint8_t cmd[2];
    
    if (g_si4732.current_mode == SI4732_MODE_FM) {
        cmd[0] = SI4732_CMD_FM_SEEK_START;
    } else {
        cmd[0] = SI4732_CMD_AM_SEEK_START;
    }
    
    cmd[1] = 0x0C;  /* Seek up, wrap */
    
    SI4732_WriteCommand(cmd, 2);
    return si4732_wait_cts(5000);
}

bool SI4732_SeekDown(void)
{
    if (!g_si4732.powered_on) return false;
    
    uint8_t cmd[2];
    
    if (g_si4732.current_mode == SI4732_MODE_FM) {
        cmd[0] = SI4732_CMD_FM_SEEK_START;
    } else {
        cmd[0] = SI4732_CMD_AM_SEEK_START;
    }
    
    cmd[1] = 0x04;  /* Seek down, wrap */
    
    SI4732_WriteCommand(cmd, 2);
    return si4732_wait_cts(5000);
}

void SI4732_SeekStop(void)
{
    /* Cancel seek by setting frequency */
    SI4732_SetFrequency(g_si4732.current_freq_hz);
}

void SI4732_GetStatus(SI4732_Status_t *status)
{
    if (!g_si4732.powered_on || status == NULL) return;
    
    uint8_t cmd[2];
    uint8_t resp[8];
    
    if (g_si4732.current_mode == SI4732_MODE_FM) {
        cmd[0] = SI4732_CMD_FM_RSQ_STATUS;
        cmd[1] = 0x00;
    } else {
        cmd[0] = SI4732_CMD_AM_RSQ_STATUS;
        cmd[1] = 0x00;
    }
    
    SI4732_WriteCommand(cmd, 2);
    if (!si4732_wait_cts(100)) return;
    SI4732_ReadResponse(resp, 8);
    
    status->valid = (resp[2] & 0x01) != 0;
    status->rssi = (int16_t)(int8_t)resp[4];
    status->snr = resp[5];
    status->stereo = (g_si4732.current_mode == SI4732_MODE_FM) && (resp[3] & 0x80);
    status->frequency = g_si4732.current_freq_hz;
    status->rds_ready = false;
    
    g_si4732.status = *status;
}

bool SI4732_GetRDS(SI4732_RDS_t *rds)
{
    if (rds == NULL || g_si4732.current_mode != SI4732_MODE_FM) {
        return false;
    }
    
    if (!g_si4732.powered_on) return false;
    
    uint8_t cmd[2] = { SI4732_CMD_FM_RDS_STATUS, 0x01 };
    uint8_t resp[13];
    
    SI4732_WriteCommand(cmd, 2);
    if (!si4732_wait_cts(100)) return false;
    SI4732_ReadResponse(resp, 13);
    
    if (!(resp[2] & 0x01)) {
        /* No RDS sync */
        return false;
    }
    
    /* Parse RDS blocks (simplified) */
    uint16_t block_a = ((uint16_t)resp[4] << 8) | resp[5];
    uint16_t block_b = ((uint16_t)resp[6] << 8) | resp[7];
    uint16_t block_c = ((uint16_t)resp[8] << 8) | resp[9];
    uint16_t block_d = ((uint16_t)resp[10] << 8) | resp[11];
    
    /* PI code */
    g_si4732.rds.program_id = block_a;
    
    /* PTY */
    g_si4732.rds.program_type = (block_b >> 5) & 0x1F;
    
    /* TP/TA */
    g_si4732.rds.tp = (block_b >> 10) & 0x01;
    g_si4732.rds.ta = (block_b >> 4) & 0x01;
    
    /* Group type */
    uint8_t group_type = (block_b >> 12) & 0x0F;
    
    if (group_type == 0) {
        /* Group 0: PS name */
        uint8_t offset = (block_b & 0x03) * 2;
        if (offset < 8) {
            g_si4732.rds.program_service[offset] = (block_d >> 8) & 0xFF;
            g_si4732.rds.program_service[offset + 1] = block_d & 0xFF;
        }
    }
    else if (group_type == 2) {
        /* Group 2: Radio text */
        uint8_t offset = (block_b & 0x0F) * 4;
        if (offset < 64) {
            g_si4732.rds.radio_text[offset] = (block_c >> 8) & 0xFF;
            g_si4732.rds.radio_text[offset + 1] = block_c & 0xFF;
            g_si4732.rds.radio_text[offset + 2] = (block_d >> 8) & 0xFF;
            g_si4732.rds.radio_text[offset + 3] = block_d & 0xFF;
        }
    }
    
    g_si4732.rds.valid = true;
    *rds = g_si4732.rds;
    
    return true;
}

void SI4732_SetVolume(uint8_t volume)
{
    if (volume > 63) volume = 63;
    g_si4732.volume = volume;
    
    if (g_si4732.powered_on && !g_si4732.muted) {
        SI4732_SetProperty(SI4732_PROP_RX_VOLUME, volume);
    }
}

void SI4732_SetMute(bool mute)
{
    g_si4732.muted = mute;
    
    if (g_si4732.powered_on) {
        SI4732_SetProperty(SI4732_PROP_RX_HARD_MUTE, mute ? 0x03 : 0x00);
    }
}

void SI4732_SetStereo(bool enable)
{
    g_si4732.stereo_enabled = enable;
    
    if (g_si4732.powered_on && g_si4732.current_mode == SI4732_MODE_FM) {
        /* Force mono if stereo disabled */
        SI4732_SetProperty(SI4732_PROP_FM_BLEND_RSSI, enable ? 49 : 127);
    }
}

void SI4732_SetMode(SI4732_Mode_t mode)
{
    if (mode == g_si4732.current_mode) return;
    
    uint32_t saved_freq = g_si4732.current_freq_hz;
    
    SI4732_PowerDown();
    SI4732_PowerUp(mode);
    
    /* Restore frequency if valid for new mode */
    SI4732_SetFrequency(saved_freq);
}

void SI4732_Process(void)
{
    if (!g_si4732.powered_on) return;
    
    /* Update status periodically */
    static uint32_t last_update = 0;
    uint32_t now = HAL_GetTick();
    
    if ((now - last_update) >= 100) {
        last_update = now;
        SI4732_GetStatus(&g_si4732.status);
        
        /* Process RDS if in FM mode */
        if (g_si4732.current_mode == SI4732_MODE_FM) {
            SI4732_GetRDS(&g_si4732.rds);
        }
    }
}
