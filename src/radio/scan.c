/**
 * @file scan.c
 * @brief Scanning Functionality Implementation
 * 
 * Provides frequency and channel scanning modes.
 */

#include "radio/scan.h"
#include "radio/radio.h"
#include "radio/vfo.h"
#include "radio/channel.h"
#include "hal/system.h"

/* Scan state */
static struct {
    bool initialized;
    bool active;
    ScanMode_t mode;
    ScanDirection_t direction;
    
    /* Timing */
    uint32_t scan_speed_ms;
    uint32_t hold_time_ms;
    uint32_t last_step_time;
    uint32_t hold_start_time;
    
    /* State */
    bool holding;
    uint32_t start_freq;
    uint32_t end_freq;
    uint16_t current_channel;
    
    /* Callback */
    Scan_Callback_t callback;
} g_scan;

#define DEFAULT_SCAN_SPEED_MS   100
#define DEFAULT_HOLD_TIME_MS    2000

void Scan_Init(void)
{
    g_scan.initialized = true;
    g_scan.active = false;
    g_scan.mode = SCAN_MODE_VFO;
    g_scan.direction = SCAN_DIR_UP;
    g_scan.scan_speed_ms = DEFAULT_SCAN_SPEED_MS;
    g_scan.hold_time_ms = DEFAULT_HOLD_TIME_MS;
    g_scan.holding = false;
    g_scan.callback = NULL;
}

void Scan_Start(ScanMode_t mode)
{
    if (g_scan.active) return;
    
    g_scan.mode = mode;
    g_scan.active = true;
    g_scan.holding = false;
    g_scan.last_step_time = HAL_GetTick();
    
    if (mode == SCAN_MODE_VFO) {
        g_scan.start_freq = VFO_GetFrequency();
    } else {
        Channel_GetCurrent(NULL, &g_scan.current_channel);
    }
    
    if (g_scan.callback) {
        g_scan.callback(SCAN_EVENT_START);
    }
}

void Scan_Stop(void)
{
    if (!g_scan.active) return;
    
    g_scan.active = false;
    g_scan.holding = false;
    
    if (g_scan.callback) {
        g_scan.callback(SCAN_EVENT_STOP);
    }
}

bool Scan_IsActive(void)
{
    return g_scan.active;
}

void Scan_SetDirection(ScanDirection_t direction)
{
    g_scan.direction = direction;
}

ScanDirection_t Scan_GetDirection(void)
{
    return g_scan.direction;
}

void Scan_SetSpeed(uint32_t ms_per_step)
{
    g_scan.scan_speed_ms = ms_per_step;
}

void Scan_SetHoldTime(uint32_t ms)
{
    g_scan.hold_time_ms = ms;
}

void Scan_SetCallback(Scan_Callback_t callback)
{
    g_scan.callback = callback;
}

void Scan_Process(void)
{
    if (!g_scan.active) return;
    
    uint32_t now = HAL_GetTick();
    
    /* Check if holding on signal */
    if (g_scan.holding) {
        if (!Radio_IsSquelchOpen()) {
            /* Signal gone, resume scanning after hold time */
            if ((now - g_scan.hold_start_time) >= g_scan.hold_time_ms) {
                g_scan.holding = false;
                if (g_scan.callback) {
                    g_scan.callback(SCAN_EVENT_RESUME);
                }
            }
        } else {
            /* Still have signal, reset hold timer */
            g_scan.hold_start_time = now;
        }
        return;
    }
    
    /* Time for next step? */
    if ((now - g_scan.last_step_time) < g_scan.scan_speed_ms) {
        return;
    }
    
    g_scan.last_step_time = now;
    
    /* Step to next frequency/channel */
    if (g_scan.mode == SCAN_MODE_VFO) {
        if (g_scan.direction == SCAN_DIR_UP) {
            VFO_StepUp();
        } else {
            VFO_StepDown();
        }
    } else {
        if (g_scan.direction == SCAN_DIR_UP) {
            Channel_Next();
        } else {
            Channel_Prev();
        }
    }
    
    /* Check for signal */
    if (Radio_IsSquelchOpen()) {
        g_scan.holding = true;
        g_scan.hold_start_time = now;
        
        if (g_scan.callback) {
            g_scan.callback(SCAN_EVENT_HIT);
        }
    }
}

void Scan_Skip(void)
{
    if (!g_scan.active) return;
    
    /* Force move to next step */
    g_scan.holding = false;
    g_scan.last_step_time = 0;
}

void Scan_Reverse(void)
{
    if (g_scan.direction == SCAN_DIR_UP) {
        g_scan.direction = SCAN_DIR_DOWN;
    } else {
        g_scan.direction = SCAN_DIR_UP;
    }
}

