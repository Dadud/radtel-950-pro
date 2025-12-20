/**
 * @file power.h
 * @brief Power Management Driver
 * 
 * Handles power control, battery monitoring, and power states.
 * 
 * Hardware connections (INFERRED from OEM firmware):
 *   - Power switch input: PE0 [CONFIRMED]
 *   - Power latch output: PA11 [HIGH confidence]
 *   - Battery sense ADC: PA1 (ADC2 CH1) [CONFIRMED]
 *   - Charger detect: Unknown
 */

#ifndef DRIVERS_POWER_H
#define DRIVERS_POWER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * POWER CONFIGURATION
 * ============================================================================ */

/* Battery voltage thresholds in mV (INFERRED - needs calibration) */
#define BATTERY_FULL_MV         8400    /* 2S LiPo full */
#define BATTERY_NOMINAL_MV      7400    /* Nominal voltage */
#define BATTERY_LOW_MV          7000    /* Low battery warning */
#define BATTERY_CRITICAL_MV     6600    /* Critical - shutdown */
#define BATTERY_EMPTY_MV        6000    /* Empty cell voltage */

/* ADC configuration */
#define BATTERY_ADC_VREF_MV     3300    /* ADC reference voltage */
#define BATTERY_ADC_RESOLUTION  4096    /* 12-bit ADC */
#define BATTERY_DIVIDER_RATIO   3       /* Voltage divider ratio (INFERRED) */

/* ============================================================================
 * POWER STATE ENUMERATION
 * ============================================================================ */

typedef enum {
    POWER_STATE_OFF = 0,        /* Power off */
    POWER_STATE_STARTING,       /* Power on sequence */
    POWER_STATE_RUNNING,        /* Normal operation */
    POWER_STATE_LOW_BATTERY,    /* Low battery mode */
    POWER_STATE_CHARGING,       /* Charging (if detected) */
    POWER_STATE_SHUTDOWN        /* Shutdown sequence */
} PowerState_t;

/* ============================================================================
 * BATTERY STATUS STRUCTURE
 * ============================================================================ */

typedef struct {
    uint16_t voltage_mv;        /* Battery voltage in mV */
    uint8_t percent;            /* Battery percentage (0-100) */
    bool is_low;                /* Low battery warning */
    bool is_critical;           /* Critical battery level */
    bool is_charging;           /* Charging detected */
} BatteryStatus_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize power management
 * 
 * Configures power control pins and ADC for battery monitoring.
 */
void Power_Init(void);

/**
 * @brief Assert power latch (keep power on)
 * 
 * Must be called early in startup to prevent power-off.
 * INFERRED: Power latch on PA11
 */
void Power_HoldLatch(void);

/**
 * @brief Release power latch (allow power off)
 * 
 * Called during shutdown to allow power to turn off.
 */
void Power_ReleaseLatch(void);

/**
 * @brief Check if power button is pressed
 * @return true if power button is held
 */
bool Power_IsButtonPressed(void);

/**
 * @brief Check if shutdown was requested
 * @return true if shutdown should proceed
 * 
 * Shutdown is requested by holding power button for ~2 seconds.
 */
bool Power_IsShutdownRequested(void);

/**
 * @brief Get current power state
 * @return Current power state
 */
PowerState_t Power_GetState(void);

/**
 * @brief Get battery status
 * @return Pointer to battery status structure
 */
const BatteryStatus_t *Power_GetBatteryStatus(void);

/**
 * @brief Read battery voltage
 * @return Battery voltage in mV
 * 
 * CONFIRMED: Uses ADC2 CH1 (PA1) from FUN_80013cd4
 */
uint16_t Power_ReadBatteryVoltage(void);

/**
 * @brief Calculate battery percentage
 * @param voltage_mv Battery voltage in mV
 * @return Percentage (0-100)
 */
uint8_t Power_CalculatePercent(uint16_t voltage_mv);

/**
 * @brief Process power management (call from main loop)
 * 
 * Monitors battery, power button, and handles state transitions.
 */
void Power_Process(void);

/**
 * @brief Request system shutdown
 */
void Power_RequestShutdown(void);

/**
 * @brief Enter low-power sleep mode
 * 
 * Reduces power consumption while maintaining wake capability.
 */
void Power_EnterSleep(void);

/**
 * @brief Enter deep sleep mode
 * 
 * Minimal power consumption, only wakes on specific events.
 */
void Power_EnterDeepSleep(void);

/**
 * @brief Set auto power-off timeout
 * @param minutes Timeout in minutes (0 = disabled)
 */
void Power_SetAutoOff(uint8_t minutes);

/**
 * @brief Reset auto power-off timer
 * 
 * Call when user activity is detected.
 */
void Power_ResetAutoOffTimer(void);

#ifdef __cplusplus
}
#endif

#endif /* DRIVERS_POWER_H */


