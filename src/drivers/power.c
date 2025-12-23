/**
 * @file power.c
 * @brief Power Management Driver Implementation
 * 
 * Handles power control, battery monitoring, and standby mode.
 */

#include "drivers/power.h"
#include "hal/gpio.h"
#include "hal/adc.h"
#include "hal/system.h"

/* Power state */
static struct {
    bool initialized;
    PowerState_t state;
    bool shutdown_requested;
    bool low_battery;
    uint16_t battery_mv;
    uint32_t last_battery_check;
    uint32_t last_standby_led_time;
    Power_Callback_t callback;
} g_power;

/* Battery thresholds (millivolts) - INFERRED */
#define BATTERY_LOW_MV          6800    /* Low battery warning */
#define BATTERY_CRITICAL_MV     6400    /* Force shutdown */
#define BATTERY_CHECK_INTERVAL  1000    /* Check every 1 second */
#define STANDBY_LED_INTERVAL    5000    /* LED blink every 5 seconds in standby */
#define STANDBY_LED_DURATION    100     /* LED on for 100ms */

void Power_Init(void)
{
    /* Configure power latch pin (PA11) - hold high to stay powered */
    HAL_GPIO_Config(GPIO_PORT_A, GPIO_PIN_11, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_10MHZ);
    
    /* Configure power switch input (PE0) */
    HAL_GPIO_Config(GPIO_PORT_E, GPIO_PIN_0, GPIO_MODE_INPUT_PULLUP, GPIO_SPEED_10MHZ);
    
    /* Configure LED pins */
    HAL_GPIO_Config(GPIO_PORT_C, GPIO_PIN_13, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_10MHZ);  /* Red LED */
    HAL_GPIO_Config(GPIO_PORT_C, GPIO_PIN_14, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_10MHZ);  /* Green LED */
    
    /* Turn off LEDs initially */
    GPIOC->CLR = GPIO_PIN_13 | GPIO_PIN_14;
    
    /* Initialize ADC for battery monitoring */
    HAL_ADC_Init(ADC_INSTANCE_2);
    
    g_power.initialized = true;
    g_power.state = POWER_STATE_NORMAL;
    g_power.shutdown_requested = false;
    g_power.low_battery = false;
    g_power.battery_mv = 8400;  /* Assume full battery at start */
    g_power.last_battery_check = 0;
    g_power.last_standby_led_time = 0;
    g_power.callback = NULL;
}

void Power_HoldLatch(void)
{
    /* Hold power latch high to stay powered on */
    GPIOA->SCR = GPIO_PIN_11;
}

void Power_ReleaseLatch(void)
{
    /* Release power latch - radio will power off */
    GPIOA->CLR = GPIO_PIN_11;
}

bool Power_IsShutdownRequested(void)
{
    /* Check power button (PE0) - active low */
    static uint32_t press_start = 0;
    static bool was_pressed = false;
    
    bool pressed = !(GPIOE->IDT & GPIO_PIN_0);
    
    if (pressed && !was_pressed) {
        press_start = HAL_GetTick();
    }
    else if (pressed && was_pressed) {
        /* Check for long press (2 seconds) */
        if ((HAL_GetTick() - press_start) >= 2000) {
            g_power.shutdown_requested = true;
        }
    }
    
    was_pressed = pressed;
    
    /* Also check for critical battery */
    if (g_power.battery_mv < BATTERY_CRITICAL_MV) {
        g_power.shutdown_requested = true;
    }
    
    return g_power.shutdown_requested;
}

PowerState_t Power_GetState(void)
{
    return g_power.state;
}

void Power_SetState(PowerState_t state)
{
    if (g_power.state == state) return;
    
    PowerState_t old_state = g_power.state;
    g_power.state = state;
    
    switch (state) {
        case POWER_STATE_NORMAL:
            /* Full power mode */
            break;
            
        case POWER_STATE_STANDBY:
            /* Enter standby mode - low power with LED blink */
            g_power.last_standby_led_time = HAL_GetTick();
            break;
            
        case POWER_STATE_TX:
            /* Transmit mode - enable PA */
            Power_SetLED(POWER_LED_RED, true);
            break;
            
        case POWER_STATE_RX:
            /* Receive mode */
            Power_SetLED(POWER_LED_GREEN, true);
            break;
            
        case POWER_STATE_SHUTDOWN:
            g_power.shutdown_requested = true;
            break;
    }
    
    if (g_power.callback) {
        g_power.callback(old_state, state);
    }
}

uint16_t Power_GetBatteryMV(void)
{
    return g_power.battery_mv;
}

uint8_t Power_GetBatteryPercent(void)
{
    /* Linear approximation: 6.4V = 0%, 8.4V = 100% */
    if (g_power.battery_mv <= 6400) return 0;
    if (g_power.battery_mv >= 8400) return 100;
    
    return (uint8_t)((g_power.battery_mv - 6400) * 100 / 2000);
}

bool Power_IsLowBattery(void)
{
    return g_power.low_battery;
}

void Power_SetLED(PowerLED_t led, bool on)
{
    switch (led) {
        case POWER_LED_RED:
            if (on) {
                GPIOC->SCR = GPIO_PIN_13;
            } else {
                GPIOC->CLR = GPIO_PIN_13;
            }
            break;
            
        case POWER_LED_GREEN:
            if (on) {
                GPIOC->SCR = GPIO_PIN_14;
            } else {
                GPIOC->CLR = GPIO_PIN_14;
            }
            break;
            
        case POWER_LED_BOTH:
            if (on) {
                GPIOC->SCR = GPIO_PIN_13 | GPIO_PIN_14;
            } else {
                GPIOC->CLR = GPIO_PIN_13 | GPIO_PIN_14;
            }
            break;
    }
}

void Power_SetCallback(Power_Callback_t callback)
{
    g_power.callback = callback;
}

void Power_EnterStandby(void)
{
    Power_SetState(POWER_STATE_STANDBY);
}

void Power_ExitStandby(void)
{
    Power_SetState(POWER_STATE_NORMAL);
}

void Power_ProcessStandbyLED(void)
{
    if (g_power.state != POWER_STATE_STANDBY) return;
    
    uint32_t now = HAL_GetTick();
    uint32_t elapsed = now - g_power.last_standby_led_time;
    
    if (elapsed >= STANDBY_LED_INTERVAL) {
        /* Turn on green LED */
        Power_SetLED(POWER_LED_GREEN, true);
        g_power.last_standby_led_time = now;
    }
    else if (elapsed >= STANDBY_LED_DURATION) {
        /* Turn off LED after duration */
        Power_SetLED(POWER_LED_GREEN, false);
    }
}

void Power_Process(void)
{
    uint32_t now = HAL_GetTick();
    
    /* Check battery periodically */
    if ((now - g_power.last_battery_check) >= BATTERY_CHECK_INTERVAL) {
        g_power.last_battery_check = now;
        g_power.battery_mv = HAL_ADC_ReadBatteryMV();
        
        bool was_low = g_power.low_battery;
        g_power.low_battery = (g_power.battery_mv < BATTERY_LOW_MV);
        
        /* Flash red LED on low battery */
        if (g_power.low_battery && !was_low) {
            Power_SetLED(POWER_LED_RED, true);
        }
    }
    
    /* Process standby LED blink */
    Power_ProcessStandbyLED();
    
    /* Check for shutdown request */
    Power_IsShutdownRequested();
}

void Power_Shutdown(void)
{
    g_power.shutdown_requested = true;
    g_power.state = POWER_STATE_SHUTDOWN;
}

bool Power_IsButtonPressed(void)
{
    return !(GPIOE->IDT & GPIO_PIN_0);
}

const BatteryStatus_t *Power_GetBatteryStatus(void)
{
    static BatteryStatus_t status;
    status.voltage_mv = g_power.battery_mv;
    status.percent = Power_GetBatteryPercent();
    status.is_low = g_power.low_battery;
    status.is_critical = (g_power.battery_mv < BATTERY_CRITICAL_MV);
    status.is_charging = false;  /* No charger detection implemented */
    return &status;
}

uint16_t Power_ReadBatteryVoltage(void)
{
    return HAL_ADC_ReadBatteryMV();
}

uint8_t Power_CalculatePercent(uint16_t voltage_mv)
{
    if (voltage_mv <= 6400) return 0;
    if (voltage_mv >= 8400) return 100;
    return (uint8_t)((voltage_mv - 6400) * 100 / 2000);
}

void Power_RequestShutdown(void)
{
    g_power.shutdown_requested = true;
}

void Power_EnterSleep(void)
{
    HAL_System_Sleep();
}

void Power_EnterDeepSleep(void)
{
    /* Enter low-power mode */
    HAL_System_Sleep();
}

void Power_SetAutoOff(uint8_t minutes)
{
    (void)minutes;
    /* TODO: Implement auto power-off timer */
}

void Power_ResetAutoOffTimer(void)
{
    /* TODO: Reset auto power-off timer */
}

