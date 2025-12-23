/**
 * @file main.c
 * @brief Radtel RT-950 Pro - Clean-room firmware re-implementation
 * 
 * This is a clean-room re-implementation based on reverse-engineering
 * of the original OEM firmware. All behavior is INFERRED from binary
 * analysis and documented accordingly.
 * 
 * Target: Artery AT32F403ARGT7 (Cortex-M4F @ 240MHz)
 * 
 * Hardware configuration (INFERRED):
 *   - 1MB Flash @ 0x08000000
 *   - 96KB SRAM @ 0x20000000
 *   - External SPI Flash for settings/channels
 *   - 320x240 TFT LCD (8080 parallel interface)
 *   - Dual BK4829 RF transceivers
 *   - SI4732 FM/AM broadcast receiver
 *   - GPS module (NMEA over UART)
 *   - Bluetooth module (AT command set)
 * 
 * @note This file is part of a clean-room reverse engineering effort.
 *       All code is original and does NOT contain proprietary source.
 */

#include "hal/system.h"
#include "hal/gpio.h"
#include "hal/spi.h"
#include "hal/uart.h"
#include "hal/adc.h"
#include "hal/dac.h"
#include "hal/dma.h"
#include "hal/timer.h"

#include "drivers/lcd.h"
#include "drivers/keypad.h"
#include "drivers/encoder.h"
#include "drivers/bk4829.h"
#include "drivers/si4732.h"
#include "drivers/spi_flash.h"
#include "drivers/audio.h"
#include "drivers/power.h"

#include "radio/radio.h"
#include "radio/channel.h"
#include "radio/vfo.h"

#include "ui/ui.h"
#include "ui/menu.h"
#include "ui/display.h"

#include "protocols/cdc_protocol.h"
#include "protocols/bluetooth.h"
#include "protocols/gps.h"

#include "config/settings.h"
#include "config/eeprom.h"

/* System tick counter (1ms resolution) */
volatile uint32_t g_systick_ms = 0;

/**
 * @brief SysTick interrupt handler - called every 1ms
 */
void SysTick_Handler(void)
{
    g_systick_ms++;
}

/**
 * @brief Get current system tick in milliseconds
 * @return Current millisecond count since boot
 */
uint32_t HAL_GetTick(void)
{
    return g_systick_ms;
}

/**
 * @brief Delay for specified milliseconds
 * @param ms Number of milliseconds to delay
 */
void HAL_Delay(uint32_t ms)
{
    uint32_t start = g_systick_ms;
    while ((g_systick_ms - start) < ms) {
        __WFI();  /* Wait for interrupt - saves power */
    }
}

/**
 * @brief Initialize all system hardware
 * 
 * Initialization order is CRITICAL - derived from OEM firmware analysis:
 * 1. Clock configuration (240MHz from internal oscillator)
 * 2. GPIO port clocks and basic pin setup
 * 3. Power management (hold power latch)
 * 4. Display (provides user feedback)
 * 5. Keypad (user input)
 * 6. SPI Flash (settings storage)
 * 7. Load settings from flash
 * 8. RF transceivers
 * 9. Audio subsystem
 * 10. GPS/Bluetooth peripherals
 */
static void System_Init(void)
{
    /* Configure system clocks - INFERRED: 240MHz from HICK + PLL */
    HAL_System_ClockConfig();
    
    /* Enable GPIO port clocks */
    HAL_GPIO_ClockEnable(GPIO_PORT_A);
    HAL_GPIO_ClockEnable(GPIO_PORT_B);
    HAL_GPIO_ClockEnable(GPIO_PORT_C);
    HAL_GPIO_ClockEnable(GPIO_PORT_D);
    HAL_GPIO_ClockEnable(GPIO_PORT_E);
    
    /* Initialize power management - CRITICAL: hold power latch first */
    Power_Init();
    Power_HoldLatch();
    
    /* Configure SysTick for 1ms interrupts */
    HAL_Timer_SysTickConfig(1000);
    
    /* Small delay for power stabilization */
    HAL_Delay(50);
    
    /* Initialize display subsystem */
    LCD_Init();
    LCD_BacklightOn();
    Display_ShowBootScreen();
    
    /* Initialize input devices */
    Keypad_Init();
    Encoder_Init();
    
    /* Initialize SPI flash for settings storage */
    SPIFlash_Init();
    
    /* Load saved settings from flash */
    Settings_Init();
    
    /* Initialize RF transceivers */
    BK4829_Init(BK4829_INSTANCE_VHF);  /* Primary RF - hardware SPI */
    BK4829_Init(BK4829_INSTANCE_UHF);  /* Secondary RF - software SPI */
    
    /* Initialize broadcast receiver */
    SI4732_Init();
    
    /* Initialize audio subsystem */
    Audio_Init();
    
    /* Initialize communication interfaces */
    GPS_Init();
    BT_Init();
    CDC_Init();
    
    /* Initialize radio state machine */
    Radio_Init();
    
    /* Initialize user interface */
    UI_Init();
}

/**
 * @brief Main application entry point
 */
int main(void)
{
    /* Full system initialization */
    System_Init();
    
    /* Display boot complete */
    Display_ShowStatus("Ready");
    HAL_Delay(500);
    
    /* Main application loop */
    while (1) {
        /* Process keypad input */
        Keypad_Process();
        
        /* Process rotary encoder */
        Encoder_Process();
        
        /* Process radio state machine */
        Radio_Process();
        
        /* Update user interface */
        UI_Process();
        
        /* Process GPS data if available */
        GPS_Process();
        
        /* Process Bluetooth commands */
        BT_Process();
        
        /* Process CDC/USB commands */
        CDC_Process();
        
        /* Flush display buffer if needed */
        Display_Update();
        
        /* Power management - check for shutdown request */
        if (Power_IsShutdownRequested()) {
            /* Save settings before shutdown */
            Settings_Save();
            
            /* Show shutdown screen */
            Display_ShowShutdownScreen();
            HAL_Delay(1000);
            
            /* Release power latch - radio will power off */
            Power_ReleaseLatch();
            
            /* Wait for power to drop */
            while (1) {
                __WFI();
            }
        }
    }
    
    return 0;  /* Never reached */
}



