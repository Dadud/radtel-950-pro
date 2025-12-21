/**
 * @file system.h
 * @brief System initialization and core HAL functions
 * 
 * Provides clock configuration, basic timing, and system services
 * for the AT32F403A microcontroller.
 * 
 * Hardware: AT32F403ARGT7 (Cortex-M4F)
 * Clock: 240MHz from internal 8MHz oscillator with PLL
 */

#ifndef HAL_SYSTEM_H
#define HAL_SYSTEM_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * MEMORY MAP - AT32F403A (CONFIRMED from datasheet)
 * ============================================================================ */

/* Flash memory */
#define FLASH_BASE          0x08000000UL
#define FLASH_SIZE          (1024 * 1024)   /* 1MB */

/* SRAM */
#define SRAM_BASE           0x20000000UL
#define SRAM_SIZE           (96 * 1024)     /* 96KB */

/* Peripheral base addresses */
#define PERIPH_BASE         0x40000000UL
#define APB1_BASE           (PERIPH_BASE + 0x00000000UL)
#define APB2_BASE           (PERIPH_BASE + 0x00010000UL)
#define AHB_BASE            (PERIPH_BASE + 0x00018000UL)

/* ============================================================================
 * SYSTEM CLOCK CONFIGURATION (INFERRED from OEM firmware)
 * ============================================================================ */

/**
 * Clock tree (INFERRED):
 *   HICK (8MHz internal) -> PLL (x60) -> SCLK (240MHz)
 *   SCLK (240MHz) -> AHB (240MHz) -> APB1 (120MHz, /2)
 *                                 -> APB2 (120MHz, /2)
 */

#define SYSTEM_CLOCK_HZ     240000000UL     /* 240 MHz */
#define AHB_CLOCK_HZ        240000000UL     /* 240 MHz */
#define APB1_CLOCK_HZ       120000000UL     /* 120 MHz */
#define APB2_CLOCK_HZ       120000000UL     /* 120 MHz */

/* ============================================================================
 * CRM (Clock and Reset Management) REGISTERS
 * ============================================================================ */

#define CRM_BASE            (AHB_BASE + 0x00009000UL)

/* CRM register offsets */
#define CRM_CTRL            (*(volatile uint32_t *)(CRM_BASE + 0x00))
#define CRM_CFG             (*(volatile uint32_t *)(CRM_BASE + 0x04))
#define CRM_CLKINT          (*(volatile uint32_t *)(CRM_BASE + 0x08))
#define CRM_APB2RST         (*(volatile uint32_t *)(CRM_BASE + 0x0C))
#define CRM_APB1RST         (*(volatile uint32_t *)(CRM_BASE + 0x10))
#define CRM_AHBEN           (*(volatile uint32_t *)(CRM_BASE + 0x14))
#define CRM_APB2EN          (*(volatile uint32_t *)(CRM_BASE + 0x18))
#define CRM_APB1EN          (*(volatile uint32_t *)(CRM_BASE + 0x1C))
#define CRM_BPDC            (*(volatile uint32_t *)(CRM_BASE + 0x20))
#define CRM_CTRLSTS         (*(volatile uint32_t *)(CRM_BASE + 0x24))
#define CRM_MISC1           (*(volatile uint32_t *)(CRM_BASE + 0x30))

/* CRM_CTRL bits */
#define CRM_CTRL_HICKEN     (1 << 0)        /* HICK enable */
#define CRM_CTRL_HICKSTBL   (1 << 1)        /* HICK stable */
#define CRM_CTRL_HICKTRIM   (0x3F << 2)     /* HICK trim */
#define CRM_CTRL_HEXTEN     (1 << 16)       /* HEXT enable */
#define CRM_CTRL_HEXTSTBL   (1 << 17)       /* HEXT stable */
#define CRM_CTRL_HEXTBYPS   (1 << 18)       /* HEXT bypass */
#define CRM_CTRL_CFDEN      (1 << 19)       /* Clock failure detect */
#define CRM_CTRL_PLLEN      (1 << 24)       /* PLL enable */
#define CRM_CTRL_PLLSTBL    (1 << 25)       /* PLL stable */

/* CRM_CFG bits */
#define CRM_CFG_SCLKSEL     (0x03 << 0)     /* System clock select */
#define CRM_CFG_SCLKSTS     (0x03 << 2)     /* System clock status */
#define CRM_CFG_AHBDIV      (0x0F << 4)     /* AHB divider */
#define CRM_CFG_APB1DIV     (0x07 << 8)     /* APB1 divider */
#define CRM_CFG_APB2DIV     (0x07 << 11)    /* APB2 divider */
#define CRM_CFG_PLLRCS      (1 << 16)       /* PLL reference clock */
#define CRM_CFG_PLLHEXTDIV  (1 << 17)       /* PLL HEXT divider */
#define CRM_CFG_PLLMULT_L   (0x0F << 18)    /* PLL multiplier low bits */
#define CRM_CFG_USBDIV      (0x03 << 22)    /* USB divider */
#define CRM_CFG_PLLMULT_H   (0x03 << 29)    /* PLL multiplier high bits */

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Configure system clocks
 * 
 * Sets up the PLL to generate 240MHz from the internal 8MHz oscillator.
 * INFERRED: OEM firmware uses HICK -> PLL x60 -> 240MHz configuration.
 */
void HAL_System_ClockConfig(void);

/**
 * @brief Get current system tick (1ms resolution)
 * @return Current tick count in milliseconds
 */
uint32_t HAL_GetTick(void);

/**
 * @brief Delay for specified milliseconds
 * @param ms Delay in milliseconds
 */
void HAL_Delay(uint32_t ms);

/**
 * @brief Delay for specified microseconds
 * @param us Delay in microseconds
 * 
 * @note For short delays, this uses cycle counting. For longer delays,
 *       it uses the SysTick counter.
 */
void HAL_DelayUs(uint32_t us);

/**
 * @brief Configure SysTick timer
 * @param ticks_per_second Desired interrupt rate (e.g., 1000 for 1ms)
 */
void HAL_Timer_SysTickConfig(uint32_t ticks_per_second);

/**
 * @brief Perform system reset
 */
void HAL_System_Reset(void);

/**
 * @brief Enter low-power sleep mode
 * 
 * The CPU will sleep until an interrupt occurs.
 */
void HAL_System_Sleep(void);

/**
 * @brief Get system clock frequency
 * @return System clock in Hz
 */
uint32_t HAL_System_GetSysClockHz(void);

/**
 * @brief Get AHB clock frequency
 * @return AHB clock in Hz
 */
uint32_t HAL_System_GetAHBClockHz(void);

/**
 * @brief Get APB1 clock frequency
 * @return APB1 clock in Hz
 */
uint32_t HAL_System_GetAPB1ClockHz(void);

/**
 * @brief Get APB2 clock frequency
 * @return APB2 clock in Hz
 */
uint32_t HAL_System_GetAPB2ClockHz(void);

#ifdef __cplusplus
}
#endif

#endif /* HAL_SYSTEM_H */



