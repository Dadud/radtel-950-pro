/**
 * @file system.c
 * @brief System HAL Implementation
 * 
 * Implements system clock configuration and timing functions.
 * Clock tree is INFERRED from OEM firmware analysis.
 */

#include "hal/system.h"

/* External declaration from system_at32f403a.c */
extern uint32_t SystemCoreClock;
extern void SystemCoreClockUpdate(void);

/* SysTick timer base */
#define SYSTICK_BASE        0xE000E010UL
#define SYSTICK_CTRL        (*(volatile uint32_t *)(SYSTICK_BASE + 0x00))
#define SYSTICK_LOAD        (*(volatile uint32_t *)(SYSTICK_BASE + 0x04))
#define SYSTICK_VAL         (*(volatile uint32_t *)(SYSTICK_BASE + 0x08))
#define SYSTICK_CALIB       (*(volatile uint32_t *)(SYSTICK_BASE + 0x0C))

/* SYSTICK control bits */
#define SYSTICK_CTRL_ENABLE     (1 << 0)
#define SYSTICK_CTRL_TICKINT    (1 << 1)
#define SYSTICK_CTRL_CLKSOURCE  (1 << 2)
#define SYSTICK_CTRL_COUNTFLAG  (1 << 16)

/* Flash wait states register */
#define FLASH_ACR           (*(volatile uint32_t *)0x40022000)

/* Ticks per microsecond for delay functions */
static uint32_t g_ticks_per_us = 240;  /* Default for 240MHz */

/**
 * @brief Configure flash wait states for target frequency
 * @param frequency Target system clock frequency
 */
static void HAL_Flash_SetLatency(uint32_t frequency)
{
    uint32_t latency;
    
    /* AT32F403A flash wait states (CONFIRMED from datasheet):
     * 0 wait states: up to 48 MHz
     * 1 wait state: 48-96 MHz
     * 2 wait states: 96-144 MHz
     * 3 wait states: 144-192 MHz
     * 4 wait states: 192-240 MHz
     */
    if (frequency <= 48000000) {
        latency = 0;
    } else if (frequency <= 96000000) {
        latency = 1;
    } else if (frequency <= 144000000) {
        latency = 2;
    } else if (frequency <= 192000000) {
        latency = 3;
    } else {
        latency = 4;
    }
    
    /* Set flash latency */
    FLASH_ACR = (FLASH_ACR & ~0x07) | latency;
}

/**
 * @brief Configure system clocks for 240MHz operation
 * 
 * INFERRED clock configuration:
 *   HICK (8MHz) / 12 * 60 = 240MHz
 * 
 * This matches the observed system clock from OEM firmware analysis.
 */
void HAL_System_ClockConfig(void)
{
    /* Set flash latency for 240MHz */
    HAL_Flash_SetLatency(240000000);
    
    /* Reset CRM to default state */
    CRM_CTRL |= CRM_CTRL_HICKEN;            /* Enable HICK */
    while (!(CRM_CTRL & CRM_CTRL_HICKSTBL)); /* Wait for HICK stable */
    
    /* Configure PLL: HICK / 12 * 60 = 240MHz */
    CRM_CFG &= ~CRM_CFG_PLLRCS;             /* PLL source = HICK */
    
    /* Set PLL multiplier to 60 (encoded in PLLMULT_L and PLLMULT_H)
     * For AT32F403A: mult = PLLMULT_L + PLLMULT_H * 16 + 2
     * So for 60: 60 = L + H*16 + 2, need L=10, H=3 (10 + 48 + 2 = 60)
     * Actually encoded as (mult - 2): 58 = 0x3A
     * PLLMULT_L (bits 21:18) = 0x0A (10)
     * PLLMULT_H (bits 30:29) = 0x03 (3)
     */
    uint32_t cfg = CRM_CFG;
    cfg &= ~(CRM_CFG_PLLMULT_L | CRM_CFG_PLLMULT_H);
    cfg |= (0x0A << 18);                    /* PLLMULT_L = 10 */
    cfg |= (0x03 << 29);                    /* PLLMULT_H = 3 */
    CRM_CFG = cfg;
    
    /* Enable PLL */
    CRM_CTRL |= CRM_CTRL_PLLEN;
    while (!(CRM_CTRL & CRM_CTRL_PLLSTBL)); /* Wait for PLL stable */
    
    /* Configure bus dividers:
     * AHB = SCLK / 1 = 240MHz
     * APB1 = AHB / 2 = 120MHz
     * APB2 = AHB / 2 = 120MHz
     */
    cfg = CRM_CFG;
    cfg &= ~(CRM_CFG_AHBDIV | CRM_CFG_APB1DIV | CRM_CFG_APB2DIV);
    cfg |= (0 << 4);                        /* AHB div = 1 */
    cfg |= (4 << 8);                        /* APB1 div = 2 */
    cfg |= (4 << 11);                       /* APB2 div = 2 */
    CRM_CFG = cfg;
    
    /* Switch system clock to PLL */
    cfg = CRM_CFG;
    cfg &= ~CRM_CFG_SCLKSEL;
    cfg |= (2 << 0);                        /* SCLK = PLL */
    CRM_CFG = cfg;
    
    /* Wait for switch to complete */
    while (((CRM_CFG & CRM_CFG_SCLKSTS) >> 2) != 2);
    
    /* Update SystemCoreClock variable */
    SystemCoreClockUpdate();
    
    /* Update ticks per microsecond */
    g_ticks_per_us = SystemCoreClock / 1000000;
}

/**
 * @brief Configure SysTick for periodic interrupts
 * @param ticks_per_second Interrupt frequency
 */
void HAL_Timer_SysTickConfig(uint32_t ticks_per_second)
{
    uint32_t reload = (SystemCoreClock / ticks_per_second) - 1;
    
    /* Disable SysTick */
    SYSTICK_CTRL = 0;
    
    /* Set reload value */
    SYSTICK_LOAD = reload & 0x00FFFFFF;
    
    /* Clear current value */
    SYSTICK_VAL = 0;
    
    /* Enable SysTick with processor clock and interrupt */
    SYSTICK_CTRL = SYSTICK_CTRL_CLKSOURCE | 
                   SYSTICK_CTRL_TICKINT | 
                   SYSTICK_CTRL_ENABLE;
}

/**
 * @brief Microsecond delay using cycle counting
 * @param us Delay in microseconds
 */
void HAL_DelayUs(uint32_t us)
{
    uint32_t ticks = us * g_ticks_per_us;
    uint32_t start = SYSTICK_VAL;
    uint32_t reload = SYSTICK_LOAD;
    uint32_t elapsed = 0;
    uint32_t last = start;
    
    while (elapsed < ticks) {
        uint32_t current = SYSTICK_VAL;
        if (current <= last) {
            elapsed += last - current;
        } else {
            elapsed += last + (reload - current) + 1;
        }
        last = current;
    }
}

/**
 * @brief Get system clock frequency
 */
uint32_t HAL_System_GetSysClockHz(void)
{
    return SystemCoreClock;
}

/**
 * @brief Get AHB clock frequency
 */
uint32_t HAL_System_GetAHBClockHz(void)
{
    uint32_t ahb_div = (CRM_CFG & CRM_CFG_AHBDIV) >> 4;
    if (ahb_div >= 8) {
        return SystemCoreClock >> (ahb_div - 7);
    }
    return SystemCoreClock;
}

/**
 * @brief Get APB1 clock frequency
 */
uint32_t HAL_System_GetAPB1ClockHz(void)
{
    uint32_t apb1_div = (CRM_CFG & CRM_CFG_APB1DIV) >> 8;
    uint32_t ahb_clk = HAL_System_GetAHBClockHz();
    if (apb1_div >= 4) {
        return ahb_clk >> (apb1_div - 3);
    }
    return ahb_clk;
}

/**
 * @brief Get APB2 clock frequency
 */
uint32_t HAL_System_GetAPB2ClockHz(void)
{
    uint32_t apb2_div = (CRM_CFG & CRM_CFG_APB2DIV) >> 11;
    uint32_t ahb_clk = HAL_System_GetAHBClockHz();
    if (apb2_div >= 4) {
        return ahb_clk >> (apb2_div - 3);
    }
    return ahb_clk;
}

/**
 * @brief System reset
 */
void HAL_System_Reset(void)
{
    /* Use CMSIS NVIC_SystemReset equivalent */
    #define AIRCR_VECTKEY_MASK  0x05FA0000
    #define SCB_AIRCR           (*(volatile uint32_t *)0xE000ED0C)
    
    /* Request system reset */
    SCB_AIRCR = AIRCR_VECTKEY_MASK | (1 << 2);
    
    /* Wait for reset */
    while (1) {
        __asm volatile ("wfi");
    }
}

/**
 * @brief Enter sleep mode
 */
void HAL_System_Sleep(void)
{
    __asm volatile ("wfi");
}


