/**
 * @file system_at32f403a.c
 * @brief System initialization for AT32F403A
 * 
 * Implements SystemInit() called from startup code before main().
 * Configures FPU, sets up default clock configuration.
 */

#include "hal/system.h"
#include <stdint.h>

/* System core clock variable - updated by clock config */
uint32_t SystemCoreClock = 8000000UL;  /* Default to HICK */

/**
 * @brief System initialization
 * 
 * Called from Reset_Handler before main().
 * - Enable FPU (already done in startup)
 * - Configure flash wait states
 * - Basic clock setup
 */
void SystemInit(void)
{
    /* Enable FPU access */
#if (__FPU_PRESENT == 1) && (__FPU_USED == 1)
    /* Already enabled in startup code, but ensure it's set */
    *((volatile uint32_t *)0xE000ED88) |= ((3UL << 10*2) | (3UL << 11*2));
#endif
    
    /* Reset CRM configuration to default */
    /* Enable HICK */
    CRM_CTRL |= CRM_CTRL_HICKEN;
    
    /* Reset CFG register */
    CRM_CFG = 0x00000000;
    
    /* Reset CTRL register bits (keep HICK enabled) */
    CRM_CTRL &= ~(CRM_CTRL_HEXTEN | CRM_CTRL_HEXTBYPS | 
                  CRM_CTRL_CFDEN | CRM_CTRL_PLLEN);
    
    /* Disable all clock interrupts */
    CRM_CLKINT = 0x00FF0000;
    
    /* Update SystemCoreClock variable */
    SystemCoreClock = 8000000UL;  /* HICK frequency */
}

/**
 * @brief Update SystemCoreClock variable
 * 
 * Called after clock configuration changes to update the global variable.
 */
void SystemCoreClockUpdate(void)
{
    uint32_t pll_mult, pll_source, ahb_div;
    uint32_t sclk_source;
    
    /* Get system clock source */
    sclk_source = (CRM_CFG & CRM_CFG_SCLKSTS) >> 2;
    
    switch (sclk_source) {
        case 0:  /* HICK */
            SystemCoreClock = 8000000UL;
            break;
            
        case 1:  /* HEXT */
            SystemCoreClock = 8000000UL;  /* Assuming 8MHz crystal */
            break;
            
        case 2:  /* PLL */
            /* Get PLL multiplier */
            pll_mult = ((CRM_CFG & CRM_CFG_PLLMULT_L) >> 18) |
                       ((CRM_CFG & CRM_CFG_PLLMULT_H) >> 25);
            pll_mult += 2;
            
            /* Get PLL source */
            pll_source = (CRM_CFG & CRM_CFG_PLLRCS) ? 8000000UL : 8000000UL;
            
            /* HICK is divided by 12 when used as PLL source */
            if (!(CRM_CFG & CRM_CFG_PLLRCS)) {
                pll_source = 8000000UL / 12;  /* ~666.7 kHz */
            }
            
            SystemCoreClock = pll_source * pll_mult;
            break;
            
        default:
            SystemCoreClock = 8000000UL;
            break;
    }
    
    /* Apply AHB prescaler */
    ahb_div = (CRM_CFG & CRM_CFG_AHBDIV) >> 4;
    if (ahb_div >= 8) {
        ahb_div = 1 << (ahb_div - 7);
    } else {
        ahb_div = 1;
    }
    
    SystemCoreClock /= ahb_div;
}



