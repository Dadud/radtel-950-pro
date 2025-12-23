/**
 * @file timer.c
 * @brief Timer Hardware Abstraction Layer Implementation
 */

#include "hal/timer.h"
#include "hal/system.h"

/* Timer control register bits */
#define TMR_CTRL1_TMREN     (1 << 0)    /* Timer enable */
#define TMR_CTRL1_OVFEN     (1 << 1)    /* Overflow event enable */
#define TMR_CTRL1_OVFS      (1 << 2)    /* Overflow event source */
#define TMR_CTRL1_OCMEN     (1 << 3)    /* One cycle mode enable */
#define TMR_CTRL1_OWCDIR    (1 << 4)    /* One way count direction */
#define TMR_CTRL1_TWCMSEL   (3 << 5)    /* Two way count mode select */
#define TMR_CTRL1_PRBEN     (1 << 7)    /* Period buffer enable */
#define TMR_CTRL1_CLKDIV    (3 << 8)    /* Clock divider */

/* Timer interrupt bits */
#define TMR_IDEN_OVFIEN     (1 << 0)    /* Overflow interrupt enable */
#define TMR_ISTS_OVFIF      (1 << 0)    /* Overflow interrupt flag */

/* Channel control bits */
#define TMR_CCTRL_C1EN      (1 << 0)    /* Channel 1 enable */
#define TMR_CCTRL_C2EN      (1 << 4)    /* Channel 2 enable */
#define TMR_CCTRL_C3EN      (1 << 8)    /* Channel 3 enable */
#define TMR_CCTRL_C4EN      (1 << 12)   /* Channel 4 enable */

/* Timer callbacks */
static Timer_Callback_t g_timer_callbacks[TIMER_COUNT] = {NULL};

/* Get timer peripheral */
static TMR_TypeDef* get_timer(Timer_t timer)
{
    switch (timer) {
        case TIMER_1: return TMR1;
        case TIMER_2: return TMR2;
        case TIMER_3: return TMR3;
        case TIMER_4: return TMR4;
        case TIMER_5: return TMR5;
        case TIMER_6: return TMR6;
        case TIMER_7: return TMR7;
        case TIMER_8: return TMR8;
        default: return NULL;
    }
}

/* Enable timer clock */
static void timer_clock_enable(Timer_t timer)
{
    switch (timer) {
        case TIMER_1:
            CRM_APB2EN |= (1 << 11);
            break;
        case TIMER_2:
            CRM_APB1EN |= (1 << 0);
            break;
        case TIMER_3:
            CRM_APB1EN |= (1 << 1);
            break;
        case TIMER_4:
            CRM_APB1EN |= (1 << 2);
            break;
        case TIMER_5:
            CRM_APB1EN |= (1 << 3);
            break;
        case TIMER_6:
            CRM_APB1EN |= (1 << 4);
            break;
        case TIMER_7:
            CRM_APB1EN |= (1 << 5);
            break;
        case TIMER_8:
            CRM_APB2EN |= (1 << 13);
            break;
        default:
            break;
    }
}

void HAL_Timer_Init(Timer_t timer, const Timer_Config_t *config)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL || config == NULL) return;
    
    /* Enable clock */
    timer_clock_enable(timer);
    
    /* Disable timer during configuration */
    tmr->CTRL1 = 0;
    
    /* Set prescaler and period */
    tmr->DIV = config->prescaler;
    tmr->PR = config->period;
    
    /* Configure count mode */
    uint32_t ctrl1 = TMR_CTRL1_PRBEN;  /* Enable period buffer */
    
    switch (config->mode) {
        case TIMER_MODE_UP:
            /* Default - count up */
            break;
        case TIMER_MODE_DOWN:
            ctrl1 |= TMR_CTRL1_OWCDIR;
            break;
        case TIMER_MODE_CENTER_1:
        case TIMER_MODE_CENTER_2:
        case TIMER_MODE_CENTER_3:
            ctrl1 |= ((config->mode - TIMER_MODE_CENTER_1 + 1) << 5);
            break;
    }
    
    tmr->CTRL1 = ctrl1;
    
    /* Enable overflow interrupt if requested */
    if (config->enable_interrupt) {
        tmr->IDEN |= TMR_IDEN_OVFIEN;
    }
    
    /* Generate update event to load prescaler */
    tmr->SWEVT = 1;
}

void HAL_Timer_DeInit(Timer_t timer)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL) return;
    
    tmr->CTRL1 = 0;
    tmr->CTRL2 = 0;
    tmr->IDEN = 0;
}

void HAL_Timer_Start(Timer_t timer)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL) return;
    
    tmr->CTRL1 |= TMR_CTRL1_TMREN;
}

void HAL_Timer_Stop(Timer_t timer)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL) return;
    
    tmr->CTRL1 &= ~TMR_CTRL1_TMREN;
}

uint32_t HAL_Timer_GetCount(Timer_t timer)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL) return 0;
    
    return tmr->CVAL;
}

void HAL_Timer_SetCount(Timer_t timer, uint32_t value)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL) return;
    
    tmr->CVAL = value;
}

void HAL_Timer_SetPeriod(Timer_t timer, uint32_t period)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL) return;
    
    tmr->PR = period;
}

void HAL_Timer_ConfigPWM(Timer_t timer, Timer_Channel_t channel,
                         PWM_Mode_t mode, uint32_t duty_cycle)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL) return;
    
    /* Set channel mode (output compare, PWM) */
    uint32_t mode_val = (mode << 4) | (1 << 3);  /* PWM mode + preload enable */
    
    if (channel < 2) {
        /* Channels 1-2 in CM1 */
        uint32_t shift = channel * 8;
        tmr->CM1 = (tmr->CM1 & ~(0xFF << shift)) | (mode_val << shift);
    } else {
        /* Channels 3-4 in CM2 */
        uint32_t shift = (channel - 2) * 8;
        tmr->CM2 = (tmr->CM2 & ~(0xFF << shift)) | (mode_val << shift);
    }
    
    /* Set duty cycle */
    HAL_Timer_SetPWMDuty(timer, channel, duty_cycle);
}

void HAL_Timer_SetPWMDuty(Timer_t timer, Timer_Channel_t channel, uint32_t duty_cycle)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL) return;
    
    switch (channel) {
        case TIMER_CHANNEL_1: tmr->C1DT = duty_cycle; break;
        case TIMER_CHANNEL_2: tmr->C2DT = duty_cycle; break;
        case TIMER_CHANNEL_3: tmr->C3DT = duty_cycle; break;
        case TIMER_CHANNEL_4: tmr->C4DT = duty_cycle; break;
    }
}

void HAL_Timer_EnablePWM(Timer_t timer, Timer_Channel_t channel)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL) return;
    
    uint32_t bit = 1 << (channel * 4);
    tmr->CCTRL |= bit;
    
    /* For advanced timers (1, 8), need to enable main output */
    if (timer == TIMER_1 || timer == TIMER_8) {
        tmr->BRK |= (1 << 15);  /* MOE - Main output enable */
    }
}

void HAL_Timer_DisablePWM(Timer_t timer, Timer_Channel_t channel)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL) return;
    
    uint32_t bit = 1 << (channel * 4);
    tmr->CCTRL &= ~bit;
}

void HAL_Timer_SetCallback(Timer_t timer, Timer_Callback_t callback)
{
    if (timer < TIMER_COUNT) {
        g_timer_callbacks[timer] = callback;
    }
}

void HAL_Timer_ClearInterrupt(Timer_t timer)
{
    TMR_TypeDef *tmr = get_timer(timer);
    if (tmr == NULL) return;
    
    tmr->ISTS = ~TMR_ISTS_OVFIF;
}

/* Timer interrupt handlers */
void TMR2_GLOBAL_IRQHandler(void)
{
    HAL_Timer_ClearInterrupt(TIMER_2);
    if (g_timer_callbacks[TIMER_2]) g_timer_callbacks[TIMER_2]();
}

void TMR3_GLOBAL_IRQHandler(void)
{
    HAL_Timer_ClearInterrupt(TIMER_3);
    if (g_timer_callbacks[TIMER_3]) g_timer_callbacks[TIMER_3]();
}

void TMR4_GLOBAL_IRQHandler(void)
{
    HAL_Timer_ClearInterrupt(TIMER_4);
    if (g_timer_callbacks[TIMER_4]) g_timer_callbacks[TIMER_4]();
}

void TMR5_GLOBAL_IRQHandler(void)
{
    HAL_Timer_ClearInterrupt(TIMER_5);
    if (g_timer_callbacks[TIMER_5]) g_timer_callbacks[TIMER_5]();
}

void TMR6_GLOBAL_IRQHandler(void)
{
    HAL_Timer_ClearInterrupt(TIMER_6);
    if (g_timer_callbacks[TIMER_6]) g_timer_callbacks[TIMER_6]();
}

void TMR7_GLOBAL_IRQHandler(void)
{
    HAL_Timer_ClearInterrupt(TIMER_7);
    if (g_timer_callbacks[TIMER_7]) g_timer_callbacks[TIMER_7]();
}

