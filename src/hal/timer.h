/**
 * @file timer.h
 * @brief Timer Hardware Abstraction Layer
 * 
 * Provides timer functionality for:
 *   - System tick (SysTick)
 *   - PWM generation (LCD backlight, tones)
 *   - Periodic interrupts
 *   - Input capture (encoder, frequency measurement)
 */

#ifndef HAL_TIMER_H
#define HAL_TIMER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * TIMER PERIPHERAL BASE ADDRESSES
 * ============================================================================ */

#define TMR1_BASE           0x40012C00UL
#define TMR2_BASE           0x40000000UL
#define TMR3_BASE           0x40000400UL
#define TMR4_BASE           0x40000800UL
#define TMR5_BASE           0x40000C00UL
#define TMR6_BASE           0x40001000UL
#define TMR7_BASE           0x40001400UL
#define TMR8_BASE           0x40013400UL

/* Timer register structure (general purpose) */
typedef struct {
    volatile uint32_t CTRL1;    /* 0x00: Control register 1 */
    volatile uint32_t CTRL2;    /* 0x04: Control register 2 */
    volatile uint32_t STCTRL;   /* 0x08: Subordinate timer control */
    volatile uint32_t IDEN;     /* 0x0C: Interrupt/DMA enable */
    volatile uint32_t ISTS;     /* 0x10: Interrupt status */
    volatile uint32_t SWEVT;    /* 0x14: Software event */
    volatile uint32_t CM1;      /* 0x18: Channel mode 1 */
    volatile uint32_t CM2;      /* 0x1C: Channel mode 2 */
    volatile uint32_t CCTRL;    /* 0x20: Channel control */
    volatile uint32_t CVAL;     /* 0x24: Counter value */
    volatile uint32_t DIV;      /* 0x28: Divider */
    volatile uint32_t PR;       /* 0x2C: Period register */
    volatile uint32_t RPR;      /* 0x30: Repetition period */
    volatile uint32_t C1DT;     /* 0x34: Channel 1 data */
    volatile uint32_t C2DT;     /* 0x38: Channel 2 data */
    volatile uint32_t C3DT;     /* 0x3C: Channel 3 data */
    volatile uint32_t C4DT;     /* 0x40: Channel 4 data */
    volatile uint32_t BRK;      /* 0x44: Break register */
    volatile uint32_t DMACTRL;  /* 0x48: DMA control */
    volatile uint32_t DMADT;    /* 0x4C: DMA data */
} TMR_TypeDef;

#define TMR1                ((TMR_TypeDef *)TMR1_BASE)
#define TMR2                ((TMR_TypeDef *)TMR2_BASE)
#define TMR3                ((TMR_TypeDef *)TMR3_BASE)
#define TMR4                ((TMR_TypeDef *)TMR4_BASE)
#define TMR5                ((TMR_TypeDef *)TMR5_BASE)
#define TMR6                ((TMR_TypeDef *)TMR6_BASE)
#define TMR7                ((TMR_TypeDef *)TMR7_BASE)
#define TMR8                ((TMR_TypeDef *)TMR8_BASE)

/* ============================================================================
 * TIMER CONFIGURATION
 * ============================================================================ */

typedef enum {
    TIMER_1 = 0,
    TIMER_2,
    TIMER_3,
    TIMER_4,
    TIMER_5,
    TIMER_6,
    TIMER_7,
    TIMER_8,
    TIMER_COUNT
} Timer_t;

typedef enum {
    TIMER_CHANNEL_1 = 0,
    TIMER_CHANNEL_2,
    TIMER_CHANNEL_3,
    TIMER_CHANNEL_4
} Timer_Channel_t;

typedef enum {
    TIMER_MODE_UP = 0,
    TIMER_MODE_DOWN,
    TIMER_MODE_CENTER_1,
    TIMER_MODE_CENTER_2,
    TIMER_MODE_CENTER_3
} Timer_CountMode_t;

typedef enum {
    PWM_MODE_1 = 6,     /* Active when CNT < CCR */
    PWM_MODE_2 = 7      /* Active when CNT >= CCR */
} PWM_Mode_t;

typedef struct {
    uint32_t prescaler;         /* Clock prescaler (0-65535) */
    uint32_t period;            /* Auto-reload period */
    Timer_CountMode_t mode;     /* Count mode */
    bool enable_interrupt;      /* Enable overflow interrupt */
} Timer_Config_t;

/* Callback function type */
typedef void (*Timer_Callback_t)(void);

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize timer
 * @param timer Timer instance
 * @param config Configuration parameters
 */
void HAL_Timer_Init(Timer_t timer, const Timer_Config_t *config);

/**
 * @brief Deinitialize timer
 * @param timer Timer instance
 */
void HAL_Timer_DeInit(Timer_t timer);

/**
 * @brief Start timer
 * @param timer Timer instance
 */
void HAL_Timer_Start(Timer_t timer);

/**
 * @brief Stop timer
 * @param timer Timer instance
 */
void HAL_Timer_Stop(Timer_t timer);

/**
 * @brief Get current counter value
 * @param timer Timer instance
 * @return Counter value
 */
uint32_t HAL_Timer_GetCount(Timer_t timer);

/**
 * @brief Set counter value
 * @param timer Timer instance
 * @param value Counter value
 */
void HAL_Timer_SetCount(Timer_t timer, uint32_t value);

/**
 * @brief Set timer period
 * @param timer Timer instance
 * @param period New period value
 */
void HAL_Timer_SetPeriod(Timer_t timer, uint32_t period);

/**
 * @brief Configure PWM output
 * @param timer Timer instance
 * @param channel PWM channel
 * @param mode PWM mode
 * @param duty_cycle Initial duty cycle (0-period)
 */
void HAL_Timer_ConfigPWM(Timer_t timer, Timer_Channel_t channel,
                         PWM_Mode_t mode, uint32_t duty_cycle);

/**
 * @brief Set PWM duty cycle
 * @param timer Timer instance
 * @param channel PWM channel
 * @param duty_cycle Duty cycle value (0-period)
 */
void HAL_Timer_SetPWMDuty(Timer_t timer, Timer_Channel_t channel, uint32_t duty_cycle);

/**
 * @brief Enable PWM output
 * @param timer Timer instance
 * @param channel PWM channel
 */
void HAL_Timer_EnablePWM(Timer_t timer, Timer_Channel_t channel);

/**
 * @brief Disable PWM output
 * @param timer Timer instance
 * @param channel PWM channel
 */
void HAL_Timer_DisablePWM(Timer_t timer, Timer_Channel_t channel);

/**
 * @brief Set timer overflow callback
 * @param timer Timer instance
 * @param callback Callback function
 */
void HAL_Timer_SetCallback(Timer_t timer, Timer_Callback_t callback);

/**
 * @brief Clear timer interrupt flag
 * @param timer Timer instance
 */
void HAL_Timer_ClearInterrupt(Timer_t timer);

#ifdef __cplusplus
}
#endif

#endif /* HAL_TIMER_H */

