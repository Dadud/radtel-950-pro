/**
 * @file dac.h
 * @brief DAC Hardware Abstraction Layer
 * 
 * Provides DAC functionality for:
 *   - Tone/beep generation (PA4/DAC1) [CONFIRMED]
 *   - APC (Automatic Power Control) (PA5/DAC2) [HIGH]
 */

#ifndef HAL_DAC_H
#define HAL_DAC_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * DAC PERIPHERAL BASE ADDRESS
 * ============================================================================ */

#define DAC_BASE            0x40007400UL

/* DAC register structure */
typedef struct {
    volatile uint32_t CTRL;     /* 0x00: Control register */
    volatile uint32_t SWTRG;    /* 0x04: Software trigger */
    volatile uint32_t D1DTH12R; /* 0x08: DAC1 12-bit right-aligned data */
    volatile uint32_t D1DTH12L; /* 0x0C: DAC1 12-bit left-aligned data */
    volatile uint32_t D1DTH8R;  /* 0x10: DAC1 8-bit right-aligned data */
    volatile uint32_t D2DTH12R; /* 0x14: DAC2 12-bit right-aligned data */
    volatile uint32_t D2DTH12L; /* 0x18: DAC2 12-bit left-aligned data */
    volatile uint32_t D2DTH8R;  /* 0x1C: DAC2 8-bit right-aligned data */
    volatile uint32_t DDTH12R;  /* 0x20: Dual 12-bit right-aligned data */
    volatile uint32_t DDTH12L;  /* 0x24: Dual 12-bit left-aligned data */
    volatile uint32_t DDTH8R;   /* 0x28: Dual 8-bit right-aligned data */
    volatile uint32_t D1ODT;    /* 0x2C: DAC1 output data */
    volatile uint32_t D2ODT;    /* 0x30: DAC2 output data */
    volatile uint32_t STS;      /* 0x34: Status register */
} DAC_TypeDef;

#define DAC                 ((DAC_TypeDef *)DAC_BASE)

/* ============================================================================
 * DAC CONFIGURATION
 * ============================================================================ */

typedef enum {
    DAC_CHANNEL_1 = 0,      /* DAC1 on PA4 - Beep/tone output */
    DAC_CHANNEL_2,          /* DAC2 on PA5 - APC control */
    DAC_CHANNEL_COUNT
} DAC_Channel_t;

typedef enum {
    DAC_TRIGGER_NONE = 0,       /* No trigger (auto conversion) */
    DAC_TRIGGER_TIMER6,         /* Timer 6 TRGO */
    DAC_TRIGGER_TIMER3,         /* Timer 3 TRGO */
    DAC_TRIGGER_TIMER7,         /* Timer 7 TRGO */
    DAC_TRIGGER_TIMER5,         /* Timer 5 TRGO */
    DAC_TRIGGER_TIMER2,         /* Timer 2 TRGO */
    DAC_TRIGGER_TIMER4,         /* Timer 4 TRGO */
    DAC_TRIGGER_EXTI9,          /* External interrupt line 9 */
    DAC_TRIGGER_SOFTWARE        /* Software trigger */
} DAC_Trigger_t;

typedef struct {
    DAC_Trigger_t trigger;
    bool enable_output_buffer;
    bool enable_dma;
} DAC_Config_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize DAC peripheral
 */
void HAL_DAC_Init(void);

/**
 * @brief Deinitialize DAC peripheral
 */
void HAL_DAC_DeInit(void);

/**
 * @brief Configure DAC channel
 * @param channel DAC channel
 * @param config Configuration parameters
 */
void HAL_DAC_ConfigChannel(DAC_Channel_t channel, const DAC_Config_t *config);

/**
 * @brief Enable DAC channel
 * @param channel DAC channel
 */
void HAL_DAC_Enable(DAC_Channel_t channel);

/**
 * @brief Disable DAC channel
 * @param channel DAC channel
 */
void HAL_DAC_Disable(DAC_Channel_t channel);

/**
 * @brief Set DAC output value (12-bit)
 * @param channel DAC channel
 * @param value 12-bit output value (0-4095)
 */
void HAL_DAC_SetValue(DAC_Channel_t channel, uint16_t value);

/**
 * @brief Set DAC output value (8-bit)
 * @param channel DAC channel
 * @param value 8-bit output value (0-255)
 */
void HAL_DAC_SetValue8(DAC_Channel_t channel, uint8_t value);

/**
 * @brief Trigger DAC conversion
 * @param channel DAC channel
 */
void HAL_DAC_SoftwareTrigger(DAC_Channel_t channel);

/**
 * @brief Start DAC with DMA
 * @param channel DAC channel
 * @param buffer Sample buffer
 * @param length Number of samples
 * @param circular Enable circular mode
 */
void HAL_DAC_StartDMA(DAC_Channel_t channel, const uint16_t *buffer, 
                      uint32_t length, bool circular);

/**
 * @brief Stop DAC DMA
 * @param channel DAC channel
 */
void HAL_DAC_StopDMA(DAC_Channel_t channel);

#ifdef __cplusplus
}
#endif

#endif /* HAL_DAC_H */

