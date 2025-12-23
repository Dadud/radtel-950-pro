/**
 * @file adc.h
 * @brief ADC Hardware Abstraction Layer
 * 
 * Provides ADC functionality for:
 *   - Battery voltage measurement (PA1) [CONFIRMED]
 *   - VOX level detection (PA0) [HIGH]
 *   - Audio input sampling
 */

#ifndef HAL_ADC_H
#define HAL_ADC_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * ADC PERIPHERAL BASE ADDRESSES
 * ============================================================================ */

#define ADC1_BASE           0x40012400UL
#define ADC2_BASE           0x40012800UL
#define ADC3_BASE           0x40013C00UL

/* ADC register structure */
typedef struct {
    volatile uint32_t STS;      /* 0x00: Status register */
    volatile uint32_t CTRL1;    /* 0x04: Control register 1 */
    volatile uint32_t CTRL2;    /* 0x08: Control register 2 */
    volatile uint32_t SPT1;     /* 0x0C: Sample time 1 */
    volatile uint32_t SPT2;     /* 0x10: Sample time 2 */
    volatile uint32_t PCDTO[4]; /* 0x14-0x20: Preempted channel data offset */
    volatile uint32_t VMHB;     /* 0x24: Voltage monitor high boundary */
    volatile uint32_t VMLB;     /* 0x28: Voltage monitor low boundary */
    volatile uint32_t OSQ1;     /* 0x2C: Ordinary sequence 1 */
    volatile uint32_t OSQ2;     /* 0x30: Ordinary sequence 2 */
    volatile uint32_t OSQ3;     /* 0x34: Ordinary sequence 3 */
    volatile uint32_t PSQ;      /* 0x38: Preempted sequence */
    volatile uint32_t PDT[4];   /* 0x3C-0x48: Preempted data */
    volatile uint32_t ODT;      /* 0x4C: Ordinary data */
} ADC_TypeDef;

#define ADC1                ((ADC_TypeDef *)ADC1_BASE)
#define ADC2                ((ADC_TypeDef *)ADC2_BASE)
#define ADC3                ((ADC_TypeDef *)ADC3_BASE)

/* ============================================================================
 * ADC CONFIGURATION
 * ============================================================================ */

typedef enum {
    ADC_INSTANCE_1 = 0,
    ADC_INSTANCE_2,
    ADC_INSTANCE_3,
    ADC_INSTANCE_COUNT
} ADC_Instance_t;

typedef enum {
    ADC_CHANNEL_0 = 0,
    ADC_CHANNEL_1,
    ADC_CHANNEL_2,
    ADC_CHANNEL_3,
    ADC_CHANNEL_4,
    ADC_CHANNEL_5,
    ADC_CHANNEL_6,
    ADC_CHANNEL_7,
    ADC_CHANNEL_8,
    ADC_CHANNEL_9,
    ADC_CHANNEL_10,
    ADC_CHANNEL_11,
    ADC_CHANNEL_12,
    ADC_CHANNEL_13,
    ADC_CHANNEL_14,
    ADC_CHANNEL_15,
    ADC_CHANNEL_TEMP = 16,      /* Internal temperature sensor */
    ADC_CHANNEL_VREF = 17       /* Internal voltage reference */
} ADC_Channel_t;

typedef enum {
    ADC_SAMPLETIME_1_5 = 0,     /* 1.5 cycles */
    ADC_SAMPLETIME_7_5,         /* 7.5 cycles */
    ADC_SAMPLETIME_13_5,        /* 13.5 cycles */
    ADC_SAMPLETIME_28_5,        /* 28.5 cycles */
    ADC_SAMPLETIME_41_5,        /* 41.5 cycles */
    ADC_SAMPLETIME_55_5,        /* 55.5 cycles */
    ADC_SAMPLETIME_71_5,        /* 71.5 cycles */
    ADC_SAMPLETIME_239_5        /* 239.5 cycles */
} ADC_SampleTime_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize ADC peripheral
 * @param instance ADC instance
 */
void HAL_ADC_Init(ADC_Instance_t instance);

/**
 * @brief Deinitialize ADC peripheral
 * @param instance ADC instance
 */
void HAL_ADC_DeInit(ADC_Instance_t instance);

/**
 * @brief Configure channel sample time
 * @param instance ADC instance
 * @param channel ADC channel
 * @param sample_time Sample time setting
 */
void HAL_ADC_ConfigChannel(ADC_Instance_t instance, ADC_Channel_t channel, 
                           ADC_SampleTime_t sample_time);

/**
 * @brief Read single conversion (blocking)
 * @param instance ADC instance
 * @param channel ADC channel
 * @return 12-bit ADC value (0-4095)
 */
uint16_t HAL_ADC_Read(ADC_Instance_t instance, ADC_Channel_t channel);

/**
 * @brief Start continuous conversion with DMA
 * @param instance ADC instance
 * @param channels Array of channels
 * @param num_channels Number of channels
 * @param buffer DMA destination buffer
 */
void HAL_ADC_StartDMA(ADC_Instance_t instance, const ADC_Channel_t *channels,
                      uint32_t num_channels, uint16_t *buffer);

/**
 * @brief Stop DMA conversion
 * @param instance ADC instance
 */
void HAL_ADC_StopDMA(ADC_Instance_t instance);

/**
 * @brief Read battery voltage
 * @return Battery voltage in millivolts
 * 
 * Uses PA1 with voltage divider ratio (INFERRED from OEM firmware)
 */
uint16_t HAL_ADC_ReadBatteryMV(void);

/**
 * @brief Read VOX level
 * @return VOX level (0-4095)
 */
uint16_t HAL_ADC_ReadVOX(void);

#ifdef __cplusplus
}
#endif

#endif /* HAL_ADC_H */

