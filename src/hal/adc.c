/**
 * @file adc.c
 * @brief ADC Hardware Abstraction Layer Implementation
 */

#include "hal/adc.h"
#include "hal/system.h"
#include "hal/gpio.h"

/* ADC status register bits */
#define ADC_STS_VMOR        (1 << 0)    /* Voltage monitor out of range */
#define ADC_STS_OCCE        (1 << 1)    /* Ordinary channel conversion end */
#define ADC_STS_PCCE        (1 << 2)    /* Preempted channel conversion end */
#define ADC_STS_PCCS        (1 << 3)    /* Preempted channel conversion start */
#define ADC_STS_OCCS        (1 << 4)    /* Ordinary channel conversion start */

/* ADC control register bits */
#define ADC_CTRL2_ADCEN     (1 << 0)    /* ADC enable */
#define ADC_CTRL2_RPEN      (1 << 1)    /* Repeat mode enable */
#define ADC_CTRL2_ADCAL     (1 << 2)    /* ADC calibration */
#define ADC_CTRL2_ADCALINIT (1 << 3)    /* ADC calibration init */
#define ADC_CTRL2_OCDMAEN   (1 << 8)    /* Ordinary channel DMA enable */
#define ADC_CTRL2_DTALIGN   (1 << 11)   /* Data alignment */
#define ADC_CTRL2_OCSWTRG   (1 << 22)   /* Ordinary channel SW trigger */

/* Battery voltage divider ratio (INFERRED) */
/* Assuming 10K/10K divider: actual = measured * 2 */
/* With 3.3V reference: mV = (adc * 3300 * 2) / 4096 */
#define BATTERY_DIVIDER_MULT    2
#define ADC_VREF_MV             3300
#define ADC_MAX_VALUE           4095

/* Get ADC peripheral pointer */
static ADC_TypeDef* get_adc(ADC_Instance_t instance)
{
    switch (instance) {
        case ADC_INSTANCE_1: return ADC1;
        case ADC_INSTANCE_2: return ADC2;
        case ADC_INSTANCE_3: return ADC3;
        default: return NULL;
    }
}

void HAL_ADC_Init(ADC_Instance_t instance)
{
    ADC_TypeDef *adc = get_adc(instance);
    if (adc == NULL) return;
    
    /* Enable ADC clock */
    switch (instance) {
        case ADC_INSTANCE_1:
            CRM_APB2EN |= (1 << 9);
            break;
        case ADC_INSTANCE_2:
            CRM_APB2EN |= (1 << 10);
            break;
        case ADC_INSTANCE_3:
            CRM_APB2EN |= (1 << 15);
            break;
        default:
            return;
    }
    
    /* Configure ADC clock prescaler (APB2 / 8 = 15MHz for 120MHz APB2) */
    /* Note: ADC clock should be <= 28MHz for AT32F403A */
    CRM_CFG = (CRM_CFG & ~(0x03 << 14)) | (0x03 << 14);  /* ADCDIV = /8 */
    
    /* Enable ADC */
    adc->CTRL2 = ADC_CTRL2_ADCEN;
    
    /* Wait a bit for ADC to stabilize */
    for (volatile int i = 0; i < 1000; i++);
    
    /* Start calibration */
    adc->CTRL2 |= ADC_CTRL2_ADCALINIT;
    while (adc->CTRL2 & ADC_CTRL2_ADCALINIT);
    
    adc->CTRL2 |= ADC_CTRL2_ADCAL;
    while (adc->CTRL2 & ADC_CTRL2_ADCAL);
    
    /* Configure for single conversion, SW trigger */
    adc->CTRL1 = 0;
    adc->CTRL2 = ADC_CTRL2_ADCEN;
}

void HAL_ADC_DeInit(ADC_Instance_t instance)
{
    ADC_TypeDef *adc = get_adc(instance);
    if (adc == NULL) return;
    
    adc->CTRL2 = 0;
}

void HAL_ADC_ConfigChannel(ADC_Instance_t instance, ADC_Channel_t channel, 
                           ADC_SampleTime_t sample_time)
{
    ADC_TypeDef *adc = get_adc(instance);
    if (adc == NULL) return;
    
    /* Set sample time */
    if (channel < 10) {
        /* Channels 0-9 in SPT2 */
        uint32_t shift = channel * 3;
        adc->SPT2 = (adc->SPT2 & ~(0x07 << shift)) | (sample_time << shift);
    } else {
        /* Channels 10-17 in SPT1 */
        uint32_t shift = (channel - 10) * 3;
        adc->SPT1 = (adc->SPT1 & ~(0x07 << shift)) | (sample_time << shift);
    }
}

uint16_t HAL_ADC_Read(ADC_Instance_t instance, ADC_Channel_t channel)
{
    ADC_TypeDef *adc = get_adc(instance);
    if (adc == NULL) return 0;
    
    /* Configure channel */
    HAL_ADC_ConfigChannel(instance, channel, ADC_SAMPLETIME_55_5);
    
    /* Set channel in sequence register (single channel, length = 1) */
    adc->OSQ1 = 0;  /* Length = 1 conversion */
    adc->OSQ3 = channel;  /* First channel in sequence */
    
    /* Clear conversion complete flag */
    adc->STS = ~ADC_STS_OCCE;
    
    /* Start conversion */
    adc->CTRL2 |= ADC_CTRL2_ADCEN | ADC_CTRL2_OCSWTRG;
    
    /* Wait for conversion complete */
    while (!(adc->STS & ADC_STS_OCCE));
    
    /* Read and return result */
    return (uint16_t)adc->ODT;
}

void HAL_ADC_StartDMA(ADC_Instance_t instance, const ADC_Channel_t *channels,
                      uint32_t num_channels, uint16_t *buffer)
{
    ADC_TypeDef *adc = get_adc(instance);
    if (adc == NULL || channels == NULL || buffer == NULL) return;
    
    /* Enable DMA mode */
    adc->CTRL2 |= ADC_CTRL2_OCDMAEN | ADC_CTRL2_RPEN;
    
    /* Configure sequence */
    adc->OSQ1 = ((num_channels - 1) & 0x0F) << 20;
    
    /* Set channels in sequence registers */
    uint32_t osq3 = 0, osq2 = 0, osq1 = adc->OSQ1;
    for (uint32_t i = 0; i < num_channels && i < 16; i++) {
        uint32_t ch = channels[i] & 0x1F;
        if (i < 6) {
            osq3 |= ch << (i * 5);
        } else if (i < 12) {
            osq2 |= ch << ((i - 6) * 5);
        } else {
            osq1 |= ch << ((i - 12) * 5);
        }
    }
    adc->OSQ3 = osq3;
    adc->OSQ2 = osq2;
    adc->OSQ1 = osq1;
    
    /* DMA configuration would be done in DMA HAL */
    /* Start conversion */
    adc->CTRL2 |= ADC_CTRL2_OCSWTRG;
}

void HAL_ADC_StopDMA(ADC_Instance_t instance)
{
    ADC_TypeDef *adc = get_adc(instance);
    if (adc == NULL) return;
    
    adc->CTRL2 &= ~(ADC_CTRL2_OCDMAEN | ADC_CTRL2_RPEN);
}

uint16_t HAL_ADC_ReadBatteryMV(void)
{
    /* Battery on PA1 = ADC channel 1 */
    /* First configure PA1 as analog input */
    HAL_GPIO_Config(GPIO_PORT_A, GPIO_PIN_1, GPIO_MODE_INPUT_ANALOG, GPIO_SPEED_2MHZ);
    
    /* Read ADC */
    uint16_t adc_val = HAL_ADC_Read(ADC_INSTANCE_2, ADC_CHANNEL_1);
    
    /* Convert to millivolts */
    uint32_t mv = ((uint32_t)adc_val * ADC_VREF_MV * BATTERY_DIVIDER_MULT) / ADC_MAX_VALUE;
    
    return (uint16_t)mv;
}

uint16_t HAL_ADC_ReadVOX(void)
{
    /* VOX on PA0 = ADC channel 0 */
    HAL_GPIO_Config(GPIO_PORT_A, GPIO_PIN_0, GPIO_MODE_INPUT_ANALOG, GPIO_SPEED_2MHZ);
    
    return HAL_ADC_Read(ADC_INSTANCE_2, ADC_CHANNEL_0);
}

