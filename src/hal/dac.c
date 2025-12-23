/**
 * @file dac.c
 * @brief DAC Hardware Abstraction Layer Implementation
 */

#include "hal/dac.h"
#include "hal/system.h"
#include "hal/gpio.h"

/* DAC control register bits */
#define DAC_CTRL_D1EN       (1 << 0)    /* DAC1 enable */
#define DAC_CTRL_D1OBDIS    (1 << 1)    /* DAC1 output buffer disable */
#define DAC_CTRL_D1TRGEN    (1 << 2)    /* DAC1 trigger enable */
#define DAC_CTRL_D1TRGSEL   (0x07 << 3) /* DAC1 trigger select */
#define DAC_CTRL_D1DMAEN    (1 << 12)   /* DAC1 DMA enable */

#define DAC_CTRL_D2EN       (1 << 16)   /* DAC2 enable */
#define DAC_CTRL_D2OBDIS    (1 << 17)   /* DAC2 output buffer disable */
#define DAC_CTRL_D2TRGEN    (1 << 18)   /* DAC2 trigger enable */
#define DAC_CTRL_D2TRGSEL   (0x07 << 19)/* DAC2 trigger select */
#define DAC_CTRL_D2DMAEN    (1 << 28)   /* DAC2 DMA enable */

void HAL_DAC_Init(void)
{
    /* Enable DAC clock */
    CRM_APB1EN |= (1 << 29);  /* DAC clock enable */
    
    /* Configure PA4 and PA5 as analog outputs */
    HAL_GPIO_Config(GPIO_PORT_A, GPIO_PIN_4, GPIO_MODE_INPUT_ANALOG, GPIO_SPEED_2MHZ);
    HAL_GPIO_Config(GPIO_PORT_A, GPIO_PIN_5, GPIO_MODE_INPUT_ANALOG, GPIO_SPEED_2MHZ);
    
    /* Reset DAC */
    DAC->CTRL = 0;
}

void HAL_DAC_DeInit(void)
{
    DAC->CTRL = 0;
}

void HAL_DAC_ConfigChannel(DAC_Channel_t channel, const DAC_Config_t *config)
{
    if (config == NULL) return;
    
    uint32_t ctrl = DAC->CTRL;
    
    if (channel == DAC_CHANNEL_1) {
        /* Clear DAC1 config bits */
        ctrl &= ~(DAC_CTRL_D1OBDIS | DAC_CTRL_D1TRGEN | DAC_CTRL_D1TRGSEL | DAC_CTRL_D1DMAEN);
        
        /* Output buffer */
        if (!config->enable_output_buffer) {
            ctrl |= DAC_CTRL_D1OBDIS;
        }
        
        /* Trigger */
        if (config->trigger != DAC_TRIGGER_NONE) {
            ctrl |= DAC_CTRL_D1TRGEN;
            ctrl |= ((config->trigger & 0x07) << 3);
        }
        
        /* DMA */
        if (config->enable_dma) {
            ctrl |= DAC_CTRL_D1DMAEN;
        }
    }
    else if (channel == DAC_CHANNEL_2) {
        /* Clear DAC2 config bits */
        ctrl &= ~(DAC_CTRL_D2OBDIS | DAC_CTRL_D2TRGEN | DAC_CTRL_D2TRGSEL | DAC_CTRL_D2DMAEN);
        
        /* Output buffer */
        if (!config->enable_output_buffer) {
            ctrl |= DAC_CTRL_D2OBDIS;
        }
        
        /* Trigger */
        if (config->trigger != DAC_TRIGGER_NONE) {
            ctrl |= DAC_CTRL_D2TRGEN;
            ctrl |= ((config->trigger & 0x07) << 19);
        }
        
        /* DMA */
        if (config->enable_dma) {
            ctrl |= DAC_CTRL_D2DMAEN;
        }
    }
    
    DAC->CTRL = ctrl;
}

void HAL_DAC_Enable(DAC_Channel_t channel)
{
    if (channel == DAC_CHANNEL_1) {
        DAC->CTRL |= DAC_CTRL_D1EN;
    }
    else if (channel == DAC_CHANNEL_2) {
        DAC->CTRL |= DAC_CTRL_D2EN;
    }
}

void HAL_DAC_Disable(DAC_Channel_t channel)
{
    if (channel == DAC_CHANNEL_1) {
        DAC->CTRL &= ~DAC_CTRL_D1EN;
    }
    else if (channel == DAC_CHANNEL_2) {
        DAC->CTRL &= ~DAC_CTRL_D2EN;
    }
}

void HAL_DAC_SetValue(DAC_Channel_t channel, uint16_t value)
{
    value &= 0x0FFF;  /* 12-bit max */
    
    if (channel == DAC_CHANNEL_1) {
        DAC->D1DTH12R = value;
    }
    else if (channel == DAC_CHANNEL_2) {
        DAC->D2DTH12R = value;
    }
}

void HAL_DAC_SetValue8(DAC_Channel_t channel, uint8_t value)
{
    if (channel == DAC_CHANNEL_1) {
        DAC->D1DTH8R = value;
    }
    else if (channel == DAC_CHANNEL_2) {
        DAC->D2DTH8R = value;
    }
}

void HAL_DAC_SoftwareTrigger(DAC_Channel_t channel)
{
    if (channel == DAC_CHANNEL_1) {
        DAC->SWTRG |= (1 << 0);
    }
    else if (channel == DAC_CHANNEL_2) {
        DAC->SWTRG |= (1 << 1);
    }
}

void HAL_DAC_StartDMA(DAC_Channel_t channel, const uint16_t *buffer, 
                      uint32_t length, bool circular)
{
    /* DMA configuration would be done in DMA HAL */
    /* This is a placeholder for the DMA setup */
    (void)buffer;
    (void)length;
    (void)circular;
    
    /* Enable DMA in DAC */
    if (channel == DAC_CHANNEL_1) {
        DAC->CTRL |= DAC_CTRL_D1DMAEN | DAC_CTRL_D1EN;
    }
    else if (channel == DAC_CHANNEL_2) {
        DAC->CTRL |= DAC_CTRL_D2DMAEN | DAC_CTRL_D2EN;
    }
}

void HAL_DAC_StopDMA(DAC_Channel_t channel)
{
    if (channel == DAC_CHANNEL_1) {
        DAC->CTRL &= ~DAC_CTRL_D1DMAEN;
    }
    else if (channel == DAC_CHANNEL_2) {
        DAC->CTRL &= ~DAC_CTRL_D2DMAEN;
    }
}

