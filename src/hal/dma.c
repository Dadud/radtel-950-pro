/**
 * @file dma.c
 * @brief DMA Hardware Abstraction Layer Implementation
 */

#include "hal/dma.h"
#include "hal/system.h"

/* DMA callbacks */
static DMA_Callback_t g_dma1_callbacks[7] = {NULL};
static DMA_Callback_t g_dma2_callbacks[5] = {NULL};

/* Get DMA peripheral */
static DMA_TypeDef* get_dma(DMA_Instance_t instance)
{
    switch (instance) {
        case DMA_INSTANCE_1: return DMA1;
        case DMA_INSTANCE_2: return DMA2;
        default: return NULL;
    }
}

/* Get DMA channel */
static DMA_Channel_TypeDef* get_channel(DMA_Instance_t instance, DMA_Channel_t channel)
{
    DMA_TypeDef *dma = get_dma(instance);
    if (dma == NULL) return NULL;
    
    if (instance == DMA_INSTANCE_1 && channel < 7) {
        return &dma->CH[channel];
    }
    else if (instance == DMA_INSTANCE_2 && channel < 5) {
        return &dma->CH[channel];
    }
    
    return NULL;
}

void HAL_DMA_Init(DMA_Instance_t instance)
{
    /* Enable DMA clock */
    if (instance == DMA_INSTANCE_1) {
        CRM_AHBEN |= (1 << 0);  /* DMA1 clock enable */
    }
    else if (instance == DMA_INSTANCE_2) {
        CRM_AHBEN |= (1 << 1);  /* DMA2 clock enable */
    }
}

void HAL_DMA_ConfigChannel(DMA_Instance_t instance, DMA_Channel_t channel,
                           const DMA_Config_t *config)
{
    DMA_Channel_TypeDef *ch = get_channel(instance, channel);
    if (ch == NULL || config == NULL) return;
    
    /* Disable channel first */
    ch->CTRL = 0;
    
    /* Build control register value */
    uint32_t ctrl = 0;
    
    /* Direction */
    if (config->direction == DMA_DIR_MEM_TO_PERIPH) {
        ctrl |= DMA_CTRL_DTD;
    }
    
    /* Circular mode */
    if (config->circular) {
        ctrl |= DMA_CTRL_LM;
    }
    
    /* Increment modes */
    if (config->periph_increment) {
        ctrl |= DMA_CTRL_PINCM;
    }
    if (config->mem_increment) {
        ctrl |= DMA_CTRL_MINCM;
    }
    
    /* Data widths */
    ctrl |= ((config->periph_width & 0x03) << 8);
    ctrl |= ((config->mem_width & 0x03) << 10);
    
    /* Priority */
    ctrl |= ((config->priority & 0x03) << 12);
    
    ch->CTRL = ctrl;
}

void HAL_DMA_Start(DMA_Instance_t instance, DMA_Channel_t channel,
                   uint32_t periph_addr, uint32_t mem_addr, uint32_t count)
{
    DMA_Channel_TypeDef *ch = get_channel(instance, channel);
    DMA_TypeDef *dma = get_dma(instance);
    if (ch == NULL || dma == NULL) return;
    
    /* Disable channel */
    ch->CTRL &= ~DMA_CTRL_CHEN;
    
    /* Clear interrupt flags */
    HAL_DMA_ClearFlags(instance, channel);
    
    /* Set addresses and count */
    ch->PADDR = periph_addr;
    ch->MADDR = mem_addr;
    ch->DTCNT = count;
    
    /* Enable channel */
    ch->CTRL |= DMA_CTRL_CHEN;
}

void HAL_DMA_Stop(DMA_Instance_t instance, DMA_Channel_t channel)
{
    DMA_Channel_TypeDef *ch = get_channel(instance, channel);
    if (ch == NULL) return;
    
    ch->CTRL &= ~DMA_CTRL_CHEN;
}

bool HAL_DMA_IsComplete(DMA_Instance_t instance, DMA_Channel_t channel)
{
    DMA_TypeDef *dma = get_dma(instance);
    if (dma == NULL) return false;
    
    /* Check transfer complete flag */
    uint32_t flag = 1 << (1 + channel * 4);  /* FDTF bit for each channel */
    return (dma->STS & flag) != 0;
}

uint32_t HAL_DMA_GetRemaining(DMA_Instance_t instance, DMA_Channel_t channel)
{
    DMA_Channel_TypeDef *ch = get_channel(instance, channel);
    if (ch == NULL) return 0;
    
    return ch->DTCNT;
}

void HAL_DMA_SetCallback(DMA_Instance_t instance, DMA_Channel_t channel,
                         DMA_Callback_t callback)
{
    if (instance == DMA_INSTANCE_1 && channel < 7) {
        g_dma1_callbacks[channel] = callback;
    }
    else if (instance == DMA_INSTANCE_2 && channel < 5) {
        g_dma2_callbacks[channel] = callback;
    }
}

void HAL_DMA_EnableInterrupt(DMA_Instance_t instance, DMA_Channel_t channel)
{
    DMA_Channel_TypeDef *ch = get_channel(instance, channel);
    if (ch == NULL) return;
    
    ch->CTRL |= DMA_CTRL_FDTIEN;
}

void HAL_DMA_ClearFlags(DMA_Instance_t instance, DMA_Channel_t channel)
{
    DMA_TypeDef *dma = get_dma(instance);
    if (dma == NULL) return;
    
    /* Clear all flags for channel (GF, FDT, HDT, DTERR) */
    uint32_t mask = 0x0F << (channel * 4);
    dma->CLR = mask;
}

/* DMA interrupt handlers */
void DMA1_Channel1_IRQHandler(void)
{
    HAL_DMA_ClearFlags(DMA_INSTANCE_1, DMA_CHANNEL_1);
    if (g_dma1_callbacks[0]) g_dma1_callbacks[0]();
}

void DMA1_Channel2_IRQHandler(void)
{
    HAL_DMA_ClearFlags(DMA_INSTANCE_1, DMA_CHANNEL_2);
    if (g_dma1_callbacks[1]) g_dma1_callbacks[1]();
}

void DMA1_Channel3_IRQHandler(void)
{
    HAL_DMA_ClearFlags(DMA_INSTANCE_1, DMA_CHANNEL_3);
    if (g_dma1_callbacks[2]) g_dma1_callbacks[2]();
}

void DMA1_Channel4_IRQHandler(void)
{
    HAL_DMA_ClearFlags(DMA_INSTANCE_1, DMA_CHANNEL_4);
    if (g_dma1_callbacks[3]) g_dma1_callbacks[3]();
}

void DMA1_Channel5_IRQHandler(void)
{
    HAL_DMA_ClearFlags(DMA_INSTANCE_1, DMA_CHANNEL_5);
    if (g_dma1_callbacks[4]) g_dma1_callbacks[4]();
}

void DMA1_Channel6_IRQHandler(void)
{
    HAL_DMA_ClearFlags(DMA_INSTANCE_1, DMA_CHANNEL_6);
    if (g_dma1_callbacks[5]) g_dma1_callbacks[5]();
}

void DMA1_Channel7_IRQHandler(void)
{
    HAL_DMA_ClearFlags(DMA_INSTANCE_1, DMA_CHANNEL_7);
    if (g_dma1_callbacks[6]) g_dma1_callbacks[6]();
}

void DMA2_Channel1_IRQHandler(void)
{
    HAL_DMA_ClearFlags(DMA_INSTANCE_2, DMA_CHANNEL_1);
    if (g_dma2_callbacks[0]) g_dma2_callbacks[0]();
}

void DMA2_Channel2_IRQHandler(void)
{
    HAL_DMA_ClearFlags(DMA_INSTANCE_2, DMA_CHANNEL_2);
    if (g_dma2_callbacks[1]) g_dma2_callbacks[1]();
}

void DMA2_Channel3_IRQHandler(void)
{
    HAL_DMA_ClearFlags(DMA_INSTANCE_2, DMA_CHANNEL_3);
    if (g_dma2_callbacks[2]) g_dma2_callbacks[2]();
}

void DMA2_Channel4_5_IRQHandler(void)
{
    /* Shared handler for channels 4 and 5 */
    if (HAL_DMA_IsComplete(DMA_INSTANCE_2, DMA_CHANNEL_4)) {
        HAL_DMA_ClearFlags(DMA_INSTANCE_2, DMA_CHANNEL_4);
        if (g_dma2_callbacks[3]) g_dma2_callbacks[3]();
    }
    if (HAL_DMA_IsComplete(DMA_INSTANCE_2, DMA_CHANNEL_5)) {
        HAL_DMA_ClearFlags(DMA_INSTANCE_2, DMA_CHANNEL_5);
        if (g_dma2_callbacks[4]) g_dma2_callbacks[4]();
    }
}

