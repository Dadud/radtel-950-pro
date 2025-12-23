/**
 * @file dma.h
 * @brief DMA Hardware Abstraction Layer
 * 
 * Provides DMA functionality for:
 *   - LCD refresh (DMA2)
 *   - ADC sampling
 *   - DAC audio output
 *   - UART data transfer
 */

#ifndef HAL_DMA_H
#define HAL_DMA_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * DMA PERIPHERAL BASE ADDRESSES
 * ============================================================================ */

#define DMA1_BASE           0x40020000UL
#define DMA2_BASE           0x40020400UL

/* DMA channel register structure */
typedef struct {
    volatile uint32_t CTRL;     /* 0x00: Control register */
    volatile uint32_t DTCNT;    /* 0x04: Data count register */
    volatile uint32_t PADDR;    /* 0x08: Peripheral address */
    volatile uint32_t MADDR;    /* 0x0C: Memory address */
} DMA_Channel_TypeDef;

/* DMA register structure */
typedef struct {
    volatile uint32_t STS;          /* 0x00: Interrupt status register */
    volatile uint32_t CLR;          /* 0x04: Interrupt flag clear register */
    DMA_Channel_TypeDef CH[7];      /* 0x08+: Channels 1-7 */
} DMA_TypeDef;

#define DMA1                ((DMA_TypeDef *)DMA1_BASE)
#define DMA2                ((DMA_TypeDef *)DMA2_BASE)

/* Channel access macros (0-indexed internally, 1-indexed in datasheet) */
#define DMA1_CH1            (&DMA1->CH[0])
#define DMA1_CH2            (&DMA1->CH[1])
#define DMA1_CH3            (&DMA1->CH[2])
#define DMA1_CH4            (&DMA1->CH[3])
#define DMA1_CH5            (&DMA1->CH[4])
#define DMA1_CH6            (&DMA1->CH[5])
#define DMA1_CH7            (&DMA1->CH[6])

#define DMA2_CH1            (&DMA2->CH[0])
#define DMA2_CH2            (&DMA2->CH[1])
#define DMA2_CH3            (&DMA2->CH[2])
#define DMA2_CH4            (&DMA2->CH[3])
#define DMA2_CH5            (&DMA2->CH[4])

/* ============================================================================
 * DMA CHANNEL CONTROL BITS
 * ============================================================================ */

#define DMA_CTRL_CHEN       (1 << 0)    /* Channel enable */
#define DMA_CTRL_FDTIEN     (1 << 1)    /* Full data transfer interrupt enable */
#define DMA_CTRL_HDTIEN     (1 << 2)    /* Half data transfer interrupt enable */
#define DMA_CTRL_DTERRIEN   (1 << 3)    /* Data transfer error interrupt enable */
#define DMA_CTRL_DTD        (1 << 4)    /* Data transfer direction (0=P->M, 1=M->P) */
#define DMA_CTRL_LM         (1 << 5)    /* Loop mode (circular) */
#define DMA_CTRL_PINCM      (1 << 6)    /* Peripheral increment mode */
#define DMA_CTRL_MINCM      (1 << 7)    /* Memory increment mode */
#define DMA_CTRL_PWIDTH     (3 << 8)    /* Peripheral data width */
#define DMA_CTRL_MWIDTH     (3 << 10)   /* Memory data width */
#define DMA_CTRL_CHPL       (3 << 12)   /* Channel priority level */
#define DMA_CTRL_M2M        (1 << 14)   /* Memory to memory mode */

/* ============================================================================
 * DMA CONFIGURATION
 * ============================================================================ */

typedef enum {
    DMA_INSTANCE_1 = 0,
    DMA_INSTANCE_2,
    DMA_INSTANCE_COUNT
} DMA_Instance_t;

typedef enum {
    DMA_CHANNEL_1 = 0,
    DMA_CHANNEL_2,
    DMA_CHANNEL_3,
    DMA_CHANNEL_4,
    DMA_CHANNEL_5,
    DMA_CHANNEL_6,
    DMA_CHANNEL_7,
    DMA_CHANNEL_COUNT
} DMA_Channel_t;

typedef enum {
    DMA_DIR_PERIPH_TO_MEM = 0,
    DMA_DIR_MEM_TO_PERIPH
} DMA_Direction_t;

typedef enum {
    DMA_WIDTH_8BIT = 0,
    DMA_WIDTH_16BIT,
    DMA_WIDTH_32BIT
} DMA_Width_t;

typedef enum {
    DMA_PRIORITY_LOW = 0,
    DMA_PRIORITY_MEDIUM,
    DMA_PRIORITY_HIGH,
    DMA_PRIORITY_VERY_HIGH
} DMA_Priority_t;

typedef struct {
    DMA_Direction_t direction;
    DMA_Width_t periph_width;
    DMA_Width_t mem_width;
    bool periph_increment;
    bool mem_increment;
    bool circular;
    DMA_Priority_t priority;
} DMA_Config_t;

/* Callback function type */
typedef void (*DMA_Callback_t)(void);

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize DMA controller
 * @param instance DMA instance
 */
void HAL_DMA_Init(DMA_Instance_t instance);

/**
 * @brief Configure DMA channel
 * @param instance DMA instance
 * @param channel DMA channel
 * @param config Configuration parameters
 */
void HAL_DMA_ConfigChannel(DMA_Instance_t instance, DMA_Channel_t channel,
                           const DMA_Config_t *config);

/**
 * @brief Start DMA transfer
 * @param instance DMA instance
 * @param channel DMA channel
 * @param periph_addr Peripheral address
 * @param mem_addr Memory address
 * @param count Number of data items to transfer
 */
void HAL_DMA_Start(DMA_Instance_t instance, DMA_Channel_t channel,
                   uint32_t periph_addr, uint32_t mem_addr, uint32_t count);

/**
 * @brief Stop DMA transfer
 * @param instance DMA instance
 * @param channel DMA channel
 */
void HAL_DMA_Stop(DMA_Instance_t instance, DMA_Channel_t channel);

/**
 * @brief Check if DMA transfer is complete
 * @param instance DMA instance
 * @param channel DMA channel
 * @return true if complete
 */
bool HAL_DMA_IsComplete(DMA_Instance_t instance, DMA_Channel_t channel);

/**
 * @brief Get remaining transfer count
 * @param instance DMA instance
 * @param channel DMA channel
 * @return Remaining data count
 */
uint32_t HAL_DMA_GetRemaining(DMA_Instance_t instance, DMA_Channel_t channel);

/**
 * @brief Set transfer complete callback
 * @param instance DMA instance
 * @param channel DMA channel
 * @param callback Callback function
 */
void HAL_DMA_SetCallback(DMA_Instance_t instance, DMA_Channel_t channel,
                         DMA_Callback_t callback);

/**
 * @brief Enable DMA interrupt
 * @param instance DMA instance
 * @param channel DMA channel
 */
void HAL_DMA_EnableInterrupt(DMA_Instance_t instance, DMA_Channel_t channel);

/**
 * @brief Clear DMA interrupt flags
 * @param instance DMA instance
 * @param channel DMA channel
 */
void HAL_DMA_ClearFlags(DMA_Instance_t instance, DMA_Channel_t channel);

#ifdef __cplusplus
}
#endif

#endif /* HAL_DMA_H */

