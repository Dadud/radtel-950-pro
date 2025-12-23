/**
 * @file vfo.h
 * @brief VFO Management
 */

#ifndef RADIO_VFO_H
#define RADIO_VFO_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VFO_OFFSET_NONE = 0,
    VFO_OFFSET_PLUS,
    VFO_OFFSET_MINUS
} VFO_Offset_t;

typedef enum {
    VFO_MOD_FM = 0,
    VFO_MOD_NFM,
    VFO_MOD_AM,
    VFO_MOD_USB,
    VFO_MOD_LSB
} VFO_Modulation_t;

typedef enum {
    VFO_BW_NARROW = 0,
    VFO_BW_WIDE
} VFO_Bandwidth_t;

typedef enum {
    VFO_POWER_LOW = 0,
    VFO_POWER_MED,
    VFO_POWER_HIGH
} VFO_Power_t;

typedef struct {
    uint32_t frequency;
    uint32_t tx_offset;
    VFO_Offset_t offset_direction;
    uint16_t tx_ctcss;
    uint16_t rx_ctcss;
    uint16_t tx_dcs;
    uint16_t rx_dcs;
    VFO_Modulation_t modulation;
    VFO_Bandwidth_t bandwidth;
    VFO_Power_t tx_power;
    uint32_t step;
} VFO_t;

void VFO_Init(void);
VFO_t *VFO_GetActive(void);
VFO_t *VFO_GetA(void);
VFO_t *VFO_GetB(void);
bool VFO_IsAActive(void);
void VFO_SetActive(bool use_a);
void VFO_Toggle(void);
bool VFO_SetFrequency(uint32_t freq);
uint32_t VFO_GetFrequency(void);
uint32_t VFO_GetTXFrequency(void);
void VFO_StepUp(void);
void VFO_StepDown(void);
void VFO_SetStep(uint32_t step_hz);
uint32_t VFO_GetStep(void);
void VFO_SetOffset(int32_t offset_hz);
int32_t VFO_GetOffset(void);
void VFO_CopyAtoB(void);
void VFO_CopyBtoA(void);
void VFO_Swap(void);

#ifdef __cplusplus
}
#endif

#endif /* RADIO_VFO_H */

