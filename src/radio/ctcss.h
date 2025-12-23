/**
 * @file ctcss.h
 * @brief CTCSS/DCS Encoding and Decoding
 */

#ifndef RADIO_CTCSS_H
#define RADIO_CTCSS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CTCSS Functions */
void CTCSS_Init(void);
uint8_t CTCSS_GetToneCount(void);
uint16_t CTCSS_GetToneFreq(uint8_t index);
int8_t CTCSS_FindTone(uint16_t freq_tenths);
void CTCSS_SetTX(uint16_t freq_tenths);
void CTCSS_SetRX(uint16_t freq_tenths);
void CTCSS_StartTX(void);
void CTCSS_StopTX(void);
void CTCSS_StartRX(void);
void CTCSS_StopRX(void);
bool CTCSS_IsDetected(void);
uint16_t CTCSS_GetDetected(void);
void CTCSS_Process(void);

/* DCS Functions */
uint8_t DCS_GetCodeCount(void);
uint16_t DCS_GetCode(uint8_t index);
int8_t DCS_FindCode(uint16_t code);
void DCS_SetTX(uint16_t code, bool inverted);
void DCS_SetRX(uint16_t code, bool inverted);
void DCS_StartTX(void);
void DCS_StopTX(void);
void DCS_StartRX(void);
void DCS_StopRX(void);
bool DCS_IsDetected(void);
uint16_t DCS_GetDetected(void);
void DCS_Process(void);

#ifdef __cplusplus
}
#endif

#endif /* RADIO_CTCSS_H */

