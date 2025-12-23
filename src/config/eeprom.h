/**
 * @file eeprom.h
 * @brief EEPROM/Flash Storage
 */

#ifndef CONFIG_EEPROM_H
#define CONFIG_EEPROM_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void EEPROM_Init(void);
void EEPROM_DeInit(void);
bool EEPROM_Read(uint32_t address, uint8_t *data, uint32_t length);
bool EEPROM_Write(uint32_t address, const uint8_t *data, uint32_t length);
bool EEPROM_Erase(void);
bool EEPROM_ReadByte(uint32_t address, uint8_t *data);
bool EEPROM_WriteByte(uint32_t address, uint8_t data);
bool EEPROM_ReadWord(uint32_t address, uint32_t *data);
bool EEPROM_WriteWord(uint32_t address, uint32_t data);
bool EEPROM_WriteInternalFlash(uint32_t address, const uint8_t *data, uint32_t length);
bool EEPROM_EraseInternalFlash(uint32_t address);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_EEPROM_H */

