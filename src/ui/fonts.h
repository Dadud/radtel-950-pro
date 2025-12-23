/**
 * @file fonts.h
 * @brief Font Rendering
 */

#ifndef UI_FONTS_H
#define UI_FONTS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void Fonts_DrawChar(uint16_t x, uint16_t y, char c, uint16_t fg, uint16_t bg, uint8_t scale);
void Fonts_DrawString(uint16_t x, uint16_t y, const char *str, uint16_t fg, uint16_t bg, uint8_t scale);
uint16_t Fonts_GetStringWidth(const char *str, uint8_t scale);
uint16_t Fonts_GetCharHeight(uint8_t scale);

#ifdef __cplusplus
}
#endif

#endif /* UI_FONTS_H */

