/**
 * @file display.h
 * @brief Display Manager
 */

#ifndef UI_DISPLAY_H
#define UI_DISPLAY_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void Display_Init(void);
void Display_Clear(void);
void Display_SetColor(uint16_t fg, uint16_t bg);
void Display_DrawText(uint16_t x, uint16_t y, const char *text, uint8_t size);
void Display_DrawRect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color);
void Display_FillRect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color);
void Display_DrawLine(uint16_t x1, uint16_t y1, uint16_t x2, uint16_t y2, uint16_t color);
void Display_Flush(void);
void Display_Update(void);
void Display_Invalidate(void);

void Display_ShowBootScreen(void);
void Display_ShowShutdownScreen(void);
void Display_ShowStatus(const char *status);
void Display_DrawMainScreen(void);
void Display_DrawMenu(void);
void Display_DrawFreqInput(void);
void Display_DrawScan(void);
void Display_DrawFM(void);
void Display_DrawChannelList(void);
void Display_ShowMessage(const char *title, const char *message);
void Display_ShowProgress(const char *title, uint8_t percent);

#ifdef __cplusplus
}
#endif

#endif /* UI_DISPLAY_H */
