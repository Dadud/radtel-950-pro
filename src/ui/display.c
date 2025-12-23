/**
 * @file display.c
 * @brief Display Manager Implementation
 */

#include "ui/display.h"
#include "ui/fonts.h"
#include "drivers/lcd.h"
#include "radio/radio.h"
#include "radio/vfo.h"
#include "drivers/power.h"
#include "hal/system.h"

#include <stdio.h>
#include <string.h>

/* Display state */
static struct {
    bool initialized;
    bool needs_refresh;
    uint16_t fg_color;
    uint16_t bg_color;
} g_display;

/* Color definitions (RGB565) */
#define COLOR_BLACK         0x0000
#define COLOR_WHITE         0xFFFF
#define COLOR_RED           0xF800
#define COLOR_GREEN         0x07E0
#define COLOR_BLUE          0x001F
#define COLOR_YELLOW        0xFFE0
#define COLOR_CYAN          0x07FF
#define COLOR_MAGENTA       0xF81F
#define COLOR_ORANGE        0xFC00
#define COLOR_GRAY          0x8410
#define COLOR_DARK_GRAY     0x4208

void Display_Init(void)
{
    LCD_Init();
    
    g_display.initialized = true;
    g_display.needs_refresh = true;
    g_display.fg_color = COLOR_WHITE;
    g_display.bg_color = COLOR_BLACK;
    
    Display_Clear();
}

void Display_Clear(void)
{
    LCD_FillRect(0, 0, 320, 240, g_display.bg_color);
}

void Display_SetColor(uint16_t fg, uint16_t bg)
{
    g_display.fg_color = fg;
    g_display.bg_color = bg;
}

void Display_DrawText(uint16_t x, uint16_t y, const char *text, uint8_t size)
{
    Fonts_DrawString(x, y, text, g_display.fg_color, g_display.bg_color, size);
}

void Display_DrawRect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color)
{
    LCD_DrawRect(x, y, w, h, color);
}

void Display_FillRect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color)
{
    LCD_FillRect(x, y, w, h, color);
}

void Display_DrawLine(uint16_t x1, uint16_t y1, uint16_t x2, uint16_t y2, uint16_t color)
{
    LCD_DrawLine(x1, y1, x2, y2, color);
}

void Display_Flush(void)
{
    LCD_Refresh();
    g_display.needs_refresh = false;
}

void Display_Update(void)
{
    if (g_display.needs_refresh) {
        Display_Flush();
    }
}

void Display_Invalidate(void)
{
    g_display.needs_refresh = true;
}

void Display_ShowBootScreen(void)
{
    Display_Clear();
    
    /* Draw logo/title */
    Display_SetColor(COLOR_CYAN, COLOR_BLACK);
    Display_DrawText(80, 80, "RT-950 Pro", 3);
    
    Display_SetColor(COLOR_WHITE, COLOR_BLACK);
    Display_DrawText(90, 130, "Open Firmware", 2);
    
    Display_SetColor(COLOR_GRAY, COLOR_BLACK);
    Display_DrawText(100, 180, "v0.1.0", 1);
    
    Display_Flush();
}

void Display_ShowShutdownScreen(void)
{
    Display_Clear();
    
    Display_SetColor(COLOR_ORANGE, COLOR_BLACK);
    Display_DrawText(100, 100, "Goodbye!", 3);
    
    Display_Flush();
}

void Display_ShowStatus(const char *status)
{
    /* Draw status bar at bottom */
    Display_FillRect(0, 220, 320, 20, COLOR_DARK_GRAY);
    Display_SetColor(COLOR_WHITE, COLOR_DARK_GRAY);
    Display_DrawText(10, 222, status, 1);
    Display_Flush();
}

void Display_DrawMainScreen(void)
{
    char buf[32];
    
    Display_Clear();
    
    /* Draw frequency */
    VFO_t *vfo = VFO_GetActive();
    uint32_t freq = vfo->frequency;
    
    snprintf(buf, sizeof(buf), "%3lu.%05lu", 
             (unsigned long)(freq / 1000000),
             (unsigned long)((freq % 1000000) / 10));
    
    Display_SetColor(COLOR_GREEN, COLOR_BLACK);
    Display_DrawText(20, 60, buf, 4);
    
    /* Draw MHz label */
    Display_SetColor(COLOR_GRAY, COLOR_BLACK);
    Display_DrawText(280, 80, "MHz", 2);
    
    /* Draw VFO indicator */
    Display_SetColor(VFO_IsAActive() ? COLOR_YELLOW : COLOR_WHITE, COLOR_BLACK);
    Display_DrawText(10, 10, VFO_IsAActive() ? "VFO-A" : "VFO-B", 2);
    
    /* Draw power indicator */
    const char *power_str = "H";
    switch (vfo->tx_power) {
        case VFO_POWER_LOW: power_str = "L"; break;
        case VFO_POWER_MED: power_str = "M"; break;
        case VFO_POWER_HIGH: power_str = "H"; break;
    }
    Display_SetColor(COLOR_RED, COLOR_BLACK);
    Display_DrawText(280, 10, power_str, 2);
    
    /* Draw battery */
    uint8_t batt_pct = Power_GetBatteryPercent();
    snprintf(buf, sizeof(buf), "%d%%", batt_pct);
    Display_SetColor(batt_pct < 20 ? COLOR_RED : COLOR_GREEN, COLOR_BLACK);
    Display_DrawText(240, 10, buf, 1);
    
    /* Draw S-meter */
    int16_t rssi = Radio_GetRSSI();
    int16_t s_level = (rssi + 130) / 6;  /* Rough S-unit conversion */
    if (s_level < 0) s_level = 0;
    if (s_level > 15) s_level = 15;
    
    Display_FillRect(20, 160, 280, 20, COLOR_DARK_GRAY);
    Display_FillRect(20, 160, s_level * 18, 20, COLOR_GREEN);
    
    /* Draw status bar */
    Display_FillRect(0, 220, 320, 20, COLOR_DARK_GRAY);
    
    RadioState_t state = Radio_GetState();
    const char *state_str = "IDLE";
    uint16_t state_color = COLOR_WHITE;
    
    switch (state) {
        case RADIO_STATE_RX:
            state_str = "RX";
            state_color = COLOR_GREEN;
            break;
        case RADIO_STATE_TX:
            state_str = "TX";
            state_color = COLOR_RED;
            break;
        case RADIO_STATE_SCAN:
            state_str = "SCAN";
            state_color = COLOR_YELLOW;
            break;
        default:
            break;
    }
    
    Display_SetColor(state_color, COLOR_DARK_GRAY);
    Display_DrawText(10, 222, state_str, 1);
}

void Display_DrawMenu(void)
{
    Display_Clear();
    
    Display_SetColor(COLOR_WHITE, COLOR_BLUE);
    Display_FillRect(0, 0, 320, 30, COLOR_BLUE);
    Display_DrawText(10, 5, "Menu", 2);
    
    /* Menu items would be drawn by Menu module */
}

void Display_DrawFreqInput(void)
{
    Display_Clear();
    
    Display_SetColor(COLOR_WHITE, COLOR_BLACK);
    Display_DrawText(80, 80, "Enter Frequency", 2);
    Display_DrawText(100, 120, "___._____", 3);
}

void Display_DrawScan(void)
{
    Display_Clear();
    
    Display_SetColor(COLOR_YELLOW, COLOR_BLACK);
    Display_DrawText(120, 100, "SCANNING", 2);
}

void Display_DrawFM(void)
{
    Display_Clear();
    
    Display_SetColor(COLOR_CYAN, COLOR_BLACK);
    Display_DrawText(100, 80, "FM Radio", 2);
    Display_DrawText(80, 120, "87.5 MHz", 3);
}

void Display_DrawChannelList(void)
{
    Display_Clear();
    
    Display_SetColor(COLOR_WHITE, COLOR_BLUE);
    Display_FillRect(0, 0, 320, 30, COLOR_BLUE);
    Display_DrawText(10, 5, "Channels", 2);
}

void Display_ShowMessage(const char *title, const char *message)
{
    /* Draw message box */
    Display_FillRect(40, 80, 240, 80, COLOR_DARK_GRAY);
    Display_DrawRect(40, 80, 240, 80, COLOR_WHITE);
    
    Display_SetColor(COLOR_WHITE, COLOR_DARK_GRAY);
    Display_DrawText(50, 90, title, 2);
    Display_DrawText(50, 120, message, 1);
    
    Display_Flush();
}

void Display_ShowProgress(const char *title, uint8_t percent)
{
    Display_FillRect(40, 80, 240, 80, COLOR_DARK_GRAY);
    Display_DrawRect(40, 80, 240, 80, COLOR_WHITE);
    
    Display_SetColor(COLOR_WHITE, COLOR_DARK_GRAY);
    Display_DrawText(50, 90, title, 2);
    
    /* Progress bar */
    Display_FillRect(50, 120, 180, 20, COLOR_BLACK);
    Display_FillRect(50, 120, (180 * percent) / 100, 20, COLOR_GREEN);
    
    char buf[8];
    snprintf(buf, sizeof(buf), "%d%%", percent);
    Display_DrawText(240, 125, buf, 1);
    
    Display_Flush();
}

