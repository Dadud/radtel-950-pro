/**
 * @file ui.h
 * @brief User Interface Management
 */

#ifndef UI_UI_H
#define UI_UI_H

#include <stdint.h>
#include <stdbool.h>
#include "drivers/keypad.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UI_SCREEN_BOOT = 0,
    UI_SCREEN_MAIN,
    UI_SCREEN_MENU,
    UI_SCREEN_SETTINGS,
    UI_SCREEN_FREQ_INPUT,
    UI_SCREEN_CHANNEL_LIST,
    UI_SCREEN_SCAN,
    UI_SCREEN_FM,
    UI_SCREEN_GPS,
    UI_SCREEN_ABOUT,
    UI_SCREEN_SHUTDOWN
} UI_Screen_t;

typedef enum {
    UI_EVENT_KEY_PRESS = 0,
    UI_EVENT_ENCODER,
    UI_EVENT_SCREEN_CHANGE,
    UI_EVENT_TIMEOUT
} UI_Event_t;

typedef void (*UI_Callback_t)(UI_Event_t event);

void UI_Init(void);
UI_Screen_t UI_GetScreen(void);
void UI_SetScreen(UI_Screen_t screen);
void UI_GoBack(void);
void UI_RegisterActivity(void);
void UI_SetScreenTimeout(uint32_t timeout_ms);
void UI_SetCallback(UI_Callback_t callback);
void UI_Process(void);
void UI_Refresh(void);
void UI_ShowMessage(const char *title, const char *message, uint32_t timeout_ms);
void UI_ShowProgress(const char *title, uint8_t percent);

#ifdef __cplusplus
}
#endif

#endif /* UI_UI_H */

