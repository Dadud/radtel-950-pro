/**
 * @file ui.c
 * @brief User Interface State Machine Implementation
 */

#include "ui/ui.h"
#include "ui/display.h"
#include "ui/menu.h"
#include "drivers/keypad.h"
#include "drivers/encoder.h"
#include "drivers/lcd.h"
#include "radio/radio.h"
#include "radio/vfo.h"
#include "hal/system.h"

/* UI state */
static struct {
    bool initialized;
    UI_Screen_t current_screen;
    UI_Screen_t previous_screen;
    uint32_t last_activity_time;
    uint32_t screen_timeout_ms;
    bool screen_off;
    UI_Callback_t callback;
} g_ui;

#define DEFAULT_SCREEN_TIMEOUT_MS   30000   /* 30 seconds */

void UI_Init(void)
{
    Display_Init();
    Menu_Init();
    
    g_ui.initialized = true;
    g_ui.current_screen = UI_SCREEN_MAIN;
    g_ui.previous_screen = UI_SCREEN_MAIN;
    g_ui.last_activity_time = HAL_GetTick();
    g_ui.screen_timeout_ms = DEFAULT_SCREEN_TIMEOUT_MS;
    g_ui.screen_off = false;
    g_ui.callback = NULL;
}

UI_Screen_t UI_GetScreen(void)
{
    return g_ui.current_screen;
}

void UI_SetScreen(UI_Screen_t screen)
{
    if (screen == g_ui.current_screen) return;
    
    g_ui.previous_screen = g_ui.current_screen;
    g_ui.current_screen = screen;
    
    /* Force immediate redraw */
    UI_Refresh();
    
    if (g_ui.callback) {
        g_ui.callback(UI_EVENT_SCREEN_CHANGE);
    }
}

void UI_GoBack(void)
{
    UI_SetScreen(g_ui.previous_screen);
}

void UI_RegisterActivity(void)
{
    g_ui.last_activity_time = HAL_GetTick();
    
    /* Turn screen back on if it was off */
    if (g_ui.screen_off) {
        g_ui.screen_off = false;
        LCD_BacklightOn();
    }
}

void UI_SetScreenTimeout(uint32_t timeout_ms)
{
    g_ui.screen_timeout_ms = timeout_ms;
}

void UI_SetCallback(UI_Callback_t callback)
{
    g_ui.callback = callback;
}

static void ui_handle_main_screen_key(Key_t key, KeyEvent_t event)
{
    if (event != KEY_EVENT_PRESS && event != KEY_EVENT_SHORT) return;
    
    switch (key) {
        case KEY_MENU:
            UI_SetScreen(UI_SCREEN_MENU);
            break;
            
        case KEY_VFO_MR:
            /* Toggle VFO/Memory mode */
            VFO_Toggle();
            break;
            
        case KEY_AB:
            /* Toggle VFO A/B */
            VFO_Toggle();
            break;
            
        case KEY_SCAN:
            UI_SetScreen(UI_SCREEN_SCAN);
            break;
            
        case KEY_FM:
            UI_SetScreen(UI_SCREEN_FM);
            break;
            
        case KEY_0:
        case KEY_1:
        case KEY_2:
        case KEY_3:
        case KEY_4:
        case KEY_5:
        case KEY_6:
        case KEY_7:
        case KEY_8:
        case KEY_9:
            /* Direct frequency entry */
            UI_SetScreen(UI_SCREEN_FREQ_INPUT);
            break;
            
        default:
            break;
    }
}

static void ui_handle_menu_key(Key_t key, KeyEvent_t event)
{
    if (event != KEY_EVENT_PRESS && event != KEY_EVENT_SHORT) return;
    
    switch (key) {
        case KEY_EXIT:
            UI_SetScreen(UI_SCREEN_MAIN);
            break;
            
        case KEY_UP:
        case KEY_ENCODER_CCW:
            Menu_Up();
            break;
            
        case KEY_DOWN:
        case KEY_ENCODER_CW:
            Menu_Down();
            break;
            
        case KEY_ENTER:
        case KEY_ENCODER_PUSH:
            Menu_Select();
            break;
            
        case KEY_MENU:
            Menu_Back();
            break;
            
        default:
            break;
    }
}

void UI_Process(void)
{
    if (!g_ui.initialized) return;
    
    uint32_t now = HAL_GetTick();
    
    /* Check screen timeout */
    if (g_ui.screen_timeout_ms > 0 && !g_ui.screen_off) {
        if ((now - g_ui.last_activity_time) >= g_ui.screen_timeout_ms) {
            g_ui.screen_off = true;
            LCD_BacklightOff();
        }
    }
    
    /* Process keypad events */
    KeyState_t key_state;
    while (Keypad_GetEvent(&key_state)) {
        UI_RegisterActivity();
        
        switch (g_ui.current_screen) {
            case UI_SCREEN_MAIN:
                ui_handle_main_screen_key(key_state.key, key_state.event);
                break;
                
            case UI_SCREEN_MENU:
            case UI_SCREEN_SETTINGS:
                ui_handle_menu_key(key_state.key, key_state.event);
                break;
                
            default:
                if (key_state.key == KEY_EXIT) {
                    UI_SetScreen(UI_SCREEN_MAIN);
                }
                break;
        }
    }
    
    /* Process encoder events */
    int8_t encoder_delta = Encoder_GetDelta();
    if (encoder_delta != 0) {
        UI_RegisterActivity();
        
        if (g_ui.current_screen == UI_SCREEN_MAIN) {
            /* Adjust frequency */
            if (encoder_delta > 0) {
                VFO_StepUp();
            } else {
                VFO_StepDown();
            }
        }
    }
    
    /* Update display */
    Display_Update();
}

void UI_Refresh(void)
{
    Display_Clear();
    
    switch (g_ui.current_screen) {
        case UI_SCREEN_MAIN:
            Display_DrawMainScreen();
            break;
            
        case UI_SCREEN_MENU:
        case UI_SCREEN_SETTINGS:
            Display_DrawMenu();
            break;
            
        case UI_SCREEN_FREQ_INPUT:
            Display_DrawFreqInput();
            break;
            
        case UI_SCREEN_SCAN:
            Display_DrawScan();
            break;
            
        case UI_SCREEN_FM:
            Display_DrawFM();
            break;
            
        case UI_SCREEN_CHANNEL_LIST:
            Display_DrawChannelList();
            break;
            
        default:
            Display_DrawMainScreen();
            break;
    }
    
    Display_Flush();
}

void UI_ShowMessage(const char *title, const char *message, uint32_t timeout_ms)
{
    Display_ShowMessage(title, message);
    
    if (timeout_ms > 0) {
        HAL_Delay(timeout_ms);
        UI_Refresh();
    }
}

void UI_ShowProgress(const char *title, uint8_t percent)
{
    Display_ShowProgress(title, percent);
}

