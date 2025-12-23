/**
 * @file menu.c
 * @brief Menu System Implementation
 */

#include "ui/menu.h"
#include "ui/display.h"
#include "config/settings.h"
#include "hal/system.h"

#include <string.h>

/* Menu item definition */
typedef struct {
    const char *label;
    MenuItemType_t type;
    void *value;
    int32_t min_value;
    int32_t max_value;
    const char **options;
    uint8_t option_count;
    Menu_ActionFunc_t action;
} MenuItem_Internal_t;

/* Menu state */
static struct {
    bool initialized;
    uint8_t current_menu;
    uint8_t current_item;
    uint8_t top_item;       /* For scrolling */
    bool editing;
    int32_t edit_value;
    Menu_Callback_t callback;
} g_menu;

#define VISIBLE_ITEMS       6
#define MENU_MAIN           0
#define MENU_RADIO          1
#define MENU_DISPLAY        2
#define MENU_SOUND          3
#define MENU_SYSTEM         4

/* Main menu items */
static const char *main_menu_items[] = {
    "Radio Settings",
    "Display",
    "Sound",
    "System",
    "About",
    "Exit"
};
#define MAIN_MENU_COUNT     6

/* Radio menu items */
static const char *radio_menu_items[] = {
    "Squelch",
    "TX Power",
    "CTCSS TX",
    "CTCSS RX",
    "DCS TX",
    "DCS RX",
    "Bandwidth",
    "Step",
    "Back"
};
#define RADIO_MENU_COUNT    9

void Menu_Init(void)
{
    g_menu.initialized = true;
    g_menu.current_menu = MENU_MAIN;
    g_menu.current_item = 0;
    g_menu.top_item = 0;
    g_menu.editing = false;
    g_menu.callback = NULL;
}

void Menu_Enter(void)
{
    g_menu.current_menu = MENU_MAIN;
    g_menu.current_item = 0;
    g_menu.top_item = 0;
    g_menu.editing = false;
}

void Menu_Exit(void)
{
    g_menu.editing = false;
}

void Menu_Up(void)
{
    if (g_menu.editing) {
        g_menu.edit_value++;
        return;
    }
    
    if (g_menu.current_item > 0) {
        g_menu.current_item--;
        
        /* Scroll if needed */
        if (g_menu.current_item < g_menu.top_item) {
            g_menu.top_item = g_menu.current_item;
        }
    }
}

void Menu_Down(void)
{
    if (g_menu.editing) {
        g_menu.edit_value--;
        return;
    }
    
    uint8_t max_items;
    switch (g_menu.current_menu) {
        case MENU_MAIN:
            max_items = MAIN_MENU_COUNT;
            break;
        case MENU_RADIO:
            max_items = RADIO_MENU_COUNT;
            break;
        default:
            max_items = 1;
            break;
    }
    
    if (g_menu.current_item < max_items - 1) {
        g_menu.current_item++;
        
        /* Scroll if needed */
        if (g_menu.current_item >= g_menu.top_item + VISIBLE_ITEMS) {
            g_menu.top_item = g_menu.current_item - VISIBLE_ITEMS + 1;
        }
    }
}

void Menu_Select(void)
{
    if (g_menu.editing) {
        /* Save edited value */
        g_menu.editing = false;
        
        if (g_menu.callback) {
            g_menu.callback(MENU_EVENT_VALUE_CHANGED);
        }
        return;
    }
    
    /* Handle menu selection */
    if (g_menu.current_menu == MENU_MAIN) {
        switch (g_menu.current_item) {
            case 0: /* Radio Settings */
                g_menu.current_menu = MENU_RADIO;
                g_menu.current_item = 0;
                g_menu.top_item = 0;
                break;
            case 1: /* Display */
                g_menu.current_menu = MENU_DISPLAY;
                g_menu.current_item = 0;
                g_menu.top_item = 0;
                break;
            case 2: /* Sound */
                g_menu.current_menu = MENU_SOUND;
                g_menu.current_item = 0;
                g_menu.top_item = 0;
                break;
            case 3: /* System */
                g_menu.current_menu = MENU_SYSTEM;
                g_menu.current_item = 0;
                g_menu.top_item = 0;
                break;
            case 4: /* About */
                /* Show about dialog */
                break;
            case 5: /* Exit */
                Menu_Exit();
                if (g_menu.callback) {
                    g_menu.callback(MENU_EVENT_EXIT);
                }
                break;
        }
    }
    else if (g_menu.current_menu == MENU_RADIO) {
        if (g_menu.current_item == RADIO_MENU_COUNT - 1) {
            /* Back */
            Menu_Back();
        } else {
            /* Start editing this value */
            g_menu.editing = true;
        }
    }
    
    if (g_menu.callback) {
        g_menu.callback(MENU_EVENT_SELECT);
    }
}

void Menu_Back(void)
{
    if (g_menu.editing) {
        g_menu.editing = false;
        return;
    }
    
    if (g_menu.current_menu != MENU_MAIN) {
        g_menu.current_menu = MENU_MAIN;
        g_menu.current_item = 0;
        g_menu.top_item = 0;
        
        if (g_menu.callback) {
            g_menu.callback(MENU_EVENT_BACK);
        }
    }
}

uint8_t Menu_GetItemCount(void)
{
    switch (g_menu.current_menu) {
        case MENU_MAIN:
            return MAIN_MENU_COUNT;
        case MENU_RADIO:
            return RADIO_MENU_COUNT;
        default:
            return 0;
    }
}

const char *Menu_GetItemLabel(uint8_t index)
{
    switch (g_menu.current_menu) {
        case MENU_MAIN:
            if (index < MAIN_MENU_COUNT) {
                return main_menu_items[index];
            }
            break;
        case MENU_RADIO:
            if (index < RADIO_MENU_COUNT) {
                return radio_menu_items[index];
            }
            break;
        default:
            break;
    }
    return "";
}

uint8_t Menu_GetSelectedIndex(void)
{
    return g_menu.current_item;
}

bool Menu_IsEditing(void)
{
    return g_menu.editing;
}

void Menu_SetCallback(Menu_Callback_t callback)
{
    g_menu.callback = callback;
}

void Menu_Draw(void)
{
    /* This would render the menu to the display */
    /* Called from Display_DrawMenu() */
}

