/**
 * @file menu.h
 * @brief Menu System
 */

#ifndef UI_MENU_H
#define UI_MENU_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MENU_ITEM_ACTION = 0,
    MENU_ITEM_TOGGLE,
    MENU_ITEM_VALUE,
    MENU_ITEM_CHOICE,
    MENU_ITEM_SUBMENU
} MenuItemType_t;

typedef enum {
    MENU_EVENT_ENTER = 0,
    MENU_EVENT_EXIT,
    MENU_EVENT_SELECT,
    MENU_EVENT_BACK,
    MENU_EVENT_VALUE_CHANGED
} MenuEvent_t;

typedef void (*Menu_ActionFunc_t)(void);
typedef void (*Menu_Callback_t)(MenuEvent_t event);

void Menu_Init(void);
void Menu_Enter(void);
void Menu_Exit(void);
void Menu_Up(void);
void Menu_Down(void);
void Menu_Select(void);
void Menu_Back(void);
uint8_t Menu_GetItemCount(void);
const char *Menu_GetItemLabel(uint8_t index);
uint8_t Menu_GetSelectedIndex(void);
bool Menu_IsEditing(void);
void Menu_SetCallback(Menu_Callback_t callback);
void Menu_Draw(void);

#ifdef __cplusplus
}
#endif

#endif /* UI_MENU_H */
