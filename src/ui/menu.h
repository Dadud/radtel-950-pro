/**
 * @file menu.h
 * @brief Menu System
 * 
 * Hierarchical menu system for radio configuration.
 * Menu structure is INFERRED from OEM firmware UI analysis.
 */

#ifndef UI_MENU_H
#define UI_MENU_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * MENU CONFIGURATION
 * ============================================================================ */

#define MENU_MAX_ITEMS          32
#define MENU_MAX_DEPTH          4
#define MENU_NAME_MAX_LEN       16
#define MENU_VALUE_MAX_LEN      24

/* ============================================================================
 * MENU ITEM TYPES
 * ============================================================================ */

typedef enum {
    MENU_TYPE_SUBMENU = 0,      /* Opens a submenu */
    MENU_TYPE_ACTION,           /* Executes an action */
    MENU_TYPE_TOGGLE,           /* On/Off toggle */
    MENU_TYPE_SELECT,           /* Selection from list */
    MENU_TYPE_NUMBER,           /* Numeric value */
    MENU_TYPE_FREQUENCY,        /* Frequency input */
    MENU_TYPE_TEXT,             /* Text input */
    MENU_TYPE_READONLY          /* Display only */
} MenuItemType_t;

/* ============================================================================
 * MENU ID ENUMERATION (INFERRED from OEM menu analysis)
 * ============================================================================ */

typedef enum {
    MENU_ID_ROOT = 0,
    
    /* Radio settings */
    MENU_ID_SQL,                /* Squelch level */
    MENU_ID_STEP,               /* Frequency step */
    MENU_ID_TXPOWER,            /* TX power */
    MENU_ID_BANDWIDTH,          /* Channel bandwidth */
    MENU_ID_MODULATION,         /* Modulation mode */
    MENU_ID_CTCSS_RX,           /* RX CTCSS */
    MENU_ID_CTCSS_TX,           /* TX CTCSS */
    MENU_ID_DCS_RX,             /* RX DCS */
    MENU_ID_DCS_TX,             /* TX DCS */
    MENU_ID_OFFSET,             /* Repeater offset */
    MENU_ID_OFFSET_DIR,         /* Offset direction */
    
    /* Display settings */
    MENU_ID_DISPLAY,            /* Display submenu */
    MENU_ID_BRIGHTNESS,         /* LCD brightness */
    MENU_ID_CONTRAST,           /* LCD contrast */
    MENU_ID_TIMEOUT,            /* Display timeout */
    MENU_ID_COLOR_SCHEME,       /* Color scheme */
    
    /* Audio settings */
    MENU_ID_AUDIO,              /* Audio submenu */
    MENU_ID_VOLUME,             /* Volume */
    MENU_ID_BEEP,               /* Beep enable */
    MENU_ID_BEEP_VOL,           /* Beep volume */
    MENU_ID_ROGER,              /* Roger beep */
    MENU_ID_VOX,                /* VOX level */
    MENU_ID_VOX_DELAY,          /* VOX delay */
    
    /* Scan settings */
    MENU_ID_SCAN,               /* Scan submenu */
    MENU_ID_SCAN_MODE,          /* Scan mode */
    MENU_ID_SCAN_RESUME,        /* Scan resume */
    MENU_ID_SCAN_DELAY,         /* Scan delay */
    
    /* Power settings */
    MENU_ID_POWER,              /* Power submenu */
    MENU_ID_AUTO_OFF,           /* Auto power off */
    MENU_ID_BAT_SAVE,           /* Battery saver */
    MENU_ID_BAT_TYPE,           /* Battery type */
    
    /* Memory management */
    MENU_ID_MEMORY,             /* Memory submenu */
    MENU_ID_MEM_WRITE,          /* Write to memory */
    MENU_ID_MEM_DELETE,         /* Delete channel */
    MENU_ID_MEM_NAME,           /* Channel name */
    
    /* GPS settings */
    MENU_ID_GPS,                /* GPS submenu */
    MENU_ID_GPS_ENABLE,         /* GPS enable */
    MENU_ID_GPS_FORMAT,         /* Coordinate format */
    MENU_ID_GPS_TIMEZONE,       /* Timezone */
    
    /* Bluetooth settings */
    MENU_ID_BLUETOOTH,          /* Bluetooth submenu */
    MENU_ID_BT_ENABLE,          /* Bluetooth enable */
    MENU_ID_BT_PAIR,            /* Pairing mode */
    MENU_ID_BT_NAME,            /* Device name */
    
    /* System */
    MENU_ID_SYSTEM,             /* System submenu */
    MENU_ID_KEYLOCK,            /* Key lock */
    MENU_ID_LANGUAGE,           /* Language */
    MENU_ID_RESET,              /* Factory reset */
    MENU_ID_VERSION,            /* Version info */
    
    MENU_ID_COUNT
} MenuID_t;

/* ============================================================================
 * MENU ITEM STRUCTURE
 * ============================================================================ */

typedef struct MenuItem {
    MenuID_t id;                /* Item ID */
    const char *name;           /* Display name */
    MenuItemType_t type;        /* Item type */
    const struct MenuItem *submenu;  /* Pointer to submenu items */
    uint8_t submenu_count;      /* Number of submenu items */
    void *value_ptr;            /* Pointer to value */
    int32_t min_value;          /* Minimum value (for numbers) */
    int32_t max_value;          /* Maximum value (for numbers) */
    const char **options;       /* Option strings (for select) */
    uint8_t option_count;       /* Number of options */
    void (*callback)(MenuID_t id, int32_t value);  /* Value change callback */
} MenuItem_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize menu system
 */
void Menu_Init(void);

/**
 * @brief Open menu
 */
void Menu_Open(void);

/**
 * @brief Close menu
 */
void Menu_Close(void);

/**
 * @brief Check if menu is open
 * @return true if menu is active
 */
bool Menu_IsOpen(void);

/**
 * @brief Navigate up in menu
 */
void Menu_Up(void);

/**
 * @brief Navigate down in menu
 */
void Menu_Down(void);

/**
 * @brief Select current item / Enter submenu
 */
void Menu_Select(void);

/**
 * @brief Go back / Exit submenu
 */
void Menu_Back(void);

/**
 * @brief Increase value of current item
 */
void Menu_IncreaseValue(void);

/**
 * @brief Decrease value of current item
 */
void Menu_DecreaseValue(void);

/**
 * @brief Get current menu item
 * @return Pointer to current item
 */
const MenuItem_t *Menu_GetCurrentItem(void);

/**
 * @brief Get current menu index
 * @return Index of highlighted item
 */
uint8_t Menu_GetCurrentIndex(void);

/**
 * @brief Get current menu item count
 * @return Number of items in current menu level
 */
uint8_t Menu_GetItemCount(void);

/**
 * @brief Get menu depth
 * @return Current submenu depth (0 = root)
 */
uint8_t Menu_GetDepth(void);

/**
 * @brief Format current item value as string
 * @param buffer Output buffer
 * @param max_len Maximum buffer length
 * @return Length of formatted string
 */
int Menu_FormatValue(char *buffer, uint32_t max_len);

/**
 * @brief Draw menu on display
 */
void Menu_Draw(void);

/**
 * @brief Process menu input
 * @param key Key code
 * @return true if key was handled
 */
bool Menu_ProcessKey(uint8_t key);

#ifdef __cplusplus
}
#endif

#endif /* UI_MENU_H */



