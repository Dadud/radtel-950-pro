/**
 * @file display.h
 * @brief Display Manager and Screen Rendering
 * 
 * High-level display management for rendering the radio UI.
 * Uses the LCD driver for low-level operations.
 * 
 * Display layout (INFERRED from UI analysis):
 *   - Status bar at top (battery, signal, icons)
 *   - Main frequency display in center
 *   - VFO/channel info below frequency
 *   - S-meter and signal bar
 *   - Function labels at bottom
 */

#ifndef UI_DISPLAY_H
#define UI_DISPLAY_H

#include <stdint.h>
#include <stdbool.h>
#include "radio/radio.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * DISPLAY LAYOUT CONSTANTS
 * ============================================================================ */

/* Screen regions */
#define DISP_STATUS_Y           0
#define DISP_STATUS_HEIGHT      24
#define DISP_MAIN_Y             24
#define DISP_MAIN_HEIGHT        120
#define DISP_INFO_Y             144
#define DISP_INFO_HEIGHT        48
#define DISP_SMETER_Y           192
#define DISP_SMETER_HEIGHT      24
#define DISP_FUNCTION_Y         216
#define DISP_FUNCTION_HEIGHT    24

/* Font sizes */
#define FONT_SMALL              1
#define FONT_MEDIUM             2
#define FONT_LARGE              3
#define FONT_XLARGE             4

/* ============================================================================
 * UI THEME COLORS
 * ============================================================================ */

typedef struct {
    uint16_t background;        /* Main background */
    uint16_t text_primary;      /* Primary text */
    uint16_t text_secondary;    /* Secondary text */
    uint16_t highlight;         /* Highlighted items */
    uint16_t status_bg;         /* Status bar background */
    uint16_t status_text;       /* Status bar text */
    uint16_t frequency;         /* Frequency display */
    uint16_t rx_active;         /* RX indicator */
    uint16_t tx_active;         /* TX indicator */
    uint16_t smeter_low;        /* S-meter low signal */
    uint16_t smeter_high;       /* S-meter high signal */
    uint16_t menu_bg;           /* Menu background */
    uint16_t menu_selected;     /* Menu selected item */
} DisplayTheme_t;

/* ============================================================================
 * DISPLAY SCREENS
 * ============================================================================ */

typedef enum {
    SCREEN_MAIN = 0,            /* Main VFO/frequency display */
    SCREEN_DUAL,                /* Dual VFO display */
    SCREEN_MEMORY,              /* Memory channel list */
    SCREEN_MENU,                /* Settings menu */
    SCREEN_FM,                  /* FM broadcast radio */
    SCREEN_SCAN,                /* Scan display */
    SCREEN_GPS,                 /* GPS information */
    SCREEN_SPECTRUM,            /* Spectrum display */
    SCREEN_ABOUT,               /* About/version info */
    SCREEN_BOOT,                /* Boot screen */
    SCREEN_SHUTDOWN             /* Shutdown screen */
} DisplayScreen_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize display manager
 */
void Display_Init(void);

/**
 * @brief Refresh display (call from main loop)
 * 
 * Updates changed portions of the screen.
 */
void Display_Refresh(void);

/**
 * @brief Force full display redraw
 */
void Display_Invalidate(void);

/**
 * @brief Set current display screen
 * @param screen Screen to display
 */
void Display_SetScreen(DisplayScreen_t screen);

/**
 * @brief Get current display screen
 * @return Current screen
 */
DisplayScreen_t Display_GetScreen(void);

/**
 * @brief Show boot screen
 */
void Display_ShowBootScreen(void);

/**
 * @brief Show shutdown screen
 */
void Display_ShowShutdownScreen(void);

/**
 * @brief Show status message
 * @param message Message to display
 */
void Display_ShowStatus(const char *message);

/**
 * @brief Show error message
 * @param message Error message
 */
void Display_ShowError(const char *message);

/**
 * @brief Show popup message
 * @param title Popup title
 * @param message Popup message
 * @param timeout_ms Auto-dismiss timeout (0 = manual dismiss)
 */
void Display_ShowPopup(const char *title, const char *message, 
                       uint32_t timeout_ms);

/**
 * @brief Dismiss any active popup
 */
void Display_DismissPopup(void);

/**
 * @brief Update frequency display
 * @param frequency Frequency in Hz
 * @param is_tx true if transmitting
 */
void Display_UpdateFrequency(uint32_t frequency, bool is_tx);

/**
 * @brief Update S-meter display
 * @param rssi RSSI in dBm
 */
void Display_UpdateSMeter(int16_t rssi);

/**
 * @brief Update status bar
 * @param status Radio status structure
 */
void Display_UpdateStatus(const RadioStatus_t *status);

/**
 * @brief Update VFO/channel info
 * @param vfo Current VFO
 * @param config VFO configuration
 */
void Display_UpdateVFOInfo(VFO_t vfo, const VFOConfig_t *config);

/**
 * @brief Show TX indicator
 * @param show true to show TX indicator
 */
void Display_ShowTXIndicator(bool show);

/**
 * @brief Draw battery indicator
 * @param percent Battery percentage (0-100)
 * @param charging true if charging
 */
void Display_DrawBattery(uint8_t percent, bool charging);

/**
 * @brief Draw signal strength bars
 * @param bars Number of bars (0-5)
 */
void Display_DrawSignal(uint8_t bars);

/**
 * @brief Set display theme
 * @param theme Theme configuration
 */
void Display_SetTheme(const DisplayTheme_t *theme);

/**
 * @brief Get current theme
 * @return Pointer to current theme
 */
const DisplayTheme_t *Display_GetTheme(void);

/**
 * @brief Set display brightness
 * @param percent Brightness percentage (0-100)
 */
void Display_SetBrightness(uint8_t percent);

#ifdef __cplusplus
}
#endif

#endif /* UI_DISPLAY_H */



