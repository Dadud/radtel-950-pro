/**
 * @file keypad.h
 * @brief Keypad Matrix Driver
 * 
 * Driver for the 4x5 matrix keypad on the RT-950 Pro.
 * 
 * Interface: Matrix scan [CONFIRMED from OEM firmware]
 *   - Row outputs (active high): PC0-PC3
 *   - Column inputs: PD4-PD7
 *   - Scan enable: PE5
 *   - Latch sense: PA12
 * 
 * Scanning is performed in FUN_80013618 in the OEM firmware.
 */

#ifndef DRIVERS_KEYPAD_H
#define DRIVERS_KEYPAD_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * KEYPAD CONFIGURATION
 * ============================================================================ */

#define KEYPAD_ROWS         4
#define KEYPAD_COLS         5
#define KEYPAD_DEBOUNCE_MS  20

/* ============================================================================
 * KEY CODES (INFERRED from OEM firmware key handler analysis)
 * ============================================================================
 * 
 * These key codes are INFERRED from the button handlers in the OEM firmware.
 * Physical layout may differ - needs hardware verification.
 */

typedef enum {
    KEY_NONE = 0,
    
    /* Numeric keys */
    KEY_0 = '0',
    KEY_1 = '1',
    KEY_2 = '2',
    KEY_3 = '3',
    KEY_4 = '4',
    KEY_5 = '5',
    KEY_6 = '6',
    KEY_7 = '7',
    KEY_8 = '8',
    KEY_9 = '9',
    
    /* Function keys */
    KEY_STAR = '*',
    KEY_HASH = '#',
    
    /* Menu/navigation keys [INFERRED] */
    KEY_MENU = 0x80,
    KEY_UP,
    KEY_DOWN,
    KEY_EXIT,
    KEY_ENTER,
    KEY_VFO_MR,
    KEY_AB,
    KEY_SCAN,
    KEY_FM,
    KEY_CALL,
    
    /* Side keys [INFERRED from pin analysis] */
    KEY_PTT = 0x90,
    KEY_PTT_EXT,
    KEY_SIDE1,
    KEY_SIDE2,
    KEY_SIDE3,
    KEY_SIDE4,
    
    /* Encoder events [INFERRED from FUN_8000e2e0] */
    KEY_ENCODER_CW = 0xA0,      /* Clockwise rotation */
    KEY_ENCODER_CCW,            /* Counter-clockwise rotation */
    KEY_ENCODER_PUSH,           /* Encoder button press */
    
    KEY_INVALID = 0xFF
} Key_t;

/* ============================================================================
 * KEY EVENT TYPES
 * ============================================================================ */

typedef enum {
    KEY_EVENT_NONE = 0,
    KEY_EVENT_PRESS,            /* Key just pressed */
    KEY_EVENT_RELEASE,          /* Key just released */
    KEY_EVENT_SHORT,            /* Short press completed */
    KEY_EVENT_LONG,             /* Long press detected (while held) */
    KEY_EVENT_REPEAT            /* Key repeat (while held) */
} KeyEvent_t;

/* ============================================================================
 * KEY STATE STRUCTURE
 * ============================================================================ */

typedef struct {
    Key_t key;                  /* Which key */
    KeyEvent_t event;           /* Event type */
    uint32_t timestamp;         /* When event occurred */
    uint32_t duration;          /* How long held (for release/long) */
} KeyState_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize keypad hardware
 * 
 * Configures GPIO pins for matrix scanning.
 * INFERRED: Pin configuration from OEM firmware GPIO setup.
 */
void Keypad_Init(void);

/**
 * @brief Process keypad scanning (call periodically)
 * 
 * Should be called from main loop or timer interrupt.
 * Performs matrix scan and debouncing.
 * CONFIRMED: Scan algorithm from FUN_80013618 in OEM firmware.
 */
void Keypad_Process(void);

/**
 * @brief Get current key state
 * @param state Pointer to state structure to fill
 * @return true if there is an event to process
 */
bool Keypad_GetEvent(KeyState_t *state);

/**
 * @brief Check if a specific key is currently pressed
 * @param key Key to check
 * @return true if key is held down
 */
bool Keypad_IsPressed(Key_t key);

/**
 * @brief Get raw key scan code (for debugging)
 * @return Raw matrix scan value
 */
uint16_t Keypad_GetRawScan(void);

/**
 * @brief Set long press threshold
 * @param ms Time in milliseconds to trigger long press
 */
void Keypad_SetLongPressTime(uint32_t ms);

/**
 * @brief Set key repeat rate
 * @param initial_ms Initial delay before repeat
 * @param repeat_ms Delay between repeats
 */
void Keypad_SetRepeatRate(uint32_t initial_ms, uint32_t repeat_ms);

/**
 * @brief Enable/disable keypad beep
 * @param enable true to enable beep on keypress
 */
void Keypad_SetBeepEnabled(bool enable);

/**
 * @brief Set keypad backlight
 * @param enable true to turn on keypad backlight
 * 
 * CONFIRMED: Backlight on PB3
 */
void Keypad_SetBacklight(bool enable);

#ifdef __cplusplus
}
#endif

#endif /* DRIVERS_KEYPAD_H */


