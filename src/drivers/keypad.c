/**
 * @file keypad.c
 * @brief Matrix Keypad Driver Implementation
 * 
 * 4x5 matrix keypad scanning.
 * Rows: PC0-PC3 (output)
 * Columns: PD4-PD7 (input with pull-down)
 */

#include "drivers/keypad.h"
#include "hal/gpio.h"
#include "hal/system.h"

/* Keypad configuration */
#define NUM_ROWS            4
#define NUM_COLS            5
#define DEBOUNCE_THRESHOLD  3
#define SCAN_INTERVAL_MS    10
#define DEFAULT_LONG_PRESS_MS   1000
#define DEFAULT_REPEAT_INITIAL  500
#define DEFAULT_REPEAT_RATE     100

/* Row pins (PC0-PC3) */
static const struct {
    GPIO_TypeDef *port;
    uint16_t pin;
} g_row_pins[NUM_ROWS] = {
    { GPIOC, GPIO_PIN_0 },
    { GPIOC, GPIO_PIN_1 },
    { GPIOC, GPIO_PIN_2 },
    { GPIOC, GPIO_PIN_3 }
};

/* Column pins (PD4-PD7, PE5) */
static const struct {
    GPIO_TypeDef *port;
    uint16_t pin;
} g_col_pins[NUM_COLS] = {
    { GPIOD, GPIO_PIN_7 },
    { GPIOD, GPIO_PIN_6 },
    { GPIOD, GPIO_PIN_5 },
    { GPIOD, GPIO_PIN_4 },
    { GPIOE, GPIO_PIN_5 }
};

/* Key mapping table [row][col] - INFERRED from OEM firmware */
static const Key_t g_key_map[NUM_ROWS][NUM_COLS] = {
    { KEY_1,     KEY_2,     KEY_3,     KEY_VFO_MR, KEY_NONE },
    { KEY_4,     KEY_5,     KEY_6,     KEY_AB,     KEY_NONE },
    { KEY_7,     KEY_8,     KEY_9,     KEY_SCAN,   KEY_NONE },
    { KEY_STAR,  KEY_0,     KEY_HASH,  KEY_FM,     KEY_SIDE1 }
};

/* Keypad state */
static struct {
    uint8_t debounce_count[NUM_ROWS][NUM_COLS];
    bool state[NUM_ROWS][NUM_COLS];
    bool prev_state[NUM_ROWS][NUM_COLS];
    
    Key_t current_key;
    uint32_t key_press_time;
    bool key_held;
    bool long_press_sent;
    bool repeat_sent;
    
    /* Event queue (simple single event) */
    KeyState_t pending_event;
    bool has_pending_event;
    
    /* Configuration */
    uint32_t long_press_ms;
    uint32_t repeat_initial_ms;
    uint32_t repeat_rate_ms;
    uint32_t last_repeat_time;
    bool beep_enabled;
    
    uint32_t last_scan_time;
} g_keypad;

void Keypad_Init(void)
{
    /* Configure row pins as outputs (active high) */
    for (int i = 0; i < NUM_ROWS; i++) {
        HAL_GPIO_Config(GPIO_PORT_C, g_row_pins[i].pin, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_10MHZ);
        g_row_pins[i].port->CLR = g_row_pins[i].pin;
    }
    
    /* Configure column pins as inputs with pull-down */
    for (int i = 0; i < 4; i++) {
        HAL_GPIO_Config(GPIO_PORT_D, g_col_pins[i].pin, GPIO_MODE_INPUT_PULLDOWN, GPIO_SPEED_10MHZ);
    }
    HAL_GPIO_Config(GPIO_PORT_E, GPIO_PIN_5, GPIO_MODE_INPUT_PULLDOWN, GPIO_SPEED_10MHZ);
    
    /* Configure keypad backlight (PB3) */
    HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_3, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_10MHZ);
    
    /* Initialize state */
    for (int r = 0; r < NUM_ROWS; r++) {
        for (int c = 0; c < NUM_COLS; c++) {
            g_keypad.debounce_count[r][c] = 0;
            g_keypad.state[r][c] = false;
            g_keypad.prev_state[r][c] = false;
        }
    }
    
    g_keypad.current_key = KEY_NONE;
    g_keypad.key_held = false;
    g_keypad.long_press_sent = false;
    g_keypad.repeat_sent = false;
    g_keypad.has_pending_event = false;
    
    g_keypad.long_press_ms = DEFAULT_LONG_PRESS_MS;
    g_keypad.repeat_initial_ms = DEFAULT_REPEAT_INITIAL;
    g_keypad.repeat_rate_ms = DEFAULT_REPEAT_RATE;
    g_keypad.beep_enabled = true;
    g_keypad.last_scan_time = 0;
}

static void keypad_push_event(Key_t key, KeyEvent_t event, uint32_t duration)
{
    g_keypad.pending_event.key = key;
    g_keypad.pending_event.event = event;
    g_keypad.pending_event.timestamp = HAL_GetTick();
    g_keypad.pending_event.duration = duration;
    g_keypad.has_pending_event = true;
}

static void keypad_scan_matrix(void)
{
    uint32_t now = HAL_GetTick();
    
    for (int row = 0; row < NUM_ROWS; row++) {
        /* Drive current row high */
        g_row_pins[row].port->SCR = g_row_pins[row].pin;
        
        /* Small delay for signal to settle */
        for (volatile int d = 0; d < 10; d++);
        
        /* Read columns */
        for (int col = 0; col < NUM_COLS; col++) {
            bool pressed = (g_col_pins[col].port->IDT & g_col_pins[col].pin) != 0;
            
            /* Debounce */
            if (pressed) {
                if (g_keypad.debounce_count[row][col] < DEBOUNCE_THRESHOLD) {
                    g_keypad.debounce_count[row][col]++;
                }
            } else {
                if (g_keypad.debounce_count[row][col] > 0) {
                    g_keypad.debounce_count[row][col]--;
                }
            }
            
            g_keypad.prev_state[row][col] = g_keypad.state[row][col];
            g_keypad.state[row][col] = (g_keypad.debounce_count[row][col] >= DEBOUNCE_THRESHOLD);
            
            /* Detect state changes */
            if (g_keypad.state[row][col] && !g_keypad.prev_state[row][col]) {
                /* Key pressed */
                Key_t key = g_key_map[row][col];
                if (key != KEY_NONE) {
                    g_keypad.current_key = key;
                    g_keypad.key_press_time = now;
                    g_keypad.key_held = true;
                    g_keypad.long_press_sent = false;
                    g_keypad.repeat_sent = false;
                    
                    keypad_push_event(key, KEY_EVENT_PRESS, 0);
                }
            }
            else if (!g_keypad.state[row][col] && g_keypad.prev_state[row][col]) {
                /* Key released */
                Key_t key = g_key_map[row][col];
                if (key != KEY_NONE && key == g_keypad.current_key) {
                    uint32_t duration = now - g_keypad.key_press_time;
                    
                    if (!g_keypad.long_press_sent) {
                        keypad_push_event(key, KEY_EVENT_SHORT, duration);
                    }
                    keypad_push_event(key, KEY_EVENT_RELEASE, duration);
                    
                    g_keypad.current_key = KEY_NONE;
                    g_keypad.key_held = false;
                }
            }
        }
        
        /* Drive row low */
        g_row_pins[row].port->CLR = g_row_pins[row].pin;
    }
    
    /* Handle long press and repeat */
    if (g_keypad.key_held && g_keypad.current_key != KEY_NONE) {
        uint32_t held_time = now - g_keypad.key_press_time;
        
        /* Long press detection */
        if (!g_keypad.long_press_sent && held_time >= g_keypad.long_press_ms) {
            keypad_push_event(g_keypad.current_key, KEY_EVENT_LONG, held_time);
            g_keypad.long_press_sent = true;
            g_keypad.last_repeat_time = now;
        }
        
        /* Repeat detection */
        if (g_keypad.long_press_sent) {
            uint32_t repeat_delay = g_keypad.repeat_sent ? 
                                    g_keypad.repeat_rate_ms : 
                                    g_keypad.repeat_initial_ms;
            
            if ((now - g_keypad.last_repeat_time) >= repeat_delay) {
                keypad_push_event(g_keypad.current_key, KEY_EVENT_REPEAT, held_time);
                g_keypad.last_repeat_time = now;
                g_keypad.repeat_sent = true;
            }
        }
    }
}

void Keypad_Process(void)
{
    uint32_t now = HAL_GetTick();
    
    if ((now - g_keypad.last_scan_time) >= SCAN_INTERVAL_MS) {
        g_keypad.last_scan_time = now;
        keypad_scan_matrix();
    }
}

bool Keypad_GetEvent(KeyState_t *state)
{
    if (!g_keypad.has_pending_event || state == NULL) {
        return false;
    }
    
    *state = g_keypad.pending_event;
    g_keypad.has_pending_event = false;
    
    return true;
}

bool Keypad_IsPressed(Key_t key)
{
    for (int r = 0; r < NUM_ROWS; r++) {
        for (int c = 0; c < NUM_COLS; c++) {
            if (g_key_map[r][c] == key && g_keypad.state[r][c]) {
                return true;
            }
        }
    }
    return false;
}

uint16_t Keypad_GetRawScan(void)
{
    uint16_t scan = 0;
    
    for (int r = 0; r < NUM_ROWS; r++) {
        for (int c = 0; c < NUM_COLS; c++) {
            if (g_keypad.state[r][c]) {
                scan |= (1 << (r * NUM_COLS + c));
            }
        }
    }
    
    return scan;
}

void Keypad_SetLongPressTime(uint32_t ms)
{
    g_keypad.long_press_ms = ms;
}

void Keypad_SetRepeatRate(uint32_t initial_ms, uint32_t repeat_ms)
{
    g_keypad.repeat_initial_ms = initial_ms;
    g_keypad.repeat_rate_ms = repeat_ms;
}

void Keypad_SetBeepEnabled(bool enable)
{
    g_keypad.beep_enabled = enable;
}

void Keypad_SetBacklight(bool enable)
{
    if (enable) {
        GPIOB->SCR = GPIO_PIN_3;
    } else {
        GPIOB->CLR = GPIO_PIN_3;
    }
}
