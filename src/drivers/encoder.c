/**
 * @file encoder.c
 * @brief Rotary Encoder Driver Implementation
 * 
 * CONFIRMED: Implementation based on Ghidra analysis of FUN_0800e2e0
 * 
 * Hardware connections (CONFIRMED):
 *   - Phase A: PB4 (mask 0x10)
 *   - Phase B: PB5 (mask 0x20)
 * 
 * The OEM firmware uses a state machine to decode quadrature signals
 * with debouncing. Events are generated for CW (0x14) and CCW (0x16).
 */

#include "drivers/encoder.h"
#include "hal/gpio.h"
#include "hal/system.h"

/* CONFIRMED: GPIO pins from OEM firmware analysis */
#define ENCODER_PORT        GPIOB
#define ENCODER_PHASE_A     GPIO_PIN_4      /* Mask 0x10 in OEM */
#define ENCODER_PHASE_B     GPIO_PIN_5      /* Mask 0x20 in OEM */

/* Debounce delay (CONFIRMED: pbVar1[4] = 200 in OEM) */
#define ENCODER_DEBOUNCE_TICKS  200

/* State machine states (CONFIRMED from FUN_0800e2e0) */
typedef enum {
    ENC_STATE_IDLE = 0,         /* Waiting for first transition */
    ENC_STATE_PHASE_A = 1,      /* Phase A changed first */
    ENC_STATE_PHASE_B = 2       /* Phase B changed first */
} EncoderStateEnum_t;

/* Direction codes (CONFIRMED from OEM) */
#define ENC_DIRECTION_NONE  0
#define ENC_DIRECTION_CW    1   /* Generates event 0x14 in OEM */
#define ENC_DIRECTION_CCW   2   /* Generates event 0x16 in OEM */

/* Internal state */
static struct {
    uint8_t last_a;                 /* Last state of phase A */
    uint8_t last_b;                 /* Last state of phase B */
    uint8_t debounce;               /* Debounce counter */
    EncoderStateEnum_t state;       /* State machine state */
    uint8_t pending_direction;      /* Pending direction (if debouncing) */
    int32_t position;               /* Accumulated position */
    int32_t delta;                  /* Delta since last read */
    uint32_t last_event_time;       /* For acceleration detection */
    bool button_pressed;            /* Button state */
    bool accel_enabled;             /* Acceleration enabled */
    uint32_t accel_threshold_ms;    /* Fast mode threshold */
    uint8_t accel_multiplier;       /* Fast mode multiplier */
    EncoderEvent_t pending_event;   /* Pending event to return */
    bool initialized;
} g_encoder = {0};

/**
 * @brief Read current phase states
 */
static inline uint8_t read_phase_a(void)
{
    return (ENCODER_PORT->IDT & ENCODER_PHASE_A) ? 1 : 0;
}

static inline uint8_t read_phase_b(void)
{
    return (ENCODER_PORT->IDT & ENCODER_PHASE_B) ? 1 : 0;
}

/**
 * @brief Initialize encoder interface
 */
void Encoder_Init(void)
{
    /* Configure phase pins as inputs with pull-up */
    HAL_GPIO_Config(GPIO_PORT_B, ENCODER_PHASE_A | ENCODER_PHASE_B,
                    GPIO_MODE_INPUT_PU, GPIO_SPEED_50MHZ);
    
    /* Initialize state */
    g_encoder.last_a = read_phase_a();
    g_encoder.last_b = read_phase_b();
    g_encoder.debounce = 0;
    g_encoder.state = ENC_STATE_IDLE;
    g_encoder.pending_direction = ENC_DIRECTION_NONE;
    g_encoder.position = 0;
    g_encoder.delta = 0;
    g_encoder.last_event_time = 0;
    g_encoder.button_pressed = false;
    g_encoder.accel_enabled = true;
    g_encoder.accel_threshold_ms = 100;
    g_encoder.accel_multiplier = 4;
    g_encoder.pending_event = ENCODER_EVENT_NONE;
    g_encoder.initialized = true;
}

/**
 * @brief Process encoder state machine
 * 
 * CONFIRMED: Implements the logic from FUN_0800e2e0
 * This should be called periodically from a timer interrupt or main loop.
 */
void Encoder_Process(void)
{
    if (!g_encoder.initialized) return;
    
    /* Handle debounce countdown */
    if (g_encoder.debounce > 0) {
        g_encoder.debounce--;
        
        if (g_encoder.debounce == 0 && g_encoder.pending_direction != ENC_DIRECTION_NONE) {
            /* Debounce complete - generate event */
            uint32_t now = HAL_GetTick();
            bool is_fast = (now - g_encoder.last_event_time) < g_encoder.accel_threshold_ms;
            g_encoder.last_event_time = now;
            
            int8_t step = 1;
            if (is_fast && g_encoder.accel_enabled) {
                step = g_encoder.accel_multiplier;
            }
            
            if (g_encoder.pending_direction == ENC_DIRECTION_CW) {
                g_encoder.position += step;
                g_encoder.delta += step;
                g_encoder.pending_event = is_fast ? ENCODER_EVENT_CW_FAST : ENCODER_EVENT_CW;
            } else {
                g_encoder.position -= step;
                g_encoder.delta -= step;
                g_encoder.pending_event = is_fast ? ENCODER_EVENT_CCW_FAST : ENCODER_EVENT_CCW;
            }
            
            g_encoder.pending_direction = ENC_DIRECTION_NONE;
        }
        return;
    }
    
    /* Read current states */
    uint8_t current_a = read_phase_a();
    uint8_t current_b = read_phase_b();
    
    switch (g_encoder.state) {
        case ENC_STATE_IDLE:
            /* Wait for first phase transition */
            if (current_a != g_encoder.last_a) {
                /* Phase A changed first */
                g_encoder.last_a = current_a;
                g_encoder.state = ENC_STATE_PHASE_A;
            } else if (current_b != g_encoder.last_b) {
                /* Phase B changed first */
                g_encoder.last_b = current_b;
                g_encoder.state = ENC_STATE_PHASE_B;
            }
            break;
            
        case ENC_STATE_PHASE_A:
            /* Phase A changed first - wait for matching state */
            if (current_a != g_encoder.last_a) {
                /* Phase A changed again - reset */
                g_encoder.last_a = current_a;
                g_encoder.last_b = current_b;
                g_encoder.state = ENC_STATE_IDLE;
            } else if (current_b != g_encoder.last_b) {
                /* Phase B also changed */
                if (current_a == current_b) {
                    /* Phases match - CW rotation detected */
                    g_encoder.pending_direction = ENC_DIRECTION_CW;
                    g_encoder.debounce = ENCODER_DEBOUNCE_TICKS;
                    g_encoder.state = ENC_STATE_IDLE;
                }
                g_encoder.last_b = current_b;
            }
            break;
            
        case ENC_STATE_PHASE_B:
            /* Phase B changed first - wait for matching state */
            if (current_b != g_encoder.last_b) {
                /* Phase B changed again - reset */
                g_encoder.last_a = current_a;
                g_encoder.last_b = current_b;
                g_encoder.state = ENC_STATE_IDLE;
            } else if (current_a != g_encoder.last_a) {
                /* Phase A also changed */
                if (current_a == current_b) {
                    /* Phases match - CCW rotation detected */
                    g_encoder.pending_direction = ENC_DIRECTION_CCW;
                    g_encoder.debounce = ENCODER_DEBOUNCE_TICKS;
                    g_encoder.state = ENC_STATE_IDLE;
                }
                g_encoder.last_a = current_a;
            }
            break;
    }
}

/**
 * @brief Get encoder event
 */
EncoderEvent_t Encoder_GetEvent(void)
{
    EncoderEvent_t event = g_encoder.pending_event;
    g_encoder.pending_event = ENCODER_EVENT_NONE;
    return event;
}

/**
 * @brief Get current encoder position
 */
int32_t Encoder_GetPosition(void)
{
    return g_encoder.position;
}

/**
 * @brief Reset encoder position to zero
 */
void Encoder_ResetPosition(void)
{
    g_encoder.position = 0;
}

/**
 * @brief Get delta since last call
 */
int32_t Encoder_GetDelta(void)
{
    int32_t delta = g_encoder.delta;
    g_encoder.delta = 0;
    return delta;
}

/**
 * @brief Check if encoder button is pressed
 */
bool Encoder_IsButtonPressed(void)
{
    return g_encoder.button_pressed;
}

/**
 * @brief Get full encoder state
 */
void Encoder_GetState(EncoderState_t *state)
{
    if (state == NULL) return;
    
    state->position = g_encoder.position;
    state->delta = g_encoder.delta;
    state->button_pressed = g_encoder.button_pressed;
    state->last_event_time = g_encoder.last_event_time;
    state->is_fast = (HAL_GetTick() - g_encoder.last_event_time) < g_encoder.accel_threshold_ms;
}

/**
 * @brief Set acceleration threshold
 */
void Encoder_SetAccelThreshold(uint32_t threshold_ms)
{
    g_encoder.accel_threshold_ms = threshold_ms;
}

/**
 * @brief Set acceleration multiplier
 */
void Encoder_SetAccelMultiplier(uint8_t multiplier)
{
    g_encoder.accel_multiplier = multiplier;
}

/**
 * @brief Enable/disable acceleration
 */
void Encoder_SetAccelEnabled(bool enable)
{
    g_encoder.accel_enabled = enable;
}
