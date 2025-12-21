/**
 * @file encoder.h
 * @brief Rotary Encoder Driver
 * 
 * Driver for the front-panel rotary encoder used for tuning and menu navigation.
 * 
 * Hardware connection (CONFIRMED from OEM firmware):
 *   - Phase A: PB4 [CONFIRMED]
 *   - Phase B: PB5 [CONFIRMED]
 *   - Push button: (shared with keypad matrix or separate)
 * 
 * Encoder handling is implemented in FUN_8000e2e0 (Encoder_HandleQuadrature).
 * Uses a state machine for debouncing and direction detection.
 */

#ifndef DRIVERS_ENCODER_H
#define DRIVERS_ENCODER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * ENCODER CONFIGURATION
 * ============================================================================ */

#define ENCODER_DEBOUNCE_US     100     /* Debounce time in microseconds */
#define ENCODER_PULSE_PER_DET   4       /* Pulses per detent (typical: 4) */

/* ============================================================================
 * ENCODER EVENT TYPES
 * ============================================================================ */

typedef enum {
    ENCODER_EVENT_NONE = 0,
    ENCODER_EVENT_CW,           /* Clockwise rotation (one detent) */
    ENCODER_EVENT_CCW,          /* Counter-clockwise rotation */
    ENCODER_EVENT_CW_FAST,      /* Fast clockwise rotation */
    ENCODER_EVENT_CCW_FAST,     /* Fast counter-clockwise rotation */
    ENCODER_EVENT_PUSH,         /* Button pressed */
    ENCODER_EVENT_RELEASE,      /* Button released */
    ENCODER_EVENT_PUSH_CW,      /* Rotated while pushed (CW) */
    ENCODER_EVENT_PUSH_CCW      /* Rotated while pushed (CCW) */
} EncoderEvent_t;

/* ============================================================================
 * ENCODER STATE STRUCTURE
 * ============================================================================ */

typedef struct {
    int32_t position;           /* Cumulative position (signed) */
    int32_t delta;              /* Change since last check */
    bool button_pressed;        /* Button is currently pressed */
    uint32_t last_event_time;   /* Timestamp of last rotation */
    bool is_fast;               /* Fast rotation detected */
} EncoderState_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize encoder hardware
 * 
 * Configures GPIO pins and sets up interrupt handling.
 * CONFIRMED: Pins PB4/PB5 from FUN_8000e2e0 analysis.
 */
void Encoder_Init(void);

/**
 * @brief Process encoder state (call from main loop or interrupt)
 * 
 * Samples encoder pins and updates state machine.
 */
void Encoder_Process(void);

/**
 * @brief Get encoder event
 * @return Most recent event, or ENCODER_EVENT_NONE
 * 
 * Each event is returned only once.
 */
EncoderEvent_t Encoder_GetEvent(void);

/**
 * @brief Get current encoder position
 * @return Cumulative position value
 */
int32_t Encoder_GetPosition(void);

/**
 * @brief Reset encoder position to zero
 */
void Encoder_ResetPosition(void);

/**
 * @brief Get delta since last call
 * @return Position change (positive = CW, negative = CCW)
 * 
 * The delta is cleared after reading.
 */
int32_t Encoder_GetDelta(void);

/**
 * @brief Check if encoder button is pressed
 * @return true if button is currently pressed
 */
bool Encoder_IsButtonPressed(void);

/**
 * @brief Get full encoder state
 * @param state Pointer to state structure to fill
 */
void Encoder_GetState(EncoderState_t *state);

/**
 * @brief Set acceleration threshold
 * @param threshold_ms Time between events to trigger fast mode
 */
void Encoder_SetAccelThreshold(uint32_t threshold_ms);

/**
 * @brief Set acceleration multiplier
 * @param multiplier Position change multiplier for fast mode
 */
void Encoder_SetAccelMultiplier(uint8_t multiplier);

/**
 * @brief Enable/disable acceleration
 * @param enable true to enable acceleration
 */
void Encoder_SetAccelEnabled(bool enable);

#ifdef __cplusplus
}
#endif

#endif /* DRIVERS_ENCODER_H */



