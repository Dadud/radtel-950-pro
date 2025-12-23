/**
 * @file audio.c
 * @brief Audio Subsystem Driver Implementation
 * 
 * Handles audio input (microphone), output (speaker), and tone generation.
 */

#include "drivers/audio.h"
#include "hal/dac.h"
#include "hal/adc.h"
#include "hal/dma.h"
#include "hal/timer.h"
#include "hal/gpio.h"
#include "hal/system.h"

/* Audio configuration */
#define AUDIO_SAMPLE_RATE       8000
#define AUDIO_BUFFER_SIZE       256
#define TONE_TABLE_SIZE         256

/* Sine wave table for tone generation */
static const uint16_t g_sine_table[TONE_TABLE_SIZE] = {
    2048, 2098, 2148, 2198, 2248, 2298, 2348, 2398,
    2447, 2496, 2545, 2594, 2642, 2690, 2737, 2784,
    2831, 2877, 2923, 2968, 3013, 3057, 3100, 3143,
    3185, 3226, 3267, 3307, 3346, 3385, 3423, 3459,
    3495, 3530, 3565, 3598, 3630, 3662, 3692, 3722,
    3750, 3777, 3804, 3829, 3853, 3876, 3898, 3919,
    3939, 3958, 3975, 3992, 4007, 4021, 4034, 4045,
    4056, 4065, 4073, 4080, 4085, 4090, 4093, 4095,
    4095, 4095, 4093, 4090, 4085, 4080, 4073, 4065,
    4056, 4045, 4034, 4021, 4007, 3992, 3975, 3958,
    3939, 3919, 3898, 3876, 3853, 3829, 3804, 3777,
    3750, 3722, 3692, 3662, 3630, 3598, 3565, 3530,
    3495, 3459, 3423, 3385, 3346, 3307, 3267, 3226,
    3185, 3143, 3100, 3057, 3013, 2968, 2923, 2877,
    2831, 2784, 2737, 2690, 2642, 2594, 2545, 2496,
    2447, 2398, 2348, 2298, 2248, 2198, 2148, 2098,
    2048, 1997, 1947, 1897, 1847, 1797, 1747, 1697,
    1648, 1599, 1550, 1501, 1453, 1405, 1358, 1311,
    1264, 1218, 1172, 1127, 1082, 1038,  995,  952,
     910,  869,  828,  788,  749,  710,  672,  636,
     600,  565,  530,  497,  465,  433,  403,  373,
     345,  318,  291,  266,  242,  219,  197,  176,
     156,  137,  120,  103,   88,   74,   61,   50,
      39,   30,   22,   15,   10,    5,    2,    0,
       0,    0,    2,    5,   10,   15,   22,   30,
      39,   50,   61,   74,   88,  103,  120,  137,
     156,  176,  197,  219,  242,  266,  291,  318,
     345,  373,  403,  433,  465,  497,  530,  565,
     600,  636,  672,  710,  749,  788,  828,  869,
     910,  952,  995, 1038, 1082, 1127, 1172, 1218,
    1264, 1311, 1358, 1405, 1453, 1501, 1550, 1599,
    1648, 1697, 1747, 1797, 1847, 1897, 1947, 1997
};

/* DTMF frequency table */
static const uint16_t g_dtmf_low[] = { 697, 770, 852, 941 };
static const uint16_t g_dtmf_high[] = { 1209, 1336, 1477, 1633 };

/* Audio state */
static struct {
    bool initialized;
    uint8_t volume;             /* 0-31 */
    bool muted;
    AudioPath_t current_path;
    
    /* Tone generation (primary) */
    bool tone_active;
    uint32_t tone_phase;
    uint32_t tone_phase_inc;
    
    /* Secondary tone (for DTMF) */
    bool tone2_active;
    uint32_t tone2_phase;
    uint32_t tone2_phase_inc;
    
    /* CTCSS state */
    bool ctcss_active;
    uint16_t ctcss_freq_tenths;
    
    /* DCS state */
    bool dcs_active;
    uint16_t dcs_code;
    bool dcs_inverted;
    
    /* Timing */
    uint32_t tone_end_time;
    bool playing;
} g_audio;

/* Timer callback for tone generation */
static void audio_timer_callback(void)
{
    if (!g_audio.playing) {
        HAL_DAC_SetValue(DAC_CHANNEL_1, 2048);
        return;
    }
    
    /* Check timing */
    if (g_audio.tone_end_time > 0 && HAL_GetTick() >= g_audio.tone_end_time) {
        g_audio.tone_active = false;
        g_audio.tone2_active = false;
        g_audio.playing = false;
        HAL_DAC_SetValue(DAC_CHANNEL_1, 2048);
        return;
    }
    
    uint32_t sample = 2048;
    
    /* Primary tone */
    if (g_audio.tone_active) {
        uint32_t index = (g_audio.tone_phase >> 24) & 0xFF;
        sample = g_sine_table[index];
        g_audio.tone_phase += g_audio.tone_phase_inc;
    }
    
    /* Secondary tone (mix for DTMF) */
    if (g_audio.tone2_active) {
        uint32_t index = (g_audio.tone2_phase >> 24) & 0xFF;
        sample = (sample + g_sine_table[index]) / 2;
        g_audio.tone2_phase += g_audio.tone2_phase_inc;
    }
    
    /* Apply volume (0-31 -> 0-100%) */
    sample = ((sample - 2048) * g_audio.volume / 31) + 2048;
    
    HAL_DAC_SetValue(DAC_CHANNEL_1, (uint16_t)sample);
}

static void audio_set_tone_freq(uint32_t freq_hz, int which)
{
    uint32_t phase_inc = (uint32_t)(((uint64_t)freq_hz << 32) / AUDIO_SAMPLE_RATE);
    
    if (which == 1) {
        g_audio.tone_phase_inc = phase_inc;
        g_audio.tone_phase = 0;
        g_audio.tone_active = true;
    } else if (which == 2) {
        g_audio.tone2_phase_inc = phase_inc;
        g_audio.tone2_phase = 0;
        g_audio.tone2_active = true;
    }
}

void Audio_Init(void)
{
    /* Initialize DAC for audio output */
    HAL_DAC_Init();
    
    DAC_Config_t dac_config = {
        .trigger = DAC_TRIGGER_TIMER6,
        .enable_output_buffer = true,
        .enable_dma = false
    };
    HAL_DAC_ConfigChannel(DAC_CHANNEL_1, &dac_config);
    HAL_DAC_Enable(DAC_CHANNEL_1);
    
    /* Initialize ADC for audio level */
    HAL_ADC_Init(ADC_INSTANCE_2);
    
    /* Configure Timer 6 for sample rate */
    Timer_Config_t timer_config = {
        .prescaler = (HAL_System_GetAPB1ClockHz() / 1000000) - 1,
        .period = (1000000 / AUDIO_SAMPLE_RATE) - 1,
        .mode = TIMER_MODE_UP,
        .enable_interrupt = true
    };
    HAL_Timer_Init(TIMER_6, &timer_config);
    HAL_Timer_SetCallback(TIMER_6, audio_timer_callback);
    HAL_Timer_Start(TIMER_6);
    
    /* Configure speaker mute pin (PE1) */
    HAL_GPIO_Config(GPIO_PORT_E, GPIO_PIN_1, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_10MHZ);
    GPIOE->SCR = GPIO_PIN_1;
    
    /* Configure mic enable pin (PB8) */
    HAL_GPIO_Config(GPIO_PORT_B, GPIO_PIN_8, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_10MHZ);
    GPIOB->CLR = GPIO_PIN_8;
    
    g_audio.initialized = true;
    g_audio.volume = 20;  /* Default volume */
    g_audio.muted = false;
    g_audio.current_path = AUDIO_PATH_SPEAKER;
    g_audio.playing = false;
}

void Audio_PlayBeep(BeepType_t type)
{
    switch (type) {
        case BEEP_KEY:
            audio_set_tone_freq(1000, 1);
            g_audio.tone_end_time = HAL_GetTick() + 50;
            break;
        case BEEP_ERROR:
            audio_set_tone_freq(400, 1);
            g_audio.tone_end_time = HAL_GetTick() + 200;
            break;
        case BEEP_CONFIRM:
            audio_set_tone_freq(1500, 1);
            g_audio.tone_end_time = HAL_GetTick() + 100;
            break;
        case BEEP_POWER_ON:
            audio_set_tone_freq(800, 1);
            g_audio.tone_end_time = HAL_GetTick() + 200;
            break;
        case BEEP_POWER_OFF:
            audio_set_tone_freq(600, 1);
            g_audio.tone_end_time = HAL_GetTick() + 200;
            break;
        case BEEP_TX_START:
            audio_set_tone_freq(1200, 1);
            g_audio.tone_end_time = HAL_GetTick() + 100;
            break;
        case BEEP_TX_END:
            audio_set_tone_freq(800, 1);
            g_audio.tone_end_time = HAL_GetTick() + 100;
            break;
        case BEEP_SCAN_HIT:
            audio_set_tone_freq(1800, 1);
            g_audio.tone_end_time = HAL_GetTick() + 100;
            break;
        case BEEP_ROGER:
            audio_set_tone_freq(1000, 1);
            g_audio.tone_end_time = HAL_GetTick() + 150;
            break;
        default:
            return;
    }
    
    g_audio.playing = true;
}

void Audio_StartCTCSS(uint16_t freq_tenths)
{
    /* Convert tenths of Hz to Hz (e.g., 885 -> 88.5 Hz) */
    uint32_t freq_hz = freq_tenths / 10;
    audio_set_tone_freq(freq_hz, 1);
    g_audio.tone_end_time = 0;  /* Continuous */
    g_audio.ctcss_active = true;
    g_audio.ctcss_freq_tenths = freq_tenths;
    g_audio.playing = true;
}

void Audio_StopCTCSS(void)
{
    g_audio.ctcss_active = false;
    g_audio.tone_active = false;
    g_audio.playing = false;
}

void Audio_StartDCS(uint16_t code, bool inverted)
{
    /* DCS requires FSK modulation - simplified placeholder */
    g_audio.dcs_active = true;
    g_audio.dcs_code = code;
    g_audio.dcs_inverted = inverted;
    /* TODO: Implement proper DCS encoding */
}

void Audio_StopDCS(void)
{
    g_audio.dcs_active = false;
    g_audio.playing = false;
}

void Audio_PlayDTMF(char digit, uint32_t duration_ms)
{
    int row = -1, col = -1;
    
    switch (digit) {
        case '1': row = 0; col = 0; break;
        case '2': row = 0; col = 1; break;
        case '3': row = 0; col = 2; break;
        case 'A': case 'a': row = 0; col = 3; break;
        case '4': row = 1; col = 0; break;
        case '5': row = 1; col = 1; break;
        case '6': row = 1; col = 2; break;
        case 'B': case 'b': row = 1; col = 3; break;
        case '7': row = 2; col = 0; break;
        case '8': row = 2; col = 1; break;
        case '9': row = 2; col = 2; break;
        case 'C': case 'c': row = 2; col = 3; break;
        case '*': row = 3; col = 0; break;
        case '0': row = 3; col = 1; break;
        case '#': row = 3; col = 2; break;
        case 'D': case 'd': row = 3; col = 3; break;
        default: return;
    }
    
    audio_set_tone_freq(g_dtmf_low[row], 1);
    audio_set_tone_freq(g_dtmf_high[col], 2);
    g_audio.tone_end_time = HAL_GetTick() + duration_ms;
    g_audio.playing = true;
}

void Audio_PlayDTMFString(const char *digits, uint32_t tone_ms, uint32_t gap_ms)
{
    /* Simple blocking implementation */
    while (*digits) {
        Audio_PlayDTMF(*digits, tone_ms);
        HAL_Delay(tone_ms + gap_ms);
        digits++;
    }
}

void Audio_SetVolume(uint8_t volume)
{
    if (volume > 31) volume = 31;
    g_audio.volume = volume;
}

uint8_t Audio_GetVolume(void)
{
    return g_audio.volume;
}

void Audio_SetMute(bool mute)
{
    g_audio.muted = mute;
    
    if (mute) {
        GPIOE->CLR = GPIO_PIN_1;
    } else {
        GPIOE->SCR = GPIO_PIN_1;
    }
}

void Audio_SetPath(AudioPath_t path)
{
    g_audio.current_path = path;
    /* TODO: Implement actual audio path switching */
}

void Audio_SetMicEnabled(bool enable)
{
    if (enable) {
        GPIOB->SCR = GPIO_PIN_8;
    } else {
        GPIOB->CLR = GPIO_PIN_8;
    }
}

uint8_t Audio_GetLevel(void)
{
    /* Read ADC channel 1 (PA1) for audio level */
    uint16_t adc_val = HAL_ADC_Read(ADC_INSTANCE_2, ADC_CHANNEL_1);
    return (uint8_t)(adc_val >> 4);  /* Scale 12-bit to 8-bit */
}

bool Audio_IsPlaying(void)
{
    return g_audio.playing;
}

void Audio_Process(void)
{
    /* Check if tone has ended */
    if (g_audio.playing && g_audio.tone_end_time > 0) {
        if (HAL_GetTick() >= g_audio.tone_end_time) {
            g_audio.tone_active = false;
            g_audio.tone2_active = false;
            g_audio.playing = false;
        }
    }
}
