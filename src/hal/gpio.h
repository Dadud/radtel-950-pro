/**
 * @file gpio.h
 * @brief GPIO Hardware Abstraction Layer
 * 
 * Provides GPIO configuration and control for the AT32F403A.
 * Pin mappings are INFERRED from OEM firmware reverse engineering.
 * 
 * Hardware: AT32F403ARGT7 - 144 pins (LQFP144)
 */

#ifndef HAL_GPIO_H
#define HAL_GPIO_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * GPIO PORT BASE ADDRESSES (CONFIRMED from datasheet)
 * ============================================================================ */

#define GPIOA_BASE          0x40010800UL
#define GPIOB_BASE          0x40010C00UL
#define GPIOC_BASE          0x40011000UL
#define GPIOD_BASE          0x40011400UL
#define GPIOE_BASE          0x40011800UL

/* GPIO register structure */
typedef struct {
    volatile uint32_t CFGLR;    /* 0x00: Configuration low (pins 0-7) */
    volatile uint32_t CFGHR;    /* 0x04: Configuration high (pins 8-15) */
    volatile uint32_t IDT;      /* 0x08: Input data */
    volatile uint32_t ODT;      /* 0x0C: Output data */
    volatile uint32_t SCR;      /* 0x10: Set/clear register (bits 0-15 set, 16-31 clear) */
    volatile uint32_t CLR;      /* 0x14: Clear register */
    volatile uint32_t WPR;      /* 0x18: Write protect */
} GPIO_TypeDef;

#define GPIOA               ((GPIO_TypeDef *)GPIOA_BASE)
#define GPIOB               ((GPIO_TypeDef *)GPIOB_BASE)
#define GPIOC               ((GPIO_TypeDef *)GPIOC_BASE)
#define GPIOD               ((GPIO_TypeDef *)GPIOD_BASE)
#define GPIOE               ((GPIO_TypeDef *)GPIOE_BASE)

/* ============================================================================
 * GPIO PORT ENUMERATION
 * ============================================================================ */

typedef enum {
    GPIO_PORT_A = 0,
    GPIO_PORT_B,
    GPIO_PORT_C,
    GPIO_PORT_D,
    GPIO_PORT_E,
    GPIO_PORT_COUNT
} GPIO_Port_t;

/* ============================================================================
 * GPIO PIN ENUMERATION
 * ============================================================================ */

typedef enum {
    GPIO_PIN_0  = (1 << 0),
    GPIO_PIN_1  = (1 << 1),
    GPIO_PIN_2  = (1 << 2),
    GPIO_PIN_3  = (1 << 3),
    GPIO_PIN_4  = (1 << 4),
    GPIO_PIN_5  = (1 << 5),
    GPIO_PIN_6  = (1 << 6),
    GPIO_PIN_7  = (1 << 7),
    GPIO_PIN_8  = (1 << 8),
    GPIO_PIN_9  = (1 << 9),
    GPIO_PIN_10 = (1 << 10),
    GPIO_PIN_11 = (1 << 11),
    GPIO_PIN_12 = (1 << 12),
    GPIO_PIN_13 = (1 << 13),
    GPIO_PIN_14 = (1 << 14),
    GPIO_PIN_15 = (1 << 15),
    GPIO_PIN_ALL = 0xFFFF
} GPIO_Pin_t;

/* ============================================================================
 * GPIO MODE ENUMERATION
 * ============================================================================ */

typedef enum {
    GPIO_MODE_INPUT_ANALOG = 0x00,      /* Analog input */
    GPIO_MODE_INPUT_FLOATING = 0x04,    /* Floating input */
    GPIO_MODE_INPUT_PULLDOWN = 0x28,    /* Input with pull-down */
    GPIO_MODE_INPUT_PULLUP = 0x48,      /* Input with pull-up */
    GPIO_MODE_OUTPUT_PP = 0x10,         /* Push-pull output */
    GPIO_MODE_OUTPUT_OD = 0x14,         /* Open-drain output */
    GPIO_MODE_AF_PP = 0x18,             /* Alternate function push-pull */
    GPIO_MODE_AF_OD = 0x1C              /* Alternate function open-drain */
} GPIO_Mode_t;

/* ============================================================================
 * GPIO SPEED ENUMERATION
 * ============================================================================ */

typedef enum {
    GPIO_SPEED_10MHZ = 1,
    GPIO_SPEED_2MHZ = 2,
    GPIO_SPEED_50MHZ = 3
} GPIO_Speed_t;

/* ============================================================================
 * PIN DEFINITIONS (INFERRED from OEM firmware analysis)
 * ============================================================================
 * 
 * These mappings were reverse-engineered from the OEM firmware binary.
 * Each pin is marked with confidence level:
 *   [CONFIRMED] - Verified through multiple sources or logic trace
 *   [HIGH]      - Strong evidence from disassembly
 *   [MEDIUM]    - Reasonable inference from context
 *   [LOW]       - Speculative, needs hardware verification
 */

/* ---- PORT A ---- */
#define PIN_VOX_DETECT          GPIOA, GPIO_PIN_0   /* [HIGH] ADC input for VOX */
#define PIN_BATTERY_DETECT      GPIOA, GPIO_PIN_1   /* [HIGH] ADC for battery voltage */
#define PIN_SINGLE_IN           GPIOA, GPIO_PIN_2   /* [MEDIUM] Unknown analog input */
#define PIN_BT_UART_IN          GPIOA, GPIO_PIN_3   /* [MEDIUM] Bluetooth serial input */
#define PIN_BEEP_OUT            GPIOA, GPIO_PIN_4   /* [CONFIRMED] DAC1 output for tones */
#define PIN_APC                 GPIOA, GPIO_PIN_5   /* [HIGH] Automatic Power Control */
#define PIN_FM_RESET            GPIOA, GPIO_PIN_6   /* [MEDIUM] FM receiver reset */
#define PIN_V3FM_EN             GPIOA, GPIO_PIN_7   /* [MEDIUM] FM enable control */
#define PIN_GPS_ENABLE          GPIOA, GPIO_PIN_8   /* [HIGH] GPS module power */
#define PIN_BT_RX               GPIOA, GPIO_PIN_9   /* [CONFIRMED] USART1 RX (Bluetooth) */
#define PIN_BT_TX               GPIOA, GPIO_PIN_10  /* [CONFIRMED] USART1 TX (Bluetooth) */
#define PIN_POWER_OFF           GPIOA, GPIO_PIN_11  /* [HIGH] Power latch control */
#define PIN_SK4                 GPIOA, GPIO_PIN_12  /* [LOW] Side key 4? */
#define PIN_SW_SDA              GPIOA, GPIO_PIN_13  /* [MEDIUM] Software I2C data */
#define PIN_SW_SCK              GPIOA, GPIO_PIN_14  /* [MEDIUM] Software I2C clock */
#define PIN_REPLAY              GPIOA, GPIO_PIN_15  /* [LOW] Audio replay control */

/* ---- PORT B ---- */
#define PIN_V3R_ENABLE          GPIOB, GPIO_PIN_0   /* [MEDIUM] RF path control */
#define PIN_V3T_ENABLE          GPIOB, GPIO_PIN_1   /* [MEDIUM] RF TX path control */
#define PIN_V3RX_ENABLE         GPIOB, GPIO_PIN_2   /* [MEDIUM] RF RX path control */
#define PIN_KEYPAD_LIGHT        GPIOB, GPIO_PIN_3   /* [HIGH] Keypad backlight */
#define PIN_ENCODER_A           GPIOB, GPIO_PIN_4   /* [CONFIRMED] Encoder phase A */
#define PIN_ENCODER_B           GPIOB, GPIO_PIN_5   /* [CONFIRMED] Encoder phase B */
#define PIN_SI4732_SCK          GPIOB, GPIO_PIN_6   /* [HIGH] SI4732 I2C clock */
#define PIN_SI4732_SDA          GPIOB, GPIO_PIN_7   /* [HIGH] SI4732 I2C data */
#define PIN_MIC_ENABLE          GPIOB, GPIO_PIN_8   /* [MEDIUM] Microphone enable */
#define PIN_LB_POWER_EN         GPIOB, GPIO_PIN_9   /* [LOW] Low-band power enable */
#define PIN_GPS_RX              GPIOB, GPIO_PIN_10  /* [HIGH] GPS UART RX */
#define PIN_GPS_TX              GPIOB, GPIO_PIN_11  /* [HIGH] GPS UART TX */
#define PIN_FLASH_CS            GPIOB, GPIO_PIN_12  /* [CONFIRMED] SPI Flash chip select */
#define PIN_FLASH_SCK           GPIOB, GPIO_PIN_13  /* [CONFIRMED] SPI Flash clock */
#define PIN_FLASH_MISO          GPIOB, GPIO_PIN_14  /* [CONFIRMED] SPI Flash MISO */
#define PIN_FLASH_MOSI          GPIOB, GPIO_PIN_15  /* [CONFIRMED] SPI Flash MOSI */

/* ---- PORT C ---- */
#define PIN_KEYPAD_R0           GPIOC, GPIO_PIN_0   /* [CONFIRMED] Keypad row 0 */
#define PIN_KEYPAD_R1           GPIOC, GPIO_PIN_1   /* [CONFIRMED] Keypad row 1 */
#define PIN_KEYPAD_R2           GPIOC, GPIO_PIN_2   /* [CONFIRMED] Keypad row 2 */
#define PIN_KEYPAD_R3           GPIOC, GPIO_PIN_3   /* [CONFIRMED] Keypad row 3 */
#define PIN_RF_BAND_RELAY       GPIOC, GPIO_PIN_4   /* [MEDIUM] Band relay control */
#define PIN_VSW_ENABLE          GPIOC, GPIO_PIN_5   /* [MEDIUM] Voltage switch enable */
#define PIN_LCD_BACKLIGHT       GPIOC, GPIO_PIN_6   /* [CONFIRMED] LCD backlight PWM */
#define PIN_PTT_DETECT          GPIOC, GPIO_PIN_7   /* [CONFIRMED] PTT button input */
#define PIN_SIDEPORT_RX         GPIOC, GPIO_PIN_8   /* [LOW] Side port RX detect */
#define PIN_SIDEPORT_PTT        GPIOC, GPIO_PIN_9   /* [LOW] Side port PTT */
#define PIN_UART_TX             GPIOC, GPIO_PIN_10  /* [HIGH] UART TX (GPS/Accessory) */
#define PIN_UART_RX             GPIOC, GPIO_PIN_11  /* [HIGH] UART RX (GPS/Accessory) */
#define PIN_BEEP_SW             GPIOC, GPIO_PIN_12  /* [MEDIUM] Beep switch/route */
#define PIN_LED_RED             GPIOC, GPIO_PIN_13  /* [CONFIRMED] Red LED */
#define PIN_LED_GREEN           GPIOC, GPIO_PIN_14  /* [CONFIRMED] Green LED */
#define PIN_EXT_SPEAKER         GPIOC, GPIO_PIN_15  /* [LOW] External speaker detect */

/* ---- PORT D ---- */
#define PIN_LCD_WR              GPIOD, GPIO_PIN_0   /* [CONFIRMED] LCD write strobe */
#define PIN_LCD_CS              GPIOD, GPIO_PIN_1   /* [CONFIRMED] LCD chip select */
#define PIN_LCD_RESET           GPIOD, GPIO_PIN_2   /* [CONFIRMED] LCD reset */
#define PIN_LCD_RS              GPIOD, GPIO_PIN_3   /* [CONFIRMED] LCD data/command */
#define PIN_KEYPAD_C3           GPIOD, GPIO_PIN_4   /* [CONFIRMED] Keypad column 3 */
#define PIN_KEYPAD_C2           GPIOD, GPIO_PIN_5   /* [CONFIRMED] Keypad column 2 */
#define PIN_KEYPAD_C1           GPIOD, GPIO_PIN_6   /* [CONFIRMED] Keypad column 1 */
#define PIN_KEYPAD_C0           GPIOD, GPIO_PIN_7   /* [CONFIRMED] Keypad column 0 */
/* PD8-PD15: LCD parallel data bus [CONFIRMED] */
#define PIN_LCD_DATA_MASK       0xFF00              /* LCD data on PD8-PD15 */

/* ---- PORT E ---- */
#define PIN_POWER_SWITCH        GPIOE, GPIO_PIN_0   /* [CONFIRMED] Power button input */
#define PIN_SPEAKER_MUTE        GPIOE, GPIO_PIN_1   /* [HIGH] Speaker mute control */
#define PIN_PTT2                GPIOE, GPIO_PIN_2   /* [MEDIUM] Secondary PTT */
#define PIN_PTT                 GPIOE, GPIO_PIN_3   /* [CONFIRMED] Primary PTT output */
#define PIN_PA_ENABLE           GPIOE, GPIO_PIN_4   /* [CONFIRMED] Power amplifier enable */
#define PIN_SIDE_KEY1           GPIOE, GPIO_PIN_5   /* [HIGH] Side key 1 input */
#define PIN_EXT_PTT             GPIOE, GPIO_PIN_6   /* [HIGH] External PTT input */
#define PIN_U3T_EN              GPIOE, GPIO_PIN_7   /* [MEDIUM] RF path control */
#define PIN_BK4829_SEN1         GPIOE, GPIO_PIN_8   /* [CONFIRMED] BK4829 #1 chip select */
#define PIN_SW_TO_BT            GPIOE, GPIO_PIN_9   /* [LOW] Switch to Bluetooth? */
#define PIN_BK4829_SCK          GPIOE, GPIO_PIN_10  /* [CONFIRMED] BK4829 SPI clock */
#define PIN_BK4829_SDA          GPIOE, GPIO_PIN_11  /* [CONFIRMED] BK4829 SPI data */
#define PIN_U3R_ENABLE          GPIOE, GPIO_PIN_12  /* [MEDIUM] RF RX path control */
#define PIN_U6R_ENABLE          GPIOE, GPIO_PIN_13  /* [MEDIUM] RF RX path control */
#define PIN_SW3T_ENABLE         GPIOE, GPIO_PIN_14  /* [MEDIUM] RF switch control */
#define PIN_BK4829_SEN2         GPIOE, GPIO_PIN_15  /* [CONFIRMED] BK4829 #2 chip select */

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Enable clock for a GPIO port
 * @param port Port to enable
 */
void HAL_GPIO_ClockEnable(GPIO_Port_t port);

/**
 * @brief Configure a GPIO pin
 * @param port GPIO port
 * @param pin Pin mask
 * @param mode Pin mode
 * @param speed Output speed (ignored for input modes)
 */
void HAL_GPIO_Config(GPIO_Port_t port, uint16_t pin, GPIO_Mode_t mode, GPIO_Speed_t speed);

/**
 * @brief Set GPIO pin(s) high
 * @param port GPIO port
 * @param pin Pin mask
 */
void HAL_GPIO_SetHigh(GPIO_Port_t port, uint16_t pin);

/**
 * @brief Set GPIO pin(s) low
 * @param port GPIO port
 * @param pin Pin mask
 */
void HAL_GPIO_SetLow(GPIO_Port_t port, uint16_t pin);

/**
 * @brief Toggle GPIO pin(s)
 * @param port GPIO port
 * @param pin Pin mask
 */
void HAL_GPIO_Toggle(GPIO_Port_t port, uint16_t pin);

/**
 * @brief Read GPIO pin state
 * @param port GPIO port
 * @param pin Pin mask
 * @return true if pin is high, false if low
 */
bool HAL_GPIO_Read(GPIO_Port_t port, uint16_t pin);

/**
 * @brief Read entire port input register
 * @param port GPIO port
 * @return 16-bit input value
 */
uint16_t HAL_GPIO_ReadPort(GPIO_Port_t port);

/**
 * @brief Write entire port output register
 * @param port GPIO port
 * @param value 16-bit output value
 */
void HAL_GPIO_WritePort(GPIO_Port_t port, uint16_t value);

/**
 * @brief Write specific pins of a port
 * @param port GPIO port
 * @param mask Pin mask (which pins to affect)
 * @param value Value to write (only masked pins affected)
 */
void HAL_GPIO_WriteMasked(GPIO_Port_t port, uint16_t mask, uint16_t value);

/* ============================================================================
 * INLINE HELPER MACROS
 * ============================================================================ */

/* Direct register access for time-critical operations */
#define GPIO_SET_PIN(port, pin)     ((port)->SCR = (pin))
#define GPIO_CLR_PIN(port, pin)     ((port)->CLR = (pin))
#define GPIO_READ_PIN(port, pin)    (((port)->IDT & (pin)) != 0)
#define GPIO_READ_PORT(port)        ((port)->IDT)
#define GPIO_WRITE_PORT(port, val)  ((port)->ODT = (val))

#ifdef __cplusplus
}
#endif

#endif /* HAL_GPIO_H */



