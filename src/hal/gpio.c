/**
 * @file gpio.c
 * @brief GPIO HAL Implementation
 * 
 * Implements GPIO configuration and control functions.
 */

#include "hal/gpio.h"
#include "hal/system.h"

/* GPIO port lookup table */
static GPIO_TypeDef * const gpio_ports[] = {
    GPIOA, GPIOB, GPIOC, GPIOD, GPIOE
};

/* CRM AHB peripheral enable bits for GPIO ports */
#define CRM_GPIOA_EN    (1 << 2)
#define CRM_GPIOB_EN    (1 << 3)
#define CRM_GPIOC_EN    (1 << 4)
#define CRM_GPIOD_EN    (1 << 5)
#define CRM_GPIOE_EN    (1 << 6)

static const uint32_t gpio_clk_bits[] = {
    CRM_GPIOA_EN,
    CRM_GPIOB_EN,
    CRM_GPIOC_EN,
    CRM_GPIOD_EN,
    CRM_GPIOE_EN
};

/**
 * @brief Enable clock for GPIO port
 */
void HAL_GPIO_ClockEnable(GPIO_Port_t port)
{
    if (port < GPIO_PORT_COUNT) {
        CRM_APB2EN |= gpio_clk_bits[port];
        /* Small delay for clock to stabilize */
        volatile uint32_t delay = 2;
        while (delay--);
    }
}

/**
 * @brief Configure GPIO pin
 * 
 * The AT32F403A uses the same GPIO configuration as STM32F1:
 * - CFGLR controls pins 0-7
 * - CFGHR controls pins 8-15
 * - Each pin uses 4 bits: MODE[1:0] | CNF[1:0]
 */
void HAL_GPIO_Config(GPIO_Port_t port, uint16_t pin, GPIO_Mode_t mode, GPIO_Speed_t speed)
{
    if (port >= GPIO_PORT_COUNT) return;
    
    GPIO_TypeDef *gpio = gpio_ports[port];
    
    /* Process each pin in the mask */
    for (int i = 0; i < 16; i++) {
        if (!(pin & (1 << i))) continue;
        
        uint32_t config = 0;
        
        /* Decode mode into CNF and MODE bits */
        switch (mode) {
            case GPIO_MODE_INPUT_ANALOG:
                config = 0x00;  /* CNF=00, MODE=00 */
                break;
            case GPIO_MODE_INPUT_FLOATING:
                config = 0x04;  /* CNF=01, MODE=00 */
                break;
            case GPIO_MODE_INPUT_PULLDOWN:
            case GPIO_MODE_INPUT_PULLUP:
                config = 0x08;  /* CNF=10, MODE=00 */
                break;
            case GPIO_MODE_OUTPUT_PP:
                config = 0x00 | speed;  /* CNF=00, MODE=speed */
                break;
            case GPIO_MODE_OUTPUT_OD:
                config = 0x04 | speed;  /* CNF=01, MODE=speed */
                break;
            case GPIO_MODE_AF_PP:
                config = 0x08 | speed;  /* CNF=10, MODE=speed */
                break;
            case GPIO_MODE_AF_OD:
                config = 0x0C | speed;  /* CNF=11, MODE=speed */
                break;
            default:
                config = 0x04;  /* Floating input as default */
                break;
        }
        
        /* Apply configuration */
        if (i < 8) {
            /* Low register (pins 0-7) */
            uint32_t shift = i * 4;
            gpio->CFGLR = (gpio->CFGLR & ~(0x0F << shift)) | (config << shift);
        } else {
            /* High register (pins 8-15) */
            uint32_t shift = (i - 8) * 4;
            gpio->CFGHR = (gpio->CFGHR & ~(0x0F << shift)) | (config << shift);
        }
        
        /* Set pull-up/pull-down via ODT register */
        if (mode == GPIO_MODE_INPUT_PULLUP) {
            gpio->SCR = (1 << i);
        } else if (mode == GPIO_MODE_INPUT_PULLDOWN) {
            gpio->CLR = (1 << i);
        }
    }
}

/**
 * @brief Set GPIO pins high
 */
void HAL_GPIO_SetHigh(GPIO_Port_t port, uint16_t pin)
{
    if (port < GPIO_PORT_COUNT) {
        gpio_ports[port]->SCR = pin;
    }
}

/**
 * @brief Set GPIO pins low
 */
void HAL_GPIO_SetLow(GPIO_Port_t port, uint16_t pin)
{
    if (port < GPIO_PORT_COUNT) {
        gpio_ports[port]->CLR = pin;
    }
}

/**
 * @brief Toggle GPIO pins
 */
void HAL_GPIO_Toggle(GPIO_Port_t port, uint16_t pin)
{
    if (port < GPIO_PORT_COUNT) {
        GPIO_TypeDef *gpio = gpio_ports[port];
        uint16_t current = gpio->ODT;
        gpio->ODT = current ^ pin;
    }
}

/**
 * @brief Read GPIO pin state
 */
bool HAL_GPIO_Read(GPIO_Port_t port, uint16_t pin)
{
    if (port < GPIO_PORT_COUNT) {
        return (gpio_ports[port]->IDT & pin) != 0;
    }
    return false;
}

/**
 * @brief Read entire GPIO port
 */
uint16_t HAL_GPIO_ReadPort(GPIO_Port_t port)
{
    if (port < GPIO_PORT_COUNT) {
        return gpio_ports[port]->IDT;
    }
    return 0;
}

/**
 * @brief Write entire GPIO port
 */
void HAL_GPIO_WritePort(GPIO_Port_t port, uint16_t value)
{
    if (port < GPIO_PORT_COUNT) {
        gpio_ports[port]->ODT = value;
    }
}

/**
 * @brief Write masked portion of GPIO port
 */
void HAL_GPIO_WriteMasked(GPIO_Port_t port, uint16_t mask, uint16_t value)
{
    if (port < GPIO_PORT_COUNT) {
        GPIO_TypeDef *gpio = gpio_ports[port];
        uint16_t current = gpio->ODT;
        gpio->ODT = (current & ~mask) | (value & mask);
    }
}


