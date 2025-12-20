/**
 * @file lcd.c
 * @brief LCD Display Driver Implementation
 * 
 * Implements the 8080 parallel interface for the TFT display.
 * Commands match ILI9341/ST7789 style controllers.
 */

#include "drivers/lcd.h"
#include "hal/gpio.h"
#include "hal/system.h"

/* Frame buffer location - matches OEM firmware */
static uint16_t * const g_framebuffer = (uint16_t *)0x20000BD0;

/* LCD control pin macros for fast access */
#define LCD_WR_LOW()    GPIOD->CLR = GPIO_PIN_0
#define LCD_WR_HIGH()   GPIOD->SCR = GPIO_PIN_0
#define LCD_CS_LOW()    GPIOD->CLR = GPIO_PIN_1
#define LCD_CS_HIGH()   GPIOD->SCR = GPIO_PIN_1
#define LCD_RST_LOW()   GPIOD->CLR = GPIO_PIN_2
#define LCD_RST_HIGH()  GPIOD->SCR = GPIO_PIN_2
#define LCD_RS_LOW()    GPIOD->CLR = GPIO_PIN_3  /* Command */
#define LCD_RS_HIGH()   GPIOD->SCR = GPIO_PIN_3  /* Data */

/* Write data byte to data bus (PD8-PD15) */
#define LCD_WRITE_DATA_BUS(d) do { \
    GPIOD->ODT = (GPIOD->ODT & 0x00FF) | ((uint16_t)(d) << 8); \
} while(0)

/**
 * @brief Strobe WR signal to clock data into LCD
 */
static inline void lcd_strobe_wr(void)
{
    LCD_WR_LOW();
    __asm volatile ("nop");
    __asm volatile ("nop");
    LCD_WR_HIGH();
}

/**
 * @brief Write command byte to LCD
 * 
 * CONFIRMED: Matches FUN_800271c0 in OEM firmware
 */
void LCD_WriteCommand(uint8_t cmd)
{
    LCD_CS_LOW();
    LCD_RS_LOW();           /* Command mode */
    LCD_WRITE_DATA_BUS(cmd);
    lcd_strobe_wr();
    LCD_CS_HIGH();
}

/**
 * @brief Write data byte to LCD
 * 
 * CONFIRMED: Matches FUN_80027220 in OEM firmware
 */
void LCD_WriteData(uint8_t data)
{
    LCD_CS_LOW();
    LCD_RS_HIGH();          /* Data mode */
    LCD_WRITE_DATA_BUS(data);
    lcd_strobe_wr();
    LCD_CS_HIGH();
}

/**
 * @brief Write 16-bit data word to LCD
 */
void LCD_WriteData16(uint16_t data)
{
    LCD_CS_LOW();
    LCD_RS_HIGH();
    
    /* High byte first */
    LCD_WRITE_DATA_BUS(data >> 8);
    lcd_strobe_wr();
    
    /* Low byte */
    LCD_WRITE_DATA_BUS(data & 0xFF);
    lcd_strobe_wr();
    
    LCD_CS_HIGH();
}

/**
 * @brief Set drawing window
 * 
 * CONFIRMED: Matches FUN_8001cb52 using 0x2A/0x2B commands
 */
void LCD_SetWindow(uint16_t x1, uint16_t y1, uint16_t x2, uint16_t y2)
{
    /* Column address set (0x2A) */
    LCD_WriteCommand(LCD_CMD_CASET);
    LCD_WriteData(x1 >> 8);
    LCD_WriteData(x1 & 0xFF);
    LCD_WriteData(x2 >> 8);
    LCD_WriteData(x2 & 0xFF);
    
    /* Row address set (0x2B) */
    LCD_WriteCommand(LCD_CMD_RASET);
    LCD_WriteData(y1 >> 8);
    LCD_WriteData(y1 & 0xFF);
    LCD_WriteData(y2 >> 8);
    LCD_WriteData(y2 & 0xFF);
    
    /* Memory write (0x2C) */
    LCD_WriteCommand(LCD_CMD_RAMWR);
}

/**
 * @brief Initialize LCD hardware
 * 
 * INFERRED: Initialization sequence from OEM firmware analysis.
 * Assumes ILI9341-compatible controller.
 */
void LCD_Init(void)
{
    /* Configure GPIO pins for LCD interface */
    /* Control pins as outputs */
    HAL_GPIO_Config(GPIO_PORT_D, GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3,
                    GPIO_MODE_OUTPUT_PP, GPIO_SPEED_50MHZ);
    
    /* Data bus as outputs (PD8-PD15) */
    HAL_GPIO_Config(GPIO_PORT_D, 0xFF00, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_50MHZ);
    
    /* Backlight control (PC6) */
    HAL_GPIO_Config(GPIO_PORT_C, GPIO_PIN_6, GPIO_MODE_OUTPUT_PP, GPIO_SPEED_2MHZ);
    
    /* Initial pin states */
    LCD_CS_HIGH();
    LCD_WR_HIGH();
    LCD_RST_HIGH();
    LCD_RS_HIGH();
    
    /* Hardware reset */
    LCD_RST_LOW();
    HAL_Delay(10);
    LCD_RST_HIGH();
    HAL_Delay(120);
    
    /* Exit sleep mode */
    LCD_WriteCommand(LCD_CMD_SLPOUT);
    HAL_Delay(120);
    
    /* Pixel format: 16-bit RGB565 */
    LCD_WriteCommand(LCD_CMD_PIXFMT);
    LCD_WriteData(0x55);    /* 16-bit/pixel */
    
    /* Memory access control - adjust for screen orientation */
    LCD_WriteCommand(LCD_CMD_MADCTL);
    LCD_WriteData(0x48);    /* Row/column exchange, RGB order */
    
    /* Display on */
    LCD_WriteCommand(LCD_CMD_DISPON);
    HAL_Delay(25);
    
    /* Clear screen */
    LCD_FillScreen(LCD_COLOR_BLACK);
}

/**
 * @brief Turn on backlight
 */
void LCD_BacklightOn(void)
{
    HAL_GPIO_SetHigh(GPIO_PORT_C, GPIO_PIN_6);
}

/**
 * @brief Turn off backlight
 */
void LCD_BacklightOff(void)
{
    HAL_GPIO_SetLow(GPIO_PORT_C, GPIO_PIN_6);
}

/**
 * @brief Set backlight brightness
 * 
 * TODO: Implement PWM for brightness control
 */
void LCD_SetBacklight(uint8_t brightness)
{
    if (brightness > 50) {
        LCD_BacklightOn();
    } else {
        LCD_BacklightOff();
    }
}

/**
 * @brief Fill entire screen with color
 */
void LCD_FillScreen(uint16_t color)
{
    LCD_FillRect(0, 0, LCD_WIDTH, LCD_HEIGHT, color);
}

/**
 * @brief Fill rectangular region
 */
void LCD_FillRect(uint16_t x, uint16_t y, uint16_t width, uint16_t height, 
                  uint16_t color)
{
    /* Bounds check */
    if (x >= LCD_WIDTH || y >= LCD_HEIGHT) return;
    if (x + width > LCD_WIDTH) width = LCD_WIDTH - x;
    if (y + height > LCD_HEIGHT) height = LCD_HEIGHT - y;
    
    LCD_SetWindow(x, y, x + width - 1, y + height - 1);
    
    uint32_t pixels = (uint32_t)width * height;
    
    LCD_CS_LOW();
    LCD_RS_HIGH();
    
    uint8_t hi = color >> 8;
    uint8_t lo = color & 0xFF;
    
    while (pixels--) {
        LCD_WRITE_DATA_BUS(hi);
        lcd_strobe_wr();
        LCD_WRITE_DATA_BUS(lo);
        lcd_strobe_wr();
    }
    
    LCD_CS_HIGH();
}

/**
 * @brief Draw single pixel
 */
void LCD_DrawPixel(uint16_t x, uint16_t y, uint16_t color)
{
    if (x >= LCD_WIDTH || y >= LCD_HEIGHT) return;
    
    LCD_SetWindow(x, y, x, y);
    LCD_WriteData16(color);
}

/**
 * @brief Draw horizontal line
 */
void LCD_DrawHLine(uint16_t x, uint16_t y, uint16_t length, uint16_t color)
{
    LCD_FillRect(x, y, length, 1, color);
}

/**
 * @brief Draw vertical line
 */
void LCD_DrawVLine(uint16_t x, uint16_t y, uint16_t length, uint16_t color)
{
    LCD_FillRect(x, y, 1, length, color);
}

/**
 * @brief Draw rectangle outline
 */
void LCD_DrawRect(uint16_t x, uint16_t y, uint16_t width, uint16_t height, 
                  uint16_t color)
{
    LCD_DrawHLine(x, y, width, color);
    LCD_DrawHLine(x, y + height - 1, width, color);
    LCD_DrawVLine(x, y, height, color);
    LCD_DrawVLine(x + width - 1, y, height, color);
}

/* Simple 5x7 font data - ASCII 32-127 */
/* TODO: Include full font data */
static const uint8_t font_5x7[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, /* Space */
    0x00, 0x00, 0x5F, 0x00, 0x00, /* ! */
    /* ... more characters ... */
};

/**
 * @brief Draw character
 * 
 * TODO: Implement full font rendering
 */
void LCD_DrawChar(uint16_t x, uint16_t y, char ch, uint16_t fg, uint16_t bg, 
                  uint8_t size)
{
    /* Placeholder - draw a rectangle for now */
    LCD_FillRect(x, y, 6 * size, 8 * size, bg);
    if (ch != ' ') {
        LCD_FillRect(x + size, y + size, 4 * size, 6 * size, fg);
    }
}

/**
 * @brief Draw string
 */
void LCD_DrawString(uint16_t x, uint16_t y, const char *str, uint16_t fg, 
                    uint16_t bg, uint8_t size)
{
    while (*str) {
        LCD_DrawChar(x, y, *str++, fg, bg, size);
        x += 6 * size;
        if (x + 6 * size > LCD_WIDTH) {
            x = 0;
            y += 8 * size;
        }
    }
}

/**
 * @brief Draw image from buffer
 */
void LCD_DrawImage(uint16_t x, uint16_t y, uint16_t width, uint16_t height, 
                   const uint16_t *data)
{
    LCD_SetWindow(x, y, x + width - 1, y + height - 1);
    
    uint32_t pixels = (uint32_t)width * height;
    
    LCD_CS_LOW();
    LCD_RS_HIGH();
    
    while (pixels--) {
        uint16_t color = *data++;
        LCD_WRITE_DATA_BUS(color >> 8);
        lcd_strobe_wr();
        LCD_WRITE_DATA_BUS(color & 0xFF);
        lcd_strobe_wr();
    }
    
    LCD_CS_HIGH();
}

/**
 * @brief Flush frame buffer to LCD
 * 
 * CONFIRMED: Based on FUN_800037b0 using DMA2
 * 
 * TODO: Implement DMA transfer for better performance
 */
void LCD_FlushBuffer(void)
{
    LCD_DrawImage(0, 0, LCD_WIDTH, LCD_HEIGHT, g_framebuffer);
}

/**
 * @brief Get frame buffer pointer
 */
uint16_t *LCD_GetFrameBuffer(void)
{
    return g_framebuffer;
}


