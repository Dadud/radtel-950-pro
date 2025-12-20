/**
 * @file lcd.h
 * @brief LCD Display Driver
 * 
 * Driver for the 320x240 TFT LCD panel using 8080-style parallel interface.
 * The LCD controller is INFERRED to be ILI9341/ST7789 compatible based on
 * command sequences found in the OEM firmware.
 * 
 * Interface: 8-bit 8080 parallel [CONFIRMED]
 *   - Data bus: PD8-PD15
 *   - WR strobe: PD0
 *   - CS: PD1
 *   - Reset: PD2
 *   - D/C (RS): PD3
 *   - Backlight: PC6
 * 
 * Resolution: 320x240 RGB565 [CONFIRMED]
 * Frame buffer: Located at 0x20000BD0 [CONFIRMED from OEM firmware]
 */

#ifndef DRIVERS_LCD_H
#define DRIVERS_LCD_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * LCD CONFIGURATION
 * ============================================================================ */

#define LCD_WIDTH           320
#define LCD_HEIGHT          240
#define LCD_PIXEL_COUNT     (LCD_WIDTH * LCD_HEIGHT)
#define LCD_BUFFER_SIZE     (LCD_PIXEL_COUNT * 2)   /* RGB565 = 2 bytes/pixel */

/* ============================================================================
 * LCD COMMAND DEFINITIONS (MIPI DCS compatible)
 * ============================================================================
 * 
 * These commands are CONFIRMED from OEM firmware analysis.
 * They match the MIPI DCS standard and ILI9341/ST7789 controllers.
 */

#define LCD_CMD_NOP         0x00    /* No operation */
#define LCD_CMD_SWRESET     0x01    /* Software reset */
#define LCD_CMD_RDDID       0x04    /* Read display ID */
#define LCD_CMD_RDDST       0x09    /* Read display status */
#define LCD_CMD_SLPIN       0x10    /* Enter sleep mode */
#define LCD_CMD_SLPOUT      0x11    /* Exit sleep mode */
#define LCD_CMD_PTLON       0x12    /* Partial mode on */
#define LCD_CMD_NORON       0x13    /* Normal mode on */
#define LCD_CMD_INVOFF      0x20    /* Inversion off */
#define LCD_CMD_INVON       0x21    /* Inversion on */
#define LCD_CMD_GAMSET      0x26    /* Gamma set */
#define LCD_CMD_DISPOFF     0x28    /* Display off */
#define LCD_CMD_DISPON      0x29    /* Display on */
#define LCD_CMD_CASET       0x2A    /* Column address set [CONFIRMED] */
#define LCD_CMD_RASET       0x2B    /* Row address set [CONFIRMED] */
#define LCD_CMD_RAMWR       0x2C    /* Memory write [CONFIRMED] */
#define LCD_CMD_RAMRD       0x2E    /* Memory read */
#define LCD_CMD_PTLAR       0x30    /* Partial area */
#define LCD_CMD_VSCRDEF     0x33    /* Vertical scroll definition */
#define LCD_CMD_TEOFF       0x34    /* Tearing effect off */
#define LCD_CMD_TEON        0x35    /* Tearing effect on */
#define LCD_CMD_MADCTL      0x36    /* Memory access control */
#define LCD_CMD_VSCRSADD    0x37    /* Vertical scroll start address */
#define LCD_CMD_IDMOFF      0x38    /* Idle mode off */
#define LCD_CMD_IDMON       0x39    /* Idle mode on */
#define LCD_CMD_PIXFMT      0x3A    /* Pixel format set */
#define LCD_CMD_WRMEMCONT   0x3C    /* Write memory continue */
#define LCD_CMD_RDMEMCONT   0x3E    /* Read memory continue */
#define LCD_CMD_SETSCANTE   0x44    /* Set scan line */
#define LCD_CMD_GETSCAN     0x45    /* Get scan line */
#define LCD_CMD_WRDISBV     0x51    /* Write display brightness */
#define LCD_CMD_RDDISBV     0x52    /* Read display brightness */
#define LCD_CMD_WRCTRLD     0x53    /* Write control display */
#define LCD_CMD_RDCTRLD     0x54    /* Read control display */
#define LCD_CMD_WRCABC      0x55    /* Write CABC */
#define LCD_CMD_RDCABC      0x56    /* Read CABC */

/* ============================================================================
 * COLOR DEFINITIONS (RGB565 format)
 * ============================================================================ */

#define LCD_COLOR_BLACK     0x0000
#define LCD_COLOR_WHITE     0xFFFF
#define LCD_COLOR_RED       0xF800
#define LCD_COLOR_GREEN     0x07E0
#define LCD_COLOR_BLUE      0x001F
#define LCD_COLOR_YELLOW    0xFFE0
#define LCD_COLOR_CYAN      0x07FF
#define LCD_COLOR_MAGENTA   0xF81F
#define LCD_COLOR_ORANGE    0xFD20
#define LCD_COLOR_GRAY      0x8410
#define LCD_COLOR_DARKGRAY  0x4208

/* Color conversion macros */
#define RGB565(r, g, b)     (((r & 0xF8) << 8) | ((g & 0xFC) << 3) | ((b & 0xF8) >> 3))

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Initialize the LCD controller
 * 
 * Performs hardware reset, sends initialization sequence, and clears display.
 * INFERRED: Initialization sequence from OEM firmware LCD_Init routines.
 */
void LCD_Init(void);

/**
 * @brief Turn on LCD backlight
 */
void LCD_BacklightOn(void);

/**
 * @brief Turn off LCD backlight
 */
void LCD_BacklightOff(void);

/**
 * @brief Set backlight brightness
 * @param brightness 0-100 percent
 */
void LCD_SetBacklight(uint8_t brightness);

/**
 * @brief Write a command byte to the LCD
 * @param cmd Command byte
 * 
 * CONFIRMED: Matches FUN_800271c0 in OEM firmware
 */
void LCD_WriteCommand(uint8_t cmd);

/**
 * @brief Write a data byte to the LCD
 * @param data Data byte
 * 
 * CONFIRMED: Matches FUN_80027220 in OEM firmware
 */
void LCD_WriteData(uint8_t data);

/**
 * @brief Write a 16-bit data word to the LCD
 * @param data Data word (RGB565 pixel)
 */
void LCD_WriteData16(uint16_t data);

/**
 * @brief Set the drawing window
 * @param x1 Start column (0-319)
 * @param y1 Start row (0-239)
 * @param x2 End column (0-319)
 * @param y2 End row (0-239)
 * 
 * CONFIRMED: Matches FUN_8001cb52 in OEM firmware
 */
void LCD_SetWindow(uint16_t x1, uint16_t y1, uint16_t x2, uint16_t y2);

/**
 * @brief Fill the entire screen with a color
 * @param color RGB565 color value
 */
void LCD_FillScreen(uint16_t color);

/**
 * @brief Fill a rectangular region
 * @param x Start X coordinate
 * @param y Start Y coordinate
 * @param width Width in pixels
 * @param height Height in pixels
 * @param color RGB565 color value
 */
void LCD_FillRect(uint16_t x, uint16_t y, uint16_t width, uint16_t height, 
                  uint16_t color);

/**
 * @brief Draw a single pixel
 * @param x X coordinate
 * @param y Y coordinate
 * @param color RGB565 color value
 */
void LCD_DrawPixel(uint16_t x, uint16_t y, uint16_t color);

/**
 * @brief Draw a horizontal line
 * @param x Start X coordinate
 * @param y Y coordinate
 * @param length Line length
 * @param color RGB565 color value
 */
void LCD_DrawHLine(uint16_t x, uint16_t y, uint16_t length, uint16_t color);

/**
 * @brief Draw a vertical line
 * @param x X coordinate
 * @param y Start Y coordinate
 * @param length Line length
 * @param color RGB565 color value
 */
void LCD_DrawVLine(uint16_t x, uint16_t y, uint16_t length, uint16_t color);

/**
 * @brief Draw a rectangle outline
 * @param x Start X coordinate
 * @param y Start Y coordinate
 * @param width Width in pixels
 * @param height Height in pixels
 * @param color RGB565 color value
 */
void LCD_DrawRect(uint16_t x, uint16_t y, uint16_t width, uint16_t height, 
                  uint16_t color);

/**
 * @brief Draw a character at the specified position
 * @param x X coordinate
 * @param y Y coordinate
 * @param ch Character to draw
 * @param fg Foreground color
 * @param bg Background color
 * @param size Font size multiplier (1, 2, 3...)
 */
void LCD_DrawChar(uint16_t x, uint16_t y, char ch, uint16_t fg, uint16_t bg, 
                  uint8_t size);

/**
 * @brief Draw a string at the specified position
 * @param x X coordinate
 * @param y Y coordinate
 * @param str Null-terminated string
 * @param fg Foreground color
 * @param bg Background color
 * @param size Font size multiplier
 */
void LCD_DrawString(uint16_t x, uint16_t y, const char *str, uint16_t fg, 
                    uint16_t bg, uint8_t size);

/**
 * @brief Draw an image from RGB565 buffer
 * @param x X coordinate
 * @param y Y coordinate
 * @param width Image width
 * @param height Image height
 * @param data Pointer to RGB565 pixel data
 */
void LCD_DrawImage(uint16_t x, uint16_t y, uint16_t width, uint16_t height, 
                   const uint16_t *data);

/**
 * @brief Flush the frame buffer to the LCD using DMA
 * 
 * CONFIRMED: Matches FUN_800037b0 in OEM firmware
 * Uses DMA2 to stream the frame buffer at 0x20000BD0 to the LCD.
 */
void LCD_FlushBuffer(void);

/**
 * @brief Get pointer to frame buffer
 * @return Pointer to frame buffer (RGB565 format)
 */
uint16_t *LCD_GetFrameBuffer(void);

#ifdef __cplusplus
}
#endif

#endif /* DRIVERS_LCD_H */


