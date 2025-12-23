/**
 * Linker script for RT-950 (non-Pro)
 * 
 * RT-950 has a ~3KB header space before code starts.
 * Reset handler is at offset 0x003191.
 */

/* Copy the base linker script and modify entry point */
INCLUDE "AT32F403AxG_FLASH.ld"

/* Note: If we need to modify entry point, we can add:
 * ENTRY(Reset_Handler)
 * But typically the vector table handles this.
 * 
 * The actual modification needed is to ensure code starts
 * at 0x08003191 instead of 0x08000000. However, this may
 * be handled by the bootloader/vector table configuration.
 */

