/*
 * AT32F403AxG_FLASH.ld
 * Linker script for AT32F403ARGT7
 * 
 * Memory Configuration:
 *   Flash: 1024KB @ 0x08000000
 *   SRAM:  96KB @ 0x20000000
 * 
 * Clean-room implementation based on Artery reference SDK.
 * Stack and heap sizes are INFERRED from OEM firmware analysis.
 */

/* Entry Point */
ENTRY(Reset_Handler)

/* End of RAM - top of stack */
_estack = 0x20018000;

/* Memory allocation */
_Min_Heap_Size = 0x1000;    /* 4KB heap */
_Min_Stack_Size = 0x1000;   /* 4KB stack */

/* Memory regions */
MEMORY
{
    /* Main flash - 1MB */
    FLASH (rx)      : ORIGIN = 0x08000000, LENGTH = 1024K
    
    /* SRAM - 96KB */
    RAM (rwx)       : ORIGIN = 0x20000000, LENGTH = 96K
}

/* Output sections */
SECTIONS
{
    /* Vector table - must be at start of flash */
    .isr_vector :
    {
        . = ALIGN(4);
        KEEP(*(.isr_vector))
        . = ALIGN(4);
    } >FLASH

    /* Program code */
    .text :
    {
        . = ALIGN(4);
        *(.text)
        *(.text*)
        *(.glue_7)
        *(.glue_7t)
        *(.eh_frame)

        KEEP(*(.init))
        KEEP(*(.fini))

        . = ALIGN(4);
        _etext = .;
    } >FLASH

    /* Read-only data */
    .rodata :
    {
        . = ALIGN(4);
        *(.rodata)
        *(.rodata*)
        . = ALIGN(4);
    } >FLASH

    /* ARM exception unwinding tables */
    .ARM.extab :
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } >FLASH

    .ARM :
    {
        __exidx_start = .;
        *(.ARM.exidx*)
        __exidx_end = .;
    } >FLASH

    /* Pre-initialization array */
    .preinit_array :
    {
        PROVIDE_HIDDEN(__preinit_array_start = .);
        KEEP(*(.preinit_array*))
        PROVIDE_HIDDEN(__preinit_array_end = .);
    } >FLASH

    /* Initialization array */
    .init_array :
    {
        PROVIDE_HIDDEN(__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array*))
        PROVIDE_HIDDEN(__init_array_end = .);
    } >FLASH

    /* Finalization array */
    .fini_array :
    {
        PROVIDE_HIDDEN(__fini_array_start = .);
        KEEP(*(SORT(.fini_array.*)))
        KEEP(*(.fini_array*))
        PROVIDE_HIDDEN(__fini_array_end = .);
    } >FLASH

    /* Initialized data - stored in flash, copied to RAM at startup */
    _sidata = LOADADDR(.data);

    .data :
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data)
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } >RAM AT> FLASH

    /* Uninitialized data - zeroed at startup */
    .bss :
    {
        . = ALIGN(4);
        _sbss = .;
        __bss_start__ = _sbss;
        *(.bss)
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
        __bss_end__ = _ebss;
    } >RAM

    /* User heap and stack section */
    ._user_heap_stack :
    {
        . = ALIGN(8);
        PROVIDE(end = .);
        PROVIDE(_end = .);
        . = . + _Min_Heap_Size;
        . = . + _Min_Stack_Size;
        . = ALIGN(8);
    } >RAM

    /* Frame buffer - placed at specific address to match OEM firmware */
    /* INFERRED: OEM firmware uses 0x20000BD0 for frame buffer */
    .framebuffer 0x20000BD0 (NOLOAD) :
    {
        PROVIDE(_framebuffer_start = .);
        . = . + (320 * 240 * 2);  /* 320x240 RGB565 */
        PROVIDE(_framebuffer_end = .);
    } >RAM

    /* Remove debug info from standard libraries */
    /DISCARD/ :
    {
        libc.a(*)
        libm.a(*)
        libgcc.a(*)
    }

    .ARM.attributes 0 : { *(.ARM.attributes) }
}

/* Provide symbols for startup code */
PROVIDE(_stack = _estack);
PROVIDE(_heap_start = _end);
PROVIDE(_heap_end = _estack - _Min_Stack_Size);


