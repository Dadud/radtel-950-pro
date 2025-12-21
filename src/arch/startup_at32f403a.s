/**
 * @file startup_at32f403a.s
 * @brief AT32F403A startup code for ARM GCC
 * 
 * Clean-room implementation based on Artery reference SDK structure.
 * Sets up stack, copies .data, clears .bss, and calls main.
 * 
 * Target: AT32F403ARGT7 (Cortex-M4F @ 240MHz)
 */

  .syntax unified
  .cpu cortex-m4
  .fpu fpv4-sp-d16
  .thumb

.global  g_pfnVectors
.global  Default_Handler
.global  Reset_Handler

/* Linker script symbols */
.word  _sidata      /* Start of .data initialization values in FLASH */
.word  _sdata       /* Start of .data section in RAM */
.word  _edata       /* End of .data section in RAM */
.word  _sbss        /* Start of .bss section in RAM */
.word  _ebss        /* End of .bss section in RAM */

/**
 * @brief Reset Handler - first code executed after reset
 */
    .section  .text.Reset_Handler
    .weak  Reset_Handler
    .type  Reset_Handler, %function
Reset_Handler:
    /* Set stack pointer */
    ldr   sp, =_estack

    /* Copy .data from flash to RAM */
    movs  r1, #0
    b     LoopCopyDataInit

CopyDataInit:
    ldr   r3, =_sidata
    ldr   r3, [r3, r1]
    str   r3, [r0, r1]
    adds  r1, r1, #4

LoopCopyDataInit:
    ldr   r0, =_sdata
    ldr   r3, =_edata
    adds  r2, r0, r1
    cmp   r2, r3
    bcc   CopyDataInit

    /* Zero-fill .bss section */
    ldr   r2, =_sbss
    b     LoopFillZerobss

FillZerobss:
    movs  r3, #0
    str   r3, [r2], #4

LoopFillZerobss:
    ldr   r3, = _ebss
    cmp   r2, r3
    bcc   FillZerobss

    /* Enable FPU - Cortex-M4F */
    ldr   r0, =0xE000ED88
    ldr   r1, [r0]
    orr   r1, r1, #(0xF << 20)
    str   r1, [r0]
    dsb
    isb

    /* Call system initialization */
    bl    SystemInit
    
    /* Call static constructors */
    bl    __libc_init_array
    
    /* Call main */
    bl    main
    
    /* Loop forever if main returns */
    b     .

    .size  Reset_Handler, .-Reset_Handler

/**
 * @brief Default interrupt handler - loops forever
 */
    .section  .text.Default_Handler,"ax",%progbits
Default_Handler:
Infinite_Loop:
    b     Infinite_Loop
    .size  Default_Handler, .-Default_Handler

/**
 * @brief Vector table
 * 
 * INFERRED from AT32F403A datasheet and OEM firmware analysis.
 * The vector table is placed at the start of flash (0x08000000).
 */
    .section  .isr_vector,"a",%progbits
    .type  g_pfnVectors, %object

g_pfnVectors:
    /* Core exceptions */
    .word  _estack                      /* 0x00: Initial stack pointer */
    .word  Reset_Handler                /* 0x04: Reset */
    .word  NMI_Handler                  /* 0x08: NMI */
    .word  HardFault_Handler            /* 0x0C: Hard fault */
    .word  MemManage_Handler            /* 0x10: Memory management fault */
    .word  BusFault_Handler             /* 0x14: Bus fault */
    .word  UsageFault_Handler           /* 0x18: Usage fault */
    .word  0                            /* 0x1C: Reserved */
    .word  0                            /* 0x20: Reserved */
    .word  0                            /* 0x24: Reserved */
    .word  0                            /* 0x28: Reserved */
    .word  SVC_Handler                  /* 0x2C: SVCall */
    .word  DebugMon_Handler             /* 0x30: Debug monitor */
    .word  0                            /* 0x34: Reserved */
    .word  PendSV_Handler               /* 0x38: PendSV */
    .word  SysTick_Handler              /* 0x3C: SysTick */

    /* External interrupts - AT32F403A specific */
    .word  WWDT_IRQHandler              /* Window Watchdog */
    .word  PVM_IRQHandler               /* PVM through EXINT */
    .word  TAMPER_IRQHandler            /* Tamper */
    .word  RTC_IRQHandler               /* RTC */
    .word  FLASH_IRQHandler             /* Flash */
    .word  CRM_IRQHandler               /* CRM (Clock and Reset) */
    .word  EXINT0_IRQHandler            /* EXINT Line 0 */
    .word  EXINT1_IRQHandler            /* EXINT Line 1 */
    .word  EXINT2_IRQHandler            /* EXINT Line 2 */
    .word  EXINT3_IRQHandler            /* EXINT Line 3 */
    .word  EXINT4_IRQHandler            /* EXINT Line 4 */
    .word  DMA1_Channel1_IRQHandler     /* DMA1 Channel 1 */
    .word  DMA1_Channel2_IRQHandler     /* DMA1 Channel 2 */
    .word  DMA1_Channel3_IRQHandler     /* DMA1 Channel 3 */
    .word  DMA1_Channel4_IRQHandler     /* DMA1 Channel 4 */
    .word  DMA1_Channel5_IRQHandler     /* DMA1 Channel 5 */
    .word  DMA1_Channel6_IRQHandler     /* DMA1 Channel 6 */
    .word  DMA1_Channel7_IRQHandler     /* DMA1 Channel 7 */
    .word  ADC1_2_IRQHandler            /* ADC1 & ADC2 */
    .word  USBFS_H_CAN1_TX_IRQHandler   /* USB High Priority / CAN1 TX */
    .word  USBFS_L_CAN1_RX0_IRQHandler  /* USB Low Priority / CAN1 RX0 */
    .word  CAN1_RX1_IRQHandler          /* CAN1 RX1 */
    .word  CAN1_SE_IRQHandler           /* CAN1 SE */
    .word  EXINT9_5_IRQHandler          /* EXINT Lines 5-9 */
    .word  TMR1_BRK_TMR9_IRQHandler     /* Timer1 Break / Timer9 */
    .word  TMR1_OVF_TMR10_IRQHandler    /* Timer1 Overflow / Timer10 */
    .word  TMR1_TRG_HALL_TMR11_IRQHandler /* Timer1 Trigger / Timer11 */
    .word  TMR1_CH_IRQHandler           /* Timer1 Channel */
    .word  TMR2_GLOBAL_IRQHandler       /* Timer2 */
    .word  TMR3_GLOBAL_IRQHandler       /* Timer3 */
    .word  TMR4_GLOBAL_IRQHandler       /* Timer4 */
    .word  I2C1_EVT_IRQHandler          /* I2C1 Event */
    .word  I2C1_ERR_IRQHandler          /* I2C1 Error */
    .word  I2C2_EVT_IRQHandler          /* I2C2 Event */
    .word  I2C2_ERR_IRQHandler          /* I2C2 Error */
    .word  SPI1_IRQHandler              /* SPI1 */
    .word  SPI2_I2S2EXT_IRQHandler      /* SPI2 / I2S2 */
    .word  USART1_IRQHandler            /* USART1 */
    .word  USART2_IRQHandler            /* USART2 */
    .word  USART3_IRQHandler            /* USART3 */
    .word  EXINT15_10_IRQHandler        /* EXINT Lines 10-15 */
    .word  RTCAlarm_IRQHandler          /* RTC Alarm */
    .word  USBFSWakeUp_IRQHandler       /* USB Wakeup */
    .word  TMR8_BRK_TMR12_IRQHandler    /* Timer8 Break / Timer12 */
    .word  TMR8_OVF_TMR13_IRQHandler    /* Timer8 Overflow / Timer13 */
    .word  TMR8_TRG_HALL_TMR14_IRQHandler /* Timer8 Trigger / Timer14 */
    .word  TMR8_CH_IRQHandler           /* Timer8 Channel */
    .word  ADC3_IRQHandler              /* ADC3 */
    .word  XMC_IRQHandler               /* XMC */
    .word  SDIO1_IRQHandler             /* SDIO1 */
    .word  TMR5_GLOBAL_IRQHandler       /* Timer5 */
    .word  SPI3_I2S3EXT_IRQHandler      /* SPI3 / I2S3 */
    .word  UART4_IRQHandler             /* UART4 */
    .word  UART5_IRQHandler             /* UART5 */
    .word  TMR6_GLOBAL_IRQHandler       /* Timer6 */
    .word  TMR7_GLOBAL_IRQHandler       /* Timer7 */
    .word  DMA2_Channel1_IRQHandler     /* DMA2 Channel 1 */
    .word  DMA2_Channel2_IRQHandler     /* DMA2 Channel 2 */
    .word  DMA2_Channel3_IRQHandler     /* DMA2 Channel 3 */
    .word  DMA2_Channel4_5_IRQHandler   /* DMA2 Channels 4-5 */
    .word  SDIO2_IRQHandler             /* SDIO2 */
    .word  I2C3_EVT_IRQHandler          /* I2C3 Event */
    .word  I2C3_ERR_IRQHandler          /* I2C3 Error */
    .word  SPI4_IRQHandler              /* SPI4 */
    .word  0                            /* Reserved */
    .word  0                            /* Reserved */
    .word  0                            /* Reserved */
    .word  0                            /* Reserved */
    .word  CAN2_TX_IRQHandler           /* CAN2 TX */
    .word  CAN2_RX0_IRQHandler          /* CAN2 RX0 */
    .word  CAN2_RX1_IRQHandler          /* CAN2 RX1 */
    .word  CAN2_SE_IRQHandler           /* CAN2 SE */
    .word  ACC_IRQHandler               /* ACC */
    .word  USBFS_MAPH_IRQHandler        /* USB Map HP */
    .word  USBFS_MAPL_IRQHandler        /* USB Map LP */
    .word  DMA2_Channel6_7_IRQHandler   /* DMA2 Channels 6-7 */
    .word  USART6_IRQHandler            /* USART6 */
    .word  UART7_IRQHandler             /* UART7 */
    .word  UART8_IRQHandler             /* UART8 */

    .size  g_pfnVectors, .-g_pfnVectors

/**
 * @brief Weak aliases for interrupt handlers
 * 
 * These can be overridden by strong definitions in user code.
 */
    .weak      NMI_Handler
    .thumb_set NMI_Handler,Default_Handler

    .weak      HardFault_Handler
    .thumb_set HardFault_Handler,Default_Handler

    .weak      MemManage_Handler
    .thumb_set MemManage_Handler,Default_Handler

    .weak      BusFault_Handler
    .thumb_set BusFault_Handler,Default_Handler

    .weak      UsageFault_Handler
    .thumb_set UsageFault_Handler,Default_Handler

    .weak      SVC_Handler
    .thumb_set SVC_Handler,Default_Handler

    .weak      DebugMon_Handler
    .thumb_set DebugMon_Handler,Default_Handler

    .weak      PendSV_Handler
    .thumb_set PendSV_Handler,Default_Handler

    .weak      SysTick_Handler
    .thumb_set SysTick_Handler,Default_Handler

    .weak      WWDT_IRQHandler
    .thumb_set WWDT_IRQHandler,Default_Handler

    .weak      PVM_IRQHandler
    .thumb_set PVM_IRQHandler,Default_Handler

    .weak      TAMPER_IRQHandler
    .thumb_set TAMPER_IRQHandler,Default_Handler

    .weak      RTC_IRQHandler
    .thumb_set RTC_IRQHandler,Default_Handler

    .weak      FLASH_IRQHandler
    .thumb_set FLASH_IRQHandler,Default_Handler

    .weak      CRM_IRQHandler
    .thumb_set CRM_IRQHandler,Default_Handler

    .weak      EXINT0_IRQHandler
    .thumb_set EXINT0_IRQHandler,Default_Handler

    .weak      EXINT1_IRQHandler
    .thumb_set EXINT1_IRQHandler,Default_Handler

    .weak      EXINT2_IRQHandler
    .thumb_set EXINT2_IRQHandler,Default_Handler

    .weak      EXINT3_IRQHandler
    .thumb_set EXINT3_IRQHandler,Default_Handler

    .weak      EXINT4_IRQHandler
    .thumb_set EXINT4_IRQHandler,Default_Handler

    .weak      DMA1_Channel1_IRQHandler
    .thumb_set DMA1_Channel1_IRQHandler,Default_Handler

    .weak      DMA1_Channel2_IRQHandler
    .thumb_set DMA1_Channel2_IRQHandler,Default_Handler

    .weak      DMA1_Channel3_IRQHandler
    .thumb_set DMA1_Channel3_IRQHandler,Default_Handler

    .weak      DMA1_Channel4_IRQHandler
    .thumb_set DMA1_Channel4_IRQHandler,Default_Handler

    .weak      DMA1_Channel5_IRQHandler
    .thumb_set DMA1_Channel5_IRQHandler,Default_Handler

    .weak      DMA1_Channel6_IRQHandler
    .thumb_set DMA1_Channel6_IRQHandler,Default_Handler

    .weak      DMA1_Channel7_IRQHandler
    .thumb_set DMA1_Channel7_IRQHandler,Default_Handler

    .weak      ADC1_2_IRQHandler
    .thumb_set ADC1_2_IRQHandler,Default_Handler

    .weak      USBFS_H_CAN1_TX_IRQHandler
    .thumb_set USBFS_H_CAN1_TX_IRQHandler,Default_Handler

    .weak      USBFS_L_CAN1_RX0_IRQHandler
    .thumb_set USBFS_L_CAN1_RX0_IRQHandler,Default_Handler

    .weak      CAN1_RX1_IRQHandler
    .thumb_set CAN1_RX1_IRQHandler,Default_Handler

    .weak      CAN1_SE_IRQHandler
    .thumb_set CAN1_SE_IRQHandler,Default_Handler

    .weak      EXINT9_5_IRQHandler
    .thumb_set EXINT9_5_IRQHandler,Default_Handler

    .weak      TMR1_BRK_TMR9_IRQHandler
    .thumb_set TMR1_BRK_TMR9_IRQHandler,Default_Handler

    .weak      TMR1_OVF_TMR10_IRQHandler
    .thumb_set TMR1_OVF_TMR10_IRQHandler,Default_Handler

    .weak      TMR1_TRG_HALL_TMR11_IRQHandler
    .thumb_set TMR1_TRG_HALL_TMR11_IRQHandler,Default_Handler

    .weak      TMR1_CH_IRQHandler
    .thumb_set TMR1_CH_IRQHandler,Default_Handler

    .weak      TMR2_GLOBAL_IRQHandler
    .thumb_set TMR2_GLOBAL_IRQHandler,Default_Handler

    .weak      TMR3_GLOBAL_IRQHandler
    .thumb_set TMR3_GLOBAL_IRQHandler,Default_Handler

    .weak      TMR4_GLOBAL_IRQHandler
    .thumb_set TMR4_GLOBAL_IRQHandler,Default_Handler

    .weak      I2C1_EVT_IRQHandler
    .thumb_set I2C1_EVT_IRQHandler,Default_Handler

    .weak      I2C1_ERR_IRQHandler
    .thumb_set I2C1_ERR_IRQHandler,Default_Handler

    .weak      I2C2_EVT_IRQHandler
    .thumb_set I2C2_EVT_IRQHandler,Default_Handler

    .weak      I2C2_ERR_IRQHandler
    .thumb_set I2C2_ERR_IRQHandler,Default_Handler

    .weak      SPI1_IRQHandler
    .thumb_set SPI1_IRQHandler,Default_Handler

    .weak      SPI2_I2S2EXT_IRQHandler
    .thumb_set SPI2_I2S2EXT_IRQHandler,Default_Handler

    .weak      USART1_IRQHandler
    .thumb_set USART1_IRQHandler,Default_Handler

    .weak      USART2_IRQHandler
    .thumb_set USART2_IRQHandler,Default_Handler

    .weak      USART3_IRQHandler
    .thumb_set USART3_IRQHandler,Default_Handler

    .weak      EXINT15_10_IRQHandler
    .thumb_set EXINT15_10_IRQHandler,Default_Handler

    .weak      RTCAlarm_IRQHandler
    .thumb_set RTCAlarm_IRQHandler,Default_Handler

    .weak      USBFSWakeUp_IRQHandler
    .thumb_set USBFSWakeUp_IRQHandler,Default_Handler

    .weak      TMR8_BRK_TMR12_IRQHandler
    .thumb_set TMR8_BRK_TMR12_IRQHandler,Default_Handler

    .weak      TMR8_OVF_TMR13_IRQHandler
    .thumb_set TMR8_OVF_TMR13_IRQHandler,Default_Handler

    .weak      TMR8_TRG_HALL_TMR14_IRQHandler
    .thumb_set TMR8_TRG_HALL_TMR14_IRQHandler,Default_Handler

    .weak      TMR8_CH_IRQHandler
    .thumb_set TMR8_CH_IRQHandler,Default_Handler

    .weak      ADC3_IRQHandler
    .thumb_set ADC3_IRQHandler,Default_Handler

    .weak      XMC_IRQHandler
    .thumb_set XMC_IRQHandler,Default_Handler

    .weak      SDIO1_IRQHandler
    .thumb_set SDIO1_IRQHandler,Default_Handler

    .weak      TMR5_GLOBAL_IRQHandler
    .thumb_set TMR5_GLOBAL_IRQHandler,Default_Handler

    .weak      SPI3_I2S3EXT_IRQHandler
    .thumb_set SPI3_I2S3EXT_IRQHandler,Default_Handler

    .weak      UART4_IRQHandler
    .thumb_set UART4_IRQHandler,Default_Handler

    .weak      UART5_IRQHandler
    .thumb_set UART5_IRQHandler,Default_Handler

    .weak      TMR6_GLOBAL_IRQHandler
    .thumb_set TMR6_GLOBAL_IRQHandler,Default_Handler

    .weak      TMR7_GLOBAL_IRQHandler
    .thumb_set TMR7_GLOBAL_IRQHandler,Default_Handler

    .weak      DMA2_Channel1_IRQHandler
    .thumb_set DMA2_Channel1_IRQHandler,Default_Handler

    .weak      DMA2_Channel2_IRQHandler
    .thumb_set DMA2_Channel2_IRQHandler,Default_Handler

    .weak      DMA2_Channel3_IRQHandler
    .thumb_set DMA2_Channel3_IRQHandler,Default_Handler

    .weak      DMA2_Channel4_5_IRQHandler
    .thumb_set DMA2_Channel4_5_IRQHandler,Default_Handler

    .weak      SDIO2_IRQHandler
    .thumb_set SDIO2_IRQHandler,Default_Handler

    .weak      I2C3_EVT_IRQHandler
    .thumb_set I2C3_EVT_IRQHandler,Default_Handler

    .weak      I2C3_ERR_IRQHandler
    .thumb_set I2C3_ERR_IRQHandler,Default_Handler

    .weak      SPI4_IRQHandler
    .thumb_set SPI4_IRQHandler,Default_Handler

    .weak      CAN2_TX_IRQHandler
    .thumb_set CAN2_TX_IRQHandler,Default_Handler

    .weak      CAN2_RX0_IRQHandler
    .thumb_set CAN2_RX0_IRQHandler,Default_Handler

    .weak      CAN2_RX1_IRQHandler
    .thumb_set CAN2_RX1_IRQHandler,Default_Handler

    .weak      CAN2_SE_IRQHandler
    .thumb_set CAN2_SE_IRQHandler,Default_Handler

    .weak      ACC_IRQHandler
    .thumb_set ACC_IRQHandler,Default_Handler

    .weak      USBFS_MAPH_IRQHandler
    .thumb_set USBFS_MAPH_IRQHandler,Default_Handler

    .weak      USBFS_MAPL_IRQHandler
    .thumb_set USBFS_MAPL_IRQHandler,Default_Handler

    .weak      DMA2_Channel6_7_IRQHandler
    .thumb_set DMA2_Channel6_7_IRQHandler,Default_Handler

    .weak      USART6_IRQHandler
    .thumb_set USART6_IRQHandler,Default_Handler

    .weak      UART7_IRQHandler
    .thumb_set UART7_IRQHandler,Default_Handler

    .weak      UART8_IRQHandler
    .thumb_set UART8_IRQHandler,Default_Handler

    .end



