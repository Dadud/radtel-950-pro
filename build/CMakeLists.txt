# ============================================================================
# Radtel RT-950 Pro Clean-Room Firmware
# CMake Build Configuration
# ============================================================================
#
# This is a clean-room re-implementation. No proprietary code is included.
# Target: AT32F403ARGT7 (ARM Cortex-M4F @ 240MHz)
# Toolchain: arm-none-eabi-gcc
#
# Build instructions:
#   mkdir -p build/output
#   cd build/output
#   cmake .. -DCMAKE_BUILD_TYPE=Release
#   make
#

cmake_minimum_required(VERSION 3.20)

# ============================================================================
# Toolchain Configuration
# ============================================================================

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Toolchain prefix - adjust if needed
set(TOOLCHAIN_PREFIX arm-none-eabi-)

set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}g++)
set(CMAKE_ASM_COMPILER ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_AR ${TOOLCHAIN_PREFIX}ar)
set(CMAKE_OBJCOPY ${TOOLCHAIN_PREFIX}objcopy)
set(CMAKE_OBJDUMP ${TOOLCHAIN_PREFIX}objdump)
set(CMAKE_SIZE ${TOOLCHAIN_PREFIX}size)

set(CMAKE_EXECUTABLE_SUFFIX_C ".elf")
set(CMAKE_EXECUTABLE_SUFFIX_CXX ".elf")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# ============================================================================
# Project Definition
# ============================================================================

project(rt950pro_firmware
    VERSION 0.1.0
    DESCRIPTION "Radtel RT-950 Pro Clean-Room Firmware"
    LANGUAGES C ASM
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ============================================================================
# MCU Configuration
# ============================================================================

set(MCU_FAMILY AT32F403A)
set(MCU_MODEL AT32F403ARGT7)
set(MCU_CORE cortex-m4)
set(MCU_FPU fpv4-sp-d16)
set(MCU_FLOAT_ABI hard)

set(FLASH_SIZE 1024K)
set(RAM_SIZE 96K)

# ============================================================================
# Compiler Flags
# ============================================================================

# CPU-specific flags
set(CPU_FLAGS
    -mcpu=${MCU_CORE}
    -mthumb
    -mfpu=${MCU_FPU}
    -mfloat-abi=${MCU_FLOAT_ABI}
)

# Common compiler flags
set(COMMON_FLAGS
    ${CPU_FLAGS}
    -Wall
    -Wextra
    -Wpedantic
    -fdata-sections
    -ffunction-sections
    -fno-common
    -fmessage-length=0
)

# Debug flags
set(DEBUG_FLAGS
    -O0
    -g3
    -DDEBUG
)

# Release flags
set(RELEASE_FLAGS
    -Os
    -g0
    -DNDEBUG
)

# Apply flags based on build type
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(${COMMON_FLAGS} ${DEBUG_FLAGS})
else()
    add_compile_options(${COMMON_FLAGS} ${RELEASE_FLAGS})
endif()

# Assembler flags
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} ${CPU_FLAGS} -x assembler-with-cpp")

# ============================================================================
# Linker Configuration
# ============================================================================

set(LINKER_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/../src/arch/AT32F403AxG_FLASH.ld)

set(LINKER_FLAGS
    ${CPU_FLAGS}
    -T${LINKER_SCRIPT}
    --specs=nano.specs
    --specs=nosys.specs
    -Wl,-Map=${PROJECT_NAME}.map,--cref
    -Wl,--gc-sections
    -Wl,--print-memory-usage
    -lm
    -lc
)

string(REPLACE ";" " " LINKER_FLAGS_STR "${LINKER_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LINKER_FLAGS_STR}")

# ============================================================================
# Include Directories
# ============================================================================

set(INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/arch
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hal
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/drivers
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/protocols
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/config
)

# ============================================================================
# Source Files
# ============================================================================

# Startup and architecture
set(ARCH_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/arch/startup_at32f403a.s
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/arch/system_at32f403a.c
)

# HAL sources
set(HAL_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hal/system.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hal/gpio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hal/spi.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hal/uart.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hal/adc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hal/dac.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hal/dma.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hal/timer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hal/i2c.c
)

# Driver sources
set(DRIVER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/drivers/lcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/drivers/keypad.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/drivers/encoder.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/drivers/bk4819.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/drivers/si4732.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/drivers/spi_flash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/drivers/audio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/drivers/power.c
)

# Radio subsystem sources
set(RADIO_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/radio/radio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/radio/channel.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/radio/vfo.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/radio/scan.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/radio/ctcss.c
)

# UI sources
set(UI_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/ui.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/display.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/menu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/fonts.c
)

# Protocol sources
set(PROTOCOL_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/protocols/cdc_protocol.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/protocols/bluetooth.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/protocols/gps.c
)

# Config sources
set(CONFIG_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/config/settings.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/config/eeprom.c
)

# Main application
set(APP_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/main.c
)

# All sources combined
set(ALL_SOURCES
    ${ARCH_SOURCES}
    ${HAL_SOURCES}
    ${DRIVER_SOURCES}
    ${RADIO_SOURCES}
    ${UI_SOURCES}
    ${PROTOCOL_SOURCES}
    ${CONFIG_SOURCES}
    ${APP_SOURCES}
)

# ============================================================================
# Compile Definitions
# ============================================================================

add_compile_definitions(
    ${MCU_FAMILY}
    ${MCU_MODEL}
    USE_STDPERIPH_DRIVER
    HEXT_VALUE=8000000
    SYSTEM_CLOCK=240000000
)

# ============================================================================
# Build Target
# ============================================================================

add_executable(${PROJECT_NAME} ${ALL_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRS})

# ============================================================================
# Post-Build Commands
# ============================================================================

# Generate binary file
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:${PROJECT_NAME}> 
            ${PROJECT_NAME}.bin
    COMMENT "Generating binary: ${PROJECT_NAME}.bin"
)

# Generate hex file
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O ihex $<TARGET_FILE:${PROJECT_NAME}> 
            ${PROJECT_NAME}.hex
    COMMENT "Generating hex: ${PROJECT_NAME}.hex"
)

# Print size information
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_SIZE} --format=berkeley $<TARGET_FILE:${PROJECT_NAME}>
    COMMENT "Size information:"
)

# ============================================================================
# Flash Target (requires OpenOCD or similar)
# ============================================================================

add_custom_target(flash
    COMMAND openocd -f interface/stlink.cfg -f target/stm32f4x.cfg 
            -c "program ${PROJECT_NAME}.elf verify reset exit"
    DEPENDS ${PROJECT_NAME}
    COMMENT "Flashing firmware via ST-Link..."
)

# ============================================================================
# Clean Target
# ============================================================================

set_property(TARGET ${PROJECT_NAME} PROPERTY ADDITIONAL_CLEAN_FILES
    ${PROJECT_NAME}.bin
    ${PROJECT_NAME}.hex
    ${PROJECT_NAME}.map
)


