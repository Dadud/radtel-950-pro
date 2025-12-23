/**
 * @file radio_model.h
 * @brief Radio Model Configuration
 * 
 * This header defines compile-time configuration for different radio models.
 * Set RADIO_MODEL via CMake to select which model to build for.
 * 
 * Models:
 *   - RT-950 (non-Pro): Single-band, single BK4829
 *   - RT-950 Pro: Dual-band, dual BK4829
 */

#ifndef CONFIG_RADIO_MODEL_H
#define CONFIG_RADIO_MODEL_H

/* ============================================================================
 * MODEL SELECTION
 * ============================================================================
 * 
 * RADIO_MODEL is defined via CMake:
 *   cmake -DRADIO_MODEL=RT950 ..
 *   cmake -DRADIO_MODEL=RT950PRO ..
 */

/* Model enumeration */
#define RADIO_MODEL_RT950     0
#define RADIO_MODEL_RT950PRO  1

/* Default to RT-950 Pro if not specified */
#ifndef RADIO_MODEL
#warning "RADIO_MODEL not defined, defaulting to RT950PRO"
#define RADIO_MODEL  RADIO_MODEL_RT950PRO
#endif

/* ============================================================================
 * MODEL-SPECIFIC CONFIGURATION
 * ============================================================================ */

#if RADIO_MODEL == RADIO_MODEL_RT950

    /* RT-950 (Non-Pro) Configuration */
    #define BK4829_INSTANCE_COUNT       1       /* Single transceiver */
    #define DUAL_BAND_ENABLED           0       /* Single-band only */
    #define CODE_BASE_OFFSET            0x003191 /* Header space */
    #define RESET_HANDLER_OFFSET        0x003191
    
    /* Features */
    #define FEATURE_GPS                 1       /* GPS supported */
    #define FEATURE_BLUETOOTH           1       /* Bluetooth supported */
    #define FEATURE_FM_RX               1       /* FM broadcast RX */
    #define FEATURE_APRS                1       /* APRS support */
    #define FEATURE_KISS_TNC            0       /* KISS TNC (Pro only) */
    
    /* Hardware */
    #define HW_HAS_DUAL_BK4829          0
    #define HW_HAS_SINGLE_BK4829        1
    
    /* Radio characteristics */
    #define FREQ_BAND_COUNT             1       /* Single band */
    #define VFO_COUNT                   2       /* A and B VFOs */
    
    /* Model name for build identification */
    #define RADIO_MODEL_NAME            "RT-950"
    #define RADIO_MODEL_STRING          "RT950"

#elif RADIO_MODEL == RADIO_MODEL_RT950PRO

    /* RT-950 Pro Configuration */
    #define BK4829_INSTANCE_COUNT       2       /* Dual transceivers */
    #define DUAL_BAND_ENABLED           1       /* Dual-band VHF/UHF */
    #define CODE_BASE_OFFSET            0x000000 /* Start at flash base */
    #define RESET_HANDLER_OFFSET        0x000000
    
    /* Features */
    #define FEATURE_GPS                 1       /* GPS supported */
    #define FEATURE_BLUETOOTH           1       /* Bluetooth supported */
    #define FEATURE_FM_RX               1       /* FM broadcast RX */
    #define FEATURE_APRS                1       /* APRS support */
    #define FEATURE_KISS_TNC            1       /* KISS TNC support */
    
    /* Hardware */
    #define HW_HAS_DUAL_BK4829          1
    #define HW_HAS_SINGLE_BK4829        0
    
    /* Radio characteristics */
    #define FREQ_BAND_COUNT             2       /* VHF and UHF */
    #define VFO_COUNT                   2       /* A and B VFOs */
    
    /* Model name for build identification */
    #define RADIO_MODEL_NAME            "RT-950 Pro"
    #define RADIO_MODEL_STRING          "RT950PRO"

#else

    #error "Unknown RADIO_MODEL value. Use RADIO_MODEL_RT950 or RADIO_MODEL_RT950PRO"

#endif

/* ============================================================================
 * CONVENIENCE MACROS
 * ============================================================================ */

/* Check if dual-band features should be compiled */
#define IS_DUAL_BAND()          (DUAL_BAND_ENABLED == 1)

/* Check if single BK4829 */
#define IS_SINGLE_BK4829()      (BK4829_INSTANCE_COUNT == 1)

/* Check if dual BK4829 */
#define IS_DUAL_BK4829()        (BK4829_INSTANCE_COUNT == 2)

/* Feature check macros */
#define FEATURE_ENABLED(feat)   (FEATURE_##feat == 1)

/* ============================================================================
 * VALIDATION
 * ============================================================================ */

#if BK4829_INSTANCE_COUNT < 1 || BK4829_INSTANCE_COUNT > 2
    #error "BK4829_INSTANCE_COUNT must be 1 or 2"
#endif

#if DUAL_BAND_ENABLED == 1 && BK4829_INSTANCE_COUNT != 2
    #error "Dual-band requires 2 BK4829 instances"
#endif

#if DUAL_BAND_ENABLED == 0 && BK4829_INSTANCE_COUNT == 2
    #warning "Single-band mode with 2 BK4829 instances - second chip unused"
#endif

#endif /* CONFIG_RADIO_MODEL_H */

