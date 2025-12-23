# UI Layer Documentation (`src/ui/`)

**AI Reasoning:** This document explains the AI's reasoning for the UI layer implementation.

> **⚠️ This is AI-generated content - verify against hardware before use**

---

## Overview

The UI layer provides user interface components: display rendering, menu system, and fonts.

---

## Display (`ui/display.c`)

### Why This Structure?

**AI Reasoning:**
- Wrapper around LCD driver for UI-specific rendering
- Provides text rendering, icons, progress bars
- Manages display regions and windows

**Functions:**
- Text rendering with different fonts
- Icon drawing
- Progress indicators
- Status displays

**Confidence:** **LOW** - UI structure mostly guessed

---

## Menu System (`ui/menu.c`)

### Why Hierarchical Menu?

**AI Reasoning:**
- Radio menus typically hierarchical (Settings → Radio → Squelch)
- Menu items have labels, values, callbacks
- Navigation via encoder/keys

**Structure:**
```c
typedef struct {
    const char *label;
    MenuItemType_t type;  // VALUE, SUBMENU, ACTION
    void *value_ptr;
    MenuCallback_t callback;
} MenuItem_t;
```

**Confidence:** **LOW** - Menu structure guessed from typical patterns

**Potential Issues:**
- Menu structure may be completely different
- Navigation logic may not match OEM
- Menu items may be hardcoded differently

---

## Fonts (`ui/fonts.c`)

### Why Bitmap Fonts?

**AI Reasoning:**
- Embedded displays typically use bitmap fonts
- Small memory footprint
- Fast rendering
- Font data stored as arrays

**Font Format:**
- Assumed: 8×8 or similar bitmap format
- Character data in arrays
- Simple lookup and rendering

**Confidence:** **LOW** - Font format completely guessed

**Potential Issues:**
- Font format may be different
- May need multiple font sizes
- Character encoding may be different (UTF-8 vs ASCII)

---

## Key AI Assumptions

1. **Menu Structure**: Guessed from typical patterns (LOW confidence)
2. **Font Format**: Completely guessed (LOW confidence)
3. **Display Layout**: Guessed (LOW confidence)

---

## Verification Needed

- [ ] Extract actual menu structure from OEM firmware
- [ ] Identify font format and extract font data
- [ ] Test menu navigation
- [ ] Verify display layouts match OEM appearance
- [ ] Test text rendering
- [ ] Verify icons/graphics rendering

---

## Data Sources

1. **Pattern Matching**: Typical embedded UI structures
2. **OEM Behavior**: Observed menu navigation (but not implementation)

