#!/bin/bash
# Simple Ghidra headless analysis script
# Usage: ./ghidra_headless_simple.sh <firmware_file> <ghidra_path>

FIRMWARE="$1"
GHIDRA_PATH="${2:-/usr/share/ghidra}"

if [ ! -f "$FIRMWARE" ]; then
    echo "Error: Firmware file not found: $FIRMWARE"
    exit 1
fi

if [ ! -d "$GHIDRA_PATH" ]; then
    echo "Error: Ghidra not found at: $GHIDRA_PATH"
    exit 1
fi

PROJECT_DIR=$(dirname "$FIRMWARE")/ghidra_project
OUTPUT_DIR=$(dirname "$FIRMWARE")/analysis

mkdir -p "$PROJECT_DIR" "$OUTPUT_DIR"

echo "Running Ghidra headless analysis..."
echo "Firmware: $FIRMWARE"
echo "Project: $PROJECT_DIR"
echo "Output: $OUTPUT_DIR"

"$GHIDRA_PATH/support/analyzeHeadless" \
    "$PROJECT_DIR" \
    "RT-950-Analysis" \
    -import "$FIRMWARE" \
    -processor ARM:LE:32:Cortex \
    -analysisTimeoutPerFile 3600 \
    -deleteProject

echo "Analysis complete. Check Ghidra project: $PROJECT_DIR"

