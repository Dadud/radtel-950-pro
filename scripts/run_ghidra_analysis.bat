@echo off
REM Automated Ghidra Headless Analysis for RT-950 Firmware
REM Usage: run_ghidra_analysis.bat [firmware_file] [project_name]

set GHIDRA_DIR=C:\Users\dadud\Downloads\ghidra_12.0_PUBLIC_20251205
set FIRMWARE=%~1
set PROJECT_NAME=%~2

if "%FIRMWARE%"=="" (
    set FIRMWARE=firmware\rt950\RT_950_V0.29_251104.BTF
)

if "%PROJECT_NAME%"=="" (
    set PROJECT_NAME=RT-950-Analysis
)

if not exist "%GHIDRA_DIR%\support\analyzeHeadless.bat" (
    echo Error: analyzeHeadless.bat not found at %GHIDRA_DIR%\support\
    echo Checking alternative locations...
    dir /s /b "%GHIDRA_DIR%\*analyzeHeadless*" 2>nul
    exit /b 1
)

if not exist "%FIRMWARE%" (
    echo Error: Firmware file not found: %FIRMWARE%
    exit /b 1
)

for %%F in ("%FIRMWARE%") do (
    set FIRMWARE_DIR=%%~dpF
    set FIRMWARE_NAME=%%~nF
)

set PROJECT_DIR=%FIRMWARE_DIR%ghidra_project
set OUTPUT_DIR=%FIRMWARE_DIR%analysis

echo ========================================
echo Ghidra Headless Analysis
echo ========================================
echo Ghidra: %GHIDRA_DIR%
echo Firmware: %FIRMWARE%
echo Project: %PROJECT_DIR%
echo Output: %OUTPUT_DIR%
echo ========================================
echo.

mkdir "%PROJECT_DIR%" 2>nul
mkdir "%OUTPUT_DIR%" 2>nul

echo Running Ghidra analysis (this may take several minutes)...
echo.

"%GHIDRA_DIR%\support\analyzeHeadless.bat" ^
    "%PROJECT_DIR%" ^
    "%PROJECT_NAME%" ^
    -import "%FIRMWARE%" ^
    -processor ARM:LE:32:Cortex ^
    -analysisTimeoutPerFile 3600 ^
    -deleteProject

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Analysis Complete!
    echo ========================================
    echo Project files: %PROJECT_DIR%
    echo.
    echo To view results, open Ghidra and import project:
    echo   1. File ^> Open Project
    echo   2. Navigate to: %PROJECT_DIR%
    echo   3. Select: %PROJECT_NAME%
    echo.
) else (
    echo.
    echo ========================================
    echo Analysis Failed with error code: %ERRORLEVEL%
    echo ========================================
    exit /b 1
)

