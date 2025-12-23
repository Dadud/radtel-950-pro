@echo off
REM Simple Ghidra headless analysis script for Windows
REM Usage: ghidra_headless_simple.bat <firmware_file> [ghidra_path]

set FIRMWARE=%~1
set GHIDRA_PATH=%~2

if "%GHIDRA_PATH%"=="" (
    REM Try to find Ghidra automatically
    if exist "C:\Program Files\Ghidra" (
        set GHIDRA_PATH=C:\Program Files\Ghidra
    ) else if exist "%USERPROFILE%\ghidra" (
        set GHIDRA_PATH=%USERPROFILE%\ghidra
    ) else (
        echo Error: Ghidra path not specified and not found automatically
        echo Usage: %~nx0 <firmware_file> [ghidra_path]
        exit /b 1
    )
)

if not exist "%FIRMWARE%" (
    echo Error: Firmware file not found: %FIRMWARE%
    exit /b 1
)

if not exist "%GHIDRA_PATH%" (
    echo Error: Ghidra not found at: %GHIDRA_PATH%
    exit /b 1
)

for %%F in ("%FIRMWARE%") do set FIRMWARE_DIR=%%~dpF
set PROJECT_DIR=%FIRMWARE_DIR%ghidra_project
set OUTPUT_DIR=%FIRMWARE_DIR%analysis

mkdir "%PROJECT_DIR%" 2>nul
mkdir "%OUTPUT_DIR%" 2>nul

echo Running Ghidra headless analysis...
echo Firmware: %FIRMWARE%
echo Project: %PROJECT_DIR%
echo Output: %OUTPUT_DIR%

"%GHIDRA_PATH%\support\analyzeHeadless.bat" ^
    "%PROJECT_DIR%" ^
    RT-950-Analysis ^
    -import "%FIRMWARE%" ^
    -processor ARM:LE:32:Cortex ^
    -analysisTimeoutPerFile 3600 ^
    -deleteProject

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Analysis complete. Check Ghidra project: %PROJECT_DIR%
) else (
    echo.
    echo Analysis failed with error code: %ERRORLEVEL%
    exit /b 1
)

