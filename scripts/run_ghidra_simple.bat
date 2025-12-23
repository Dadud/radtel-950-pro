@echo off
REM Simple Ghidra headless analysis - direct execution
REM Usage: run_ghidra_simple.bat

set GHIDRA_DIR=C:\Users\dadud\Downloads\ghidra_12.0_PUBLIC_20251205\ghidra_12.0_PUBLIC
set FIRMWARE=firmware\rt950\RT_950_V0.29_251104.BTF
set PROJECT_DIR=firmware\rt950\ghidra_project
set PROJECT_NAME=RT-950-Analysis

echo ========================================
echo Running Ghidra Headless Analysis
echo ========================================
echo.
echo This will analyze the RT-950 firmware.
echo Analysis typically takes 5-15 minutes.
echo.
pause

mkdir "%PROJECT_DIR%" 2>nul

"%GHIDRA_DIR%\support\analyzeHeadless.bat" ^
    "%PROJECT_DIR%" ^
    "%PROJECT_NAME%" ^
    -import "%FIRMWARE%" ^
    -processor ARM:LE:32:Cortex ^
    -analysisTimeoutPerFile 3600

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Analysis Complete!
    echo ========================================
    echo.
    echo Project saved to: %PROJECT_DIR%
    echo.
    echo To view results:
    echo   1. Open Ghidra
    echo   2. File ^> Open Project
    echo   3. Navigate to: %CD%\%PROJECT_DIR%
    echo   4. Select: %PROJECT_NAME%
    echo.
) else (
    echo.
    echo Analysis failed with error code: %ERRORLEVEL%
)

pause

