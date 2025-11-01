@echo off
title DomainScout Pro - Installer
color 0A

echo.
echo ========================================================
echo           DOMAINSCOUT PRO - AUTO INSTALLER
echo              Premium Domain Intelligence
echo ========================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH!
    echo.
    echo Please install Python 3.8 or higher from:
    echo https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [INFO] Running automated setup...
echo.
python auto_setup.py

if errorlevel 1 (
    echo.
    echo [ERROR] Setup failed! Please check errors above.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo [SUCCESS] Setup completed successfully!
echo ========================================================
echo.
echo To start DomainScout Pro, run:
echo   START_DOMAINSCOUT.bat
echo.
pause
