@echo off
title DomainScout Pro
color 0B

echo.
echo ========================================================
echo           DOMAINSCOUT PRO - LAUNCHING
echo              Premium Domain Intelligence
echo ========================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH!
    pause
    exit /b 1
)

echo [INFO] Starting DomainScout Pro...
echo.
python domainscout_pro.py

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to start application!
    echo.
    echo If this is your first time, please run INSTALL.bat first
    echo.
    pause
)
