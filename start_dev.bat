@echo off
REM ================================================
REM SecureVault - Development Server Startup Script
REM ================================================

echo.
echo ====================================================
echo   SecureVault - Secure File Locker System
echo   Development Server
echo ====================================================
echo.

REM Set development environment
set FLASK_ENV=development

echo [INFO] Environment: DEVELOPMENT
echo [INFO] Server: Flask Debug Server
echo [INFO] Port: 5000
echo [INFO] Debug Mode: ON
echo.
echo ====================================================
echo   Starting server at http://localhost:5000
echo   Press Ctrl+C to stop
echo ====================================================
echo.

python app.py
