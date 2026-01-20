@echo off
REM ================================================
REM SecureVault - Production Server Startup Script
REM ================================================

echo.
echo ====================================================
echo   SecureVault - Secure File Locker System
echo   Production Server Startup
echo ====================================================
echo.

REM Set production environment
set FLASK_ENV=production

REM Generate a secure secret key if not already set
if "%SECRET_KEY%"=="" (
    echo [WARNING] No SECRET_KEY set. Generating random key...
    echo [WARNING] For production, set SECRET_KEY environment variable!
    for /f "delims=" %%i in ('python -c "import secrets; print(secrets.token_hex(32))"') do set SECRET_KEY=%%i
)

REM Check if waitress is installed
pip show waitress >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing waitress...
    pip install waitress
)

echo.
echo [INFO] Environment: PRODUCTION
echo [INFO] Server: Waitress WSGI
echo [INFO] Port: 5000
echo [INFO] Threads: 4
echo.
echo [SECURITY] Session Cookie: Secure + HttpOnly
echo [SECURITY] CSRF Protection: Enabled
echo [SECURITY] Rate Limiting: Enabled
echo.
echo ====================================================
echo   Starting server at http://localhost:5000
echo   Press Ctrl+C to stop
echo ====================================================
echo.

REM Start production server with waitress
python -c "from waitress import serve; from app import create_app; app = create_app('production'); print('🔐 SecureVault Production Server Running...'); serve(app, host='0.0.0.0', port=5000, threads=4)"
