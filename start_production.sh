#!/bin/bash
# ================================================
# SecureVault - Production Server Startup Script
# For Linux/Mac
# ================================================

echo ""
echo "===================================================="
echo "  SecureVault - Secure File Locker System"
echo "  Production Server Startup"
echo "===================================================="
echo ""

# Set production environment
export FLASK_ENV=production

# Check if SECRET_KEY is set
if [ -z "$SECRET_KEY" ]; then
    echo "[WARNING] No SECRET_KEY set. Generating random key..."
    echo "[WARNING] For production, set SECRET_KEY environment variable!"
    export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
fi

# Check if gunicorn is installed
if ! command -v gunicorn &> /dev/null; then
    echo "[INFO] Installing gunicorn..."
    pip install gunicorn
fi

echo ""
echo "[INFO] Environment: PRODUCTION"
echo "[INFO] Server: Gunicorn WSGI"
echo "[INFO] Port: 5000"
echo "[INFO] Workers: 4"
echo ""
echo "[SECURITY] Session Cookie: Secure + HttpOnly"
echo "[SECURITY] CSRF Protection: Enabled"
echo "[SECURITY] Rate Limiting: Enabled"
echo ""
echo "===================================================="
echo "  Starting server at http://localhost:5000"
echo "  Press Ctrl+C to stop"
echo "===================================================="
echo ""

# Start production server with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app('production')"
