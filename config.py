import os
from datetime import timedelta

class Config:
    """Base configuration."""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    
    # Database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///file_locker.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session settings - SECURE FOR PRODUCTION
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)  # Shorter session for security
    SESSION_COOKIE_SECURE = True  # Only send over HTTPS
    SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE = 'Strict'  # Strict CSRF protection
    SESSION_COOKIE_NAME = '__Host-session'  # Secure cookie prefix
    
    # File upload settings
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max file size
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 
        'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z', 'mp3', 
        'mp4', 'avi', 'mkv', 'csv', 'json', 'xml'
    }
    
    # Crypto settings - STRONG PARAMETERS
    PBKDF2_ITERATIONS = 100000  # NIST recommended minimum
    SALT_LENGTH = 16
    KEY_LENGTH = 32  # 256 bits for AES-256
    
    # bcrypt settings
    BCRYPT_ROUNDS = 12  # Good balance of security and performance
    
    # Security settings
    MAX_LOGIN_ATTEMPTS = 5  # Lock account after 5 failed attempts
    LOGIN_LOCKOUT_DURATION = timedelta(minutes=15)  # 15 minute lockout
    MAX_FILE_ACCESS_ATTEMPTS = 10  # Lock file after 10 failed attempts
    
    # Rate limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "100 per minute"
    RATELIMIT_LOGIN = "5 per minute"
    RATELIMIT_UPLOAD = "10 per minute"
    
    # Security Headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development
    SESSION_COOKIE_NAME = 'session'  # Standard name for development


class ProductionConfig(Config):
    """Production configuration with maximum security."""
    DEBUG = False
    TESTING = False
    
    # Force HTTPS
    PREFERRED_URL_SCHEME = 'https'
    
    # Use environment variable for secret key in production (with fallback)
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    
    # Use production database (with fallback to SQLite)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///file_locker.db'


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
