"""
Security middleware and utilities for production deployment.
Implements rate limiting, security headers, and brute-force protection.
"""

from functools import wraps
from datetime import datetime, timedelta
from flask import request, abort, current_app, g
from collections import defaultdict
import threading


class RateLimiter:
    """
    In-memory rate limiter for brute-force protection.
    For production, consider using Redis-based rate limiting.
    """
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_rate_limited(self, key, limit, period_seconds):
        """
        Check if a key has exceeded the rate limit.
        
        Args:
            key: Unique identifier (e.g., IP address, user ID)
            limit: Maximum number of requests allowed
            period_seconds: Time period in seconds
            
        Returns:
            True if rate limited, False otherwise
        """
        now = datetime.now()
        cutoff = now - timedelta(seconds=period_seconds)
        
        with self.lock:
            # Clean old entries
            self.requests[key] = [t for t in self.requests[key] if t > cutoff]
            
            # Check limit
            if len(self.requests[key]) >= limit:
                return True
            
            # Record request
            self.requests[key].append(now)
            return False
    
    def clear(self, key):
        """Clear rate limit for a key."""
        with self.lock:
            if key in self.requests:
                del self.requests[key]


class LoginAttemptTracker:
    """
    Track failed login attempts for account lockout.
    """
    
    def __init__(self):
        self.failed_attempts = defaultdict(list)
        self.lockouts = {}
        self.lock = threading.Lock()
    
    def record_failed_attempt(self, identifier):
        """Record a failed login attempt."""
        with self.lock:
            self.failed_attempts[identifier].append(datetime.now())
    
    def get_failed_attempts(self, identifier, window_minutes=15):
        """Get number of failed attempts within the time window."""
        cutoff = datetime.now() - timedelta(minutes=window_minutes)
        
        with self.lock:
            attempts = [t for t in self.failed_attempts[identifier] if t > cutoff]
            self.failed_attempts[identifier] = attempts
            return len(attempts)
    
    def is_locked_out(self, identifier):
        """Check if an identifier is locked out."""
        with self.lock:
            if identifier in self.lockouts:
                if datetime.now() < self.lockouts[identifier]:
                    return True
                else:
                    del self.lockouts[identifier]
            return False
    
    def lockout(self, identifier, duration_minutes=15):
        """Lock out an identifier for a specified duration."""
        with self.lock:
            self.lockouts[identifier] = datetime.now() + timedelta(minutes=duration_minutes)
    
    def clear(self, identifier):
        """Clear failed attempts and lockout for an identifier."""
        with self.lock:
            if identifier in self.failed_attempts:
                del self.failed_attempts[identifier]
            if identifier in self.lockouts:
                del self.lockouts[identifier]


# Global instances
rate_limiter = RateLimiter()
login_tracker = LoginAttemptTracker()


def add_security_headers(response):
    """
    Add security headers to response.
    Called as an after_request handler.
    """
    headers = current_app.config.get('SECURITY_HEADERS', {})
    for header, value in headers.items():
        response.headers[header] = value
    
    # Additional security headers
    response.headers['X-Request-Id'] = getattr(g, 'request_id', 'unknown')
    
    return response


def rate_limit(limit=100, period=60, key_func=None):
    """
    Rate limiting decorator.
    
    Args:
        limit: Maximum number of requests
        period: Time period in seconds
        key_func: Function to generate rate limit key (default: IP address)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_app.config.get('RATELIMIT_ENABLED', True):
                return f(*args, **kwargs)
            
            # Get rate limit key
            if key_func:
                key = key_func()
            else:
                key = request.remote_addr
            
            # Check rate limit
            if rate_limiter.is_rate_limited(key, limit, period):
                abort(429, description="Too many requests. Please try again later.")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def check_login_attempts(identifier):
    """
    Check if login should be blocked due to too many failed attempts.
    Returns True if blocked, False if allowed.
    """
    max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
    lockout_duration = current_app.config.get('LOGIN_LOCKOUT_DURATION', timedelta(minutes=15))
    
    # Check if already locked out
    if login_tracker.is_locked_out(identifier):
        return True
    
    # Check if should be locked out
    attempts = login_tracker.get_failed_attempts(identifier)
    if attempts >= max_attempts:
        login_tracker.lockout(identifier, lockout_duration.total_seconds() / 60)
        return True
    
    return False


def record_failed_login(identifier):
    """Record a failed login attempt."""
    login_tracker.record_failed_attempt(identifier)


def clear_login_attempts(identifier):
    """Clear failed login attempts after successful login."""
    login_tracker.clear(identifier)


def validate_file_extension(filename):
    """
    Validate file extension against allowed list.
    
    Args:
        filename: Name of the file to validate
        
    Returns:
        True if allowed, False otherwise
    """
    if '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    allowed = current_app.config.get('ALLOWED_EXTENSIONS', set())
    
    # If no restrictions configured, allow all
    if not allowed:
        return True
    
    return ext in allowed


def sanitize_filename(filename):
    """
    Sanitize a filename to prevent path traversal and other attacks.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    import re
    from werkzeug.utils import secure_filename
    
    # Use Werkzeug's secure_filename
    filename = secure_filename(filename)
    
    # Additional sanitization
    # Remove any remaining suspicious characters
    filename = re.sub(r'[^\w\s\-\.]', '', filename)
    
    # Limit filename length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:250] + ('.' + ext if ext else '')
    
    return filename


def get_client_ip():
    """
    Get the real client IP address, handling proxies.
    """
    # Check for X-Forwarded-For header (behind proxy/load balancer)
    if request.headers.get('X-Forwarded-For'):
        # Take the first IP in the chain
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    
    # Check for X-Real-IP header
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    
    # Fall back to remote_addr
    return request.remote_addr


def generate_request_id():
    """Generate a unique request ID for tracking."""
    import uuid
    return str(uuid.uuid4())[:8]
