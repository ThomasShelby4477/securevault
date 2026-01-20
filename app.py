"""
Secure Web-Based File Locking & Password Protection System
Main Flask Application - Production Ready
"""

import os
import uuid
from flask import Flask, g, request
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from config import config
from models import db
from models.user import User

# Initialize CSRF protection globally
csrf = CSRFProtect()


def create_app(config_name=None):
    """Application factory pattern with security enhancements."""
    
    # Determine configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    app.config.from_object(config.get(config_name, config['default']))
    
    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.session_protection = 'strong'  # Enhanced session security
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Security: Add request ID for tracking
    @app.before_request
    def before_request():
        g.request_id = str(uuid.uuid4())[:8]
    
    # Security: Add security headers to all responses
    @app.after_request
    def add_security_headers(response):
        from security import add_security_headers as add_headers
        return add_headers(response)
    
    # Security: Log all requests (for audit trail)
    @app.after_request
    def log_request(response):
        if app.config.get('DEBUG'):
            app.logger.debug(
                f"[{g.get('request_id', 'N/A')}] "
                f"{request.method} {request.path} -> {response.status_code}"
            )
        return response
    
    # Error handlers
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return {'error': 'Too many requests. Please try again later.'}, 429
    
    @app.errorhandler(413)
    def file_too_large(e):
        return {'error': 'File too large. Maximum size is 500MB.'}, 413
    
    @app.errorhandler(403)
    def forbidden(e):
        return {'error': 'Access denied.'}, 403
    
    # Register blueprints
    from routes.auth import auth_bp
    from routes.files import files_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    
    # Register template utilities
    from geolocation import format_ip_with_location
    
    @app.context_processor
    def utility_processor():
        return {'get_ip_location': format_ip_with_location}
    
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Ensure upload folder exists with secure permissions
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    return app


# Create application instance
app = create_app()


if __name__ == '__main__':
    # Development server only - use Gunicorn/uWSGI for production
    print("⚠️  Running in development mode. Use Gunicorn for production!")
    print("🔐 SecureVault File Locker System")
    print("📍 http://localhost:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
