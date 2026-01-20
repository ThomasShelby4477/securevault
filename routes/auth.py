"""Authentication routes with production security."""

from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp

from models import db
from models.user import User
from models.audit import AuditLog
from crypto.engine import CryptoEngine
from security import (
    rate_limit, check_login_attempts, record_failed_login, 
    clear_login_attempts, get_client_ip
)


auth_bp = Blueprint('auth', __name__)


# ============== Forms with Enhanced Validation ==============

class LoginForm(FlaskForm):
    """Login form with email and password."""
    email = EmailField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Please enter a valid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required')
    ])


class SignupForm(FlaskForm):
    """Registration form with strong password requirements."""
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=80, message='Username must be 3-80 characters'),
        Regexp(r'^[\w]+$', message='Username can only contain letters, numbers, and underscores')
    ])
    email = EmailField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Please enter a valid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=8, message='Password must be at least 8 characters'),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
            message='Password must include uppercase, lowercase, number, and special character'
        )
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('password', message='Passwords must match')
    ])
    
    def validate_email(self, field):
        """Check if email is already registered."""
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('Email already registered')
    
    def validate_username(self, field):
        """Check if username is already taken."""
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')


# ============== Routes with Security ==============

@auth_bp.route('/login', methods=['GET', 'POST'])
@rate_limit(limit=10, period=60)  # 10 requests per minute
def login():
    """Handle user login with brute-force protection."""
    if current_user.is_authenticated:
        return redirect(url_for('files.dashboard'))
    
    form = LoginForm()
    client_ip = get_client_ip()
    
    # Check for account lockout
    if check_login_attempts(client_ip):
        flash('Too many failed attempts. Please try again in 15 minutes.', 'error')
        AuditLog.log(
            action=AuditLog.ACTION_LOGIN_FAILED,
            resource_type='session',
            details=f'Locked out: {client_ip}',
            ip_address=client_ip,
            user_agent=request.user_agent.string[:255] if request.user_agent.string else None,
            status='failure'
        )
        return render_template('login.html', form=form)
    
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()
        
        if user and CryptoEngine.verify_password(form.password.data, user.password_hash):
            # Clear failed attempts on successful login
            clear_login_attempts(client_ip)
            clear_login_attempts(email)
            
            login_user(user, remember=False)  # Don't remember for security
            user.update_last_login()
            
            # Log successful login
            AuditLog.log(
                action=AuditLog.ACTION_LOGIN,
                user_id=user.id,
                resource_type='session',
                ip_address=client_ip,
                user_agent=request.user_agent.string[:255] if request.user_agent.string else None,
                status='success'
            )
            
            flash('Welcome back!', 'success')
            next_page = request.args.get('next')
            
            # Security: Validate next URL to prevent open redirect
            if next_page and not next_page.startswith('/'):
                next_page = None
            
            return redirect(next_page if next_page else url_for('files.dashboard'))
        else:
            # Record failed attempt
            record_failed_login(client_ip)
            record_failed_login(email if user else 'unknown')
            
            # Log failed login attempt
            AuditLog.log(
                action=AuditLog.ACTION_LOGIN_FAILED,
                user_id=user.id if user else None,
                resource_type='session',
                details=f'Failed login for: {email}',
                ip_address=client_ip,
                user_agent=request.user_agent.string[:255] if request.user_agent.string else None,
                status='failure'
            )
            
            # Generic error message to prevent user enumeration
            flash('Invalid email or password', 'error')
    
    return render_template('login.html', form=form)


@auth_bp.route('/signup', methods=['GET', 'POST'])
@rate_limit(limit=5, period=60)  # 5 signups per minute per IP
def signup():
    """Handle user registration with rate limiting."""
    if current_user.is_authenticated:
        return redirect(url_for('files.dashboard'))
    
    form = SignupForm()
    client_ip = get_client_ip()
    
    if form.validate_on_submit():
        # Create new user with hashed password
        user = User(
            username=form.username.data.strip(),
            email=form.email.data.lower().strip(),
            password_hash=CryptoEngine.hash_password(form.password.data)
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log signup
        AuditLog.log(
            action=AuditLog.ACTION_SIGNUP,
            user_id=user.id,
            resource_type='user',
            resource_id=user.id,
            ip_address=client_ip,
            user_agent=request.user_agent.string[:255] if request.user_agent.string else None,
            status='success'
        )
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('signup.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    client_ip = get_client_ip()
    
    # Log logout
    AuditLog.log(
        action=AuditLog.ACTION_LOGOUT,
        user_id=current_user.id,
        resource_type='session',
        ip_address=client_ip,
        status='success'
    )
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
