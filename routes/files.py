"""File management routes for upload, download, lock/unlock operations."""

import os
import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, jsonify, current_app
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import PasswordField
from wtforms.validators import DataRequired, Length
from werkzeug.utils import secure_filename
from io import BytesIO

from models import db
from models.file import File
from models.audit import AuditLog
from crypto.engine import CryptoEngine


files_bp = Blueprint('files', __name__)


# ============== Forms ==============

class UploadForm(FlaskForm):
    """File upload form with encryption password."""
    file = FileField('File', validators=[FileRequired()])
    password = PasswordField('Encryption Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters')
    ])


class PasswordForm(FlaskForm):
    """Password form for file operations."""
    password = PasswordField('Password', validators=[DataRequired()])


# ============== Routes ==============

@files_bp.route('/')
@files_bp.route('/dashboard')
@login_required
def dashboard():
    """Display user's file dashboard."""
    files = File.query.filter_by(user_id=current_user.id).order_by(File.uploaded_at.desc()).all()
    upload_form = UploadForm()
    password_form = PasswordForm()
    return render_template('dashboard.html', files=files, upload_form=upload_form, password_form=password_form)


@files_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file upload with encryption."""
    form = UploadForm()
    
    if form.validate_on_submit():
        file = form.file.data
        password = form.password.data
        
        # Read file data
        file_data = file.read()
        original_filename = secure_filename(file.filename)
        file_size = len(file_data)
        
        # Encrypt the file
        try:
            encrypted_data, salt = CryptoEngine.encrypt_file(file_data, password)
        except Exception as e:
            flash('Encryption failed. Please try again.', 'error')
            return redirect(url_for('files.dashboard'))
        
        # Generate unique filename for storage
        encrypted_filename = f"{uuid.uuid4().hex}.enc"
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        # Ensure upload directory exists
        os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save encrypted file
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Create database record
        file_record = File(
            original_filename=original_filename,
            encrypted_filename=encrypted_filename,
            file_size=file_size,
            mime_type=file.content_type,
            salt=salt,
            is_locked=True,
            user_id=current_user.id
        )
        
        db.session.add(file_record)
        db.session.commit()
        
        # Log upload
        AuditLog.log(
            action=AuditLog.ACTION_FILE_UPLOAD,
            user_id=current_user.id,
            resource_type='file',
            resource_id=file_record.id,
            details=f'Uploaded: {original_filename} ({file_record.formatted_size})',
            ip_address=request.remote_addr,
            status='success'
        )
        
        flash(f'File "{original_filename}" uploaded and encrypted successfully!', 'success')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{error}', 'error')
    
    return redirect(url_for('files.dashboard'))


@files_bp.route('/download/<int:file_id>', methods=['POST'])
@login_required
def download_file(file_id):
    """Handle file download with decryption."""
    file_record = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    
    password = request.form.get('password')
    if not password:
        flash('Password is required', 'error')
        return redirect(url_for('files.dashboard'))
    
    # Read encrypted file
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_record.encrypted_filename)
    
    if not os.path.exists(file_path):
        flash('File not found on server', 'error')
        return redirect(url_for('files.dashboard'))
    
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Attempt decryption
    try:
        decrypted_data = CryptoEngine.decrypt_file(encrypted_data, password, file_record.salt)
    except Exception:
        # Log failed attempt
        file_record.record_failed_attempt()
        AuditLog.log(
            action=AuditLog.ACTION_UNLOCK_FAILED,
            user_id=current_user.id,
            resource_type='file',
            resource_id=file_record.id,
            details=f'Failed download attempt: {file_record.original_filename}',
            ip_address=request.remote_addr,
            status='failure'
        )
        flash('Incorrect password or file corrupted', 'error')
        return redirect(url_for('files.dashboard'))
    
    # Log successful download
    file_record.record_access()
    file_record.reset_failed_attempts()
    AuditLog.log(
        action=AuditLog.ACTION_FILE_DOWNLOAD,
        user_id=current_user.id,
        resource_type='file',
        resource_id=file_record.id,
        details=f'Downloaded: {file_record.original_filename}',
        ip_address=request.remote_addr,
        status='success'
    )
    
    # Send decrypted file with explicit filename header
    response = send_file(
        BytesIO(decrypted_data),
        download_name=file_record.original_filename,
        mimetype=file_record.mime_type or 'application/octet-stream',
        as_attachment=True
    )
    # Explicitly override Content-Disposition to ensure correct filename
    response.headers['Content-Disposition'] = f'attachment; filename="{file_record.original_filename}"'
    return response


@files_bp.route('/verify/<int:file_id>', methods=['POST'])
@login_required
def verify_password(file_id):
    """Verify file password (AJAX endpoint)."""
    file_record = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'valid': False, 'message': 'Password required'})
    
    # Read a portion of the encrypted file to verify
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_record.encrypted_filename)
    
    if not os.path.exists(file_path):
        return jsonify({'valid': False, 'message': 'File not found'})
    
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Verify password
    is_valid = CryptoEngine.verify_file_password(encrypted_data, password, file_record.salt)
    
    if is_valid:
        return jsonify({'valid': True, 'message': 'Password verified'})
    else:
        file_record.record_failed_attempt()
        return jsonify({'valid': False, 'message': 'Incorrect password'})


@files_bp.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete an encrypted file."""
    file_record = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    
    # Delete physical file
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_record.encrypted_filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    filename = file_record.original_filename
    
    # Log deletion
    AuditLog.log(
        action=AuditLog.ACTION_FILE_DELETE,
        user_id=current_user.id,
        resource_type='file',
        resource_id=file_record.id,
        details=f'Deleted: {filename}',
        ip_address=request.remote_addr,
        status='success'
    )
    
    # Delete database record
    db.session.delete(file_record)
    db.session.commit()
    
    flash(f'File "{filename}" deleted successfully', 'success')
    return redirect(url_for('files.dashboard'))


@files_bp.route('/logs')
@login_required
def activity_logs():
    """Display user's activity logs."""
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.filter_by(user_id=current_user.id)\
        .order_by(AuditLog.timestamp.desc())\
        .paginate(page=page, per_page=20, error_out=False)
    
    return render_template('logs.html', logs=logs)
