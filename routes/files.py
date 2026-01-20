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
    """
    DEPRECATED: Legacy server-side encryption.
    Redirects to dashboard or returns error.
    New uploads must use E2E encryption.
    """
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': 'Server-side encryption is disabled. Use E2E encryption.'}), 400
    
    flash('Standard upload is disabled. Please use the "Upload & Encrypt (E2E)" button.', 'warning')
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


# ============== E2E Encrypted Routes ==============

@files_bp.route('/upload-e2e', methods=['POST'])
@login_required
def upload_e2e():
    """
    Handle E2E encrypted file upload.
    File is already encrypted in the browser - server just stores it.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    salt_b64 = request.form.get('salt')
    original_filename = request.form.get('original_filename', 'unknown')
    original_size = request.form.get('original_size', 0)
    
    if not salt_b64:
        return jsonify({'error': 'Missing encryption salt'}), 400
    
    # Read the already-encrypted data
    encrypted_data = file.read()
    
    # Generate unique filename for storage
    encrypted_filename = f"{uuid.uuid4().hex}.e2e"
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], encrypted_filename)
    
    # Ensure upload directory exists
    os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Save encrypted file (already encrypted by browser)
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    # Create database record
    file_record = File(
        original_filename=secure_filename(original_filename),
        encrypted_filename=encrypted_filename,
        file_size=int(original_size),
        mime_type='application/octet-stream',
        salt=salt_b64,  # Store base64 salt for E2E
        is_locked=True,
        is_e2e=True,  # Mark as E2E encrypted
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
        details=f'E2E Upload: {original_filename} ({file_record.formatted_size})',
        ip_address=request.remote_addr,
        status='success'
    )
    
    return jsonify({'success': True, 'message': 'File uploaded successfully'})


@files_bp.route('/download-e2e/<int:file_id>', methods=['POST'])
@login_required
def download_e2e(file_id):
    """
    Download E2E encrypted file.
    Returns raw encrypted bytes - decryption happens in browser.
    """
    file_record = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    
    # Read encrypted file
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_record.encrypted_filename)
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Log download
    file_record.record_access()
    AuditLog.log(
        action=AuditLog.ACTION_FILE_DOWNLOAD,
        user_id=current_user.id,
        resource_type='file',
        resource_id=file_record.id,
        details=f'E2E Download: {file_record.original_filename}',
        ip_address=request.remote_addr,
        status='success'
    )
    
    # Return raw encrypted bytes - browser will decrypt
    return send_file(
        BytesIO(encrypted_data),
        mimetype='application/octet-stream',
        as_attachment=False
    )


@files_bp.route('/file-info/<int:file_id>')
@login_required
def file_info(file_id):
    """Get file metadata for E2E decryption."""
    file_record = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    
    return jsonify({
        'id': file_record.id,
        'filename': file_record.original_filename,
        'salt': file_record.salt,
        'is_e2e': getattr(file_record, 'is_e2e', False),
        'size': file_record.file_size,
        'mime_type': file_record.mime_type or 'application/octet-stream'
    })
