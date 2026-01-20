from datetime import datetime
from models import db

class File(db.Model):
    """Model for encrypted files with lock status."""
    
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), unique=True, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # Size in bytes
    mime_type = db.Column(db.String(100))
    
    # Encryption metadata
    salt = db.Column(db.LargeBinary(16), nullable=False)  # For key derivation
    is_locked = db.Column(db.Boolean, default=True)
    
    # Ownership and timestamps
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)
    
    # Access tracking
    download_count = db.Column(db.Integer, default=0)
    failed_attempts = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<File {self.original_filename}>'
    
    def record_access(self):
        """Record file access."""
        self.last_accessed = datetime.utcnow()
        self.download_count += 1
        db.session.commit()
    
    def record_failed_attempt(self):
        """Record failed unlock attempt."""
        self.failed_attempts += 1
        db.session.commit()
    
    def reset_failed_attempts(self):
        """Reset failed attempts counter."""
        self.failed_attempts = 0
        db.session.commit()
    
    @property
    def formatted_size(self):
        """Return human-readable file size."""
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
