from datetime import datetime
from models import db

class AuditLog(db.Model):
    """Audit log for tracking all security-relevant events."""
    
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Nullable for failed login attempts
    action = db.Column(db.String(50), nullable=False)
    resource_type = db.Column(db.String(50))  # 'file', 'user', 'session'
    resource_id = db.Column(db.Integer)  # ID of the affected resource
    details = db.Column(db.Text)  # JSON string with additional details
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.String(255))
    status = db.Column(db.String(20), default='success')  # 'success', 'failure', 'warning'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Action types
    ACTION_LOGIN = 'login'
    ACTION_LOGOUT = 'logout'
    ACTION_LOGIN_FAILED = 'login_failed'
    ACTION_SIGNUP = 'signup'
    ACTION_FILE_UPLOAD = 'file_upload'
    ACTION_FILE_DOWNLOAD = 'file_download'
    ACTION_FILE_DELETE = 'file_delete'
    ACTION_FILE_LOCK = 'file_lock'
    ACTION_FILE_UNLOCK = 'file_unlock'
    ACTION_UNLOCK_FAILED = 'unlock_failed'
    
    def __repr__(self):
        return f'<AuditLog {self.action} by User {self.user_id}>'
    
    @classmethod
    def log(cls, action, user_id=None, resource_type=None, resource_id=None,
            details=None, ip_address=None, user_agent=None, status='success'):
        """Create a new audit log entry."""
        log_entry = cls(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status
        )
        db.session.add(log_entry)
        db.session.commit()
        return log_entry
    
    @property
    def action_icon(self):
        """Return appropriate icon for the action type."""
        icons = {
            'login': '🔓',
            'logout': '🚪',
            'login_failed': '⛔',
            'signup': '👤',
            'file_upload': '📤',
            'file_download': '📥',
            'file_delete': '🗑️',
            'file_lock': '🔒',
            'file_unlock': '🔓',
            'unlock_failed': '❌'
        }
        return icons.get(self.action, '📋')
    
    @property
    def action_color(self):
        """Return appropriate color class for the action."""
        colors = {
            'success': 'success',
            'failure': 'danger',
            'warning': 'warning'
        }
        return colors.get(self.status, 'secondary')
