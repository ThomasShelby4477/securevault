/**
 * SecureVault - Main JavaScript
 * Client-side functionality for the File Locker System
 */

// ============================================
// Password Toggle Functionality
// ============================================

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const eyeIcon = input.parentElement.querySelector('.eye-icon');

    if (input.type === 'password') {
        input.type = 'text';
        eyeIcon.textContent = '🙈';
    } else {
        input.type = 'password';
        eyeIcon.textContent = '👁️';
    }
}

// ============================================
// Password Strength Indicator
// ============================================

function checkPasswordStrength(password) {
    let strength = 0;

    // Length check
    if (password.length >= 8) strength += 1;
    if (password.length >= 12) strength += 1;
    if (password.length >= 16) strength += 1;

    // Character type checks
    if (/[a-z]/.test(password)) strength += 1;
    if (/[A-Z]/.test(password)) strength += 1;
    if (/[0-9]/.test(password)) strength += 1;
    if (/[^a-zA-Z0-9]/.test(password)) strength += 1;

    return Math.min(strength, 5);
}

function updatePasswordStrength(inputId, strengthId) {
    const input = document.getElementById(inputId);
    const strengthDiv = document.getElementById(strengthId);

    if (!input || !strengthDiv) return;

    const password = input.value;
    const strength = checkPasswordStrength(password);

    const colors = ['#eb3349', '#f45c43', '#f7971e', '#38ef7d', '#11998e'];
    const labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
    const widths = ['20%', '40%', '60%', '80%', '100%'];

    const index = Math.max(0, strength - 1);

    if (password.length === 0) {
        strengthDiv.innerHTML = '';
    } else {
        strengthDiv.innerHTML = `
            <div class="password-strength-bar" style="
                width: ${widths[index]};
                background: ${colors[index]};
            "></div>
            <span style="
                font-size: 0.75rem;
                color: ${colors[index]};
                margin-top: 4px;
                display: block;
            ">${labels[index]}</span>
        `;
    }
}

// Attach to password inputs
document.addEventListener('DOMContentLoaded', function () {
    // Signup password strength
    const signupPassword = document.getElementById('password');
    if (signupPassword && document.getElementById('password-strength')) {
        signupPassword.addEventListener('input', function () {
            updatePasswordStrength('password', 'password-strength');
        });
    }

    // Upload encryption password strength
    const encryptPassword = document.getElementById('encrypt-password');
    if (encryptPassword && document.getElementById('encrypt-password-strength')) {
        encryptPassword.addEventListener('input', function () {
            updatePasswordStrength('encrypt-password', 'encrypt-password-strength');
        });
    }
});

// ============================================
// Flash Message Auto-dismiss
// ============================================

document.addEventListener('DOMContentLoaded', function () {
    const flashMessages = document.querySelectorAll('.flash-message');

    flashMessages.forEach((message, index) => {
        setTimeout(() => {
            message.style.animation = 'slideOut 0.3s ease forwards';
            setTimeout(() => message.remove(), 300);
        }, 5000 + (index * 500));
    });
});

// Add slideOut animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// ============================================
// Form Validation
// ============================================

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePassword(password) {
    return password.length >= 8;
}

// ============================================
// Loading State for Buttons
// ============================================

function setButtonLoading(button, loading) {
    if (loading) {
        button.disabled = true;
        button.dataset.originalText = button.innerHTML;
        button.innerHTML = `
            <span class="spinner" style="
                display: inline-block;
                width: 16px;
                height: 16px;
                border: 2px solid rgba(255,255,255,0.3);
                border-top-color: white;
                border-radius: 50%;
                animation: spin 0.8s linear infinite;
            "></span>
            <span>Processing...</span>
        `;
    } else {
        button.disabled = false;
        if (button.dataset.originalText) {
            button.innerHTML = button.dataset.originalText;
        }
    }
}

// Add spinner animation
const spinnerStyle = document.createElement('style');
spinnerStyle.textContent = `
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
`;
document.head.appendChild(spinnerStyle);

// ============================================
// AJAX Password Verification
// ============================================

async function verifyFilePassword(fileId, password) {
    try {
        const response = await fetch(`/verify/${fileId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ password })
        });

        const data = await response.json();
        return data.valid;
    } catch (error) {
        console.error('Password verification failed:', error);
        return false;
    }
}

// ============================================
// File Size Formatting
// ============================================

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';

    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));

    return parseFloat((bytes / Math.pow(1024, i)).toFixed(1)) + ' ' + units[i];
}

// ============================================
// Keyboard Shortcuts
// ============================================

document.addEventListener('keydown', function (e) {
    // Ctrl/Cmd + U = Open upload modal
    if ((e.ctrlKey || e.metaKey) && e.key === 'u') {
        e.preventDefault();
        const uploadBtn = document.querySelector('.upload-btn');
        if (uploadBtn) {
            uploadBtn.click();
        }
    }
});

// ============================================
// Accessibility Improvements
// ============================================

// Focus trap for modals
function trapFocus(element) {
    const focusableElements = element.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    element.addEventListener('keydown', function (e) {
        if (e.key === 'Tab') {
            if (e.shiftKey) {
                if (document.activeElement === firstElement) {
                    lastElement.focus();
                    e.preventDefault();
                }
            } else {
                if (document.activeElement === lastElement) {
                    firstElement.focus();
                    e.preventDefault();
                }
            }
        }
    });
}

// Apply focus trap to modals when opened
document.querySelectorAll('.modal').forEach(modal => {
    trapFocus(modal);
});

// ============================================
// Copy to Clipboard Utility
// ============================================

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        console.error('Failed to copy:', err);
        return false;
    }
}

// ============================================
// Console Security Notice
// ============================================

console.log('%c🔐 SecureVault', 'font-size: 24px; font-weight: bold; color: #667eea;');
console.log('%cYour files are protected with AES-256-GCM encryption', 'font-size: 12px; color: #888;');
console.log('%c⚠️ Warning: Never share your encryption passwords!', 'font-size: 12px; color: #f45c43;');
