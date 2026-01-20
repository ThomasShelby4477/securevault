/**
 * SecureVault Client-Side Encryption Module
 * Implements true End-to-End Encryption using Web Crypto API
 * 
 * Flow: File → Browser Encryption → Server (never sees plaintext) → Storage
 */

class E2ECrypto {
    // Encryption parameters matching server-side
    static PBKDF2_ITERATIONS = 100000;
    static SALT_LENGTH = 16;
    static IV_LENGTH = 12;  // GCM standard
    static KEY_LENGTH = 256;  // bits

    /**
     * Generate cryptographically secure random bytes
     */
    static generateSalt() {
        return crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
    }

    static generateIV() {
        return crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
    }

    /**
     * Derive encryption key from password using PBKDF2
     * @param {string} password - User's encryption password
     * @param {Uint8Array} salt - Random salt
     * @returns {Promise<CryptoKey>} - Derived AES-GCM key
     */
    static async deriveKey(password, salt) {
        // Import password as raw key material
        const passwordBuffer = new TextEncoder().encode(password);
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        // Derive AES-GCM key using PBKDF2
        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: this.KEY_LENGTH },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt a file in the browser
     * @param {ArrayBuffer} fileData - Raw file bytes
     * @param {string} password - Encryption password
     * @returns {Promise<{encrypted: Uint8Array, salt: Uint8Array, iv: Uint8Array}>}
     */
    static async encryptFile(fileData, password) {
        const salt = this.generateSalt();
        const iv = this.generateIV();
        const key = await this.deriveKey(password, salt);

        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            fileData
        );

        return {
            encrypted: new Uint8Array(encryptedBuffer),
            salt: salt,
            iv: iv
        };
    }

    /**
     * Decrypt a file in the browser
     * @param {ArrayBuffer} encryptedData - Encrypted file with prepended IV
     * @param {string} password - Decryption password
     * @param {Uint8Array} salt - Salt used during encryption
     * @returns {Promise<ArrayBuffer>} - Decrypted file data
     */
    static async decryptFile(encryptedData, password, salt) {
        // Extract IV from first 12 bytes
        const dataArray = new Uint8Array(encryptedData);
        const iv = dataArray.slice(0, this.IV_LENGTH);
        const ciphertext = dataArray.slice(this.IV_LENGTH);

        const key = await this.deriveKey(password, salt);

        try {
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                ciphertext
            );
            return decryptedBuffer;
        } catch (error) {
            throw new Error('Decryption failed: Invalid password or corrupted file');
        }
    }

    /**
     * Pack encrypted data with IV for storage
     * Format: [IV (12 bytes)][Encrypted Data]
     */
    static packEncryptedData(iv, encrypted) {
        const packed = new Uint8Array(iv.length + encrypted.length);
        packed.set(iv, 0);
        packed.set(encrypted, iv.length);
        return packed;
    }

    /**
     * Convert Uint8Array to Base64 for transmission
     */
    static arrayToBase64(array) {
        return btoa(String.fromCharCode.apply(null, array));
    }

    /**
     * Convert Base64 to Uint8Array
     */
    static base64ToArray(base64) {
        const binary = atob(base64);
        const array = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            array[i] = binary.charCodeAt(i);
        }
        return array;
    }

    /**
     * Read file as ArrayBuffer
     */
    static readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(reader.error);
            reader.readAsArrayBuffer(file);
        });
    }
}

/**
 * E2E Upload Handler
 * Encrypts file in browser before sending to server
 */
async function e2eUploadFile(file, password, csrfToken) {
    const statusEl = document.getElementById('upload-status');

    try {
        // Show encryption status
        if (statusEl) {
            statusEl.innerHTML = '<span class="encrypting">🔐 Encrypting in browser...</span>';
        }

        // Read file
        const fileData = await E2ECrypto.readFileAsArrayBuffer(file);

        // Encrypt in browser
        const { encrypted, salt, iv } = await E2ECrypto.encryptFile(fileData, password);

        // Pack IV with encrypted data
        const packedData = E2ECrypto.packEncryptedData(iv, encrypted);

        // Update status
        if (statusEl) {
            statusEl.innerHTML = '<span class="uploading">📤 Uploading encrypted file...</span>';
        }

        // Create form data with encrypted content
        const formData = new FormData();
        formData.append('file', new Blob([packedData]), file.name + '.e2e');
        formData.append('salt', E2ECrypto.arrayToBase64(salt));
        formData.append('original_filename', file.name);
        formData.append('original_size', file.size);
        formData.append('e2e_encrypted', 'true');

        // Upload to server
        const response = await fetch('/upload-e2e', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrfToken
            },
            body: formData
        });

        if (response.ok) {
            if (statusEl) {
                statusEl.innerHTML = '<span class="success">✅ File encrypted & uploaded!</span>';
            }
            // Reload page after short delay
            setTimeout(() => location.reload(), 1000);
            return true;
        } else {
            throw new Error('Upload failed');
        }

    } catch (error) {
        console.error('E2E Upload error:', error);
        if (statusEl) {
            statusEl.innerHTML = `<span class="error">❌ ${error.message}</span>`;
        }
        return false;
    }
}

/**
 * E2E Download Handler
 * Downloads encrypted file and decrypts in browser
 */
async function e2eDownloadFile(fileId, password, filename, salt, csrfToken, mimeType) {
    const statusEl = document.getElementById('download-status');

    try {
        // Show download status
        if (statusEl) {
            statusEl.innerHTML = '<span class="downloading">📥 Downloading encrypted file...</span>';
        }

        // Fetch encrypted file
        const response = await fetch(`/download-e2e/${fileId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ password: 'dummy' })  // Server doesn't need real password
        });

        if (!response.ok) {
            throw new Error('Download failed');
        }

        // Get encrypted data
        const encryptedData = await response.arrayBuffer();

        // Update status
        if (statusEl) {
            statusEl.innerHTML = '<span class="decrypting">🔓 Decrypting in browser...</span>';
        }

        // Convert salt from base64
        const saltArray = E2ECrypto.base64ToArray(salt);

        // Decrypt in browser
        const decryptedData = await E2ECrypto.decryptFile(encryptedData, password, saltArray);

        // Create download link
        console.log('Creating blob download link for:', filename, 'Type:', mimeType);
        const blob = new Blob([decryptedData], { type: mimeType || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();

        // Small delay before cleanup to ensure event propogation
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);

        if (statusEl) {
            statusEl.innerHTML = '<span class="success">✅ File decrypted & downloaded!</span>';
        }

        // Close modal after delay
        setTimeout(() => {
            const modal = document.getElementById('download-modal');
            if (modal) modal.classList.remove('active');
        }, 1500);

        return true;

    } catch (error) {
        console.error('E2E Download error:', error);
        if (statusEl) {
            statusEl.innerHTML = `<span class="error">❌ ${error.message}</span>`;
        }
        return false;
    }
}

// Export for use
window.E2ECrypto = E2ECrypto;
window.e2eUploadFile = e2eUploadFile;
window.e2eDownloadFile = e2eDownloadFile;

console.log('🔐 E2E Encryption Module Loaded');
console.log('📋 Using: AES-256-GCM + PBKDF2 (100k iterations)');
console.log('🛡️ Files are encrypted IN YOUR BROWSER before upload');
