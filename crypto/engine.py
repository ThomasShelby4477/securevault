"""Cryptographic engine for file encryption and password hashing."""

import os
import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class CryptoEngine:
    """Handles all cryptographic operations for the file locker."""
    
    # Configuration
    PBKDF2_ITERATIONS = 100000
    SALT_LENGTH = 16
    KEY_LENGTH = 32  # 256 bits for AES-256
    NONCE_LENGTH = 12  # 96 bits for AES-GCM
    BCRYPT_ROUNDS = 12
    
    @classmethod
    def generate_salt(cls):
        """Generate a random salt for key derivation."""
        return os.urandom(cls.SALT_LENGTH)
    
    @classmethod
    def derive_key(cls, password: str, salt: bytes) -> bytes:
        """
        Derive a 256-bit encryption key from password using PBKDF2.
        
        Args:
            password: User's encryption password
            salt: Random salt (must be stored with encrypted file)
            
        Returns:
            32-byte key suitable for AES-256
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=cls.KEY_LENGTH,
            salt=salt,
            iterations=cls.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    @classmethod
    def encrypt_file(cls, plaintext: bytes, password: str) -> tuple[bytes, bytes]:
        """
        Encrypt file data using AES-256-GCM.
        
        Args:
            plaintext: Raw file bytes to encrypt
            password: User's encryption password
            
        Returns:
            Tuple of (encrypted_data, salt)
            encrypted_data format: nonce (12 bytes) + ciphertext + auth_tag (16 bytes)
        """
        # Generate random salt and derive key
        salt = cls.generate_salt()
        key = cls.derive_key(password, salt)
        
        # Generate random nonce
        nonce = os.urandom(cls.NONCE_LENGTH)
        
        # Encrypt with AES-GCM (provides both encryption and authentication)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Prepend nonce to ciphertext (tag is already appended by AESGCM)
        encrypted_data = nonce + ciphertext
        
        return encrypted_data, salt
    
    @classmethod
    def decrypt_file(cls, encrypted_data: bytes, password: str, salt: bytes) -> bytes:
        """
        Decrypt file data using AES-256-GCM.
        
        Args:
            encrypted_data: Encrypted bytes (nonce + ciphertext + tag)
            password: User's encryption password
            salt: Salt used during encryption
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            cryptography.exceptions.InvalidTag: If password is wrong or data is tampered
        """
        # Derive key from password and salt
        key = cls.derive_key(password, salt)
        
        # Extract nonce and ciphertext
        nonce = encrypted_data[:cls.NONCE_LENGTH]
        ciphertext = encrypted_data[cls.NONCE_LENGTH:]
        
        # Decrypt and verify authentication tag
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext
    
    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Hash a password using bcrypt for secure storage.
        
        Args:
            password: Plain text password
            
        Returns:
            bcrypt hash as string
        """
        salt = bcrypt.gensalt(rounds=cls.BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    @classmethod
    def verify_password(cls, password: str, password_hash: str) -> bool:
        """
        Verify a password against its bcrypt hash.
        
        Args:
            password: Plain text password to verify
            password_hash: Stored bcrypt hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                password_hash.encode('utf-8')
            )
        except Exception:
            return False
    
    @classmethod
    def verify_file_password(cls, encrypted_data: bytes, password: str, salt: bytes) -> bool:
        """
        Verify if a password can decrypt the file (without full decryption).
        
        This attempts decryption to verify the GCM authentication tag.
        
        Args:
            encrypted_data: First chunk of encrypted file
            password: Password to verify
            salt: Salt used during encryption
            
        Returns:
            True if password is correct, False otherwise
        """
        try:
            cls.decrypt_file(encrypted_data, password, salt)
            return True
        except Exception:
            return False
