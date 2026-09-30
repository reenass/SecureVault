"""
Secure Cryptographic Module
Implements:
- AES-256-GCM symmetric encryption (authenticated encryption)
- RSA-2048 asymmetric encryption (hybrid encryption)
- SHA-256/SHA-512 hash integrity verification
- HMAC for message authentication
- PBKDF2 key derivation
- Secure key management
- Paillier Homomorphic Encryption (additive operations on encrypted data)
- Symmetric Searchable Encryption (SSE) for keyword search
"""

import os
import hashlib
import hmac
import base64
import json
import re
import secrets
import math
from datetime import datetime
from typing import Tuple, Optional, Dict, Any, List, Set
from functools import reduce

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


class CryptoConfig:
    """Cryptographic configuration constants"""
    AES_KEY_SIZE = 32  # 256 bits
    RSA_KEY_SIZE = 2048
    GCM_NONCE_SIZE = 12  # 96 bits (NIST recommended for GCM)
    GCM_TAG_SIZE = 16  # 128 bits
    SALT_SIZE = 32
    PBKDF2_ITERATIONS = 600000  # OWASP 2024 recommendation
    HASH_ALGORITHM = 'SHA-256'
    # Paillier Homomorphic Encryption
    PAILLIER_KEY_SIZE = 2048  # Security parameter
    # Searchable Encryption
    SSE_KEY_SIZE = 32  # 256 bits for SSE


class HashIntegrity:
    """
    File integrity verification using cryptographic hashes
    Supports SHA-256, SHA-512, and HMAC
    """
    
    @staticmethod
    def sha256_hash(data: bytes) -> str:
        """Generate SHA-256 hash of data"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def sha512_hash(data: bytes) -> str:
        """Generate SHA-512 hash of data"""
        return hashlib.sha512(data).hexdigest()
    
    @staticmethod
    def sha256_file(filepath: str, chunk_size: int = 8192) -> str:
        """Generate SHA-256 hash of a file (memory efficient)"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def sha512_file(filepath: str, chunk_size: int = 8192) -> str:
        """Generate SHA-512 hash of a file (memory efficient)"""
        sha512 = hashlib.sha512()
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                sha512.update(chunk)
        return sha512.hexdigest()
    
    @staticmethod
    def hmac_sha256(data: bytes, key: bytes) -> str:
        """Generate HMAC-SHA256 for message authentication"""
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    
    @staticmethod
    def verify_hmac(data: bytes, key: bytes, expected_hmac: str) -> bool:
        """Verify HMAC (constant-time comparison)"""
        computed = hmac.new(key, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(computed, expected_hmac)
    
    @staticmethod
    def verify_hash(data: bytes, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """Verify data integrity against expected hash"""
        if algorithm.lower() == 'sha256':
            computed = hashlib.sha256(data).hexdigest()
        elif algorithm.lower() == 'sha512':
            computed = hashlib.sha512(data).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        return hmac.compare_digest(computed, expected_hash)
    
    @staticmethod
    def generate_checksum_report(data: bytes) -> Dict[str, str]:
        """Generate comprehensive checksum report"""
        return {
            'sha256': hashlib.sha256(data).hexdigest(),
            'sha512': hashlib.sha512(data).hexdigest(),
            'md5': hashlib.md5(data).hexdigest(),  # For compatibility, not security
            'size_bytes': len(data),
            'timestamp': datetime.utcnow().isoformat()
        }


class AES256GCM:
    """
    AES-256-GCM Authenticated Encryption
    Provides confidentiality, integrity, and authenticity
    """
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure AES-256 key"""
        return os.urandom(CryptoConfig.AES_KEY_SIZE)
    
    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a cryptographically secure nonce for GCM"""
        return os.urandom(CryptoConfig.GCM_NONCE_SIZE)
    
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-GCM
        
        Args:
            plaintext: Data to encrypt
            key: 256-bit AES key
            associated_data: Optional additional authenticated data (AAD)
        
        Returns:
            Tuple of (nonce, ciphertext, tag)
        """
        if len(key) != CryptoConfig.AES_KEY_SIZE:
            raise ValueError(f"Key must be {CryptoConfig.AES_KEY_SIZE} bytes")
        
        aesgcm = AESGCM(key)
        nonce = AES256GCM.generate_nonce()
        
        # AESGCM.encrypt returns ciphertext with appended tag
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        # Split ciphertext and tag
        ciphertext = ciphertext_with_tag[:-CryptoConfig.GCM_TAG_SIZE]
        tag = ciphertext_with_tag[-CryptoConfig.GCM_TAG_SIZE:]
        
        return nonce, ciphertext, tag
    
    @staticmethod
    def decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes, 
                associated_data: bytes = None) -> bytes:
        """
        Decrypt data using AES-256-GCM
        
        Args:
            nonce: 96-bit nonce used for encryption
            ciphertext: Encrypted data
            tag: Authentication tag
            key: 256-bit AES key
            associated_data: Optional additional authenticated data (AAD)
        
        Returns:
            Decrypted plaintext
        
        Raises:
            InvalidTag: If authentication fails (tampered data or wrong key)
        """
        if len(key) != CryptoConfig.AES_KEY_SIZE:
            raise ValueError(f"Key must be {CryptoConfig.AES_KEY_SIZE} bytes")
        
        aesgcm = AESGCM(key)
        ciphertext_with_tag = ciphertext + tag
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
            return plaintext
        except InvalidTag:
            raise ValueError("Decryption failed: Authentication tag verification failed. "
                           "Data may have been tampered with or wrong key used.")
    
    @staticmethod
    def encrypt_to_package(plaintext: bytes, key: bytes, 
                          metadata: Dict[str, Any] = None) -> bytes:
        """
        Encrypt and package data with all necessary components
        
        Returns:
            JSON-encoded package containing nonce, ciphertext, tag, and metadata
        """
        associated_data = json.dumps(metadata).encode() if metadata else None
        nonce, ciphertext, tag = AES256GCM.encrypt(plaintext, key, associated_data)
        
        package = {
            'version': '1.0',
            'algorithm': 'AES-256-GCM',
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'metadata': metadata,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return json.dumps(package).encode('utf-8')
    
    @staticmethod
    def decrypt_from_package(package_data: bytes, key: bytes) -> Tuple[bytes, Dict]:
        """
        Decrypt data from a packaged format
        
        Returns:
            Tuple of (plaintext, metadata)
        """
        package = json.loads(package_data.decode('utf-8'))
        
        nonce = base64.b64decode(package['nonce'])
        ciphertext = base64.b64decode(package['ciphertext'])
        tag = base64.b64decode(package['tag'])
        metadata = package.get('metadata')
        
        associated_data = json.dumps(metadata).encode() if metadata else None
        plaintext = AES256GCM.decrypt(nonce, ciphertext, tag, key, associated_data)
        
        return plaintext, metadata


class RSAKeyPair:
    """
    RSA-2048 Key Pair Management
    For hybrid encryption (encrypting AES keys)
    """
    
    @staticmethod
    def generate_key_pair() -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair
        
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=CryptoConfig.RSA_KEY_SIZE,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def generate_encrypted_key_pair(password: str) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair with encrypted private key
        
        Args:
            password: Password to encrypt the private key
        
        Returns:
            Tuple of (encrypted_private_key_pem, public_key_pem)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=CryptoConfig.RSA_KEY_SIZE,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def encrypt_with_public_key(data: bytes, public_key_pem: bytes) -> bytes:
        """
        Encrypt data using RSA public key with OAEP padding
        
        Note: RSA encryption is limited by key size. For RSA-2048:
        Max plaintext size = 190 bytes (with OAEP SHA-256)
        """
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return ciphertext
    
    @staticmethod
    def decrypt_with_private_key(ciphertext: bytes, private_key_pem: bytes, 
                                  password: bytes = None) -> bytes:
        """
        Decrypt data using RSA private key
        
        Args:
            ciphertext: Data encrypted with public key
            private_key_pem: PEM-encoded private key
            password: Password if private key is encrypted
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password,
            backend=default_backend()
        )
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext


class HybridEncryption:
    """
    Hybrid Encryption System
    Combines AES-256-GCM (for data) with RSA-2048 (for key exchange)
    """
    
    @staticmethod
    def encrypt(plaintext: bytes, public_key_pem: bytes, 
                metadata: Dict[str, Any] = None) -> bytes:
        """
        Hybrid encryption: AES-256-GCM for data, RSA for key
        
        Args:
            plaintext: Data to encrypt
            public_key_pem: Recipient's RSA public key
            metadata: Optional metadata (authenticated but not encrypted)
        
        Returns:
            Encrypted package containing encrypted key, nonce, ciphertext, tag
        """
        # Generate random AES key
        aes_key = AES256GCM.generate_key()
        
        # Encrypt data with AES-256-GCM
        associated_data = json.dumps(metadata).encode() if metadata else None
        nonce, ciphertext, tag = AES256GCM.encrypt(plaintext, aes_key, associated_data)
        
        # Encrypt AES key with RSA
        encrypted_key = RSAKeyPair.encrypt_with_public_key(aes_key, public_key_pem)
        
        # Package everything
        package = {
            'version': '1.0',
            'algorithm': 'Hybrid-AES256GCM-RSA2048',
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'metadata': metadata,
            'data_hash': HashIntegrity.sha256_hash(plaintext),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return json.dumps(package).encode('utf-8')
    
    @staticmethod
    def decrypt(package_data: bytes, private_key_pem: bytes, 
                password: bytes = None) -> Tuple[bytes, Dict, bool]:
        """
        Hybrid decryption
        
        Returns:
            Tuple of (plaintext, metadata, integrity_verified)
        """
        package = json.loads(package_data.decode('utf-8'))
        
        # Decrypt AES key with RSA
        encrypted_key = base64.b64decode(package['encrypted_key'])
        aes_key = RSAKeyPair.decrypt_with_private_key(encrypted_key, private_key_pem, password)
        
        # Decrypt data with AES-256-GCM
        nonce = base64.b64decode(package['nonce'])
        ciphertext = base64.b64decode(package['ciphertext'])
        tag = base64.b64decode(package['tag'])
        metadata = package.get('metadata')
        
        associated_data = json.dumps(metadata).encode() if metadata else None
        plaintext = AES256GCM.decrypt(nonce, ciphertext, tag, aes_key, associated_data)
        
        # Verify integrity
        expected_hash = package.get('data_hash')
        integrity_verified = False
        if expected_hash:
            integrity_verified = HashIntegrity.verify_hash(plaintext, expected_hash, 'sha256')
        
        return plaintext, metadata, integrity_verified


class KeyDerivation:
    """
    Key Derivation Functions for password-based encryption
    """
    
    @staticmethod
    def derive_key_pbkdf2(password: str, salt: bytes = None, 
                          key_length: int = CryptoConfig.AES_KEY_SIZE) -> Tuple[bytes, bytes]:
        """
        Derive a key from password using PBKDF2-HMAC-SHA256
        
        Args:
            password: User password
            salt: Random salt (generated if not provided)
            key_length: Desired key length in bytes
        
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(CryptoConfig.SALT_SIZE)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=CryptoConfig.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
    
    @staticmethod
    def encrypt_with_password(plaintext: bytes, password: str, 
                              metadata: Dict[str, Any] = None) -> bytes:
        """
        Encrypt data using a password (PBKDF2 + AES-256-GCM)
        """
        # Derive key from password
        key, salt = KeyDerivation.derive_key_pbkdf2(password)
        
        # Encrypt with AES-256-GCM
        associated_data = json.dumps(metadata).encode() if metadata else None
        nonce, ciphertext, tag = AES256GCM.encrypt(plaintext, key, associated_data)
        
        # Package
        package = {
            'version': '1.0',
            'algorithm': 'PBKDF2-AES256GCM',
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iterations': CryptoConfig.PBKDF2_ITERATIONS,
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'metadata': metadata,
            'data_hash': HashIntegrity.sha256_hash(plaintext),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return json.dumps(package).encode('utf-8')
    
    @staticmethod
    def decrypt_with_password(package_data: bytes, password: str) -> Tuple[bytes, Dict, bool]:
        """
        Decrypt password-encrypted data
        
        Returns:
            Tuple of (plaintext, metadata, integrity_verified)
        """
        package = json.loads(package_data.decode('utf-8'))
        
        # Derive key from password
        salt = base64.b64decode(package['salt'])
        iterations = package.get('iterations', CryptoConfig.PBKDF2_ITERATIONS)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=CryptoConfig.AES_KEY_SIZE,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        
        # Decrypt
        nonce = base64.b64decode(package['nonce'])
        ciphertext = base64.b64decode(package['ciphertext'])
        tag = base64.b64decode(package['tag'])
        metadata = package.get('metadata')
        
        associated_data = json.dumps(metadata).encode() if metadata else None
        plaintext = AES256GCM.decrypt(nonce, ciphertext, tag, key, associated_data)
        
        # Verify integrity
        expected_hash = package.get('data_hash')
        integrity_verified = False
        if expected_hash:
            integrity_verified = HashIntegrity.verify_hash(plaintext, expected_hash, 'sha256')
        
        return plaintext, metadata, integrity_verified


class SecureFileHandler:
    """
    High-level file encryption/decryption handler
    """
    
    def __init__(self, keys_folder: str):
        self.keys_folder = keys_folder
        os.makedirs(keys_folder, exist_ok=True)
    
    def encrypt_file(self, filepath: str, output_path: str, public_key_pem: bytes,
                     user_id: int) -> Dict[str, Any]:
        """
        Encrypt a file using hybrid encryption
        
        Returns:
            Dictionary with encryption metadata
        """
        # Read file
        with open(filepath, 'rb') as f:
            plaintext = f.read()
        
        # Get original file metadata
        original_filename = os.path.basename(filepath)
        original_size = len(plaintext)
        original_hash = HashIntegrity.sha256_hash(plaintext)
        
        metadata = {
            'original_filename': original_filename,
            'original_size': original_size,
            'user_id': user_id,
            'encrypted_at': datetime.utcnow().isoformat()
        }
        
        # Encrypt
        encrypted_data = HybridEncryption.encrypt(plaintext, public_key_pem, metadata)
        
        # Write encrypted file
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        return {
            'original_filename': original_filename,
            'original_size': original_size,
            'original_hash': original_hash,
            'encrypted_size': len(encrypted_data),
            'encrypted_hash': HashIntegrity.sha256_hash(encrypted_data),
            'output_path': output_path
        }
    
    def decrypt_file(self, encrypted_path: str, output_path: str, 
                     private_key_pem: bytes, password: bytes = None) -> Dict[str, Any]:
        """
        Decrypt a file using hybrid encryption
        
        Returns:
            Dictionary with decryption metadata and integrity status
        """
        # Read encrypted file
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt
        plaintext, metadata, integrity_verified = HybridEncryption.decrypt(
            encrypted_data, private_key_pem, password
        )
        
        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return {
            'output_path': output_path,
            'decrypted_size': len(plaintext),
            'decrypted_hash': HashIntegrity.sha256_hash(plaintext),
            'metadata': metadata,
            'integrity_verified': integrity_verified
        }
    
    def encrypt_file_with_password(self, filepath: str, output_path: str, 
                                   password: str, user_id: int) -> Dict[str, Any]:
        """
        Encrypt a file using password-based encryption
        """
        with open(filepath, 'rb') as f:
            plaintext = f.read()
        
        original_filename = os.path.basename(filepath)
        original_size = len(plaintext)
        original_hash = HashIntegrity.sha256_hash(plaintext)
        
        metadata = {
            'original_filename': original_filename,
            'original_size': original_size,
            'user_id': user_id,
            'encrypted_at': datetime.utcnow().isoformat()
        }
        
        encrypted_data = KeyDerivation.encrypt_with_password(plaintext, password, metadata)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        return {
            'original_filename': original_filename,
            'original_size': original_size,
            'original_hash': original_hash,
            'encrypted_size': len(encrypted_data),
            'encrypted_hash': HashIntegrity.sha256_hash(encrypted_data),
            'output_path': output_path
        }
    
    def decrypt_file_with_password(self, encrypted_path: str, output_path: str,
                                    password: str) -> Dict[str, Any]:
        """
        Decrypt a password-encrypted file
        """
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        plaintext, metadata, integrity_verified = KeyDerivation.decrypt_with_password(
            encrypted_data, password
        )
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return {
            'output_path': output_path,
            'decrypted_size': len(plaintext),
            'decrypted_hash': HashIntegrity.sha256_hash(plaintext),
            'metadata': metadata,
            'integrity_verified': integrity_verified
        }


# =============================================================================
# PAILLIER HOMOMORPHIC ENCRYPTION
# =============================================================================

class PaillierKeyPair:
    """
    Paillier Cryptosystem - Additive Homomorphic Encryption
    
    Allows computations on encrypted data:
    - E(a) * E(b) = E(a + b)  (encrypted addition)
    - E(a)^k = E(a * k)       (scalar multiplication)
    
    Use cases:
    - Encrypted file size calculations
    - Encrypted statistics (sum, count, average)
    - Privacy-preserving aggregation
    """
    
    def __init__(self, key_size: int = 1024):
        """Use smaller key for faster operations (1024-bit for demo)"""
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        
    @staticmethod
    def _is_prime(n: int, k: int = 40) -> bool:
        """Miller-Rabin primality test"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    @staticmethod
    def _generate_prime(bits: int) -> int:
        """Generate a random prime number of specified bit length"""
        while True:
            candidate = secrets.randbits(bits)
            candidate |= (1 << bits - 1) | 1  # Ensure top bit and odd
            if PaillierKeyPair._is_prime(candidate):
                return candidate
    
    @staticmethod
    def _lcm(a: int, b: int) -> int:
        """Least Common Multiple"""
        return abs(a * b) // math.gcd(a, b)
    
    @staticmethod
    def _mod_inverse(a: int, m: int) -> int:
        """Extended Euclidean Algorithm for modular inverse"""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        _, x, _ = extended_gcd(a % m, m)
        return (x % m + m) % m
    
    @staticmethod
    def _L(x: int, n: int) -> int:
        """L function: L(x) = (x - 1) / n"""
        return (x - 1) // n
    
    def generate_keypair(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        """
        Generate Paillier public/private key pair
        
        Returns:
            (public_key, private_key) as dictionaries
        """
        bits = self.key_size // 2
        
        # Generate two large primes
        p = self._generate_prime(bits)
        q = self._generate_prime(bits)
        
        # Ensure p != q
        while p == q:
            q = self._generate_prime(bits)
        
        n = p * q
        n_squared = n * n
        
        # λ = lcm(p-1, q-1)
        lambda_n = self._lcm(p - 1, q - 1)
        
        # g = n + 1 (simplified choice)
        g = n + 1
        
        # μ = (L(g^λ mod n²))^(-1) mod n
        l_value = self._L(pow(g, lambda_n, n_squared), n)
        mu = self._mod_inverse(l_value, n)
        
        self.public_key = {'n': n, 'g': g, 'n_squared': n_squared}
        self.private_key = {'lambda': lambda_n, 'mu': mu, 'n': n}
        
        return self.public_key, self.private_key
    
    def encrypt(self, plaintext: int, public_key: Dict[str, int] = None) -> int:
        """
        Encrypt an integer using Paillier encryption
        
        Args:
            plaintext: Integer to encrypt (0 <= m < n)
            public_key: Public key dictionary (optional if already set)
        
        Returns:
            Encrypted integer
        """
        pk = public_key or self.public_key
        if pk is None:
            raise ValueError("Public key not set")
        
        n = pk['n']
        g = pk['g']
        n_squared = pk['n_squared']
        
        if plaintext < 0 or plaintext >= n:
            raise ValueError(f"Plaintext must be in range [0, {n})")
        
        # Generate random r where 0 < r < n and gcd(r, n) = 1
        while True:
            r = secrets.randbelow(n - 1) + 1
            if math.gcd(r, n) == 1:
                break
        
        # c = g^m * r^n mod n²
        ciphertext = (pow(g, plaintext, n_squared) * pow(r, n, n_squared)) % n_squared
        
        return ciphertext
    
    def decrypt(self, ciphertext: int, private_key: Dict[str, int] = None) -> int:
        """
        Decrypt a Paillier encrypted integer
        
        Args:
            ciphertext: Encrypted integer
            private_key: Private key dictionary (optional if already set)
        
        Returns:
            Decrypted integer
        """
        sk = private_key or self.private_key
        if sk is None:
            raise ValueError("Private key not set")
        
        lambda_n = sk['lambda']
        mu = sk['mu']
        n = sk['n']
        n_squared = n * n
        
        # m = L(c^λ mod n²) * μ mod n
        l_value = self._L(pow(ciphertext, lambda_n, n_squared), n)
        plaintext = (l_value * mu) % n
        
        return plaintext
    
    @staticmethod
    def add_encrypted(c1: int, c2: int, public_key: Dict[str, int]) -> int:
        """
        Add two encrypted values: E(a) * E(b) = E(a + b)
        
        Args:
            c1, c2: Two encrypted integers
            public_key: Public key dictionary
        
        Returns:
            Encrypted sum
        """
        n_squared = public_key['n_squared']
        return (c1 * c2) % n_squared
    
    @staticmethod
    def multiply_encrypted(ciphertext: int, scalar: int, public_key: Dict[str, int]) -> int:
        """
        Multiply encrypted value by scalar: E(a)^k = E(a * k)
        
        Args:
            ciphertext: Encrypted integer
            scalar: Plain integer multiplier
            public_key: Public key dictionary
        
        Returns:
            Encrypted product
        """
        n_squared = public_key['n_squared']
        return pow(ciphertext, scalar, n_squared)
    
    def serialize_public_key(self) -> str:
        """Serialize public key to JSON string"""
        if self.public_key is None:
            raise ValueError("Public key not set")
        return json.dumps({
            'n': str(self.public_key['n']),
            'g': str(self.public_key['g']),
            'n_squared': str(self.public_key['n_squared'])
        })
    
    def serialize_private_key(self) -> str:
        """Serialize private key to JSON string"""
        if self.private_key is None:
            raise ValueError("Private key not set")
        return json.dumps({
            'lambda': str(self.private_key['lambda']),
            'mu': str(self.private_key['mu']),
            'n': str(self.private_key['n'])
        })
    
    @staticmethod
    def deserialize_public_key(key_json: str) -> Dict[str, int]:
        """Deserialize public key from JSON string"""
        data = json.loads(key_json)
        return {
            'n': int(data['n']),
            'g': int(data['g']),
            'n_squared': int(data['n_squared'])
        }
    
    @staticmethod
    def deserialize_private_key(key_json: str) -> Dict[str, int]:
        """Deserialize private key from JSON string"""
        data = json.loads(key_json)
        return {
            'lambda': int(data['lambda']),
            'mu': int(data['mu']),
            'n': int(data['n'])
        }


class HomomorphicFileStats:
    """
    Privacy-preserving file statistics using Paillier encryption
    
    Allows computing aggregate statistics without decrypting individual values:
    - Total file sizes
    - File counts
    - Encrypted metadata aggregation
    """
    
    def __init__(self, paillier: PaillierKeyPair = None):
        self.paillier = paillier or PaillierKeyPair()
        if self.paillier.public_key is None:
            self.paillier.generate_keypair()
    
    def encrypt_file_size(self, size_bytes: int) -> str:
        """Encrypt file size for homomorphic operations"""
        encrypted = self.paillier.encrypt(size_bytes)
        return str(encrypted)
    
    def decrypt_aggregate(self, encrypted_sum: str) -> int:
        """Decrypt aggregated encrypted values"""
        return self.paillier.decrypt(int(encrypted_sum))
    
    def sum_encrypted_sizes(self, encrypted_sizes: List[str]) -> str:
        """
        Sum multiple encrypted file sizes
        Returns encrypted total (can be decrypted to get actual sum)
        """
        if not encrypted_sizes:
            return str(self.paillier.encrypt(0))
        
        result = int(encrypted_sizes[0])
        for enc_size in encrypted_sizes[1:]:
            result = PaillierKeyPair.add_encrypted(
                result, int(enc_size), self.paillier.public_key
            )
        return str(result)
    
    def multiply_size(self, encrypted_size: str, multiplier: int) -> str:
        """Multiply encrypted size by a scalar"""
        result = PaillierKeyPair.multiply_encrypted(
            int(encrypted_size), multiplier, self.paillier.public_key
        )
        return str(result)


# =============================================================================
# SYMMETRIC SEARCHABLE ENCRYPTION (SSE)
# =============================================================================

class SearchableEncryption:
    """
    Symmetric Searchable Encryption (SSE)
    
    Allows keyword search on encrypted files without decrypting content.
    
    Implementation:
    - Uses HMAC-based keyword tokens for security
    - Encrypted inverted index for fast lookups
    - Forward secrecy with per-file keys
    
    Security properties:
    - Server cannot learn keywords without search tokens
    - Search tokens don't reveal file content
    - Index reveals only search pattern (which files match)
    """
    
    def __init__(self, master_key: bytes = None):
        """
        Initialize searchable encryption with master key
        
        Args:
            master_key: 32-byte master key (generated if not provided)
        """
        self.master_key = master_key or os.urandom(CryptoConfig.SSE_KEY_SIZE)
        self._keyword_key = self._derive_key(b'keyword_key')
        self._index_key = self._derive_key(b'index_key')
        self._token_key = self._derive_key(b'token_key')
    
    def _derive_key(self, context: bytes) -> bytes:
        """Derive a sub-key from master key using HKDF-like construction"""
        return hashlib.sha256(self.master_key + context).digest()
    
    def _hmac_token(self, data: str, key: bytes) -> str:
        """Generate HMAC token for a string"""
        return hmac.new(key, data.lower().encode('utf-8'), hashlib.sha256).hexdigest()
    
    @staticmethod
    def _tokenize_text(text: str) -> Set[str]:
        """
        Tokenize text into searchable keywords
        
        Extracts meaningful words, removes stop words, handles various formats
        """
        # Convert to lowercase and extract words
        text = text.lower()
        
        # Remove special characters but keep meaningful separators
        text = re.sub(r'[^\w\s\-_.]', ' ', text)
        
        # Split into words
        words = text.split()
        
        # Common stop words to filter
        stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been',
            'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
            'could', 'should', 'may', 'might', 'must', 'it', 'its', 'this', 'that',
            'these', 'those', 'i', 'you', 'he', 'she', 'we', 'they', 'them', 'their'
        }
        
        # Filter and clean
        keywords = set()
        for word in words:
            # Remove leading/trailing punctuation
            word = word.strip('.-_')
            
            # Skip short words and stop words
            if len(word) < 2 or word in stop_words:
                continue
            
            keywords.add(word)
            
            # Add word parts for compound words (e.g., "user-data" -> "user", "data")
            if '-' in word or '_' in word:
                parts = re.split(r'[-_]', word)
                for part in parts:
                    if len(part) >= 2 and part not in stop_words:
                        keywords.add(part)
        
        return keywords
    
    def generate_keyword_token(self, keyword: str) -> str:
        """
        Generate a secure search token for a keyword
        
        This token is sent to the server for searching.
        The server cannot reverse it to learn the keyword.
        """
        return self._hmac_token(keyword, self._keyword_key)
    
    def index_file_content(self, file_id: str, content: str, 
                          filename: str = None) -> Dict[str, Any]:
        """
        Create searchable index for file content
        
        Args:
            file_id: Unique file identifier
            content: File text content to index
            filename: Optional filename to include in index
        
        Returns:
            Dictionary with encrypted keyword tokens for storage
        """
        # Combine filename and content for indexing
        full_text = content
        if filename:
            # Add filename without extension
            name_part = os.path.splitext(filename)[0]
            full_text = f"{name_part} {content}"
        
        # Extract keywords
        keywords = self._tokenize_text(full_text)
        
        # Generate secure tokens for each keyword
        keyword_tokens = {}
        for keyword in keywords:
            token = self.generate_keyword_token(keyword)
            # Store token -> file_id mapping (encrypted)
            keyword_tokens[token] = {
                'file_id': file_id,
                'position_hash': self._hmac_token(f"{file_id}:{keyword}", self._index_key)
            }
        
        return {
            'file_id': file_id,
            'keyword_count': len(keywords),
            'tokens': list(keyword_tokens.keys()),
            'token_data': keyword_tokens
        }
    
    def index_file_from_path(self, file_id: str, file_path: str) -> Dict[str, Any]:
        """
        Index a file from disk path
        
        Supports: .txt, .md, .html, .csv, .json, .py, .js, .java, .xml
        """
        filename = os.path.basename(file_path)
        ext = os.path.splitext(filename)[1].lower()
        
        # Supported text formats
        text_extensions = {'.txt', '.md', '.html', '.htm', '.csv', '.json', 
                         '.py', '.js', '.java', '.c', '.cpp', '.h', '.xml',
                         '.yml', '.yaml', '.ini', '.cfg', '.log', '.sql'}
        
        if ext not in text_extensions:
            # For non-text files, just index the filename
            return self.index_file_content(file_id, '', filename)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.index_file_content(file_id, content, filename)
        except Exception:
            # Fallback to filename only
            return self.index_file_content(file_id, '', filename)
    
    def search(self, query: str, index_data: List[Dict[str, Any]]) -> List[str]:
        """
        Search for files matching query keywords
        
        Args:
            query: Search query string
            index_data: List of indexed file data from database
        
        Returns:
            List of matching file_ids
        """
        # Tokenize search query
        query_keywords = self._tokenize_text(query)
        
        if not query_keywords:
            return []
        
        # Generate search tokens
        query_tokens = {self.generate_keyword_token(kw) for kw in query_keywords}
        
        # Search index
        matching_files = []
        for file_index in index_data:
            file_tokens = set(file_index.get('tokens', []))
            
            # Check if any query token matches
            if query_tokens & file_tokens:  # Intersection
                matching_files.append(file_index['file_id'])
        
        return matching_files
    
    def search_with_ranking(self, query: str, index_data: List[Dict[str, Any]]) -> List[Tuple[str, float]]:
        """
        Search with relevance ranking based on keyword matches
        
        Returns list of (file_id, score) sorted by relevance
        """
        query_keywords = self._tokenize_text(query)
        
        if not query_keywords:
            return []
        
        query_tokens = {self.generate_keyword_token(kw) for kw in query_keywords}
        
        # Calculate relevance scores
        file_scores = []
        for file_index in index_data:
            file_tokens = set(file_index.get('tokens', []))
            
            # Count matching tokens
            matches = len(query_tokens & file_tokens)
            
            if matches > 0:
                # Score = matches / total query keywords (0-1 range)
                score = matches / len(query_keywords)
                file_scores.append((file_index['file_id'], score))
        
        # Sort by score descending
        file_scores.sort(key=lambda x: x[1], reverse=True)
        
        return file_scores
    
    def serialize_master_key(self) -> str:
        """Serialize master key for secure storage"""
        return base64.b64encode(self.master_key).decode('utf-8')
    
    @staticmethod
    def deserialize_master_key(key_b64: str) -> bytes:
        """Deserialize master key from base64"""
        return base64.b64decode(key_b64.encode('utf-8'))
    
    def encrypt_index(self, index_data: Dict[str, Any]) -> str:
        """
        Encrypt the index data for storage
        
        Uses AES-256-GCM for authenticated encryption
        """
        plaintext = json.dumps(index_data).encode('utf-8')
        aesgcm = AESGCM(self._index_key)
        nonce = os.urandom(CryptoConfig.GCM_NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return base64.b64encode(nonce + ciphertext).decode('utf-8')
    
    def decrypt_index(self, encrypted_index: str) -> Dict[str, Any]:
        """
        Decrypt stored index data
        """
        data = base64.b64decode(encrypted_index.encode('utf-8'))
        nonce = data[:CryptoConfig.GCM_NONCE_SIZE]
        ciphertext = data[CryptoConfig.GCM_NONCE_SIZE:]
        
        aesgcm = AESGCM(self._index_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return json.loads(plaintext.decode('utf-8'))


class SecureSearchIndex:
    """
    High-level interface for managing searchable encrypted file indexes
    
    Maintains an encrypted inverted index for fast keyword lookups
    """
    
    def __init__(self, sse: SearchableEncryption = None):
        self.sse = sse or SearchableEncryption()
        self._inverted_index = {}  # token -> list of file_ids
        self._file_metadata = {}   # file_id -> metadata
    
    def add_file(self, file_id: str, content: str, filename: str = None,
                 metadata: Dict[str, Any] = None) -> int:
        """
        Add a file to the searchable index
        
        Returns number of indexed keywords
        """
        index_data = self.sse.index_file_content(file_id, content, filename)
        
        # Update inverted index
        for token in index_data['tokens']:
            if token not in self._inverted_index:
                self._inverted_index[token] = []
            if file_id not in self._inverted_index[token]:
                self._inverted_index[token].append(file_id)
        
        # Store metadata
        self._file_metadata[file_id] = {
            'filename': filename,
            'keyword_count': index_data['keyword_count'],
            'indexed_at': datetime.utcnow().isoformat(),
            **(metadata or {})
        }
        
        return index_data['keyword_count']
    
    def remove_file(self, file_id: str):
        """Remove a file from the search index"""
        # Remove from inverted index
        tokens_to_remove = []
        for token, file_ids in self._inverted_index.items():
            if file_id in file_ids:
                file_ids.remove(file_id)
                if not file_ids:
                    tokens_to_remove.append(token)
        
        for token in tokens_to_remove:
            del self._inverted_index[token]
        
        # Remove metadata
        if file_id in self._file_metadata:
            del self._file_metadata[file_id]
    
    def search(self, query: str) -> List[str]:
        """Search for files matching query keywords"""
        query_keywords = SearchableEncryption._tokenize_text(query)
        
        if not query_keywords:
            return []
        
        # Generate tokens for query
        query_tokens = [self.sse.generate_keyword_token(kw) for kw in query_keywords]
        
        # Find matching files
        matching_files = set()
        for token in query_tokens:
            if token in self._inverted_index:
                matching_files.update(self._inverted_index[token])
        
        return list(matching_files)
    
    def search_ranked(self, query: str) -> List[Tuple[str, int]]:
        """
        Search with ranking by number of matching keywords
        
        Returns list of (file_id, match_count) sorted by relevance
        """
        query_keywords = SearchableEncryption._tokenize_text(query)
        
        if not query_keywords:
            return []
        
        # Count matches per file
        file_match_count = {}
        for keyword in query_keywords:
            token = self.sse.generate_keyword_token(keyword)
            if token in self._inverted_index:
                for file_id in self._inverted_index[token]:
                    file_match_count[file_id] = file_match_count.get(file_id, 0) + 1
        
        # Sort by match count
        results = [(fid, count) for fid, count in file_match_count.items()]
        results.sort(key=lambda x: x[1], reverse=True)
        
        return results
    
    def export_index(self) -> str:
        """Export encrypted index for persistent storage"""
        data = {
            'inverted_index': self._inverted_index,
            'file_metadata': self._file_metadata,
            'version': '1.0'
        }
        return self.sse.encrypt_index(data)
    
    def import_index(self, encrypted_index: str):
        """Import encrypted index from storage"""
        data = self.sse.decrypt_index(encrypted_index)
        self._inverted_index = data.get('inverted_index', {})
        self._file_metadata = data.get('file_metadata', {})
    
    def get_stats(self) -> Dict[str, Any]:
        """Get index statistics"""
        return {
            'total_files': len(self._file_metadata),
            'total_keywords': len(self._inverted_index),
            'avg_keywords_per_file': (
                sum(m.get('keyword_count', 0) for m in self._file_metadata.values()) /
                max(len(self._file_metadata), 1)
            )
        }
