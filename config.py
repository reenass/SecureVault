"""
Configuration settings for Secure Cloud Storage Application
"""
import os
from datetime import timedelta

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-super-secret-key-change-in-production-12345'
    
    # Database Configuration - MySQL
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'password')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'secure_cloud_storage')
    
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }
    
    # File Upload Configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    ENCRYPTED_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'encrypted_files')
    KEYS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max file size
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', 'csv', 'json', 'xml', 'mp3', 'mp4', 'avi', 'mov'}
    
    # Security Configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Encryption Configuration
    AES_KEY_SIZE = 32  # 256 bits
    RSA_KEY_SIZE = 2048
    GCM_TAG_LENGTH = 16  # 128 bits
    GCM_NONCE_LENGTH = 12  # 96 bits (recommended for GCM)
    
    # PBKDF2 Configuration for Key Derivation
    PBKDF2_ITERATIONS = 600000  # OWASP recommended
    PBKDF2_SALT_LENGTH = 32


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///secure_cloud_dev.db'  # SQLite for easy development


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
