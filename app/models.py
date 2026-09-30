"""
Database Models for Secure Cloud Storage
Implements:
- User management with secure password hashing
- File metadata storage
- Activity logging
- Key management
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """User model with secure authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # Profile
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    profile_image = db.Column(db.String(255))
    
    # Security
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))
    
    # Key Management
    public_key = db.Column(db.Text)  # RSA public key (PEM format)
    private_key_encrypted = db.Column(db.Text)  # RSA private key encrypted with user password
    key_generated_at = db.Column(db.DateTime)
    
    # Storage quota (in bytes)
    storage_quota = db.Column(db.BigInteger, default=5368709120)  # 5 GB default
    storage_used = db.Column(db.BigInteger, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    files = db.relationship('File', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    activities = db.relationship('ActivityLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    shared_files = db.relationship('SharedFile', backref='shared_with_user', 
                                   foreign_keys='SharedFile.shared_with_id', lazy='dynamic')
    
    def set_password(self, password):
        """Hash and store password using Argon2 via werkzeug"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')
    
    def check_password(self, password):
        """Verify password against stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def get_full_name(self):
        """Return user's full name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username
    
    def get_storage_percentage(self):
        """Return storage usage as percentage"""
        if self.storage_quota == 0:
            return 100
        return round((self.storage_used / self.storage_quota) * 100, 2)
    
    def has_storage_space(self, file_size):
        """Check if user has enough storage space"""
        return (self.storage_used + file_size) <= self.storage_quota
    
    def __repr__(self):
        return f'<User {self.username}>'


class File(db.Model):
    """File model with encryption metadata"""
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    
    # File Information
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)  # UUID-based name
    file_extension = db.Column(db.String(20))
    mime_type = db.Column(db.String(100))
    
    # Size Information
    original_size = db.Column(db.BigInteger, nullable=False)
    encrypted_size = db.Column(db.BigInteger, nullable=False)
    
    # Integrity Hashes
    original_hash_sha256 = db.Column(db.String(64), nullable=False)
    original_hash_sha512 = db.Column(db.String(128))
    encrypted_hash_sha256 = db.Column(db.String(64), nullable=False)
    hmac_signature = db.Column(db.String(64))
    
    # Encryption Metadata
    encryption_algorithm = db.Column(db.String(50), default='AES-256-GCM')
    encryption_mode = db.Column(db.String(20), default='hybrid')  # hybrid, password, symmetric
    key_derivation = db.Column(db.String(50))  # PBKDF2 parameters if applicable
    
    # File Path
    storage_path = db.Column(db.String(500), nullable=False)
    
    # Status
    is_encrypted = db.Column(db.Boolean, default=True)
    is_deleted = db.Column(db.Boolean, default=False)
    is_shared = db.Column(db.Boolean, default=False)
    
    # Folder/Organization
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)
    
    # Ownership
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime)
    
    # Relationships
    shares = db.relationship('SharedFile', backref='file', lazy='dynamic', cascade='all, delete-orphan')
    versions = db.relationship('FileVersion', backref='file', lazy='dynamic', cascade='all, delete-orphan')
    
    def get_file_type_icon(self):
        """Return appropriate icon class based on file type"""
        icons = {
            'pdf': 'fa-file-pdf',
            'doc': 'fa-file-word', 'docx': 'fa-file-word',
            'xls': 'fa-file-excel', 'xlsx': 'fa-file-excel',
            'ppt': 'fa-file-powerpoint', 'pptx': 'fa-file-powerpoint',
            'jpg': 'fa-file-image', 'jpeg': 'fa-file-image', 'png': 'fa-file-image', 'gif': 'fa-file-image',
            'mp3': 'fa-file-audio', 'wav': 'fa-file-audio',
            'mp4': 'fa-file-video', 'avi': 'fa-file-video', 'mov': 'fa-file-video',
            'zip': 'fa-file-archive', 'rar': 'fa-file-archive',
            'txt': 'fa-file-alt',
            'py': 'fa-file-code', 'js': 'fa-file-code', 'html': 'fa-file-code', 'css': 'fa-file-code',
        }
        return icons.get(self.file_extension, 'fa-file')
    
    def format_size(self):
        """Return human-readable file size"""
        size = self.original_size
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    @property
    def file_size(self):
        """Alias for original_size (template compatibility)"""
        return self.original_size or 0
    
    @property
    def file_type(self):
        """Alias for file_extension (template compatibility)"""
        return self.file_extension or ''
    
    def __repr__(self):
        return f'<File {self.original_filename}>'


class Folder(db.Model):
    """Folder model for organizing files"""
    __tablename__ = 'folders'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=False)
    
    # Hierarchy
    parent_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)
    children = db.relationship('Folder', backref=db.backref('parent', remote_side=[id]), lazy='dynamic')
    
    # Ownership
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Files in folder
    files = db.relationship('File', backref='folder', lazy='dynamic')
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Folder {self.name}>'


class SharedFile(db.Model):
    """File sharing model"""
    __tablename__ = 'shared_files'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    
    # File being shared
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    
    # Sharing details
    shared_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # None for public links
    
    # Share link (for public sharing)
    share_link = db.Column(db.String(100), unique=True)
    share_password_hash = db.Column(db.String(256))  # Optional password protection
    
    # Permissions
    can_view = db.Column(db.Boolean, default=True)
    can_download = db.Column(db.Boolean, default=True)
    can_edit = db.Column(db.Boolean, default=False)
    
    # Expiration
    expires_at = db.Column(db.DateTime)
    max_downloads = db.Column(db.Integer)
    download_count = db.Column(db.Integer, default=0)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)
    
    # Relationship to shared_by user
    shared_by = db.relationship('User', foreign_keys=[shared_by_id], backref='files_shared')
    
    def is_expired(self):
        """Check if share has expired"""
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return True
        if self.max_downloads and self.download_count >= self.max_downloads:
            return True
        return False
    
    def __repr__(self):
        return f'<SharedFile {self.uuid}>'


class FileVersion(db.Model):
    """File version history"""
    __tablename__ = 'file_versions'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    version_number = db.Column(db.Integer, nullable=False)
    
    # Version file info
    stored_filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    hash_sha256 = db.Column(db.String(64), nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<FileVersion {self.file_id}:v{self.version_number}>'


class ActivityLog(db.Model):
    """Activity logging for security audit"""
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # User reference (can be null for system actions)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    
    # Activity details
    action = db.Column(db.String(50), nullable=False)  # login, upload, download, delete, share, etc.
    resource_type = db.Column(db.String(50))  # file, folder, user, etc.
    resource_id = db.Column(db.Integer)
    resource_name = db.Column(db.String(255))
    
    # Additional context
    details = db.Column(db.Text)  # JSON string for additional details
    
    # Request information
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6
    user_agent = db.Column(db.String(500))
    
    # Status
    status = db.Column(db.String(20), default='success')  # success, failed, warning
    error_message = db.Column(db.Text)
    
    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Security hash of the log entry (tamper detection)
    log_hash = db.Column(db.String(64))
    
    @staticmethod
    def create_log(user_id, action, resource_type=None, resource_id=None, 
                   resource_name=None, details=None, ip_address=None, 
                   user_agent=None, status='success', error_message=None):
        """Factory method to create activity logs"""
        import hashlib
        import json
        
        log = ActivityLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            details=json.dumps(details) if details else None,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            error_message=error_message
        )
        
        # Generate integrity hash
        hash_content = f"{user_id}:{action}:{resource_type}:{resource_id}:{log.created_at}"
        log.log_hash = hashlib.sha256(hash_content.encode()).hexdigest()
        
        return log
    
    def __repr__(self):
        return f'<ActivityLog {self.action} by User {self.user_id}>'


class SystemSettings(db.Model):
    """System-wide settings"""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    description = db.Column(db.String(255))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<SystemSetting {self.key}>'


class FileSearchIndex(db.Model):
    """
    Searchable Encryption Index
    Stores encrypted keyword tokens for each file
    """
    __tablename__ = 'file_search_indexes'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Encrypted search tokens (JSON array of HMAC tokens)
    search_tokens = db.Column(db.Text)  # JSON array of keyword tokens
    
    # Index metadata
    keyword_count = db.Column(db.Integer, default=0)
    indexed_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Index status
    is_indexed = db.Column(db.Boolean, default=True)
    index_version = db.Column(db.String(10), default='1.0')
    
    # Relationships
    file = db.relationship('File', backref=db.backref('search_index', uselist=False, cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('search_indexes', lazy='dynamic'))
    
    __table_args__ = (
        db.Index('idx_search_user', 'user_id'),
        db.Index('idx_search_file', 'file_id'),
    )
    
    def set_tokens(self, tokens: list):
        """Store tokens as JSON"""
        import json
        self.search_tokens = json.dumps(tokens)
    
    def get_tokens(self) -> list:
        """Retrieve tokens from JSON"""
        import json
        if self.search_tokens:
            return json.loads(self.search_tokens)
        return []
    
    def __repr__(self):
        return f'<FileSearchIndex file_id={self.file_id} keywords={self.keyword_count}>'


class HomomorphicKey(db.Model):
    """
    Paillier Homomorphic Encryption Keys
    Stores user's homomorphic encryption keys for privacy-preserving operations
    """
    __tablename__ = 'homomorphic_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False)
    
    # Paillier key components (stored as large number strings)
    public_key_n = db.Column(db.Text)  # n value
    public_key_g = db.Column(db.Text)  # g value
    public_key_n_squared = db.Column(db.Text)  # n² value
    
    # Private key encrypted with user password
    private_key_encrypted = db.Column(db.Text)  # Encrypted lambda and mu
    
    # Key metadata
    key_size = db.Column(db.Integer, default=1024)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('homomorphic_key', uselist=False, cascade='all, delete-orphan'))
    
    def get_public_key(self) -> dict:
        """Get public key as dictionary"""
        return {
            'n': int(self.public_key_n),
            'g': int(self.public_key_g),
            'n_squared': int(self.public_key_n_squared)
        }
    
    def set_public_key(self, public_key: dict):
        """Set public key from dictionary"""
        self.public_key_n = str(public_key['n'])
        self.public_key_g = str(public_key['g'])
        self.public_key_n_squared = str(public_key['n_squared'])
    
    def __repr__(self):
        return f'<HomomorphicKey user_id={self.user_id}>'


class SearchMasterKey(db.Model):
    """
    User's Searchable Encryption Master Key
    Used to generate search tokens
    """
    __tablename__ = 'search_master_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False)
    
    # Master key encrypted with user password
    encrypted_master_key = db.Column(db.Text, nullable=False)
    
    # Key metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    rotated_at = db.Column(db.DateTime)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('search_key', uselist=False, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<SearchMasterKey user_id={self.user_id}>'


class EncryptedFileStat(db.Model):
    """
    Homomorphically Encrypted File Statistics
    Allows computing aggregates without decryption
    """
    __tablename__ = 'encrypted_file_stats'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id', ondelete='CASCADE'), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Homomorphically encrypted values
    encrypted_size = db.Column(db.Text)  # Encrypted file size
    encrypted_count = db.Column(db.Text)  # Encrypted count (always 1)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    file = db.relationship('File', backref=db.backref('encrypted_stats', uselist=False, cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('encrypted_stats', lazy='dynamic'))
    
    def __repr__(self):
        return f'<EncryptedFileStat file_id={self.file_id}>'


def init_db(app):
    """Initialize database and create tables"""
    db.init_app(app)
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True,
                first_name='System',
                last_name='Administrator'
            )
            admin.set_password('admin123')  # Change in production!
            db.session.add(admin)
            db.session.commit()


class RecentSearch(db.Model):
    """
    User's Recent Search History
    Stores search queries for quick access and suggestions
    """
    __tablename__ = 'recent_searches'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Search details
    query = db.Column(db.String(500), nullable=False)
    results_count = db.Column(db.Integer, default=0)
    search_type = db.Column(db.String(20), default='full')  # full, filename, content
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('recent_searches', lazy='dynamic', cascade='all, delete-orphan'))
    
    __table_args__ = (
        db.Index('idx_recent_search_user', 'user_id'),
        db.Index('idx_recent_search_created', 'created_at'),
    )
    
    def __repr__(self):
        return f'<RecentSearch user_id={self.user_id} query="{self.query[:20]}...">'


class SearchSuggestion(db.Model):
    """
    Search Suggestions based on popular keywords
    Aggregated from indexed files
    """
    __tablename__ = 'search_suggestions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Suggestion data
    keyword = db.Column(db.String(100), nullable=False)
    frequency = db.Column(db.Integer, default=1)  # How often this keyword appears
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('search_suggestions', lazy='dynamic', cascade='all, delete-orphan'))
    
    __table_args__ = (
        db.Index('idx_suggestion_user_keyword', 'user_id', 'keyword'),
        db.UniqueConstraint('user_id', 'keyword', name='uq_user_keyword'),
    )
    
    def __repr__(self):
        return f'<SearchSuggestion keyword="{self.keyword}" freq={self.frequency}>'
