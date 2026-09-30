"""
Flask Routes for Secure Cloud Storage
Implements:
- User authentication (login, register, logout)
- File operations (upload, download, delete, share)
- Dashboard and file management
- Admin panel
- Searchable Encryption (keyword search in files)
- Homomorphic Encryption operations
"""

import os
import uuid
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    send_file, jsonify, current_app, abort
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)
from werkzeug.utils import secure_filename

from .models import (
    db, User, File, Folder, SharedFile, ActivityLog, FileVersion,
    FileSearchIndex, HomomorphicKey, SearchMasterKey, EncryptedFileStat
)
from .crypto import (
    AES256GCM, RSAKeyPair, HybridEncryption, HashIntegrity,
    KeyDerivation, SecureFileHandler, SearchableEncryption,
    PaillierKeyPair, HomomorphicFileStats
)

# Blueprints
main = Blueprint('main', __name__)
auth = Blueprint('auth', __name__)
files = Blueprint('files', __name__)
admin = Blueprint('admin', __name__)
search = Blueprint('search', __name__)  # New search blueprint
homomorphic = Blueprint('homomorphic', __name__)  # New homomorphic blueprint

# Login Manager Setup
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(f):
    """Decorator for admin-only routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def log_activity(action, resource_type=None, resource_id=None, resource_name=None,
                 details=None, status='success', error_message=None):
    """Helper function to log user activities"""
    log = ActivityLog.create_log(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        details=details,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string[:500] if request.user_agent else None,
        status=status,
        error_message=error_message
    )
    db.session.add(log)
    db.session.commit()


def allowed_file(filename):
    """Check if file extension is allowed"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in current_app.config.get('ALLOWED_EXTENSIONS', set())


# ==================== MAIN ROUTES ====================

@main.route('/')
def index():
    """Landing page"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('index.html')


@main.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    # Get user's recent files
    recent_files = File.query.filter_by(
        user_id=current_user.id, 
        is_deleted=False
    ).order_by(File.created_at.desc()).limit(10).all()
    
    # Get user's folders
    folders = Folder.query.filter_by(
        user_id=current_user.id,
        parent_id=None
    ).order_by(Folder.name).all()
    
    # Storage stats
    storage_used = current_user.storage_used
    storage_quota = current_user.storage_quota
    storage_percent = current_user.get_storage_percentage()
    
    # File count
    total_files = File.query.filter_by(user_id=current_user.id, is_deleted=False).count()
    shared_count = File.query.filter_by(user_id=current_user.id, is_shared=True, is_deleted=False).count()
    
    # Recent activity
    recent_activity = ActivityLog.query.filter_by(
        user_id=current_user.id
    ).order_by(ActivityLog.created_at.desc()).limit(5).all()
    
    return render_template('dashboard.html',
                         recent_files=recent_files,
                         folders=folders,
                         storage_used=storage_used,
                         storage_quota=storage_quota,
                         storage_percent=storage_percent,
                         total_files=total_files,
                         shared_count=shared_count,
                         recent_activity=recent_activity)


@main.route('/my-files')
@main.route('/my-files/<folder_uuid>')
@login_required
def my_files(folder_uuid=None):
    """File browser"""
    current_folder = None
    parent_folder = None
    
    if folder_uuid:
        current_folder = Folder.query.filter_by(uuid=folder_uuid, user_id=current_user.id).first_or_404()
        parent_folder = current_folder.parent
    
    # Get subfolders
    if current_folder:
        subfolders = Folder.query.filter_by(
            user_id=current_user.id,
            parent_id=current_folder.id
        ).order_by(Folder.name).all()
        
        files_list = File.query.filter_by(
            user_id=current_user.id,
            folder_id=current_folder.id,
            is_deleted=False
        ).order_by(File.original_filename).all()
    else:
        subfolders = Folder.query.filter_by(
            user_id=current_user.id,
            parent_id=None
        ).order_by(Folder.name).all()
        
        files_list = File.query.filter_by(
            user_id=current_user.id,
            folder_id=None,
            is_deleted=False
        ).order_by(File.original_filename).all()
    
    # Build breadcrumb
    breadcrumb = []
    if current_folder:
        folder = current_folder
        while folder:
            breadcrumb.insert(0, folder)
            folder = folder.parent
    
    return render_template('my_files.html',
                         current_folder=current_folder,
                         parent_folder=parent_folder,
                         subfolders=subfolders,
                         files=files_list,
                         breadcrumb=breadcrumb)


@main.route('/shared-with-me')
@login_required
def shared_with_me():
    """Files shared with current user"""
    shared = SharedFile.query.filter_by(
        shared_with_id=current_user.id,
        is_active=True
    ).order_by(SharedFile.created_at.desc()).all()
    
    return render_template('shared_with_me.html', shared_files=shared)


@main.route('/trash')
@login_required
def trash():
    """Deleted files"""
    deleted_files = File.query.filter_by(
        user_id=current_user.id,
        is_deleted=True
    ).order_by(File.deleted_at.desc()).all()
    
    return render_template('trash.html', files=deleted_files)


@main.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            current_user.first_name = request.form.get('first_name')
            current_user.last_name = request.form.get('last_name')
            db.session.commit()
            flash('Profile updated successfully.', 'success')
            
        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not current_user.check_password(current_password):
                flash('Current password is incorrect.', 'error')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'error')
            elif len(new_password) < 8:
                flash('Password must be at least 8 characters.', 'error')
            else:
                current_user.set_password(new_password)
                db.session.commit()
                log_activity('password_change', 'user', current_user.id)
                flash('Password changed successfully.', 'success')
        
        elif action == 'regenerate_keys':
            password = request.form.get('key_password')
            if not current_user.check_password(password):
                flash('Password verification failed.', 'error')
            else:
                # Generate new key pair
                private_pem, public_pem = RSAKeyPair.generate_key_pair()
                
                # Encrypt private key with user password
                encrypted_private = KeyDerivation.encrypt_with_password(
                    private_pem, password, {'type': 'rsa_private_key'}
                )
                
                current_user.public_key = public_pem.decode('utf-8')
                current_user.private_key_encrypted = encrypted_private.decode('utf-8')
                current_user.key_generated_at = datetime.utcnow()
                db.session.commit()
                
                log_activity('key_regeneration', 'user', current_user.id)
                flash('Encryption keys regenerated successfully.', 'success')
        
        return redirect(url_for('main.settings'))
    
    return render_template('settings.html')


# ==================== AUTH ROUTES ====================

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account has been deactivated.', 'error')
                return render_template('login.html')
            
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_activity('login', 'user', user.id)
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            log_activity('login_failed', 'user', details={'username': username}, status='failed')
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')


@auth.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        errors = []
        
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists.')
        
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')
        
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html')
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        
        # Generate RSA key pair for hybrid encryption
        private_pem, public_pem = RSAKeyPair.generate_key_pair()
        
        # Encrypt private key with user password
        encrypted_private = KeyDerivation.encrypt_with_password(
            private_pem, password, {'type': 'rsa_private_key'}
        )
        
        user.public_key = public_pem.decode('utf-8')
        user.private_key_encrypted = encrypted_private.decode('utf-8')
        user.key_generated_at = datetime.utcnow()
        
        db.session.add(user)
        db.session.commit()
        
        log_activity('registration', 'user', user.id)
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')


@auth.route('/logout')
@login_required
def logout():
    """User logout"""
    log_activity('logout', 'user', current_user.id)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))


# ==================== FILE ROUTES ====================

@files.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """File upload"""
    if request.method == 'POST':
        # Accept both 'file' and 'files' field names
        file = request.files.get('file') or request.files.get('files')
        if not file:
            flash('No file selected.', 'error')
            return redirect(request.url)
        
        folder_uuid = request.form.get('folder_uuid')
        encryption_mode = request.form.get('encryption_mode', 'hybrid')
        file_password = request.form.get('file_password')
        
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)
        
        if not allowed_file(file.filename):
            flash('File type not allowed.', 'error')
            return redirect(request.url)
        
        # Read file content
        file_content = file.read()
        original_filename = secure_filename(file.filename)
        original_size = len(file_content)
        
        # Check storage quota
        if not current_user.has_storage_space(original_size):
            flash('Storage quota exceeded.', 'error')
            return redirect(request.url)
        
        # Generate hashes for integrity
        original_hash_sha256 = HashIntegrity.sha256_hash(file_content)
        original_hash_sha512 = HashIntegrity.sha512_hash(file_content)
        
        # Generate unique filename for storage
        file_uuid = str(uuid.uuid4())
        file_ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
        stored_filename = f"{file_uuid}.enc"
        
        # Ensure directories exist
        upload_dir = current_app.config.get('ENCRYPTED_FOLDER', 'encrypted_files')
        os.makedirs(upload_dir, exist_ok=True)
        storage_path = os.path.join(upload_dir, stored_filename)
        
        # Encrypt file based on mode
        if encryption_mode == 'password' and file_password:
            # Password-based encryption
            metadata = {
                'original_filename': original_filename,
                'original_size': original_size,
                'user_id': current_user.id
            }
            encrypted_data = KeyDerivation.encrypt_with_password(file_content, file_password, metadata)
            key_derivation = 'PBKDF2-SHA256'
        else:
            # Hybrid encryption (default)
            public_key = current_user.public_key.encode('utf-8')
            metadata = {
                'original_filename': original_filename,
                'original_size': original_size,
                'user_id': current_user.id
            }
            encrypted_data = HybridEncryption.encrypt(file_content, public_key, metadata)
            key_derivation = None
        
        # Save encrypted file
        with open(storage_path, 'wb') as f:
            f.write(encrypted_data)
        
        encrypted_size = len(encrypted_data)
        encrypted_hash = HashIntegrity.sha256_hash(encrypted_data)
        
        # Get folder if specified
        folder_id = None
        if folder_uuid:
            folder = Folder.query.filter_by(uuid=folder_uuid, user_id=current_user.id).first()
            if folder:
                folder_id = folder.id
        
        # Create file record
        new_file = File(
            uuid=file_uuid,
            original_filename=original_filename,
            stored_filename=stored_filename,
            file_extension=file_ext,
            mime_type=file.content_type,
            original_size=original_size,
            encrypted_size=encrypted_size,
            original_hash_sha256=original_hash_sha256,
            original_hash_sha512=original_hash_sha512,
            encrypted_hash_sha256=encrypted_hash,
            encryption_algorithm='AES-256-GCM',
            encryption_mode=encryption_mode,
            key_derivation=key_derivation,
            storage_path=storage_path,
            user_id=current_user.id,
            folder_id=folder_id
        )
        
        # Update user storage
        current_user.storage_used += original_size
        
        db.session.add(new_file)
        db.session.commit()
        
        log_activity('upload', 'file', new_file.id, original_filename, 
                    details={'size': original_size, 'encrypted_size': encrypted_size})
        
        flash(f'File "{original_filename}" uploaded and encrypted successfully.', 'success')
        
        if folder_uuid:
            return redirect(url_for('main.my_files', folder_uuid=folder_uuid))
        return redirect(url_for('main.my_files'))
    
    # GET request - show upload form
    folder_uuid = request.args.get('folder')
    folders = Folder.query.filter_by(user_id=current_user.id).all()
    
    return render_template('upload.html', folders=folders, current_folder_uuid=folder_uuid)


@files.route('/download/<file_uuid>', methods=['GET', 'POST'])
@login_required
def download(file_uuid):
    """File download with decryption"""
    file_record = File.query.filter_by(uuid=file_uuid).first_or_404()
    
    # Check ownership or share access
    if file_record.user_id != current_user.id:
        # Check if file is shared with user
        share = SharedFile.query.filter_by(
            file_id=file_record.id,
            shared_with_id=current_user.id,
            is_active=True,
            can_download=True
        ).first()
        
        if not share or share.is_expired():
            abort(403)
    
    if file_record.encryption_mode == 'password':
        # Password-protected file needs password
        if request.method == 'POST':
            file_password = request.form.get('file_password')
            
            try:
                with open(file_record.storage_path, 'rb') as f:
                    encrypted_data = f.read()
                
                plaintext, metadata, integrity_ok = KeyDerivation.decrypt_with_password(
                    encrypted_data, file_password
                )
                
                if not integrity_ok:
                    flash('Warning: File integrity check failed!', 'warning')
                
                # Update last accessed
                file_record.last_accessed = datetime.utcnow()
                db.session.commit()
                
                log_activity('download', 'file', file_record.id, file_record.original_filename)
                
                # Return file
                from io import BytesIO
                return send_file(
                    BytesIO(plaintext),
                    download_name=file_record.original_filename,
                    as_attachment=True
                )
                
            except Exception as e:
                flash('Decryption failed. Wrong password or corrupted file.', 'error')
                return redirect(url_for('files.download', file_uuid=file_uuid))
        
        return render_template('download_password.html', file=file_record)
    
    else:
        # Hybrid encryption - need user password to decrypt private key
        if request.method == 'POST':
            user_password = request.form.get('user_password')
            
            try:
                # Decrypt user's private key
                encrypted_private = current_user.private_key_encrypted.encode('utf-8')
                private_key, _, _ = KeyDerivation.decrypt_with_password(
                    encrypted_private, user_password
                )
                
                # Read encrypted file
                with open(file_record.storage_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # Decrypt file
                plaintext, metadata, integrity_ok = HybridEncryption.decrypt(
                    encrypted_data, private_key
                )
                
                if not integrity_ok:
                    flash('Warning: File integrity check failed!', 'warning')
                
                # Update last accessed
                file_record.last_accessed = datetime.utcnow()
                db.session.commit()
                
                log_activity('download', 'file', file_record.id, file_record.original_filename)
                
                # Return file
                from io import BytesIO
                return send_file(
                    BytesIO(plaintext),
                    download_name=file_record.original_filename,
                    as_attachment=True
                )
                
            except Exception as e:
                flash('Decryption failed. Wrong password or corrupted file.', 'error')
                return redirect(url_for('files.download', file_uuid=file_uuid))
        
        return render_template('download_verify.html', file=file_record)


@files.route('/delete/<file_uuid>', methods=['POST'])
@login_required
def delete(file_uuid):
    """Move file to trash"""
    file_record = File.query.filter_by(uuid=file_uuid, user_id=current_user.id).first_or_404()
    
    file_record.is_deleted = True
    file_record.deleted_at = datetime.utcnow()
    db.session.commit()
    
    log_activity('delete', 'file', file_record.id, file_record.original_filename)
    flash(f'File "{file_record.original_filename}" moved to trash.', 'success')
    
    return redirect(request.referrer or url_for('main.my_files'))


@files.route('/restore/<file_uuid>', methods=['POST'])
@login_required
def restore(file_uuid):
    """Restore file from trash"""
    file_record = File.query.filter_by(uuid=file_uuid, user_id=current_user.id).first_or_404()
    
    file_record.is_deleted = False
    file_record.deleted_at = None
    db.session.commit()
    
    log_activity('restore', 'file', file_record.id, file_record.original_filename)
    flash(f'File "{file_record.original_filename}" restored.', 'success')
    
    return redirect(url_for('main.trash'))


@files.route('/permanent-delete/<file_uuid>', methods=['POST'])
@login_required
def permanent_delete(file_uuid):
    """Permanently delete file"""
    file_record = File.query.filter_by(uuid=file_uuid, user_id=current_user.id).first_or_404()
    
    # Delete physical file
    if os.path.exists(file_record.storage_path):
        os.remove(file_record.storage_path)
    
    # Update user storage
    current_user.storage_used -= file_record.original_size
    if current_user.storage_used < 0:
        current_user.storage_used = 0
    
    filename = file_record.original_filename
    
    db.session.delete(file_record)
    db.session.commit()
    
    log_activity('permanent_delete', 'file', details={'filename': filename})
    flash(f'File "{filename}" permanently deleted.', 'success')
    
    return redirect(url_for('main.trash'))


@files.route('/verify/<file_uuid>')
@login_required
def verify_integrity(file_uuid):
    """Verify file integrity"""
    file_record = File.query.filter_by(uuid=file_uuid, user_id=current_user.id).first_or_404()
    
    try:
        # Check encrypted file hash
        with open(file_record.storage_path, 'rb') as f:
            encrypted_data = f.read()
        
        current_hash = HashIntegrity.sha256_hash(encrypted_data)
        encrypted_ok = current_hash == file_record.encrypted_hash_sha256
        
        result = {
            'file': file_record.original_filename,
            'encrypted_integrity': encrypted_ok,
            'stored_hash': file_record.encrypted_hash_sha256,
            'current_hash': current_hash
        }
        
        log_activity('verify_integrity', 'file', file_record.id, file_record.original_filename,
                    details=result)
        
        return render_template('verify_integrity.html', result=result, file=file_record)
        
    except Exception as e:
        flash(f'Integrity check failed: {str(e)}', 'error')
        return redirect(url_for('main.my_files'))


@files.route('/share/<file_uuid>', methods=['GET', 'POST'])
@login_required
def share(file_uuid):
    """Share a file"""
    file_record = File.query.filter_by(uuid=file_uuid, user_id=current_user.id).first_or_404()
    
    if request.method == 'POST':
        share_type = request.form.get('share_type')
        
        if share_type == 'user':
            # Share with specific user
            share_email = request.form.get('share_email')
            recipient = User.query.filter_by(email=share_email).first()
            
            if not recipient:
                flash('User not found.', 'error')
                return redirect(request.url)
            
            if recipient.id == current_user.id:
                flash('Cannot share with yourself.', 'error')
                return redirect(request.url)
            
            share = SharedFile(
                file_id=file_record.id,
                shared_by_id=current_user.id,
                shared_with_id=recipient.id,
                can_view=True,
                can_download='can_download' in request.form
            )
            
        else:
            # Create share link
            share_link = str(uuid.uuid4())[:16]
            expires_days = int(request.form.get('expires_days', 7))
            max_downloads = request.form.get('max_downloads')
            link_password = request.form.get('link_password')
            
            share = SharedFile(
                file_id=file_record.id,
                shared_by_id=current_user.id,
                share_link=share_link,
                can_view=True,
                can_download=True,
                expires_at=datetime.utcnow() + timedelta(days=expires_days) if expires_days > 0 else None,
                max_downloads=int(max_downloads) if max_downloads else None
            )
            
            if link_password:
                from werkzeug.security import generate_password_hash
                share.share_password_hash = generate_password_hash(link_password)
        
        file_record.is_shared = True
        db.session.add(share)
        db.session.commit()
        
        log_activity('share', 'file', file_record.id, file_record.original_filename)
        flash('File shared successfully.', 'success')
        
        if share.share_link:
            share_url = url_for('files.shared_link', share_link=share.share_link, _external=True)
            flash(f'Share link: {share_url}', 'info')
        
        return redirect(url_for('main.my_files'))
    
    return render_template('share.html', file=file_record)


@files.route('/s/<share_link>', methods=['GET', 'POST'])
def shared_link(share_link):
    """Access shared file via link"""
    share = SharedFile.query.filter_by(share_link=share_link, is_active=True).first_or_404()
    
    if share.is_expired():
        flash('This share link has expired.', 'error')
        return redirect(url_for('main.index'))
    
    # Check password if required
    if share.share_password_hash:
        if request.method == 'POST':
            password = request.form.get('password')
            from werkzeug.security import check_password_hash
            if not check_password_hash(share.share_password_hash, password):
                flash('Invalid password.', 'error')
                return render_template('shared_link_password.html', share=share)
        else:
            return render_template('shared_link_password.html', share=share)
    
    file_record = share.file
    share.last_accessed = datetime.utcnow()
    db.session.commit()
    
    return render_template('shared_file_view.html', share=share, file=file_record)


@files.route('/folder/create', methods=['POST'])
@login_required
def create_folder():
    """Create a new folder"""
    folder_name = request.form.get('folder_name')
    parent_uuid = request.form.get('parent_uuid')
    
    if not folder_name:
        flash('Folder name is required.', 'error')
        return redirect(request.referrer or url_for('main.my_files'))
    
    parent_id = None
    if parent_uuid:
        parent = Folder.query.filter_by(uuid=parent_uuid, user_id=current_user.id).first()
        if parent:
            parent_id = parent.id
    
    folder = Folder(
        name=folder_name,
        user_id=current_user.id,
        parent_id=parent_id
    )
    
    db.session.add(folder)
    db.session.commit()
    
    log_activity('create_folder', 'folder', folder.id, folder_name)
    flash(f'Folder "{folder_name}" created.', 'success')
    
    if parent_uuid:
        return redirect(url_for('main.my_files', folder_uuid=parent_uuid))
    return redirect(url_for('main.my_files'))


# ==================== ADMIN ROUTES ====================

@admin.route('/')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    total_users = User.query.count()
    total_files = File.query.filter_by(is_deleted=False).count()
    total_storage = db.session.query(db.func.sum(File.original_size)).scalar() or 0
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_activity = ActivityLog.query.order_by(ActivityLog.created_at.desc()).limit(20).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_files=total_files,
                         total_storage=total_storage,
                         recent_users=recent_users,
                         recent_activity=recent_activity)


@admin.route('/users')
@login_required
@admin_required
def admin_users():
    """User management"""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)


@admin.route('/user/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    """Toggle user active status"""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Cannot deactivate your own account.', 'error')
        return redirect(url_for('admin.admin_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    log_activity(f'user_{status}', 'user', user.id, user.username)
    flash(f'User {user.username} has been {status}.', 'success')
    
    return redirect(url_for('admin.admin_users'))


@admin.route('/activity-logs')
@login_required
@admin_required
def activity_logs():
    """View activity logs"""
    page = request.args.get('page', 1, type=int)
    logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).paginate(
        page=page, per_page=50
    )
    return render_template('admin/activity_logs.html', logs=logs)


# ==================== API ROUTES ====================

@files.route('/api/file-info/<file_uuid>')
@login_required
def api_file_info(file_uuid):
    """Get file information as JSON"""
    file_record = File.query.filter_by(uuid=file_uuid, user_id=current_user.id).first_or_404()
    
    return jsonify({
        'uuid': file_record.uuid,
        'filename': file_record.original_filename,
        'size': file_record.original_size,
        'encrypted_size': file_record.encrypted_size,
        'hash_sha256': file_record.original_hash_sha256,
        'encryption': file_record.encryption_algorithm,
        'created_at': file_record.created_at.isoformat(),
        'is_shared': file_record.is_shared
    })


@files.route('/api/storage-stats')
@login_required
def api_storage_stats():
    """Get storage statistics"""
    return jsonify({
        'used': current_user.storage_used,
        'quota': current_user.storage_quota,
        'percentage': current_user.get_storage_percentage(),
        'remaining': current_user.storage_quota - current_user.storage_used
    })


# ==================== SEARCH ROUTES ====================

def get_user_search_encryption(user, password=None):
    """Get or create user's searchable encryption instance"""
    search_key = SearchMasterKey.query.filter_by(user_id=user.id).first()
    
    if search_key and password:
        # Decrypt master key
        try:
            master_key_data, _, _ = KeyDerivation.decrypt_with_password(
                search_key.encrypted_master_key.encode('utf-8'), password
            )
            return SearchableEncryption(master_key_data)
        except Exception:
            return None
    
    return None


def create_user_search_key(user, password):
    """Create new search master key for user"""
    sse = SearchableEncryption()  # Generates new master key
    
    # Encrypt master key with user password
    encrypted_key = KeyDerivation.encrypt_with_password(
        sse.master_key, password, {'type': 'search_master_key'}
    )
    
    search_key = SearchMasterKey(
        user_id=user.id,
        encrypted_master_key=encrypted_key.decode('utf-8')
    )
    db.session.add(search_key)
    db.session.commit()
    
    return sse


def index_file_for_search(file_record, content, sse):
    """Index a file for searchable encryption"""
    # Create search index
    index_data = sse.index_file_content(
        file_record.uuid,
        content,
        file_record.original_filename
    )
    
    # Check if index already exists
    existing_index = FileSearchIndex.query.filter_by(file_id=file_record.id).first()
    
    if existing_index:
        existing_index.set_tokens(index_data['tokens'])
        existing_index.keyword_count = index_data['keyword_count']
        existing_index.updated_at = datetime.utcnow()
    else:
        search_index = FileSearchIndex(
            file_id=file_record.id,
            user_id=file_record.user_id
        )
        search_index.set_tokens(index_data['tokens'])
        search_index.keyword_count = index_data['keyword_count']
        db.session.add(search_index)
    
    db.session.commit()
    return index_data['keyword_count']


@search.route('/')
@login_required
def search_page():
    """Search page"""
    return render_template('search.html')


@search.route('/files', methods=['GET', 'POST'])
@login_required
def search_files():
    """Search files by keyword"""
    query = request.args.get('q', '') or request.form.get('query', '')
    password = request.form.get('password', '')
    
    if not query:
        return render_template('search.html', results=[], query='')
    
    # Get user's search key
    search_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    
    if not search_key:
        flash('Search not available. Please enable search indexing in settings.', 'warning')
        return render_template('search.html', results=[], query=query, needs_setup=True)
    
    # For POST requests, decrypt and search
    if request.method == 'POST' and password:
        sse = get_user_search_encryption(current_user, password)
        
        if not sse:
            flash('Invalid password for search decryption.', 'error')
            return render_template('search.html', results=[], query=query, need_password=True)
        
        # Get all user's indexed files
        indexes = FileSearchIndex.query.filter_by(user_id=current_user.id, is_indexed=True).all()
        
        # Convert to search format
        index_data = [{'file_id': idx.file.uuid, 'tokens': idx.get_tokens()} for idx in indexes]
        
        # Perform search with ranking
        results = sse.search_with_ranking(query, index_data)
        
        # Get file details for results
        result_files = []
        for file_uuid, score in results:
            file_record = File.query.filter_by(uuid=file_uuid, user_id=current_user.id).first()
            if file_record and not file_record.is_deleted:
                result_files.append({
                    'file': file_record,
                    'score': round(score * 100, 1),
                    'keywords_matched': int(score * len(SearchableEncryption._tokenize_text(query)))
                })
        
        log_activity('search', 'file', details={'query': query, 'results': len(result_files)})
        
        return render_template('search_results.html', 
                             results=result_files, 
                             query=query,
                             total_results=len(result_files))
    
    # GET request - ask for password
    return render_template('search.html', query=query, need_password=True)


@search.route('/index-file/<file_uuid>', methods=['POST'])
@login_required
def index_single_file(file_uuid):
    """Index a single file for search"""
    password = request.form.get('password', '')
    
    file_record = File.query.filter_by(uuid=file_uuid, user_id=current_user.id).first_or_404()
    
    if not password:
        flash('Password required for indexing.', 'error')
        return redirect(url_for('main.my_files'))
    
    # Get or create search encryption
    search_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    if search_key:
        sse = get_user_search_encryption(current_user, password)
    else:
        sse = create_user_search_key(current_user, password)
    
    if not sse:
        flash('Invalid password.', 'error')
        return redirect(url_for('main.my_files'))
    
    # Read and decrypt file content for indexing
    try:
        with open(file_record.storage_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt based on encryption mode
        if file_record.encryption_mode == 'password':
            file_password = request.form.get('file_password', password)
            plaintext, _, _ = KeyDerivation.decrypt_with_password(encrypted_data, file_password)
        else:
            private_key_encrypted = current_user.private_key_encrypted
            private_key, _, _ = KeyDerivation.decrypt_with_password(
                private_key_encrypted.encode('utf-8'), password
            )
            plaintext, _, _ = HybridEncryption.decrypt(encrypted_data, private_key)
        
        # Try to decode as text
        try:
            content = plaintext.decode('utf-8')
        except UnicodeDecodeError:
            content = ''  # Binary file - index filename only
        
        # Index the file
        keyword_count = index_file_for_search(file_record, content, sse)
        
        flash(f'File indexed successfully. {keyword_count} keywords extracted.', 'success')
        log_activity('index_file', 'file', file_record.id, file_record.original_filename,
                    details={'keywords': keyword_count})
        
    except Exception as e:
        flash(f'Error indexing file: {str(e)}', 'error')
    
    return redirect(url_for('main.my_files'))


@search.route('/reindex-all', methods=['POST'])
@login_required
def reindex_all_files():
    """Reindex all user's files"""
    password = request.form.get('password', '')
    
    if not password:
        flash('Password required for reindexing.', 'error')
        return redirect(url_for('main.settings'))
    
    # Get or create search encryption
    search_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    if search_key:
        sse = get_user_search_encryption(current_user, password)
    else:
        sse = create_user_search_key(current_user, password)
    
    if not sse:
        flash('Invalid password.', 'error')
        return redirect(url_for('main.settings'))
    
    # Get all user's files
    files = File.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    
    indexed_count = 0
    error_count = 0
    
    for file_record in files:
        try:
            with open(file_record.storage_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt
            if file_record.encryption_mode == 'password':
                # Skip password-encrypted files for bulk reindex
                continue
            else:
                private_key_encrypted = current_user.private_key_encrypted
                private_key, _, _ = KeyDerivation.decrypt_with_password(
                    private_key_encrypted.encode('utf-8'), password
                )
                plaintext, _, _ = HybridEncryption.decrypt(encrypted_data, private_key)
            
            # Decode and index
            try:
                content = plaintext.decode('utf-8')
            except UnicodeDecodeError:
                content = ''
            
            index_file_for_search(file_record, content, sse)
            indexed_count += 1
            
        except Exception:
            error_count += 1
    
    flash(f'Reindexed {indexed_count} files. {error_count} errors.', 'success')
    log_activity('reindex_all', 'file', details={'indexed': indexed_count, 'errors': error_count})
    
    return redirect(url_for('main.settings'))


@search.route('/api/search')
@login_required  
def api_search():
    """API endpoint for search (requires auth token in real impl)"""
    query = request.args.get('q', '')
    
    if not query:
        return jsonify({'error': 'No query provided', 'results': []})
    
    # This is a simplified version - in production, use session-based search tokens
    indexes = FileSearchIndex.query.filter_by(user_id=current_user.id, is_indexed=True).all()
    
    # Return indexed file info (tokens are encrypted)
    return jsonify({
        'query': query,
        'indexed_files': len(indexes),
        'message': 'Use POST /search/files with password to perform encrypted search'
    })


# ==================== HOMOMORPHIC ENCRYPTION ROUTES ====================

def get_user_homomorphic_keys(user):
    """Get user's homomorphic encryption keys"""
    hk = HomomorphicKey.query.filter_by(user_id=user.id).first()
    if hk:
        return hk.get_public_key()
    return None


def create_user_homomorphic_keys(user, password):
    """Create homomorphic encryption keys for user"""
    paillier = PaillierKeyPair(key_size=1024)  # Use 1024 for speed
    public_key, private_key = paillier.generate_keypair()
    
    # Encrypt private key
    private_key_json = paillier.serialize_private_key()
    encrypted_private = KeyDerivation.encrypt_with_password(
        private_key_json.encode('utf-8'), password, {'type': 'paillier_private_key'}
    )
    
    hk = HomomorphicKey(
        user_id=user.id,
        key_size=1024
    )
    hk.set_public_key(public_key)
    hk.private_key_encrypted = encrypted_private.decode('utf-8')
    
    db.session.add(hk)
    db.session.commit()
    
    return paillier


@homomorphic.route('/setup', methods=['GET', 'POST'])
@login_required
def setup_homomorphic():
    """Setup homomorphic encryption keys"""
    existing_key = HomomorphicKey.query.filter_by(user_id=current_user.id).first()
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        if not password:
            flash('Password required.', 'error')
            return render_template('homomorphic_setup.html', has_keys=bool(existing_key))
        
        if existing_key:
            # Delete existing keys
            EncryptedFileStat.query.filter_by(user_id=current_user.id).delete()
            db.session.delete(existing_key)
            db.session.commit()
        
        # Generate new keys
        try:
            paillier = create_user_homomorphic_keys(current_user, password)
            flash('Homomorphic encryption keys generated successfully!', 'success')
            log_activity('homomorphic_setup', 'user', current_user.id)
        except Exception as e:
            flash(f'Error generating keys: {str(e)}', 'error')
        
        return redirect(url_for('homomorphic.dashboard'))
    
    return render_template('homomorphic_setup.html', has_keys=bool(existing_key))


@homomorphic.route('/dashboard')
@login_required
def dashboard():
    """Homomorphic encryption dashboard"""
    hk = HomomorphicKey.query.filter_by(user_id=current_user.id).first()
    
    if not hk:
        return redirect(url_for('homomorphic.setup_homomorphic'))
    
    # Get encrypted stats
    stats = EncryptedFileStat.query.filter_by(user_id=current_user.id).all()
    
    return render_template('homomorphic_dashboard.html', 
                         has_keys=True,
                         stats_count=len(stats),
                         key_created=hk.created_at)


@homomorphic.route('/encrypt-stats', methods=['POST'])
@login_required
def encrypt_file_stats():
    """Encrypt file statistics for homomorphic operations"""
    password = request.form.get('password', '')
    
    hk = HomomorphicKey.query.filter_by(user_id=current_user.id).first()
    if not hk:
        flash('Homomorphic keys not set up.', 'error')
        return redirect(url_for('homomorphic.setup_homomorphic'))
    
    if not password:
        flash('Password required.', 'error')
        return redirect(url_for('homomorphic.dashboard'))
    
    # Get Paillier with public key
    paillier = PaillierKeyPair()
    paillier.public_key = hk.get_public_key()
    
    # Get user's files
    files = File.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    
    encrypted_count = 0
    for file_record in files:
        # Check if already encrypted
        existing = EncryptedFileStat.query.filter_by(file_id=file_record.id).first()
        if existing:
            continue
        
        # Encrypt file size
        encrypted_size = paillier.encrypt(file_record.original_size)
        encrypted_count_val = paillier.encrypt(1)  # Count = 1
        
        stat = EncryptedFileStat(
            file_id=file_record.id,
            user_id=current_user.id,
            encrypted_size=str(encrypted_size),
            encrypted_count=str(encrypted_count_val)
        )
        db.session.add(stat)
        encrypted_count += 1
    
    db.session.commit()
    
    flash(f'Encrypted statistics for {encrypted_count} files.', 'success')
    log_activity('encrypt_stats', 'file', details={'count': encrypted_count})
    
    return redirect(url_for('homomorphic.dashboard'))


@homomorphic.route('/compute-total', methods=['POST'])
@login_required
def compute_encrypted_total():
    """Compute total storage using homomorphic operations"""
    password = request.form.get('password', '')
    
    hk = HomomorphicKey.query.filter_by(user_id=current_user.id).first()
    if not hk:
        flash('Homomorphic keys not set up.', 'error')
        return redirect(url_for('homomorphic.setup_homomorphic'))
    
    if not password:
        flash('Password required to decrypt result.', 'error')
        return redirect(url_for('homomorphic.dashboard'))
    
    # Get encrypted stats
    stats = EncryptedFileStat.query.filter_by(user_id=current_user.id).all()
    
    if not stats:
        flash('No encrypted statistics found. Please encrypt file stats first.', 'warning')
        return redirect(url_for('homomorphic.dashboard'))
    
    # Get public key for homomorphic operations
    public_key = hk.get_public_key()
    
    # Sum encrypted sizes (homomorphic addition)
    total_encrypted = int(stats[0].encrypted_size)
    total_count_encrypted = int(stats[0].encrypted_count)
    
    for stat in stats[1:]:
        total_encrypted = PaillierKeyPair.add_encrypted(
            total_encrypted, int(stat.encrypted_size), public_key
        )
        total_count_encrypted = PaillierKeyPair.add_encrypted(
            total_count_encrypted, int(stat.encrypted_count), public_key
        )
    
    # Decrypt the result
    try:
        # Get private key
        private_key_encrypted = hk.private_key_encrypted
        private_key_json, _, _ = KeyDerivation.decrypt_with_password(
            private_key_encrypted.encode('utf-8'), password
        )
        private_key = PaillierKeyPair.deserialize_private_key(private_key_json.decode('utf-8'))
        
        paillier = PaillierKeyPair()
        paillier.private_key = private_key
        
        # Decrypt totals
        total_size = paillier.decrypt(total_encrypted)
        total_files = paillier.decrypt(total_count_encrypted)
        
        # Format size
        def format_bytes(size):
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024:
                    return f"{size:.2f} {unit}"
                size /= 1024
            return f"{size:.2f} TB"
        
        result = {
            'total_size': format_bytes(total_size),
            'total_size_bytes': total_size,
            'total_files': total_files,
            'computed_homomorphically': True
        }
        
        flash(f'Computed using homomorphic encryption: {total_files} files, {format_bytes(total_size)} total', 'success')
        log_activity('homomorphic_compute', 'file', 
                    details={'total_size': total_size, 'total_files': total_files})
        
        return render_template('homomorphic_result.html', result=result)
        
    except Exception as e:
        flash(f'Error decrypting result: {str(e)}', 'error')
        return redirect(url_for('homomorphic.dashboard'))


@homomorphic.route('/api/encrypted-stats')
@login_required
def api_encrypted_stats():
    """Get encrypted statistics (without decryption)"""
    hk = HomomorphicKey.query.filter_by(user_id=current_user.id).first()
    if not hk:
        return jsonify({'error': 'Homomorphic keys not set up'})
    
    stats = EncryptedFileStat.query.filter_by(user_id=current_user.id).all()
    
    return jsonify({
        'encrypted_stats_count': len(stats),
        'public_key_n_length': len(hk.public_key_n) if hk.public_key_n else 0,
        'message': 'Statistics are encrypted. Use compute-total with password to decrypt.'
    })


@homomorphic.route('/demo')
@login_required
def demo_homomorphic():
    """Demo page showing homomorphic encryption capabilities"""
    return render_template('homomorphic_demo.html')
