"""
Unified Security Routes for Secure Cloud Storage
Combines:
- Searchable Symmetric Encryption (SSE)
- Paillier Homomorphic Encryption
- Security Dashboard

Developed by: Dr. Mohammed Tawfik
Email: kmkhol01@gmail.com
"""

import os
import json
from datetime import datetime
from functools import wraps

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    jsonify, current_app, abort
)
from flask_login import login_required, current_user

from .models import (
    db, User, File, FileSearchIndex, HomomorphicKey, SearchMasterKey,
    EncryptedFileStat, ActivityLog
)
from .crypto import (
    AES256GCM, KeyDerivation, SearchableEncryption, PaillierKeyPair,
    HashIntegrity
)

# Create unified security blueprint
security = Blueprint('security', __name__, url_prefix='/security')


def log_activity(action, resource_type=None, resource_id=None, resource_name=None,
                 details=None, status='success', error_message=None):
    """Helper function to log security activities"""
    try:
        log = ActivityLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            details=json.dumps(details) if details else None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string[:500] if request.user_agent else None,
            status=status,
            error_message=error_message
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Error logging activity: {e}")


def get_sse_instance(password: str):
    """
    Get SSE instance with user's master key
    Returns (sse_instance, error_message) tuple
    """
    # Get user's SSE key
    sse_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    if not sse_key:
        return None, "SSE not enabled. Please enable it first."
    
    try:
        # Decrypt master key
        master_key_bytes, _, _ = KeyDerivation.decrypt_with_password(
            sse_key.encrypted_master_key.encode('utf-8'), password
        )
        
        # Initialize SSE with master key
        sse = SearchableEncryption(master_key_bytes)
        return sse, None
    except Exception as e:
        return None, f"Invalid password or corrupted key: {str(e)}"


# ==================== UNIFIED SECURITY DASHBOARD ====================

@security.route('/dashboard')
@login_required
def security_dashboard():
    """
    Unified Security Dashboard
    Combines SSE and Homomorphic Encryption on ONE page
    """
    # Check SSE status
    sse_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    sse_enabled = sse_key is not None
    
    # Check Homomorphic Encryption status
    he_key = HomomorphicKey.query.filter_by(user_id=current_user.id).first()
    he_enabled = he_key is not None
    
    # SSE statistics
    indexed_files = 0
    total_keywords = 0
    if sse_enabled:
        indexed_files = FileSearchIndex.query.filter_by(user_id=current_user.id).count()
        total_keywords = db.session.query(
            db.func.sum(FileSearchIndex.keyword_count)
        ).filter_by(user_id=current_user.id).scalar() or 0
    
    # Homomorphic statistics
    encrypted_stats_count = 0
    if he_enabled:
        encrypted_stats_count = EncryptedFileStat.query.filter_by(
            user_id=current_user.id
        ).count()
    
    # Total files count
    total_files = File.query.filter_by(user_id=current_user.id, is_deleted=False).count()
    
    return render_template('security_dashboard.html',
                         sse_enabled=sse_enabled,
                         he_enabled=he_enabled,
                         indexed_files=indexed_files,
                         total_keywords=total_keywords,
                         encrypted_stats_count=encrypted_stats_count,
                         total_files=total_files,
                         search_results=None,
                         search_query=None,
                         he_result=None)


# ==================== SEARCHABLE SYMMETRIC ENCRYPTION ====================

@security.route('/enable-sse', methods=['POST'])
@login_required
def enable_sse():
    """Enable Searchable Symmetric Encryption for user"""
    password = request.form.get('password', '')
    
    if not password:
        flash('Password required to enable SSE.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Verify password
    if not current_user.check_password(password):
        flash('Invalid password.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Check if already enabled - if so, we'll re-index
    existing = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    if existing:
        # Delete existing indexes
        FileSearchIndex.query.filter_by(user_id=current_user.id).delete()
        db.session.delete(existing)
        db.session.commit()
    
    try:
        # Generate SSE master key
        sse = SearchableEncryption()
        master_key = sse.master_key
        
        # Encrypt master key with user's password
        encrypted_key = KeyDerivation.encrypt_with_password(
            master_key, password, {'type': 'sse_master_key'}
        )
        
        # Store encrypted master key
        search_key = SearchMasterKey(
            user_id=current_user.id,
            encrypted_master_key=encrypted_key.decode('utf-8')
        )
        db.session.add(search_key)
        db.session.commit()
        
        # Index existing files
        files = File.query.filter_by(user_id=current_user.id, is_deleted=False).all()
        indexed_count = 0
        total_keywords = 0
        
        for file in files:
            try:
                # Create searchable index data
                index_data = sse.index_file_content(
                    str(file.id), 
                    '',  # No content for now, just filename
                    file.original_filename
                )
                
                # Create search index entry
                index_entry = FileSearchIndex(
                    file_id=file.id,
                    user_id=current_user.id,
                    keyword_count=index_data['keyword_count']
                )
                index_entry.set_tokens(index_data['tokens'])
                
                db.session.add(index_entry)
                indexed_count += 1
                total_keywords += index_data['keyword_count']
            except Exception as e:
                print(f"Error indexing file {file.id}: {e}")
                continue
        
        db.session.commit()
        
        flash(f'SSE enabled! Indexed {indexed_count} files with {total_keywords} keywords.', 'success')
        log_activity('enable_sse', 'user', current_user.id, 
                    details={'indexed_files': indexed_count, 'keywords': total_keywords})
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error enabling SSE: {str(e)}', 'error')
    
    return redirect(url_for('security.security_dashboard'))


@security.route('/reindex', methods=['POST'])
@login_required
def reindex_files():
    """Re-index all files for SSE search"""
    password = request.form.get('password', '')
    
    if not password:
        flash('Password required.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Verify password
    if not current_user.check_password(password):
        flash('Invalid password.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Get SSE instance
    sse, error = get_sse_instance(password)
    if error:
        flash(error, 'error')
        return redirect(url_for('security.security_dashboard'))
    
    try:
        # Delete existing indexes
        FileSearchIndex.query.filter_by(user_id=current_user.id).delete()
        
        # Re-index all files
        files = File.query.filter_by(user_id=current_user.id, is_deleted=False).all()
        indexed_count = 0
        total_keywords = 0
        
        for file in files:
            try:
                index_data = sse.index_file_content(
                    str(file.id), 
                    '',
                    file.original_filename
                )
                
                index_entry = FileSearchIndex(
                    file_id=file.id,
                    user_id=current_user.id,
                    keyword_count=index_data['keyword_count']
                )
                index_entry.set_tokens(index_data['tokens'])
                
                db.session.add(index_entry)
                indexed_count += 1
                total_keywords += index_data['keyword_count']
            except Exception as e:
                print(f"Error indexing file {file.id}: {e}")
                continue
        
        db.session.commit()
        
        flash(f'Re-indexed {indexed_count} files with {total_keywords} keywords.', 'success')
        log_activity('reindex_sse', 'user', current_user.id,
                    details={'indexed_files': indexed_count, 'keywords': total_keywords})
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error re-indexing: {str(e)}', 'error')
    
    return redirect(url_for('security.security_dashboard'))


@security.route('/search', methods=['POST'])
@login_required
def search_files():
    """Search encrypted files using SSE"""
    query = request.form.get('query', '').strip()
    password = request.form.get('password', '')
    
    if not query:
        flash('Please enter a search query.', 'warning')
        return redirect(url_for('security.security_dashboard'))
    
    if not password:
        flash('Password required to search.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Verify password
    if not current_user.check_password(password):
        flash('Invalid password.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Get SSE instance with same master key
    sse, error = get_sse_instance(password)
    if error:
        flash(error, 'error')
        return redirect(url_for('security.security_dashboard'))
    
    try:
        # Tokenize query (same way we tokenize filenames)
        query_keywords = SearchableEncryption._tokenize_text(query)
        
        if not query_keywords:
            flash('No valid search keywords found. Try different terms.', 'warning')
            return redirect(url_for('security.security_dashboard'))
        
        # Generate tokens for query keywords
        query_tokens = set()
        for kw in query_keywords:
            token = sse.generate_keyword_token(kw)
            query_tokens.add(token)
        
        # Search in index
        search_indexes = FileSearchIndex.query.filter_by(user_id=current_user.id).all()
        matching_file_ids = []
        match_scores = {}  # file_id -> number of matching keywords
        
        for idx in search_indexes:
            try:
                file_tokens = set(idx.get_tokens())
                
                # Check for matches
                matches = query_tokens & file_tokens
                if matches:
                    matching_file_ids.append(idx.file_id)
                    match_scores[idx.file_id] = len(matches)
            except Exception as e:
                print(f"Error searching index {idx.id}: {e}")
                continue
        
        # Get matching files, sorted by relevance
        search_results = []
        if matching_file_ids:
            files = File.query.filter(
                File.id.in_(matching_file_ids),
                File.is_deleted == False
            ).all()
            
            # Sort by match score (descending)
            files.sort(key=lambda f: match_scores.get(f.id, 0), reverse=True)
            search_results = files
        
        log_activity('search_files', 'file', 
                    details={'query': query, 'keywords': list(query_keywords), 
                            'results': len(search_results)})
        
        # Return with results
        sse_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
        he_key = HomomorphicKey.query.filter_by(user_id=current_user.id).first()
        
        indexed_files = FileSearchIndex.query.filter_by(user_id=current_user.id).count()
        total_keywords = db.session.query(
            db.func.sum(FileSearchIndex.keyword_count)
        ).filter_by(user_id=current_user.id).scalar() or 0
        
        total_files = File.query.filter_by(user_id=current_user.id, is_deleted=False).count()
        
        encrypted_stats_count = EncryptedFileStat.query.filter_by(
            user_id=current_user.id
        ).count() if he_key else 0
        
        if not search_results:
            flash(f'No files found matching "{query}". Try different keywords.', 'info')
        
        return render_template('security_dashboard.html',
                             sse_enabled=True,
                             he_enabled=he_key is not None,
                             indexed_files=indexed_files,
                             total_keywords=total_keywords,
                             total_files=total_files,
                             encrypted_stats_count=encrypted_stats_count,
                             search_results=search_results,
                             search_query=query,
                             search_keywords=list(query_keywords),
                             he_result=None)
        
    except Exception as e:
        flash(f'Search error: {str(e)}', 'error')
        return redirect(url_for('security.security_dashboard'))


@security.route('/disable-sse', methods=['POST'])
@login_required
def disable_sse():
    """Disable SSE and remove all indexes"""
    password = request.form.get('password', '')
    
    if not password:
        flash('Password required.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    if not current_user.check_password(password):
        flash('Invalid password.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    try:
        # Delete all indexes
        FileSearchIndex.query.filter_by(user_id=current_user.id).delete()
        
        # Delete master key
        SearchMasterKey.query.filter_by(user_id=current_user.id).delete()
        
        db.session.commit()
        flash('SSE disabled and all indexes removed.', 'success')
        log_activity('disable_sse', 'user', current_user.id)
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error disabling SSE: {str(e)}', 'error')
    
    return redirect(url_for('security.security_dashboard'))


# ==================== HOMOMORPHIC ENCRYPTION ====================

@security.route('/setup-homomorphic', methods=['POST'])
@login_required
def setup_homomorphic():
    """Setup Paillier Homomorphic Encryption keys"""
    password = request.form.get('password', '')
    
    if not password:
        flash('Password required.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Verify password
    if not current_user.check_password(password):
        flash('Invalid password.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Check if already exists
    existing = HomomorphicKey.query.filter_by(user_id=current_user.id).first()
    if existing:
        # Delete existing keys
        EncryptedFileStat.query.filter_by(user_id=current_user.id).delete()
        db.session.delete(existing)
        db.session.commit()
    
    try:
        # Generate Paillier keys (1024-bit for speed)
        flash('Generating Paillier keys... This may take a moment.', 'info')
        paillier = PaillierKeyPair(key_size=1024)
        public_key, private_key = paillier.generate_keypair()
        
        # Encrypt private key
        private_key_json = paillier.serialize_private_key()
        encrypted_private = KeyDerivation.encrypt_with_password(
            private_key_json.encode('utf-8'), password, {'type': 'paillier_private_key'}
        )
        
        # Store keys
        hk = HomomorphicKey(
            user_id=current_user.id,
            key_size=1024
        )
        hk.set_public_key(public_key)
        hk.private_key_encrypted = encrypted_private.decode('utf-8')
        
        db.session.add(hk)
        db.session.commit()
        
        flash('Paillier Homomorphic keys generated successfully!', 'success')
        log_activity('setup_homomorphic', 'user', current_user.id)
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error generating keys: {str(e)}', 'error')
    
    return redirect(url_for('security.security_dashboard'))


@security.route('/encrypt-stats', methods=['POST'])
@login_required
def encrypt_stats():
    """Encrypt file statistics for homomorphic operations"""
    password = request.form.get('password', '')
    
    if not password:
        flash('Password required.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Get homomorphic key
    hk = HomomorphicKey.query.filter_by(user_id=current_user.id).first()
    if not hk:
        flash('Homomorphic keys not set up.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    try:
        # Initialize Paillier with public key
        paillier = PaillierKeyPair()
        paillier.public_key = hk.get_public_key()
        
        # Get user's files
        files = File.query.filter_by(user_id=current_user.id, is_deleted=False).all()
        
        encrypted_count = 0
        for file in files:
            # Skip if already encrypted
            existing = EncryptedFileStat.query.filter_by(file_id=file.id).first()
            if existing:
                continue
            
            # Encrypt file size
            encrypted_size = paillier.encrypt(file.original_size)
            encrypted_count_val = paillier.encrypt(1)  # Count = 1
            
            stat = EncryptedFileStat(
                file_id=file.id,
                user_id=current_user.id,
                encrypted_size=str(encrypted_size),
                encrypted_count=str(encrypted_count_val)
            )
            db.session.add(stat)
            encrypted_count += 1
        
        db.session.commit()
        
        flash(f'Encrypted statistics for {encrypted_count} new files.', 'success')
        log_activity('encrypt_stats', 'file', details={'count': encrypted_count})
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error encrypting stats: {str(e)}', 'error')
    
    return redirect(url_for('security.security_dashboard'))


@security.route('/compute-total', methods=['POST'])
@login_required
def compute_total():
    """Compute total storage using homomorphic operations"""
    password = request.form.get('password', '')
    
    if not password:
        flash('Password required to decrypt result.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Verify password
    if not current_user.check_password(password):
        flash('Invalid password.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Get homomorphic key
    hk = HomomorphicKey.query.filter_by(user_id=current_user.id).first()
    if not hk:
        flash('Homomorphic keys not set up.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    # Get encrypted stats
    stats = EncryptedFileStat.query.filter_by(user_id=current_user.id).all()
    
    if not stats:
        flash('No encrypted statistics found. Please encrypt file stats first.', 'warning')
        return redirect(url_for('security.security_dashboard'))
    
    try:
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
        
        he_result = {
            'total_size': format_bytes(total_size),
            'total_size_bytes': total_size,
            'total_files': total_files
        }
        
        flash(f'Computed homomorphically: {total_files} files, {format_bytes(total_size)} total', 'success')
        log_activity('homomorphic_compute', 'file', 
                    details={'total_size': total_size, 'total_files': total_files})
        
        # Return with result
        sse_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
        indexed_files = FileSearchIndex.query.filter_by(user_id=current_user.id).count()
        total_keywords = db.session.query(
            db.func.sum(FileSearchIndex.keyword_count)
        ).filter_by(user_id=current_user.id).scalar() or 0
        total_files_count = File.query.filter_by(user_id=current_user.id, is_deleted=False).count()
        encrypted_stats_count = len(stats)
        
        return render_template('security_dashboard.html',
                             sse_enabled=sse_key is not None,
                             he_enabled=True,
                             indexed_files=indexed_files,
                             total_keywords=total_keywords,
                             total_files=total_files_count,
                             encrypted_stats_count=encrypted_stats_count,
                             search_results=None,
                             search_query=None,
                             he_result=he_result)
        
    except Exception as e:
        flash(f'Error computing: {str(e)}', 'error')
        return redirect(url_for('security.security_dashboard'))


@security.route('/disable-homomorphic', methods=['POST'])
@login_required
def disable_homomorphic():
    """Disable Homomorphic Encryption"""
    password = request.form.get('password', '')
    
    if not password:
        flash('Password required.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    if not current_user.check_password(password):
        flash('Invalid password.', 'error')
        return redirect(url_for('security.security_dashboard'))
    
    try:
        EncryptedFileStat.query.filter_by(user_id=current_user.id).delete()
        HomomorphicKey.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        
        flash('Homomorphic encryption disabled.', 'success')
        log_activity('disable_homomorphic', 'user', current_user.id)
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('security.security_dashboard'))


# ==================== API ENDPOINTS ====================

@security.route('/api/status')
@login_required
def api_status():
    """Get security features status"""
    sse_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    he_key = HomomorphicKey.query.filter_by(user_id=current_user.id).first()
    
    return jsonify({
        'sse_enabled': sse_key is not None,
        'he_enabled': he_key is not None,
        'indexed_files': FileSearchIndex.query.filter_by(user_id=current_user.id).count(),
        'encrypted_stats': EncryptedFileStat.query.filter_by(user_id=current_user.id).count(),
        'total_files': File.query.filter_by(user_id=current_user.id, is_deleted=False).count(),
        'developer': 'Dr. Mohammed Tawfik',
        'email': 'kmkhol01@gmail.com'
    })


@security.route('/api/search-preview', methods=['POST'])
@login_required
def api_search_preview():
    """Preview search tokenization (for debugging)"""
    query = request.json.get('query', '')
    
    if not query:
        return jsonify({'error': 'No query provided'})
    
    keywords = SearchableEncryption._tokenize_text(query)
    
    return jsonify({
        'query': query,
        'keywords': list(keywords),
        'keyword_count': len(keywords)
    })


@security.route('/api/algorithms')
def api_algorithms():
    """Get list of cryptographic algorithms used"""
    return jsonify({
        'algorithms': [
            {
                'name': 'AES-256-GCM',
                'type': 'Symmetric Encryption',
                'description': 'Authenticated encryption with 256-bit key',
                'parameters': {
                    'key_size': '256 bits',
                    'nonce_size': '96 bits',
                    'tag_size': '128 bits'
                }
            },
            {
                'name': 'RSA-2048 OAEP',
                'type': 'Asymmetric Encryption',
                'description': 'Hybrid key exchange with optimal padding',
                'parameters': {
                    'key_size': '2048 bits',
                    'padding': 'OAEP',
                    'hash': 'SHA-256'
                }
            },
            {
                'name': 'Paillier Cryptosystem',
                'type': 'Homomorphic Encryption',
                'description': 'Additive homomorphic encryption',
                'parameters': {
                    'key_size': '1024 bits',
                    'operations': ['Addition', 'Scalar Multiplication'],
                    'property': 'E(a)·E(b) = E(a+b)'
                }
            },
            {
                'name': 'SSE (HMAC-SHA256)',
                'type': 'Searchable Encryption',
                'description': 'Privacy-preserving keyword search',
                'parameters': {
                    'token_algorithm': 'HMAC-SHA256',
                    'key_size': '256 bits',
                    'index': 'Encrypted inverted index'
                }
            },
            {
                'name': 'PBKDF2-HMAC-SHA256',
                'type': 'Key Derivation',
                'description': 'Password-based key derivation',
                'parameters': {
                    'iterations': '600,000',
                    'salt_size': '256 bits',
                    'standard': 'OWASP 2024'
                }
            }
        ],
        'developer': {
            'name': 'Dr. Mohammed Tawfik',
            'email': 'kmkhol01@gmail.com'
        }
    })
