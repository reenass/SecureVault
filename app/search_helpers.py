"""
Search Helpers for Secure Cloud Storage
========================================
Provides auto-indexing and search utilities
"""

import os
from datetime import datetime
from flask import current_app
from flask_login import current_user

from .models import db, File, FileSearchIndex, SearchMasterKey
from .crypto import SearchableEncryption, KeyDerivation, HybridEncryption


def auto_index_file(file_record, plaintext_content, password=None, sse=None):
    """
    Automatically index a file after upload
    
    Args:
        file_record: The File model instance
        plaintext_content: The decrypted file content (bytes or string)
        password: User's password (optional if sse provided)
        sse: SearchableEncryption instance (optional if password provided)
    
    Returns:
        int: Number of keywords indexed, or 0 if indexing failed
    """
    try:
        # Check if user has search enabled
        search_key = SearchMasterKey.query.filter_by(user_id=file_record.user_id).first()
        
        if not search_key:
            # User hasn't enabled search, skip indexing
            return 0
        
        # Get or create SSE instance
        if not sse and password:
            try:
                decrypted_key, _, _ = KeyDerivation.decrypt_with_password(
                    search_key.encrypted_master_key.encode('utf-8'), password
                )
                sse = SearchableEncryption(decrypted_key)
            except Exception as e:
                current_app.logger.warning(f"Failed to decrypt search key for auto-indexing: {e}")
                return 0
        
        if not sse:
            return 0
        
        # Convert content to string if bytes
        if isinstance(plaintext_content, bytes):
            try:
                content = plaintext_content.decode('utf-8')
            except UnicodeDecodeError:
                content = ''  # Binary file - index filename only
        else:
            content = plaintext_content or ''
        
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
            existing_index.is_indexed = True
        else:
            search_index = FileSearchIndex(
                file_id=file_record.id,
                user_id=file_record.user_id
            )
            search_index.set_tokens(index_data['tokens'])
            search_index.keyword_count = index_data['keyword_count']
            db.session.add(search_index)
        
        db.session.commit()
        
        current_app.logger.info(
            f"Auto-indexed file {file_record.uuid} with {index_data['keyword_count']} keywords"
        )
        
        return index_data['keyword_count']
        
    except Exception as e:
        current_app.logger.error(f"Auto-indexing failed for {file_record.uuid}: {e}")
        return 0


def get_indexable_extensions():
    """Return list of file extensions that can be indexed for full-text search"""
    return {
        # Text files
        '.txt', '.md', '.markdown', '.rst', '.text',
        # Documents
        '.html', '.htm', '.xml', '.json', '.yaml', '.yml',
        # Code files
        '.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.hpp',
        '.cs', '.go', '.rs', '.rb', '.php', '.swift', '.kt',
        '.sql', '.sh', '.bash', '.ps1', '.bat', '.cmd',
        # Config files
        '.ini', '.cfg', '.conf', '.config', '.env',
        # Data files
        '.csv', '.tsv', '.log',
        # Web files
        '.css', '.scss', '.sass', '.less',
        '.vue', '.jsx', '.tsx', '.svelte'
    }


def is_indexable(filename):
    """Check if a file can be indexed based on its extension"""
    ext = os.path.splitext(filename.lower())[1]
    return ext in get_indexable_extensions()


def get_search_stats(user_id):
    """Get search statistics for a user"""
    total_files = File.query.filter_by(
        user_id=user_id,
        is_deleted=False
    ).count()
    
    indexed_files = FileSearchIndex.query.filter_by(
        user_id=user_id,
        is_indexed=True
    ).count()
    
    total_keywords = db.session.query(
        db.func.sum(FileSearchIndex.keyword_count)
    ).filter_by(
        user_id=user_id,
        is_indexed=True
    ).scalar() or 0
    
    search_enabled = SearchMasterKey.query.filter_by(user_id=user_id).first() is not None
    
    return {
        'total_files': total_files,
        'indexed_files': indexed_files,
        'total_keywords': total_keywords,
        'search_enabled': search_enabled,
        'indexing_progress': round(
            (indexed_files / total_files * 100) if total_files > 0 else 0, 1
        )
    }


def reindex_user_files(user, password, skip_password_encrypted=True):
    """
    Reindex all files for a user
    
    Args:
        user: User model instance
        password: User's account password
        skip_password_encrypted: Whether to skip password-encrypted files
    
    Returns:
        dict: Statistics about the reindexing process
    """
    # Get or create search encryption
    search_key = SearchMasterKey.query.filter_by(user_id=user.id).first()
    
    if not search_key:
        # Create new search key
        sse = SearchableEncryption()
        encrypted_key = KeyDerivation.encrypt_with_password(
            sse.master_key, password, {'type': 'search_master_key'}
        )
        search_key = SearchMasterKey(
            user_id=user.id,
            encrypted_master_key=encrypted_key.decode('utf-8')
        )
        db.session.add(search_key)
        db.session.commit()
    else:
        try:
            decrypted_key, _, _ = KeyDerivation.decrypt_with_password(
                search_key.encrypted_master_key.encode('utf-8'), password
            )
            sse = SearchableEncryption(decrypted_key)
        except Exception:
            return {'success': False, 'error': 'Invalid password'}
    
    # Get all user's files
    files = File.query.filter_by(
        user_id=user.id,
        is_deleted=False
    ).all()
    
    stats = {
        'success': True,
        'total': len(files),
        'indexed': 0,
        'skipped': 0,
        'errors': 0
    }
    
    for file_record in files:
        try:
            # Skip password-encrypted files if requested
            if skip_password_encrypted and file_record.encryption_mode == 'password':
                stats['skipped'] += 1
                continue
            
            # Read encrypted file
            with open(file_record.storage_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt
            if file_record.encryption_mode == 'password':
                # This should only happen if skip_password_encrypted is False
                stats['skipped'] += 1
                continue
            else:
                private_key_encrypted = user.private_key_encrypted
                private_key, _, _ = KeyDerivation.decrypt_with_password(
                    private_key_encrypted.encode('utf-8'), password
                )
                plaintext, _, _ = HybridEncryption.decrypt(encrypted_data, private_key)
            
            # Index the file
            keywords = auto_index_file(file_record, plaintext, sse=sse)
            
            if keywords > 0:
                stats['indexed'] += 1
            else:
                stats['skipped'] += 1
                
        except Exception as e:
            current_app.logger.error(f"Error reindexing {file_record.uuid}: {e}")
            stats['errors'] += 1
    
    return stats
