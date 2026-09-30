"""
Enhanced Search Routes for Secure Cloud Storage
================================================
Features:
- Basic filename search (no password required)
- Full-text encrypted search (password required)
- Search filters (date, type, size)
- Fuzzy/partial matching
- Auto-indexing on upload
- Recent searches history
- Search suggestions
- Advanced search operators
"""

import os
import re
import json
from datetime import datetime, timedelta
from functools import wraps
from collections import Counter

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    jsonify, current_app, session
)
from flask_login import login_required, current_user

from .models import (
    db, File, FileSearchIndex, SearchMasterKey, ActivityLog
)
from .crypto import SearchableEncryption, KeyDerivation

# Try to import RecentSearch, fallback if not available
try:
    from .models import RecentSearch
    HAS_RECENT_SEARCH_MODEL = True
except ImportError:
    HAS_RECENT_SEARCH_MODEL = False

# Create blueprint
search_bp = Blueprint('search_enhanced', __name__, url_prefix='/search')


# ==================== HELPER FUNCTIONS ====================

def get_user_search_encryption(user, password):
    """Get user's searchable encryption instance with decrypted master key"""
    search_key = SearchMasterKey.query.filter_by(user_id=user.id).first()
    
    if not search_key:
        return None
    
    if not password:
        return None
    
    try:
        # Decrypt the master key with user's password
        decrypted_key, _, _ = KeyDerivation.decrypt_with_password(
            search_key.encrypted_master_key.encode('utf-8'), password
        )
        return SearchableEncryption(decrypted_key)
    except Exception as e:
        current_app.logger.error(f"Failed to decrypt search key: {e}")
        return None


def create_user_search_key(user, password):
    """Create new search master key for user"""
    sse = SearchableEncryption()  # Generate new master key
    
    # Encrypt master key with user's password
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


def log_activity(action, entity_type, entity_id=None, entity_name=None, details=None):
    """Log user activity"""
    try:
        log = ActivityLog(
            user_id=current_user.id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            entity_name=entity_name,
            details=json.dumps(details) if details else None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string[:255] if request.user_agent else None
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        pass


def save_recent_search(query, results_count):
    """Save search to recent searches history"""
    try:
        # Check if RecentSearch model is available
        if HAS_RECENT_SEARCH_MODEL:
            recent = RecentSearch(
                user_id=current_user.id,
                query=query,
                results_count=results_count
            )
            db.session.add(recent)
            db.session.commit()
        else:
            # Store in session as fallback
            if 'recent_searches' not in session:
                session['recent_searches'] = []
            
            session['recent_searches'].insert(0, {
                'query': query,
                'results': results_count,
                'timestamp': datetime.utcnow().isoformat()
            })
            # Keep only last 10 searches
            session['recent_searches'] = session['recent_searches'][:10]
            session.modified = True
    except Exception as e:
        current_app.logger.warning(f"Failed to save recent search: {e}")
        # Fallback to session storage
        if 'recent_searches' not in session:
            session['recent_searches'] = []
        session['recent_searches'].insert(0, {
            'query': query,
            'results': results_count,
            'timestamp': datetime.utcnow().isoformat()
        })
        session['recent_searches'] = session['recent_searches'][:10]
        session.modified = True


def parse_search_query(query):
    """
    Parse advanced search query with operators
    Supports: AND, OR, NOT, "exact phrase", filetype:ext, date:range
    """
    result = {
        'keywords': [],
        'exact_phrases': [],
        'exclude_keywords': [],
        'file_types': [],
        'date_filter': None,
        'size_filter': None
    }
    
    # Extract exact phrases (in quotes)
    phrases = re.findall(r'"([^"]+)"', query)
    result['exact_phrases'] = phrases
    query = re.sub(r'"[^"]+"', '', query)
    
    # Extract file type filters
    type_matches = re.findall(r'filetype:(\w+)', query, re.IGNORECASE)
    result['file_types'] = [t.lower() for t in type_matches]
    query = re.sub(r'filetype:\w+', '', query, flags=re.IGNORECASE)
    
    # Extract date filters (date:today, date:week, date:month, date:year)
    date_match = re.search(r'date:(\w+)', query, re.IGNORECASE)
    if date_match:
        result['date_filter'] = date_match.group(1).lower()
        query = re.sub(r'date:\w+', '', query, flags=re.IGNORECASE)
    
    # Extract size filters (size:>1mb, size:<100kb)
    size_match = re.search(r'size:([<>])(\d+)(kb|mb|gb)?', query, re.IGNORECASE)
    if size_match:
        operator = size_match.group(1)
        size = int(size_match.group(2))
        unit = (size_match.group(3) or 'kb').lower()
        
        multipliers = {'kb': 1024, 'mb': 1024*1024, 'gb': 1024*1024*1024}
        size_bytes = size * multipliers.get(unit, 1024)
        
        result['size_filter'] = {'operator': operator, 'size': size_bytes}
        query = re.sub(r'size:[<>]\d+\w*', '', query, flags=re.IGNORECASE)
    
    # Handle NOT operator
    not_matches = re.findall(r'-(\w+)', query)
    result['exclude_keywords'] = [w.lower() for w in not_matches]
    query = re.sub(r'-\w+', '', query)
    
    # Remaining words are keywords
    words = query.split()
    for word in words:
        word = word.strip().lower()
        if word and word not in ['and', 'or', 'not'] and len(word) >= 2:
            result['keywords'].append(word)
    
    return result


def match_filename(filename, search_terms):
    """Check if filename matches search terms with fuzzy matching"""
    filename_lower = filename.lower()
    name_without_ext = os.path.splitext(filename_lower)[0]
    
    # Split filename into parts
    name_parts = re.split(r'[-_.\s]', name_without_ext)
    name_parts = [p for p in name_parts if p]
    
    for term in search_terms:
        term_lower = term.lower()
        
        # Exact substring match
        if term_lower in filename_lower:
            return True
        
        # Partial match in name parts
        for part in name_parts:
            if term_lower in part or part in term_lower:
                return True
            
            # Fuzzy match: allow 1 character difference for words > 4 chars
            if len(term_lower) > 4 and len(part) > 4:
                if levenshtein_distance(term_lower, part) <= 1:
                    return True
    
    return False


def levenshtein_distance(s1, s2):
    """Calculate Levenshtein distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def apply_filters(files_query, parsed_query):
    """Apply search filters to query"""
    # File type filter
    if parsed_query['file_types']:
        files_query = files_query.filter(
            File.file_extension.in_(parsed_query['file_types'])
        )
    
    # Date filter
    if parsed_query['date_filter']:
        now = datetime.utcnow()
        date_ranges = {
            'today': now - timedelta(days=1),
            'week': now - timedelta(weeks=1),
            'month': now - timedelta(days=30),
            'year': now - timedelta(days=365)
        }
        if parsed_query['date_filter'] in date_ranges:
            files_query = files_query.filter(
                File.created_at >= date_ranges[parsed_query['date_filter']]
            )
    
    # Size filter
    if parsed_query['size_filter']:
        sf = parsed_query['size_filter']
        if sf['operator'] == '>':
            files_query = files_query.filter(File.original_size > sf['size'])
        else:
            files_query = files_query.filter(File.original_size < sf['size'])
    
    return files_query


# ==================== ROUTES ====================

@search_bp.route('/')
@login_required
def search_page():
    """Main search page"""
    # Get search statistics
    total_indexed = FileSearchIndex.query.filter_by(
        user_id=current_user.id, is_indexed=True
    ).count()
    
    total_files = File.query.filter_by(
        user_id=current_user.id, is_deleted=False
    ).count()
    
    # Check if search is enabled
    search_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    search_enabled = search_key is not None
    
    # Get recent searches from session
    recent_searches = session.get('recent_searches', [])[:5]
    
    return render_template('search_enhanced.html',
                         search_enabled=search_enabled,
                         total_indexed=total_indexed,
                         total_files=total_files,
                         recent_searches=recent_searches)


@search_bp.route('/quick', methods=['GET'])
@login_required
def quick_search():
    """
    Quick filename search - no password required
    Searches filenames only, not encrypted content
    """
    query = request.args.get('q', '').strip()
    
    if not query or len(query) < 2:
        return jsonify({'results': [], 'query': query})
    
    # Parse search query
    parsed = parse_search_query(query)
    all_terms = parsed['keywords'] + parsed['exact_phrases']
    
    if not all_terms:
        return jsonify({'results': [], 'query': query})
    
    # Build base query
    files_query = File.query.filter_by(
        user_id=current_user.id,
        is_deleted=False
    )
    
    # Apply filters
    files_query = apply_filters(files_query, parsed)
    
    # Get all matching files
    all_files = files_query.all()
    
    # Filter by filename match
    results = []
    for f in all_files:
        if match_filename(f.original_filename, all_terms):
            # Check exclusions
            excluded = False
            for ex in parsed['exclude_keywords']:
                if ex in f.original_filename.lower():
                    excluded = True
                    break
            
            if not excluded:
                results.append({
                    'uuid': f.uuid,
                    'filename': f.original_filename,
                    'extension': f.file_extension,
                    'size': f.format_size(),
                    'date': f.created_at.strftime('%b %d, %Y'),
                    'match_type': 'filename'
                })
    
    # Sort by relevance (exact match first)
    results.sort(key=lambda x: (
        query.lower() not in x['filename'].lower(),
        x['filename'].lower()
    ))
    
    # Limit results
    results = results[:20]
    
    return jsonify({
        'results': results,
        'query': query,
        'total': len(results)
    })


@search_bp.route('/full', methods=['GET', 'POST'])
@login_required
def full_search():
    """
    Full-text encrypted search
    Searches both filenames and encrypted file content
    Requires password to generate search tokens
    """
    query = request.args.get('q', '') or request.form.get('query', '')
    password = request.form.get('password', '')
    search_type = request.form.get('search_type', 'all')  # all, filename, content
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    if not query:
        total_indexed = FileSearchIndex.query.filter_by(
            user_id=current_user.id, is_indexed=True
        ).count()
        total_files = File.query.filter_by(
            user_id=current_user.id, is_deleted=False
        ).count()
        search_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
        recent_searches = session.get('recent_searches', [])[:5]
        return render_template('search_enhanced.html',
                             results=[],
                             query='',
                             search_enabled=search_key is not None,
                             total_indexed=total_indexed,
                             total_files=total_files,
                             recent_searches=recent_searches)
    
    # Parse search query
    parsed = parse_search_query(query)
    all_terms = parsed['keywords'] + parsed['exact_phrases']
    
    # Check if search key exists
    search_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    
    # If no password provided, show password prompt
    if request.method == 'GET' or not password:
        # First do a quick filename search
        files_query = File.query.filter_by(
            user_id=current_user.id,
            is_deleted=False
        )
        files_query = apply_filters(files_query, parsed)
        all_files = files_query.all()
        
        filename_results = []
        for f in all_files:
            if match_filename(f.original_filename, all_terms):
                filename_results.append({
                    'file': f,
                    'score': 100.0,
                    'match_type': 'filename',
                    'keywords_matched': len(all_terms)
                })
        
        return render_template('search_results_enhanced.html',
                             results=filename_results,
                             query=query,
                             total_results=len(filename_results),
                             need_password=bool(search_key),
                             search_type=search_type,
                             has_encrypted_search=bool(search_key),
                             page=page,
                             per_page=per_page,
                             total_pages=(len(filename_results) + per_page - 1) // per_page if filename_results else 0,
                             parsed_query=parsed)
    
    # Password provided - do full encrypted search
    if not search_key:
        flash('Search indexing not enabled. Enable it in settings first.', 'warning')
        return redirect(url_for('search_enhanced.search_page'))
    
    # Get search encryption instance
    sse = get_user_search_encryption(current_user, password)
    
    if not sse:
        flash('Invalid password. Please try again.', 'error')
        return render_template('search_results_enhanced.html',
                             results=[],
                             query=query,
                             total_results=0,
                             need_password=True,
                             has_encrypted_search=True,
                             password_error=True,
                             search_type=search_type,
                             page=1,
                             per_page=per_page,
                             total_pages=0,
                             parsed_query=parsed)
    
    # Get all indexed files
    indexes = FileSearchIndex.query.filter_by(
        user_id=current_user.id,
        is_indexed=True
    ).all()
    
    # Build index data
    index_data = []
    for idx in indexes:
        if idx.file and not idx.file.is_deleted:
            index_data.append({
                'file_id': idx.file.uuid,
                'tokens': idx.get_tokens()
            })
    
    # Perform encrypted search
    if all_terms:
        search_results = sse.search_with_ranking(query, index_data)
    else:
        search_results = []
    
    # Get file details and combine with filename matches
    result_files = []
    seen_uuids = set()
    
    # Add encrypted content matches
    for file_uuid, score in search_results:
        file_record = File.query.filter_by(
            uuid=file_uuid,
            user_id=current_user.id
        ).first()
        
        if file_record and not file_record.is_deleted:
            seen_uuids.add(file_uuid)
            result_files.append({
                'file': file_record,
                'score': round(score * 100, 1),
                'match_type': 'content',
                'keywords_matched': int(score * len(all_terms)) if all_terms else 0
            })
    
    # Add filename matches that weren't in content results
    if search_type in ['all', 'filename']:
        files_query = File.query.filter_by(
            user_id=current_user.id,
            is_deleted=False
        )
        files_query = apply_filters(files_query, parsed)
        all_files = files_query.all()
        
        for f in all_files:
            if f.uuid not in seen_uuids and match_filename(f.original_filename, all_terms):
                result_files.append({
                    'file': f,
                    'score': 75.0,  # Filename match score
                    'match_type': 'filename',
                    'keywords_matched': len(all_terms)
                })
    
    # Sort by score
    result_files.sort(key=lambda x: x['score'], reverse=True)
    
    # Pagination
    total_results = len(result_files)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_results = result_files[start:end]
    
    # Save to recent searches
    save_recent_search(query, total_results)
    
    # Log activity
    log_activity('search', 'file', details={
        'query': query,
        'results': total_results,
        'search_type': search_type
    })
    
    return render_template('search_results_enhanced.html',
                         results=paginated_results,
                         query=query,
                         total_results=total_results,
                         need_password=False,
                         search_type=search_type,
                         page=page,
                         per_page=per_page,
                         total_pages=(total_results + per_page - 1) // per_page,
                         parsed_query=parsed)


@search_bp.route('/suggestions', methods=['GET'])
@login_required
def search_suggestions():
    """Get search suggestions based on filenames"""
    prefix = request.args.get('q', '').strip().lower()
    
    if len(prefix) < 2:
        return jsonify({'suggestions': []})
    
    # Get user's files
    files = File.query.filter_by(
        user_id=current_user.id,
        is_deleted=False
    ).all()
    
    # Extract unique words from filenames
    word_counts = Counter()
    for f in files:
        name = os.path.splitext(f.original_filename)[0].lower()
        words = re.split(r'[-_.\s]', name)
        for word in words:
            if word and len(word) >= 2:
                word_counts[word] += 1
    
    # Filter by prefix and sort by frequency
    suggestions = [
        word for word in word_counts.keys()
        if word.startswith(prefix)
    ]
    suggestions.sort(key=lambda w: word_counts[w], reverse=True)
    
    return jsonify({'suggestions': suggestions[:10]})


@search_bp.route('/index-file/<file_uuid>', methods=['POST'])
@login_required
def index_single_file(file_uuid):
    """Index a single file for encrypted search"""
    from .crypto import HybridEncryption
    
    password = request.form.get('password', '')
    
    file_record = File.query.filter_by(
        uuid=file_uuid,
        user_id=current_user.id
    ).first_or_404()
    
    if not password:
        return jsonify({
            'success': False,
            'error': 'Password required for indexing'
        }), 400
    
    # Get or create search encryption
    search_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    if search_key:
        sse = get_user_search_encryption(current_user, password)
    else:
        sse = create_user_search_key(current_user, password)
    
    if not sse:
        return jsonify({
            'success': False,
            'error': 'Invalid password'
        }), 401
    
    try:
        # Read and decrypt file content
        with open(file_record.storage_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt based on encryption mode
        if file_record.encryption_mode == 'password':
            file_password = request.form.get('file_password', password)
            plaintext, _, _ = KeyDerivation.decrypt_with_password(
                encrypted_data, file_password
            )
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
        
        log_activity('index_file', 'file', file_record.id,
                    file_record.original_filename,
                    details={'keywords': keyword_count})
        
        return jsonify({
            'success': True,
            'keywords': keyword_count,
            'message': f'File indexed with {keyword_count} keywords'
        })
        
    except Exception as e:
        current_app.logger.error(f"Error indexing file: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


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
    return index_data['keyword_count']


@search_bp.route('/reindex-all', methods=['POST'])
@login_required
def reindex_all_files():
    """Reindex all user's files"""
    from .crypto import HybridEncryption
    
    password = request.form.get('password', '')
    
    if not password:
        return jsonify({
            'success': False,
            'error': 'Password required'
        }), 400
    
    # Get or create search encryption
    search_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    if search_key:
        sse = get_user_search_encryption(current_user, password)
    else:
        sse = create_user_search_key(current_user, password)
    
    if not sse:
        return jsonify({
            'success': False,
            'error': 'Invalid password'
        }), 401
    
    # Get all user's files
    files = File.query.filter_by(
        user_id=current_user.id,
        is_deleted=False
    ).all()
    
    indexed_count = 0
    error_count = 0
    
    for file_record in files:
        try:
            with open(file_record.storage_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Only process hybrid-encrypted files for bulk reindex
            if file_record.encryption_mode == 'password':
                continue
            
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
            
        except Exception as e:
            current_app.logger.error(f"Error indexing {file_record.uuid}: {e}")
            error_count += 1
    
    log_activity('reindex_all', 'file', details={
        'indexed': indexed_count,
        'errors': error_count
    })
    
    return jsonify({
        'success': True,
        'indexed': indexed_count,
        'errors': error_count,
        'message': f'Indexed {indexed_count} files ({error_count} errors)'
    })


@search_bp.route('/stats', methods=['GET'])
@login_required
def search_stats():
    """Get search statistics for current user"""
    # Total files
    total_files = File.query.filter_by(
        user_id=current_user.id,
        is_deleted=False
    ).count()
    
    # Indexed files
    indexed_files = FileSearchIndex.query.filter_by(
        user_id=current_user.id,
        is_indexed=True
    ).count()
    
    # Total keywords
    total_keywords = db.session.query(
        db.func.sum(FileSearchIndex.keyword_count)
    ).filter_by(
        user_id=current_user.id,
        is_indexed=True
    ).scalar() or 0
    
    # Search key status
    search_key = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    
    # Recent searches count
    recent_searches = session.get('recent_searches', [])
    
    return jsonify({
        'total_files': total_files,
        'indexed_files': indexed_files,
        'total_keywords': total_keywords,
        'search_enabled': search_key is not None,
        'recent_searches_count': len(recent_searches),
        'indexing_progress': round(
            (indexed_files / total_files * 100) if total_files > 0 else 0, 1
        )
    })


@search_bp.route('/enable', methods=['POST'])
@login_required
def enable_search():
    """Enable search indexing for user"""
    password = request.form.get('password', '')
    
    if not password:
        return jsonify({
            'success': False,
            'error': 'Password required'
        }), 400
    
    # Check if already enabled
    existing = SearchMasterKey.query.filter_by(user_id=current_user.id).first()
    if existing:
        return jsonify({
            'success': False,
            'error': 'Search already enabled'
        }), 400
    
    try:
        sse = create_user_search_key(current_user, password)
        
        log_activity('enable_search', 'user', current_user.id)
        
        return jsonify({
            'success': True,
            'message': 'Search indexing enabled successfully'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@search_bp.route('/clear-history', methods=['POST'])
@login_required
def clear_search_history():
    """Clear recent search history"""
    session.pop('recent_searches', None)
    return jsonify({'success': True})
