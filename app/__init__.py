```python
"""
Secure Cloud Storage Application Factory
Includes:
- File encryption (AES-256-GCM, RSA-2048 Hybrid)
- Searchable Encryption for keyword search
- Homomorphic Encryption for privacy-preserving computations
"""

import os
from flask import Flask
from flask_wtf.csrf import CSRFProtect

from .models import db, init_db
from .routes import main, auth, files, admin, search, homomorphic, login_manager
from .security_routes import security
from .search_routes import search_bp as search_enhanced


csrf = CSRFProtect()


def create_app(config_name='default'):
    """Application factory pattern"""

    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')

    # Load configuration
    from config import config
    app.config.from_object(config[config_name])

    # Ensure directories exist
    os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'), exist_ok=True)
    os.makedirs(app.config.get('ENCRYPTED_FOLDER', 'encrypted_files'), exist_ok=True)
    os.makedirs(app.config.get('KEYS_FOLDER', 'keys'), exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)

    # Register blueprints
    app.register_blueprint(main)
    app.register_blueprint(auth, url_prefix='/auth')
    app.register_blueprint(files, url_prefix='/files')
    app.register_blueprint(admin, url_prefix='/admin')
    app.register_blueprint(search, url_prefix='/search-legacy')
    app.register_blueprint(search_enhanced)  # Enhanced search at /search
    app.register_blueprint(homomorphic, url_prefix='/homomorphic')
    app.register_blueprint(security)  # Unified security dashboard

    # Create database tables
    with app.app_context():
        db.create_all()

        # Create default admin if not exists
        from .models import User
        admin_user = User.query.filter_by(username='admin').first()

        if not admin_user:
            from .crypto import RSAKeyPair, KeyDerivation

            # Get admin password from environment variable.
            # If not provided, generate a random password locally.
            admin_password = os.environ.get('ADMIN_PASSWORD')

            if not admin_password:
                admin_password = os.urandom(16).hex()

            admin_user = User(
                username='admin',
                email='admin@securecloud.local',
                is_admin=True,
                first_name='System',
                last_name='Administrator'
            )

            admin_user.set_password(admin_password)

            # Generate RSA keys for admin
            private_pem, public_pem = RSAKeyPair.generate_key_pair()

            encrypted_private = KeyDerivation.encrypt_with_password(
                private_pem,
                admin_password,
                {'type': 'rsa_private_key'}
            )

            admin_user.public_key = public_pem.decode('utf-8')
            admin_user.private_key_encrypted = encrypted_private.decode('utf-8')

            from datetime import datetime
            admin_user.key_generated_at = datetime.utcnow()

            db.session.add(admin_user)
            db.session.commit()

            print("Default admin user created.")
            print(f"Admin username: admin")
            print(f"Admin password: {admin_password}")

    # Template context processors
    @app.context_processor
    def utility_processor():
        def format_bytes(size):
            """Format bytes to human readable"""
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} PB"

        def format_datetime(dt):
            """Format datetime"""
            if dt:
                return dt.strftime('%Y-%m-%d %H:%M')
            return ''

        return dict(format_bytes=format_bytes, format_datetime=format_datetime)

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>404 - Not Found</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1>404</h1>
            <p>Page not found</p>
            <a href="/">Go Home</a>
        </body>
        </html>
        """), 404

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>403 - Forbidden</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1>403</h1>
            <p>Access denied</p>
            <a href="/">Go Home</a>
        </body>
        </html>
        """), 403

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>500 - Server Error</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1>500</h1>
            <p>Internal server error</p>
            <a href="/">Go Home</a>
        </body>
        </html>
        """), 500

    return app


from flask import render_template_string
```
