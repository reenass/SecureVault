```python
#!/usr/bin/env python3
"""
Secure Cloud Storage Application
Run this file to start the Flask server

Usage:
    python run.py

Environment Variables:
    FLASK_ENV: development, production, or testing (default: development)
    SECRET_KEY: Flask secret key
    MYSQL_HOST: MySQL host (default: localhost)
    MYSQL_USER: MySQL user (default: root)
    MYSQL_PASSWORD: MySQL password
    MYSQL_DB: MySQL database name (default: secure_cloud_storage)
    ADMIN_PASSWORD: Admin account password
"""

import os
from app import create_app

# Get configuration from environment
config_name = os.environ.get('FLASK_ENV', 'development')

# Create application
app = create_app(config_name)

if __name__ == '__main__':
    # Development server settings
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = config_name == 'development'

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║          🔐 Secure Cloud Storage Application 🔐              ║
╠══════════════════════════════════════════════════════════════╣
║  Environment: {config_name:<45} ║
║  Server: http://{host}:{port:<40} ║
║                                                              ║
║  Admin credentials are configured through environment vars.  ║
║                                                              ║
║  Features:                                                   ║
║  • AES-256-GCM Encryption                                    ║
║  • RSA-2048 Hybrid Encryption                                ║
║  • SHA-256 File Integrity Verification                       ║
║  • Secure File Sharing                                       ║
║  • User Authentication & Authorization                       ║
╚══════════════════════════════════════════════════════════════╝
    """)

    # Run the application
    app.run(
        host=host,
        port=port,
        debug=debug
    )
```
