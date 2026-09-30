#!/bin/bash

echo "🚀 Starting Secure Cloud Storage..."
echo ""

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate || . venv/Scripts/activate
    echo "✅ Virtual environment activated"
else
    echo "❌ Virtual environment not found!"
    echo "Please run: ./setup.sh first"
    exit 1
fi

# Check if database exists
if [ ! -f "instance/storage.db" ]; then
    echo "⚠️  Database not found. Creating..."
    python3 << END
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
    print("✅ Database created")
END
fi

echo ""
echo "=================================================="
echo "  🔒 SECURE CLOUD STORAGE"
echo "  Running on: http://localhost:5000"
echo "=================================================="
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Run the application
python run.py
