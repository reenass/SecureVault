#!/bin/bash

echo "=================================================="
echo "  🔒 SECURE CLOUD STORAGE - SETUP & RUN"
echo "=================================================="
echo ""

# Check Python version
echo "1️⃣  Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found! Please install Python 3.8+"
    exit 1
fi
echo "✅ Python found: $(python3 --version)"
echo ""

# Create virtual environment
echo "2️⃣  Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi
echo ""

# Activate virtual environment
echo "3️⃣  Activating virtual environment..."
source venv/bin/activate || . venv/Scripts/activate
echo "✅ Virtual environment activated"
echo ""

# Install dependencies
echo "4️⃣  Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
echo "✅ Dependencies installed"
echo ""

# Create necessary directories
echo "5️⃣  Creating directories..."
mkdir -p uploads keys instance migrations
echo "✅ Directories created"
echo ""

# Initialize database
echo "6️⃣  Initializing database..."
python3 << END
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
    print("✅ Database initialized")
END
echo ""

echo "=================================================="
echo "  ✅ SETUP COMPLETE!"
echo "=================================================="
echo ""
echo "🚀 To start the application, run:"
echo "   ./start.sh"
echo ""
echo "Or manually:"
echo "   source venv/bin/activate"
echo "   python run.py"
echo ""
echo "📱 Then open: http://localhost:5000"
echo ""
