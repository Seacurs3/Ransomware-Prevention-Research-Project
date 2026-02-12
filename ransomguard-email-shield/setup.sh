#!/bin/bash

# RansomGuard Email Shield - Automated Setup Script
# This script automates the installation process

echo "============================================================"
echo "  RansomGuard Email Shield - Automated Setup"
echo "  AI-Powered Pre-Execution Ransomware Detection"
echo "============================================================"
echo ""

# Check Python version
echo "[1/5] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✓ Python $PYTHON_VERSION found"
echo ""

# Create virtual environment
echo "[2/5] Creating virtual environment..."
if [ -d "venv" ]; then
    echo "⚠️  Virtual environment already exists. Skipping..."
else
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi
echo ""

# Activate virtual environment
echo "[3/5] Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Install dependencies
echo "[4/5] Installing dependencies..."
echo "This may take a few minutes..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt
if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "❌ Error installing dependencies"
    echo "Try running manually: pip install -r requirements.txt"
    exit 1
fi
echo ""

# Train ML model
echo "[5/5] Training machine learning model..."
python train_model.py
if [ $? -eq 0 ]; then
    echo "✓ Model training complete"
else
    echo "❌ Error training model"
    exit 1
fi
echo ""

# Create test files
echo "Creating test files for demonstration..."
python create_test_files.py
echo ""

echo "============================================================"
echo "  ✓ Setup Complete!"
echo "============================================================"
echo ""
echo "To start the application:"
echo "  1. Activate virtual environment (if not already active):"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run the application:"
echo "     python app.py"
echo ""
echo "  3. Open your browser to:"
echo "     http://localhost:5000"
echo ""
echo "Need help? Read the documentation:"
echo "  - README.md - Full documentation"
echo "  - docs/QUICKSTART.md - Quick start guide"
echo "  - docs/ARCHITECTURE.md - System architecture"
echo ""
echo "For NC Innovation Grant demonstration:"
echo "  - Test files created in: ./test_files/"
echo "  - Send these as email attachments to test the system"
echo ""
echo "============================================================"
