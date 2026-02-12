@echo off
REM RansomGuard Email Shield - Windows Setup Script

echo ============================================================
echo   RansomGuard Email Shield - Automated Setup
echo   AI-Powered Pre-Execution Ransomware Detection
echo ============================================================
echo.

REM Check Python installation
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found. Please install Python 3.8 or higher.
    pause
    exit /b 1
)
echo Python found
echo.

REM Create virtual environment
echo [2/5] Creating virtual environment...
if exist "venv\" (
    echo Virtual environment already exists. Skipping...
) else (
    python -m venv venv
    echo Virtual environment created
)
echo.

REM Activate virtual environment
echo [3/5] Activating virtual environment...
call venv\Scripts\activate.bat
echo Virtual environment activated
echo.

REM Install dependencies
echo [4/5] Installing dependencies...
echo This may take a few minutes...
python -m pip install --upgrade pip >nul 2>&1
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo Error installing dependencies
    echo Try running manually: pip install -r requirements.txt
    pause
    exit /b 1
)
echo Dependencies installed successfully
echo.

REM Train ML model
echo [5/5] Training machine learning model...
python train_model.py
if errorlevel 1 (
    echo Error training model
    pause
    exit /b 1
)
echo Model training complete
echo.

REM Create test files
echo Creating test files for demonstration...
python create_test_files.py
echo.

echo ============================================================
echo   Setup Complete!
echo ============================================================
echo.
echo To start the application:
echo   1. Activate virtual environment:
echo      venv\Scripts\activate.bat
echo.
echo   2. Run the application:
echo      python app.py
echo.
echo   3. Open your browser to:
echo      http://localhost:5000
echo.
echo Need help? Read the documentation:
echo   - README.md - Full documentation
echo   - docs\QUICKSTART.md - Quick start guide
echo   - docs\ARCHITECTURE.md - System architecture
echo.
echo ============================================================
pause
