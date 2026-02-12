"""
RansomGuard Email Shield - Configuration
"""

import os

class Config:
    """Application configuration"""
    
    # Application settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = True
    
    # Directories
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    QUARANTINE_DIR = os.path.join(BASE_DIR, 'quarantine')
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    MODELS_DIR = os.path.join(BASE_DIR, 'models')
    
    # Email settings
    DEFAULT_IMAP_SERVER = 'imap.gmail.com'
    DEFAULT_IMAP_PORT = 993
    
    # Detection thresholds
    BLOCK_THRESHOLD = 0.9      # Risk score >= 0.9 = BLOCK
    QUARANTINE_THRESHOLD = 0.7  # Risk score >= 0.7 = QUARANTINE
    WARN_THRESHOLD = 0.5        # Risk score >= 0.5 = WARN
    
    # File analysis settings
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
    HIGH_ENTROPY_THRESHOLD = 7.0
    SUSPICIOUS_EXTENSIONS = [
        '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
        '.vbs', '.js', '.jar', '.zip', '.rar', '.7z',
        '.docm', '.xlsm', '.pptm',
        '.pdf.exe', '.doc.exe'
    ]
    
    # Machine Learning
    ML_MODEL_PATH = os.path.join(MODELS_DIR, 'ransomware_classifier.pkl')
    ML_SCALER_PATH = os.path.join(MODELS_DIR, 'feature_scaler.pkl')
    
    # Logging
    LOG_FILE = os.path.join(LOGS_DIR, 'ransomguard.log')
    DECISION_LOG = os.path.join(LOGS_DIR, 'decisions.jsonl')
    
    @staticmethod
    def init_app():
        """Initialize application directories"""
        for directory in [Config.QUARANTINE_DIR, Config.LOGS_DIR, Config.MODELS_DIR]:
            os.makedirs(directory, exist_ok=True)
