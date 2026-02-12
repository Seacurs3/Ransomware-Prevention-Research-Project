# RansomGuard Email Shield - System Architecture

## Overview

RansomGuard Email Shield is a **pre-execution ransomware detection system** that analyzes email attachments using static analysis and machine learning before they can execute on target systems.

---

## System Components

### 1. Email Connector (`modules/email_connector.py`)

**Purpose**: Establish secure connection to email servers and fetch emails with attachments.

**Features**:
- IMAP/SSL connection support
- Multi-provider compatibility (Gmail, Outlook, Exchange)
- Unread email filtering
- Attachment detection
- Connection state management

**Key Methods**:
```python
connect()                  # Establish IMAP connection
fetch_unread_emails()      # Get emails with attachments
disconnect()               # Close connection safely
```

---

### 2. Attachment Extractor (`modules/attachment_extractor.py`)

**Purpose**: Safely extract and manage email attachments for analysis.

**Features**:
- Safe file extraction from email MIME parts
- Filename sanitization (prevent path traversal)
- Hash calculation (MD5, SHA256)
- Suspicious extension detection
- Quarantine management

**Key Methods**:
```python
extract_attachments()      # Extract all attachments from email
is_suspicious_extension()  # Check for dangerous file types
cleanup_old_files()        # Maintain quarantine directory
```

**Suspicious Extensions Detected**:
- Executables: `.exe`, `.scr`, `.bat`, `.com`, `.vbs`
- Archives: `.zip`, `.rar`, `.7z`
- Office Macros: `.docm`, `.xlsm`, `.pptm`
- Double Extensions: `.pdf.exe`, `.doc.exe`

---

### 3. Static Analyzer (`modules/static_analyzer.py`)

**Purpose**: Perform comprehensive static analysis without executing files.

**Analysis Features**:

#### Basic File Analysis
- File size, type, extension
- MIME type detection
- Hash computation (MD5, SHA256)

#### Entropy Analysis
- Calculate Shannon entropy (0-8 scale)
- High entropy indicates encryption/packing
- Threshold: 7.0+ is suspicious

#### PE File Analysis (Windows Executables)
- Section count and names
- Import table analysis
- Packing detection
- Suspicious API extraction

**Suspicious APIs Monitored**:
```
Encryption:    CryptEncrypt, CryptDecrypt, CryptGenKey
File Ops:      CreateFile, WriteFile, DeleteFile
Registry:      RegSetValue, RegDeleteKey
Memory:        VirtualAlloc, VirtualProtect
Injection:     CreateRemoteThread, WriteProcessMemory
Network:       InternetOpen, HttpSendRequest
```

#### String Analysis
- Extract ASCII strings
- Search for ransomware keywords
- Detect ransom notes

**Ransomware Keywords**:
- encrypt, decrypt, ransom, bitcoin, wallet
- payment, unlock, restore, recover, key

**Key Methods**:
```python
analyze_file()             # Comprehensive file analysis
_calculate_entropy()       # Shannon entropy calculation
_analyze_pe_file()         # Windows executable analysis
_detect_packing()          # Packer detection
_extract_suspicious_apis() # Dangerous API enumeration
```

---

### 4. ML Classifier (`modules/ml_classifier.py`)

**Purpose**: Machine learning-based ransomware classification.

**Model Details**:
- **Algorithm**: Random Forest Classifier
- **Features**: 13 static analysis features
- **Training Data**: 250 synthetic samples
  - 120 ransomware samples
  - 130 benign samples
- **Validation**: 5-fold cross-validation
- **Accuracy**: ~95% on test data

**13 Features Used**:
1. File size
2. Entropy
3. Number of PE sections
4. Number of imports
5. Is packed (boolean)
6. Is DLL (boolean)
7. Number of suspicious APIs
8. Is executable (boolean)
9. Is Office macro (boolean)
10. Is archive (boolean)
11. High entropy flag (boolean)
12. Number of suspicious strings
13. Maximum section entropy

**Feature Engineering**:
```python
prepare_features()  # Convert analysis to ML feature vector
```

**Model Training**:
```python
train()            # Train Random Forest model
predict()          # Classify file as ransomware/benign
save_model()       # Persist trained model
load_model()       # Load pre-trained model
```

**Output**:
```python
{
    'is_ransomware': bool,
    'confidence': float,           # Max probability (0-1)
    'ransomware_probability': float,
    'benign_probability': float
}
```

---

### 5. Decision Engine (`modules/decision_engine.py`)

**Purpose**: Make final decisions based on multi-factor risk assessment.

**Risk Scoring Formula**:

```
Risk Score (0-1) = 
    ML Probability        × 0.35  (35%)
  + Entropy Score         × 0.15  (15%)
  + Packing Detection     × 0.15  (15%)
  + Suspicious APIs       × 0.15  (15%)
  + Extension Risk        × 0.10  (10%)
  + Suspicious Strings    × 0.05  (5%)
  + File Size Anomaly     × 0.05  (5%)
```

**Decision Thresholds**:

| Risk Score | Action | Description |
|------------|--------|-------------|
| ≥ 0.90 | **BLOCK** | High confidence threat |
| 0.70 - 0.89 | **QUARANTINE** | Suspicious, needs review |
| 0.50 - 0.69 | **WARN** | Potentially suspicious |
| < 0.50 | **ALLOW** | Appears safe |

**Critical Indicators** (Override normal thresholds):
- Entropy > 7.8 (extremely high)
- Packed + 8+ suspicious APIs
- ML confidence > 95%

**Key Methods**:
```python
evaluate()                 # Make decision on file
_calculate_risk_score()    # Compute multi-factor risk
_decide_action()           # Determine action based on risk
get_statistics()           # Return detection stats
export_decisions()         # Export audit trail
```

---

### 6. Web Dashboard (Flask Application)

**Purpose**: User interface for system control and monitoring.

**Frontend Components**:
- `templates/dashboard.html` - Main HTML interface
- `static/css/dashboard.css` - Styling
- `static/js/dashboard.js` - Interactivity

**Backend API Endpoints**:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Dashboard homepage |
| `/api/connect` | POST | Connect to email server |
| `/api/disconnect` | POST | Disconnect from server |
| `/api/scan` | POST | Scan emails for threats |
| `/api/stats` | GET | Get detection statistics |
| `/api/recent-decisions` | GET | Get recent decisions |
| `/api/export-decisions` | GET | Export results to JSON |
| `/api/status` | GET | System status |
| `/api/health` | GET | Health check |

**Dashboard Features**:
- Real-time statistics display
- Email server connection management
- Live scanning results
- Detailed threat analysis
- Export functionality
- Visual risk indicators

---

## Data Flow

```
1. USER ACTION
   ↓
   User clicks "Scan Emails"
   ↓

2. EMAIL FETCHING
   ↓
   EmailConnector.fetch_unread_emails()
   ↓
   Returns list of emails with attachments
   ↓

3. ATTACHMENT EXTRACTION
   ↓
   AttachmentExtractor.extract_attachments()
   ↓
   Saves files to quarantine/ directory
   ↓

4. STATIC ANALYSIS
   ↓
   StaticAnalyzer.analyze_file()
   ↓
   Extracts 13 features from file
   ↓

5. ML CLASSIFICATION
   ↓
   RansomwareClassifier.predict()
   ↓
   Returns probability scores
   ↓

6. DECISION MAKING
   ↓
   DecisionEngine.evaluate()
   ↓
   Calculates risk score (0-1)
   ↓
   Determines action: BLOCK/QUARANTINE/WARN/ALLOW
   ↓

7. LOGGING & DISPLAY
   ↓
   - Write to logs/decisions.jsonl
   - Update statistics
   - Display in dashboard
   - Return result to user
```

---

## File System Structure

```
ransomguard-email-shield/
├── app.py                    # Main Flask application
├── config.py                 # Configuration settings
├── train_model.py            # Model training script
│
├── modules/                  # Core detection engine
│   ├── email_connector.py
│   ├── attachment_extractor.py
│   ├── static_analyzer.py
│   ├── ml_classifier.py
│   └── decision_engine.py
│
├── models/                   # Trained ML models
│   ├── ransomware_classifier.pkl
│   └── feature_scaler.pkl
│
├── static/                   # Web assets
│   ├── css/dashboard.css
│   └── js/dashboard.js
│
├── templates/                # HTML templates
│   └── dashboard.html
│
├── logs/                     # System logs
│   ├── ransomguard.log       # Application log
│   └── decisions.jsonl       # Decision audit trail
│
└── quarantine/               # Extracted attachments
```

---

## Security Considerations

### Safe File Handling
- Files extracted to isolated quarantine directory
- Filename sanitization prevents path traversal
- No execution of analyzed files
- Automatic cleanup of old quarantined files

### Credential Security
- Email passwords stored only in memory
- No credential persistence
- IMAP/SSL encryption for email connections
- App passwords recommended over regular passwords

### Error Handling
- Graceful degradation on analysis errors
- Default to QUARANTINE on uncertain cases
- Comprehensive logging for audit trails
- Exception handling at all levels

---

## Performance Characteristics

### Analysis Speed
- Small files (<1MB): ~0.1-0.5 seconds
- Medium files (1-10MB): ~0.5-2 seconds
- Large files (10-50MB): ~2-5 seconds

### Resource Usage
- Memory: ~100-200MB base + file size
- CPU: Minimal (single-threaded analysis)
- Disk: Quarantine directory grows with analyzed files

### Scalability
- Single instance: 100-1000 emails/hour
- Parallel processing: Possible with worker queues
- Cloud deployment: Horizontal scaling supported

---

## Extension Points

### For Student Researchers

**Easy Extensions**:
1. Add new suspicious file extensions
2. Modify risk thresholds
3. Enhance dashboard UI
4. Add email notifications

**Medium Extensions**:
1. Implement sandbox execution analysis
2. Add YARA rule matching
3. Create machine learning ensemble
4. Implement continuous monitoring

**Advanced Extensions**:
1. Deep learning classification
2. Behavioral analysis integration
3. Multi-language support
4. Cloud deployment automation

---

## Configuration Options

Edit `config.py` to customize:

```python
# Detection Thresholds
BLOCK_THRESHOLD = 0.9
QUARANTINE_THRESHOLD = 0.7
WARN_THRESHOLD = 0.5

# File Analysis
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
HIGH_ENTROPY_THRESHOLD = 7.0

# Suspicious Extensions
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', ...
]
```

---

## Logging & Audit Trail

### Application Log (`logs/ransomguard.log`)
- System events
- Connection status
- Errors and warnings
- Analysis progress

### Decision Log (`logs/decisions.jsonl`)
- JSON Lines format
- One decision per line
- Complete analysis details
- Timestamp and metadata

**Decision Record Example**:
```json
{
  "timestamp": "2025-02-10T10:30:45",
  "filename": "invoice.pdf.exe",
  "action": "BLOCK",
  "risk_score": 0.92,
  "reason": "High-risk ransomware indicators",
  "details": {
    "ml_prediction": {...},
    "file_size": 524288,
    "entropy": 7.8,
    "is_packed": true,
    "suspicious_apis": 8
  }
}
```

---

**System Architecture Version 1.0**  
*Last Updated: February 2025*
