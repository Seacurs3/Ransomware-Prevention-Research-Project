# RansomGuard Email Shield 🛡️

**AI-Powered Pre-Execution Ransomware Detection System**

A university research project for NC Innovation Grant - Protecting small businesses and government organizations from ransomware attacks through intelligent email gateway analysis.

---

## 🎯 Project Overview

RansomGuard Email Shield is a **pre-execution ransomware detection system** that analyzes email attachments **before** they can execute on target systems. Using a combination of static analysis and machine learning, it provides real-time protection against ransomware threats delivered through email.

### Key Features

- ✅ **Pre-Execution Detection** - Stops ransomware before it runs
- 🤖 **AI-Powered Analysis** - Machine learning-based threat classification
- 📧 **Email Gateway Integration** - Works with Gmail, Outlook, and Exchange
- 📊 **Real-Time Dashboard** - Web-based monitoring and control
- 🔍 **Static File Analysis** - Entropy, packing, API detection
- 💰 **Low-Cost Solution** - Open-source and resource-efficient
- 📈 **Comprehensive Reporting** - Detailed threat analysis and logging

### Target Use Cases

- Small business email protection
- Government agency security
- Educational institution defense
- Non-profit organization protection

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────┐
│      Email Server (IMAP)                │
│   (Gmail / Outlook / Exchange)          │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│    RansomGuard Email Shield             │
│                                         │
│  ┌────────────────────────────────┐    │
│  │ 1. Email Connector             │    │
│  │ 2. Attachment Extractor        │    │
│  │ 3. Static Analyzer             │    │
│  │ 4. ML Classifier               │    │
│  │ 5. Decision Engine             │    │
│  │ 6. Web Dashboard               │    │
│  └────────────────────────────────┘    │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Action: BLOCK / QUARANTINE / ALLOW     │
└─────────────────────────────────────────┘
```

### Detection Pipeline

1. **Email Fetching** - Connects to email server via IMAP
2. **Attachment Extraction** - Safely extracts email attachments
3. **Static Analysis** - Analyzes file properties without execution:
   - File entropy (detects encryption/packing)
   - PE file structure analysis
   - Suspicious API imports
   - String analysis for ransomware keywords
4. **ML Classification** - Random Forest model prediction
5. **Risk Scoring** - Multi-factor risk assessment
6. **Decision Making** - Block, quarantine, warn, or allow
7. **Reporting** - Detailed logging and dashboard display

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Email account with IMAP enabled
- For Gmail: App Password required (see Setup section)

### Installation

1. **Clone or download the repository**

```bash
cd ransomguard-email-shield
```

2. **Create virtual environment**

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Train the ML model**

```bash
python train_model.py
```

This will create:
- `models/ransomware_classifier.pkl` - Trained Random Forest model
- `models/feature_scaler.pkl` - Feature normalization scaler

5. **Run the application**

```bash
python app.py
```

6. **Access the dashboard**

Open your browser and navigate to:
```
http://localhost:5000
```

---

## 📧 Email Setup

### Gmail Setup

1. Enable 2-Factor Authentication:
   - Go to Google Account → Security
   - Enable 2-Step Verification

2. Generate App Password:
   - Go to Security → 2-Step Verification → App passwords
   - Select "Mail" and "Other (Custom name)"
   - Copy the 16-character password

3. Use in RansomGuard:
   - Email: your.email@gmail.com
   - Password: [16-character app password]
   - IMAP Server: imap.gmail.com

### Outlook/Office 365 Setup

1. Enable IMAP:
   - Outlook Settings → Mail → Sync email → IMAP
   - Enable IMAP access

2. Use in RansomGuard:
   - Email: your.email@outlook.com
   - Password: [your account password or app password if 2FA enabled]
   - IMAP Server: outlook.office365.com

### Other Email Providers

Check your provider's documentation for:
- IMAP server address
- IMAP port (usually 993 for SSL)
- App password requirements

---

## 🎓 For Undergraduate Researchers

### Getting Started

This project is designed to be accessible for undergraduate computer science students. Here's how to begin:

1. **Understand the Architecture**
   - Review `docs/ARCHITECTURE.md` for system design
   - Study the detection pipeline diagram above

2. **Explore the Code**
   - Start with `app.py` - Main application
   - Then `modules/` - Core detection components
   - Finally `static/` and `templates/` - Web interface

3. **Experiment Safely**
   - Use EICAR test file for safe malware testing
   - Create synthetic test files (high entropy, suspicious names)
   - NEVER download or test with real ransomware

4. **Extend the System**
   - Add new detection features
   - Improve ML model with better features
   - Enhance the dashboard UI
   - Add email notification system

### Research Opportunities

- **Feature Engineering**: Develop new static analysis features
- **ML Improvements**: Experiment with different algorithms (SVM, Neural Networks)
- **Real-time Protection**: Implement continuous email monitoring
- **Behavioral Analysis**: Add sandbox execution analysis
- **Performance Optimization**: Improve analysis speed

---

## 🔬 Technical Details

### Static Analysis Features

The system extracts 13 features from each file:

1. **File size** - Executable size in bytes
2. **Entropy** - Measure of randomness (0-8)
3. **Number of sections** - PE file sections
4. **Number of imports** - Imported functions
5. **Is packed** - Binary packing detection
6. **Is DLL** - Dynamic link library flag
7. **Suspicious APIs** - Count of crypto/file APIs
8. **Is executable** - .exe file type
9. **Is Office macro** - Macro-enabled document
10. **Is archive** - Compressed file
11. **High entropy flag** - Entropy > 7.0
12. **Suspicious strings** - Ransomware keywords
13. **Max section entropy** - Highest section entropy

### Machine Learning Model

- **Algorithm**: Random Forest Classifier
- **Features**: 13 static analysis features
- **Training**: 250 synthetic samples (120 ransomware, 130 benign)
- **Validation**: 5-fold cross-validation
- **Test Accuracy**: ~95% on synthetic data

### Risk Scoring Formula

```
Risk Score = 
  (ML Probability × 0.35) +
  (Entropy Score × 0.15) +
  (Packing Detection × 0.15) +
  (Suspicious APIs × 0.15) +
  (Extension Risk × 0.10) +
  (Suspicious Strings × 0.05) +
  (File Size Anomaly × 0.05)
```

### Decision Thresholds

- **BLOCK**: Risk ≥ 0.90 - High confidence threat
- **QUARANTINE**: Risk ≥ 0.70 - Suspicious, needs review
- **WARN**: Risk ≥ 0.50 - Potentially suspicious
- **ALLOW**: Risk < 0.50 - Appears safe

---

## 📊 Dashboard Features

### Statistics Dashboard
- Total files analyzed
- Blocked threats
- Quarantined files
- Allowed attachments

### Email Connection Panel
- IMAP server configuration
- Connection status monitoring
- One-click email scanning

### Results Display
- Real-time threat detection results
- Detailed file analysis
- Risk scores and indicators
- Threat pattern visualization

### Export Functionality
- JSON export of all decisions
- Audit trail for compliance
- Research data collection

---

## 🧪 Testing

### Safe Testing Methods

1. **EICAR Test File**
```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
```

2. **High Entropy File**
```bash
dd if=/dev/urandom of=high_entropy.bin bs=1M count=1
```

3. **Suspicious Name Test**
```bash
touch invoice.pdf.exe
```

### Running Tests

```bash
# Unit tests (when implemented)
python -m pytest tests/

# Manual testing workflow
1. Start application
2. Connect to test email account
3. Send test emails with safe attachments
4. Verify detection results
```

---

## 💡 NC Innovation Grant Information

### Grant Proposal Talking Points

**Problem Statement**
- 60% of ransomware attacks target small businesses
- Average loss per attack: $100,000+
- 60% of affected businesses close within 6 months
- Current solutions too expensive for small organizations

**Innovation**
- Pre-execution detection (stops threats before execution)
- AI-powered analysis (machine learning classification)
- Low-cost deployment (~$5-10 per endpoint/year)
- Open-source foundation (transparent, auditable)

**Market Fit**
- Target: 500+ North Carolina small businesses
- Government agencies and educational institutions
- Integration: Email gateway (Gmail, Outlook, Exchange)
- Scalability: Cloud-native architecture

**Technical Innovation**
- Hybrid static analysis + ML approach
- Real-time email integration
- Minimal false positives
- Lightweight deployment

**Research Foundation**
- Based on peer-reviewed USENIX/NDSS research
- Undergraduate participation (workforce development)
- Open-source community contribution

### Deployment Plan

**Phase 1** (Months 1-3): Prototype Development
- Core detection engine
- Email integration
- Basic dashboard

**Phase 2** (Months 4-6): Pilot Testing
- 10-20 small business deployments
- Performance optimization
- User feedback integration

**Phase 3** (Months 7-9): Scaling
- 100+ organization deployments
- Advanced features
- Cloud deployment option

**Phase 4** (Months 10-12): Evaluation & Reporting
- Effectiveness analysis
- Cost-benefit study
- Final grant reporting

---

## 📁 Project Structure

```
ransomguard-email-shield/
│
├── app.py                      # Main Flask application
├── config.py                   # Configuration settings
├── train_model.py              # ML model training script
├── requirements.txt            # Python dependencies
│
├── modules/                    # Core detection modules
│   ├── email_connector.py      # Email server connection
│   ├── attachment_extractor.py # Attachment handling
│   ├── static_analyzer.py      # Static file analysis
│   ├── ml_classifier.py        # ML classification
│   └── decision_engine.py      # Decision making logic
│
├── models/                     # Trained ML models
│   ├── ransomware_classifier.pkl
│   └── feature_scaler.pkl
│
├── static/                     # Frontend assets
│   ├── css/
│   │   └── dashboard.css       # Dashboard styles
│   └── js/
│       └── dashboard.js        # Dashboard interactivity
│
├── templates/                  # HTML templates
│   └── dashboard.html          # Main dashboard
│
├── logs/                       # Application logs
│   ├── ransomguard.log         # System log
│   └── decisions.jsonl         # Decision audit trail
│
├── quarantine/                 # Quarantined files
│
└── docs/                       # Documentation
    └── README.md               # This file
```

---

## 🔧 Configuration

Edit `config.py` to customize:

```python
# Detection thresholds
BLOCK_THRESHOLD = 0.9
QUARANTINE_THRESHOLD = 0.7
WARN_THRESHOLD = 0.5

# File size limits
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# Entropy threshold
HIGH_ENTROPY_THRESHOLD = 7.0
```

---

## 🐛 Troubleshooting

### Common Issues

**1. Email Connection Failed**
- Verify IMAP is enabled
- Check app password (not regular password for Gmail)
- Ensure firewall allows IMAP (port 993)

**2. Model Not Found**
- Run `python train_model.py` first
- Check that `models/` directory exists

**3. Import Errors**
- Activate virtual environment
- Reinstall dependencies: `pip install -r requirements.txt`

**4. python-magic Errors (Linux)**
```bash
# Ubuntu/Debian
sudo apt-get install libmagic1

# macOS
brew install libmagic
```

---

## 📚 References

### Academic Research
- UNVEIL (USENIX Security 2016)
- ShieldFS (ACSAC 2016)
- Ransomware Detection Papers: https://github.com/data-storage-lab/Security

### Resources
- [Ransomware Overview](https://www.cisa.gov/stopransomware)
- [Email Security Best Practices](https://www.nist.gov/cybersecurity)
- [Machine Learning for Malware Detection](https://www.usenix.org/publications)

---

## 👥 Contributors

This is a university research project for NC Innovation Grant.

**Research Team:**
- Principal Investigator: [Your Faculty Name]
- Student Researchers: [Your Student Names]
- Institution: [Your University]

---

## 📄 License

This project is developed for educational and research purposes as part of NC Innovation Grant.

---

## 🤝 Contributing

This is a research project, but we welcome:
- Bug reports
- Feature suggestions
- Code improvements
- Documentation enhancements

---

## 📞 Contact

For questions about this project:
- Email: [your.email@university.edu]
- Institution: [Your University]
- Grant: NC Innovation Grant Program

---

## ⚠️ Disclaimer

This is a research prototype. For production use:
- Conduct thorough security audits
- Implement proper access controls
- Use secure credential storage
- Follow data protection regulations
- Test extensively with real-world data

**Do not test with live ransomware samples without proper safety measures!**

---

**Built with ❤️ for NC Innovation Grant**

*Protecting North Carolina's small businesses and government organizations from ransomware threats*
