"""
RansomGuard Email Shield - Main Application
AI-Powered Pre-Execution Ransomware Detection System
"""

from flask import Flask, render_template, jsonify, request, send_file
import logging
import os
from datetime import datetime
import json

from config import Config
from modules.email_connector import EmailConnector
from modules.attachment_extractor import AttachmentExtractor
from modules.static_analyzer import StaticAnalyzer
from modules.ml_classifier import RansomwareClassifier
from modules.decision_engine import DecisionEngine

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize directories
Config.init_app()

# Initialize components
email_connector = None
attachment_extractor = AttachmentExtractor(Config.QUARANTINE_DIR)
static_analyzer = StaticAnalyzer()
ml_classifier = RansomwareClassifier(Config.ML_MODEL_PATH, Config.ML_SCALER_PATH)
decision_engine = DecisionEngine()

# Try to load pre-trained model
try:
    if os.path.exists(Config.ML_MODEL_PATH):
        ml_classifier.load_model()
        logger.info("✓ Pre-trained model loaded successfully")
    else:
        logger.warning("⚠ No pre-trained model found. Run train_model.py first or use with limited accuracy.")
except Exception as e:
    logger.error(f"Error loading model: {e}")


@app.route('/')
def index():
    """Dashboard homepage"""
    return render_template('dashboard.html')


@app.route('/api/connect', methods=['POST'])
def connect_email():
    """Connect to email server"""
    global email_connector
    
    try:
        data = request.json
        
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Email and password required'
            }), 400
        
        email_connector = EmailConnector(
            email_address=data['email'],
            password=data['password'],
            imap_server=data.get('imap_server', Config.DEFAULT_IMAP_SERVER)
        )
        
        if email_connector.connect():
            logger.info(f"Connected to email: {data['email']}")
            return jsonify({
                'status': 'success',
                'message': f'Successfully connected to {data["email"]}'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to connect. Check credentials and enable IMAP/App Password.'
            }), 400
            
    except Exception as e:
        logger.error(f"Connection error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Connection error: {str(e)}'
        }), 500


@app.route('/api/disconnect', methods=['POST'])
def disconnect_email():
    """Disconnect from email server"""
    global email_connector
    
    try:
        if email_connector:
            email_connector.disconnect()
            email_connector = None
            
        return jsonify({
            'status': 'success',
            'message': 'Disconnected from email server'
        })
        
    except Exception as e:
        logger.error(f"Disconnect error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Disconnect error: {str(e)}'
        }), 500


@app.route('/api/scan', methods=['POST'])
def scan_emails():
    """Scan emails for ransomware"""
    global email_connector
    
    if not email_connector or not email_connector.is_connected:
        return jsonify({
            'status': 'error',
            'message': 'Not connected to email server'
        }), 400
    
    try:
        # Fetch unread emails
        logger.info("Fetching unread emails...")
        emails = email_connector.fetch_unread_emails(limit=10)
        
        if not emails:
            return jsonify({
                'status': 'success',
                'message': 'No unread emails with attachments found',
                'results': []
            })
        
        results = []
        
        for email_data in emails:
            logger.info(f"Processing email: {email_data['subject']}")
            
            # Extract attachments
            attachments = attachment_extractor.extract_attachments(
                email_data['message'],
                email_data['id']
            )
            
            for attachment in attachments:
                try:
                    # Perform static analysis
                    logger.info(f"Analyzing: {attachment['filename']}")
                    analysis = static_analyzer.analyze_file(attachment['filepath'])
                    
                    # ML classification
                    features = ml_classifier.prepare_features(analysis)
                    ml_prediction = ml_classifier.predict(features)
                    
                    # Make decision
                    decision = decision_engine.evaluate(analysis, ml_prediction, attachment)
                    
                    # Compile result
                    result = {
                        'email_id': email_data['id'],
                        'email_subject': email_data['subject'],
                        'email_from': email_data['from'],
                        'email_date': email_data['date'],
                        'attachment_name': attachment['filename'],
                        'attachment_size': attachment['size'],
                        'attachment_type': attachment['content_type'],
                        'decision': decision,
                        'threat_details': {
                            'entropy': analysis.get('entropy', 0),
                            'is_packed': analysis.get('is_packed', False),
                            'suspicious_apis': len(analysis.get('suspicious_apis', [])),
                            'ml_confidence': ml_prediction.get('confidence', 0)
                        }
                    }
                    
                    results.append(result)
                    
                    logger.info(f"Result: {decision['action']} - {attachment['filename']}")
                    
                except Exception as e:
                    logger.error(f"Error analyzing attachment {attachment['filename']}: {e}")
                    results.append({
                        'email_subject': email_data['subject'],
                        'attachment_name': attachment['filename'],
                        'decision': {
                            'action': 'ERROR',
                            'reason': f'Analysis error: {str(e)}'
                        }
                    })
        
        return jsonify({
            'status': 'success',
            'message': f'Scanned {len(results)} attachments',
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Scan error: {str(e)}'
        }), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get scanning statistics"""
    try:
        stats = decision_engine.get_statistics()
        return jsonify({
            'status': 'success',
            'statistics': stats
        })
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/recent-decisions', methods=['GET'])
def get_recent_decisions():
    """Get recent decisions"""
    try:
        limit = request.args.get('limit', 10, type=int)
        decisions = decision_engine.get_recent_decisions(limit)
        
        return jsonify({
            'status': 'success',
            'decisions': decisions
        })
    except Exception as e:
        logger.error(f"Error getting recent decisions: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/export-decisions', methods=['GET'])
def export_decisions():
    """Export all decisions to JSON file"""
    try:
        filepath = decision_engine.export_decisions()
        
        if filepath:
            return send_file(
                filepath,
                as_attachment=True,
                download_name=f'ransomguard_decisions_{datetime.now().strftime("%Y%m%d")}.json'
            )
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to export decisions'
            }), 500
            
    except Exception as e:
        logger.error(f"Error exporting decisions: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    try:
        status = {
            'email_connected': email_connector is not None and email_connector.is_connected,
            'email_address': email_connector.email_address if email_connector else None,
            'model_loaded': ml_classifier.is_trained,
            'quarantine_files': len(os.listdir(Config.QUARANTINE_DIR)) if os.path.exists(Config.QUARANTINE_DIR) else 0,
            'uptime': 'Running'
        }
        
        return jsonify({
            'status': 'success',
            'system_status': status
        })
        
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'status': 'error',
        'message': 'Endpoint not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({
        'status': 'error',
        'message': 'Internal server error'
    }), 500


if __name__ == '__main__':
    logger.info("="*60)
    logger.info("RansomGuard Email Shield Starting...")
    logger.info("AI-Powered Pre-Execution Ransomware Detection")
    logger.info("="*60)
    
    # Run Flask app
    app.run(
        debug=Config.DEBUG,
        host='0.0.0.0',
        port=5000
    )
