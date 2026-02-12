"""
Decision Engine Module
Makes final decisions on whether to block, quarantine, or allow files
"""

import json
from datetime import datetime
import logging
from config import Config

logger = logging.getLogger(__name__)


class DecisionEngine:
    """Make decisions on email attachments based on analysis"""
    
    def __init__(self, 
                 block_threshold=None, 
                 quarantine_threshold=None, 
                 warn_threshold=None):
        
        self.block_threshold = block_threshold or Config.BLOCK_THRESHOLD
        self.quarantine_threshold = quarantine_threshold or Config.QUARANTINE_THRESHOLD
        self.warn_threshold = warn_threshold or Config.WARN_THRESHOLD
        
        self.action_log = []
        self.statistics = {
            'total_analyzed': 0,
            'blocked': 0,
            'quarantined': 0,
            'warned': 0,
            'allowed': 0
        }
        
        logger.info(f"Decision Engine initialized (thresholds: block={self.block_threshold}, "
                   f"quarantine={self.quarantine_threshold}, warn={self.warn_threshold})")
    
    def evaluate(self, analysis_result, ml_prediction, attachment_info):
        """Evaluate file and make decision"""
        
        try:
            # Calculate comprehensive risk score
            risk_score = self._calculate_risk_score(analysis_result, ml_prediction)
            
            # Make decision based on risk score
            action, reason = self._decide_action(risk_score, analysis_result, ml_prediction)
            
            # Create decision record
            decision = {
                'timestamp': datetime.now().isoformat(),
                'filename': attachment_info.get('filename', 'unknown'),
                'filepath': attachment_info.get('filepath', 'unknown'),
                'action': action,
                'risk_score': round(risk_score, 4),
                'reason': reason,
                'details': {
                    'ml_prediction': ml_prediction,
                    'file_size': analysis_result.get('size', 0),
                    'entropy': analysis_result.get('entropy', 0),
                    'is_packed': analysis_result.get('is_packed', False),
                    'suspicious_apis': len(analysis_result.get('suspicious_apis', [])),
                    'extension': analysis_result.get('extension', 'unknown')
                }
            }
            
            # Log decision
            self._log_decision(decision)
            
            # Update statistics
            self._update_statistics(action)
            
            logger.info(f"Decision for {attachment_info.get('filename')}: {action} (risk={risk_score:.3f})")
            
            return decision
            
        except Exception as e:
            logger.error(f"Error in decision evaluation: {e}")
            # Default to quarantine on error
            return {
                'timestamp': datetime.now().isoformat(),
                'filename': attachment_info.get('filename', 'unknown'),
                'action': 'QUARANTINE',
                'risk_score': 0.5,
                'reason': f'Error in analysis: {str(e)}',
                'error': str(e)
            }
    
    def _calculate_risk_score(self, analysis, ml_prediction):
        """Calculate comprehensive risk score (0-1)"""
        
        score = 0.0
        weights = {
            'ml_model': 0.35,
            'entropy': 0.15,
            'packing': 0.15,
            'suspicious_apis': 0.15,
            'extension': 0.10,
            'strings': 0.05,
            'file_size': 0.05
        }
        
        # 1. ML Model Prediction (35% weight)
        ml_prob = ml_prediction.get('ransomware_probability', 0)
        score += ml_prob * weights['ml_model']
        
        # 2. Entropy Analysis (15% weight)
        entropy = analysis.get('entropy', 0)
        if entropy > 7.5:
            score += weights['entropy']
        elif entropy > 7.0:
            score += weights['entropy'] * 0.7
        elif entropy > 6.5:
            score += weights['entropy'] * 0.4
        
        # 3. Packing Detection (15% weight)
        if analysis.get('is_packed', False):
            score += weights['packing']
        
        # 4. Suspicious APIs (15% weight)
        num_suspicious_apis = len(analysis.get('suspicious_apis', []))
        if num_suspicious_apis > 8:
            score += weights['suspicious_apis']
        elif num_suspicious_apis > 5:
            score += weights['suspicious_apis'] * 0.7
        elif num_suspicious_apis > 2:
            score += weights['suspicious_apis'] * 0.4
        
        # 5. Suspicious Extension (10% weight)
        ext = analysis.get('extension', '').lower()
        if ext in ['.exe', '.scr', '.bat', '.vbs', '.js']:
            score += weights['extension']
        elif ext in ['.docm', '.xlsm', '.pptm']:
            score += weights['extension'] * 0.6
        
        # 6. Suspicious Strings (5% weight)
        num_strings = analysis.get('num_suspicious_strings', 0)
        if num_strings > 5:
            score += weights['strings']
        elif num_strings > 2:
            score += weights['strings'] * 0.5
        
        # 7. File Size Anomaly (5% weight)
        size = analysis.get('size', 0)
        # Very small executables or very large documents are suspicious
        if ext in ['.exe', '.dll'] and size < 50000:
            score += weights['file_size']
        elif ext in ['.doc', '.docx', '.xls', '.xlsx'] and size > 10000000:
            score += weights['file_size'] * 0.5
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _decide_action(self, risk_score, analysis, ml_prediction):
        """Decide action based on risk score and analysis"""
        
        # Critical indicators that override normal thresholds
        critical_indicators = []
        
        # Check for extremely high entropy (almost certainly encrypted)
        if analysis.get('entropy', 0) > 7.8:
            critical_indicators.append("Extremely high entropy (likely encrypted)")
        
        # Check for packing + high suspicious API count
        if (analysis.get('is_packed', False) and 
            len(analysis.get('suspicious_apis', [])) > 8):
            critical_indicators.append("Packed executable with many crypto APIs")
        
        # Check for ML high confidence
        if ml_prediction.get('ransomware_probability', 0) > 0.95:
            critical_indicators.append("ML model very high confidence")
        
        # Make decision
        if critical_indicators or risk_score >= self.block_threshold:
            action = "BLOCK"
            if critical_indicators:
                reason = f"Critical threat detected: {'; '.join(critical_indicators)}"
            else:
                reason = f"High-risk ransomware indicators (score: {risk_score:.2f})"
        
        elif risk_score >= self.quarantine_threshold:
            action = "QUARANTINE"
            reason = f"Suspicious file requiring review (score: {risk_score:.2f})"
        
        elif risk_score >= self.warn_threshold:
            action = "WARN"
            reason = f"Potentially suspicious - delivered with warning (score: {risk_score:.2f})"
        
        else:
            action = "ALLOW"
            reason = f"File appears safe (score: {risk_score:.2f})"
        
        return action, reason
    
    def _log_decision(self, decision):
        """Log decision to file and memory"""
        try:
            # Add to memory log
            self.action_log.append(decision)
            
            # Write to file
            with open(Config.DECISION_LOG, 'a') as f:
                f.write(json.dumps(decision) + '\n')
                
        except Exception as e:
            logger.error(f"Error logging decision: {e}")
    
    def _update_statistics(self, action):
        """Update decision statistics"""
        self.statistics['total_analyzed'] += 1
        action_key = action.lower()
        if action_key in self.statistics:
            self.statistics[action_key] += 1
    
    def get_statistics(self):
        """Get current statistics"""
        return self.statistics.copy()
    
    def get_recent_decisions(self, limit=10):
        """Get recent decisions"""
        return self.action_log[-limit:]
    
    def reset_statistics(self):
        """Reset statistics"""
        self.statistics = {
            'total_analyzed': 0,
            'blocked': 0,
            'quarantined': 0,
            'warned': 0,
            'allowed': 0
        }
        logger.info("Statistics reset")
    
    def export_decisions(self, filepath=None):
        """Export all decisions to JSON file"""
        try:
            filepath = filepath or f"decisions_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(filepath, 'w') as f:
                json.dump(self.action_log, f, indent=2)
            
            logger.info(f"Exported {len(self.action_log)} decisions to {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error exporting decisions: {e}")
            return None
