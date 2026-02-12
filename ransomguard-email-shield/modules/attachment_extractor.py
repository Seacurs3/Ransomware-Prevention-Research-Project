"""
Attachment Extractor Module
Extracts and saves email attachments for analysis
"""

import os
import email
from datetime import datetime
import logging
import hashlib

logger = logging.getLogger(__name__)


class AttachmentExtractor:
    """Extract attachments from emails for analysis"""
    
    def __init__(self, quarantine_dir="quarantine"):
        self.quarantine_dir = quarantine_dir
        os.makedirs(quarantine_dir, exist_ok=True)
        logger.info(f"Attachment extractor initialized: {quarantine_dir}")
    
    def extract_attachments(self, email_msg, email_id="unknown"):
        """Extract all attachments from email message"""
        attachments = []
        attachment_count = 0
        
        try:
            for part in email_msg.walk():
                # Skip multipart containers
                if part.get_content_maintype() == 'multipart':
                    continue
                
                # Skip parts without content disposition
                if part.get('Content-Disposition') is None:
                    continue
                
                filename = part.get_filename()
                if filename:
                    attachment_count += 1
                    
                    # Get file content
                    file_data = part.get_payload(decode=True)
                    
                    if file_data:
                        # Save attachment
                        filepath = self._save_attachment(file_data, filename, email_id)
                        
                        if filepath:
                            attachments.append({
                                'filename': filename,
                                'filepath': filepath,
                                'content_type': part.get_content_type(),
                                'size': len(file_data),
                                'extension': os.path.splitext(filename)[1].lower(),
                                'is_suspicious_extension': self.is_suspicious_extension(filename),
                                'md5': self._calculate_hash(file_data, 'md5'),
                                'sha256': self._calculate_hash(file_data, 'sha256')
                            })
                            logger.info(f"Extracted: {filename} ({len(file_data)} bytes)")
            
            logger.info(f"Extracted {len(attachments)} attachments from email {email_id}")
            return attachments
            
        except Exception as e:
            logger.error(f"Error extracting attachments: {e}")
            return []
    
    def _save_attachment(self, file_data, filename, email_id):
        """Save attachment to quarantine directory"""
        try:
            # Create unique filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            safe_filename = f"{email_id}_{timestamp}_{self._sanitize_filename(filename)}"
            filepath = os.path.join(self.quarantine_dir, safe_filename)
            
            # Save file
            with open(filepath, 'wb') as f:
                f.write(file_data)
            
            logger.debug(f"Saved attachment: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error saving attachment {filename}: {e}")
            return None
    
    def _sanitize_filename(self, filename):
        """Sanitize filename to prevent path traversal"""
        # Remove any directory separators
        filename = os.path.basename(filename)
        
        # Remove potentially dangerous characters
        dangerous_chars = ['/', '\\', '..', '\x00']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Limit filename length
        if len(filename) > 200:
            name, ext = os.path.splitext(filename)
            filename = name[:200-len(ext)] + ext
        
        return filename
    
    def _calculate_hash(self, data, algorithm='sha256'):
        """Calculate hash of file data"""
        try:
            hash_func = hashlib.new(algorithm)
            hash_func.update(data)
            return hash_func.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating {algorithm} hash: {e}")
            return None
    
    def get_suspicious_extensions(self):
        """List of commonly used ransomware file extensions"""
        return [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.js', '.jar', '.zip', '.rar', '.7z',
            '.docm', '.xlsm', '.pptm',  # Macro-enabled Office
            '.pdf.exe', '.doc.exe', '.txt.exe',  # Double extensions
            '.ace', '.cab', '.msi', '.reg'
        ]
    
    def is_suspicious_extension(self, filename):
        """Check if file has suspicious extension"""
        filename_lower = filename.lower()
        suspicious = self.get_suspicious_extensions()
        
        # Check for suspicious extensions
        for ext in suspicious:
            if filename_lower.endswith(ext):
                return True
        
        # Check for double extensions (e.g., file.pdf.exe)
        parts = filename_lower.split('.')
        if len(parts) >= 3:
            # Check if last extension is executable
            if f".{parts[-1]}" in ['.exe', '.scr', '.bat', '.com', '.vbs']:
                return True
        
        return False
    
    def cleanup_old_files(self, days=7):
        """Remove quarantined files older than specified days"""
        try:
            current_time = datetime.now().timestamp()
            removed_count = 0
            
            for filename in os.listdir(self.quarantine_dir):
                filepath = os.path.join(self.quarantine_dir, filename)
                
                if os.path.isfile(filepath):
                    file_age = current_time - os.path.getmtime(filepath)
                    
                    # Remove if older than specified days
                    if file_age > (days * 24 * 3600):
                        os.remove(filepath)
                        removed_count += 1
            
            logger.info(f"Cleaned up {removed_count} old quarantined files")
            return removed_count
            
        except Exception as e:
            logger.error(f"Error cleaning up files: {e}")
            return 0
