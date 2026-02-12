"""
Email Connector Module
Connects to email servers and fetches emails for analysis
"""

import imaplib
import email
from email.header import decode_header
import os
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class EmailConnector:
    """Connect to email server and fetch emails"""
    
    def __init__(self, email_address, password, imap_server="imap.gmail.com", port=993):
        self.email_address = email_address
        self.password = password
        self.imap_server = imap_server
        self.port = port
        self.mail = None
        self.is_connected = False
    
    def connect(self):
        """Establish connection to email server"""
        try:
            logger.info(f"Connecting to {self.imap_server}:{self.port}")
            self.mail = imaplib.IMAP4_SSL(self.imap_server, self.port)
            self.mail.login(self.email_address, self.password)
            self.is_connected = True
            logger.info(f"✓ Connected to {self.email_address}")
            return True
        except imaplib.IMAP4.error as e:
            logger.error(f"IMAP error: {e}")
            self.is_connected = False
            return False
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self.is_connected = False
            return False
    
    def fetch_unread_emails(self, limit=10):
        """Fetch unread emails with attachments"""
        if not self.is_connected:
            logger.error("Not connected to email server")
            return []
        
        try:
            self.mail.select("inbox")
            status, messages = self.mail.search(None, 'UNSEEN')
            
            if status != 'OK':
                logger.error("Failed to search for emails")
                return []
            
            email_ids = messages[0].split()
            logger.info(f"Found {len(email_ids)} unread emails")
            
            # Limit number of emails to process
            email_ids = email_ids[-limit:] if len(email_ids) > limit else email_ids
            
            emails = []
            for email_id in email_ids:
                try:
                    status, msg_data = self.mail.fetch(email_id, "(RFC822)")
                    
                    if status != 'OK':
                        continue
                    
                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1])
                            
                            # Only process emails with attachments
                            if self._has_attachments(msg):
                                emails.append({
                                    'id': email_id.decode(),
                                    'message': msg,
                                    'subject': self._decode_subject(msg.get("Subject", "")),
                                    'from': msg.get("From", ""),
                                    'to': msg.get("To", ""),
                                    'date': msg.get("Date", ""),
                                    'has_attachments': True
                                })
                except Exception as e:
                    logger.error(f"Error processing email {email_id}: {e}")
                    continue
            
            logger.info(f"Processed {len(emails)} emails with attachments")
            return emails
            
        except Exception as e:
            logger.error(f"Error fetching emails: {e}")
            return []
    
    def _has_attachments(self, msg):
        """Check if email has attachments"""
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            if part.get_filename():
                return True
        return False
    
    def _decode_subject(self, subject):
        """Decode email subject"""
        if not subject:
            return "No Subject"
        
        try:
            decoded_parts = decode_header(subject)
            decoded_subject = ""
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    try:
                        decoded_subject += part.decode(encoding or 'utf-8', errors='ignore')
                    except:
                        decoded_subject += part.decode('utf-8', errors='ignore')
                else:
                    decoded_subject += str(part)
            
            return decoded_subject
        except Exception as e:
            logger.error(f"Error decoding subject: {e}")
            return str(subject)
    
    def mark_as_read(self, email_id):
        """Mark email as read"""
        try:
            self.mail.store(email_id, '+FLAGS', '\\Seen')
            return True
        except Exception as e:
            logger.error(f"Error marking email as read: {e}")
            return False
    
    def disconnect(self):
        """Close email connection"""
        if self.mail and self.is_connected:
            try:
                self.mail.close()
                self.mail.logout()
                self.is_connected = False
                logger.info("Disconnected from email server")
            except Exception as e:
                logger.error(f"Error disconnecting: {e}")
    
    def __del__(self):
        """Cleanup on deletion"""
        self.disconnect()
