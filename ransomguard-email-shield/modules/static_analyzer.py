"""
Static Analyzer Module
Performs pre-execution analysis of suspicious files
"""

import os
import hashlib
import math
from collections import Counter
import logging

logger = logging.getLogger(__name__)

# Import optional dependencies
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    logger.warning("python-magic not available, file type detection limited")

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    logger.warning("pefile not available, PE analysis disabled")


class StaticAnalyzer:
    """Perform static analysis on suspicious files"""
    
    def __init__(self):
        if HAS_MAGIC:
            try:
                self.magic = magic.Magic(mime=True)
            except:
                self.magic = None
        else:
            self.magic = None
        
        logger.info("Static analyzer initialized")
    
    def analyze_file(self, filepath):
        """Comprehensive static analysis of file"""
        try:
            logger.info(f"Analyzing file: {filepath}")
            
            features = {}
            
            # Basic file properties
            features.update(self._get_basic_features(filepath))
            
            # Entropy analysis (important for detecting encryption/packing)
            features['entropy'] = self._calculate_entropy(filepath)
            features['is_high_entropy'] = features['entropy'] > 7.0
            
            # File hashes
            features['md5'] = self._get_file_hash(filepath, 'md5')
            features['sha256'] = self._get_file_hash(filepath, 'sha256')
            
            # PE file analysis (if Windows executable)
            if filepath.lower().endswith(('.exe', '.dll', '.sys', '.scr')):
                if HAS_PEFILE:
                    features.update(self._analyze_pe_file(filepath))
                else:
                    features['is_pe'] = True
                    features['pe_analysis_available'] = False
            
            # String analysis
            features.update(self._analyze_strings(filepath))
            
            logger.info(f"Analysis complete: {filepath}")
            return features
            
        except Exception as e:
            logger.error(f"Error analyzing file {filepath}: {e}")
            return {'error': str(e), 'filename': os.path.basename(filepath)}
    
    def _get_basic_features(self, filepath):
        """Extract basic file features"""
        try:
            stats = os.stat(filepath)
            
            features = {
                'filename': os.path.basename(filepath),
                'filepath': filepath,
                'size': stats.st_size,
                'extension': os.path.splitext(filepath)[1].lower()
            }
            
            # MIME type detection
            if self.magic:
                try:
                    features['mime_type'] = self.magic.from_file(filepath)
                except:
                    features['mime_type'] = 'unknown'
            else:
                # Fallback basic detection
                features['mime_type'] = self._detect_mime_basic(filepath)
            
            return features
            
        except Exception as e:
            logger.error(f"Error getting basic features: {e}")
            return {}
    
    def _detect_mime_basic(self, filepath):
        """Basic MIME type detection without python-magic"""
        ext_map = {
            '.exe': 'application/x-executable',
            '.dll': 'application/x-dll',
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.zip': 'application/zip',
            '.rar': 'application/x-rar',
            '.7z': 'application/x-7z-compressed'
        }
        
        ext = os.path.splitext(filepath)[1].lower()
        return ext_map.get(ext, 'application/octet-stream')
    
    def _analyze_pe_file(self, filepath):
        """Analyze Windows PE executable"""
        try:
            pe = pefile.PE(filepath)
            
            features = {
                'is_pe': True,
                'pe_analysis_available': True,
                'num_sections': len(pe.sections),
                'is_dll': pe.is_dll(),
                'is_exe': pe.is_exe(),
            }
            
            # Import analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                features['num_imports'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                features['suspicious_apis'] = self._extract_suspicious_apis(pe)
                features['num_suspicious_apis'] = len(features['suspicious_apis'])
            else:
                features['num_imports'] = 0
                features['suspicious_apis'] = []
                features['num_suspicious_apis'] = 0
            
            # Packing detection
            features['is_packed'] = self._detect_packing(pe)
            
            # Section analysis
            features['section_names'] = [
                section.Name.decode('utf-8', errors='ignore').rstrip('\x00') 
                for section in pe.sections
            ]
            
            # Section entropy (high entropy sections suggest packing/encryption)
            section_entropies = []
            for section in pe.sections:
                entropy = self._calculate_section_entropy(section)
                section_entropies.append(entropy)
            
            features['max_section_entropy'] = max(section_entropies) if section_entropies else 0
            features['avg_section_entropy'] = sum(section_entropies) / len(section_entropies) if section_entropies else 0
            
            pe.close()
            return features
            
        except Exception as e:
            logger.error(f"Error analyzing PE file: {e}")
            return {
                'is_pe': True,
                'pe_analysis_available': False,
                'pe_error': str(e)
            }
    
    def _detect_packing(self, pe):
        """Detect if PE file is packed (common in ransomware)"""
        try:
            # Check for high entropy in sections
            for section in pe.sections:
                entropy = self._calculate_section_entropy(section)
                if entropy > 7.2:  # High entropy suggests packing/encryption
                    return True
            
            # Check for common packer section names
            packer_sections = [
                b'UPX0', b'UPX1', b'UPX2',
                b'.themida', b'.enigma', b'.aspack',
                b'.petite', b'.neolit', b'MEW'
            ]
            
            for section in pe.sections:
                for packer in packer_sections:
                    if packer in section.Name:
                        return True
            
            # Check for low number of imports (often indicates packing)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                if len(pe.DIRECTORY_ENTRY_IMPORT) < 3:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error detecting packing: {e}")
            return False
    
    def _calculate_section_entropy(self, section):
        """Calculate entropy of PE section"""
        try:
            data = section.get_data()
            if not data or len(data) == 0:
                return 0
            
            entropy = 0
            counter = Counter(data)
            length = len(data)
            
            for count in counter.values():
                if count > 0:
                    p_x = count / length
                    entropy -= p_x * math.log2(p_x)
            
            return entropy
            
        except Exception as e:
            logger.error(f"Error calculating section entropy: {e}")
            return 0
    
    def _extract_suspicious_apis(self, pe):
        """Extract potentially malicious API calls"""
        suspicious_apis = [
            # Encryption/Cryptography
            'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptAcquireContext',
            'CryptCreateHash', 'CryptHashData', 'CryptDeriveKey',
            
            # File operations
            'CreateFile', 'WriteFile', 'DeleteFile', 'MoveFile', 'CopyFile',
            'FindFirstFile', 'FindNextFile', 'SetFilePointer',
            
            # Registry manipulation
            'RegSetValue', 'RegDeleteKey', 'RegCreateKey', 'RegOpenKey',
            
            # Memory manipulation
            'VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx',
            
            # Process injection
            'CreateRemoteThread', 'WriteProcessMemory', 'OpenProcess',
            
            # Network activity
            'InternetOpen', 'HttpSendRequest', 'InternetConnect', 'WinHttpOpen',
            
            # Service manipulation
            'CreateService', 'StartService', 'ControlService'
        ]
        
        found_apis = []
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            try:
                                api_name = imp.name.decode('utf-8', errors='ignore')
                                if any(suspicious.lower() in api_name.lower() for suspicious in suspicious_apis):
                                    if api_name not in found_apis:
                                        found_apis.append(api_name)
                            except:
                                continue
        except Exception as e:
            logger.error(f"Error extracting APIs: {e}")
        
        return found_apis
    
    def _calculate_entropy(self, filepath):
        """Calculate file entropy (high entropy = encryption/packing)"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            if not data or len(data) == 0:
                return 0
            
            # Sample large files to avoid memory issues
            if len(data) > 1024 * 1024:  # 1MB
                # Sample 1MB from different parts
                samples = []
                sample_size = 1024 * 256  # 256KB samples
                step = len(data) // 4
                
                for i in range(0, len(data), step):
                    samples.append(data[i:i+sample_size])
                
                data = b''.join(samples[:4])
            
            entropy = 0
            counter = Counter(data)
            length = len(data)
            
            for count in counter.values():
                if count > 0:
                    p_x = count / length
                    entropy -= p_x * math.log2(p_x)
            
            return round(entropy, 4)
            
        except Exception as e:
            logger.error(f"Error calculating entropy: {e}")
            return 0
    
    def _get_file_hash(self, filepath, algorithm='sha256'):
        """Calculate file hash"""
        try:
            hash_func = hashlib.new(algorithm)
            
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            
            return hash_func.hexdigest()
            
        except Exception as e:
            logger.error(f"Error calculating {algorithm} hash: {e}")
            return None
    
    def _analyze_strings(self, filepath, min_length=4):
        """Extract and analyze strings from file"""
        try:
            suspicious_strings = []
            ransomware_keywords = [
                'encrypt', 'decrypt', 'ransom', 'bitcoin', 'btc', 'wallet',
                'payment', 'unlock', 'restore', 'recover', 'key', 'private',
                'cryptocurrency', 'locked', 'files encrypted'
            ]
            
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings
            current_string = ""
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        # Check for suspicious keywords
                        lower_string = current_string.lower()
                        for keyword in ransomware_keywords:
                            if keyword in lower_string:
                                if current_string not in suspicious_strings:
                                    suspicious_strings.append(current_string)
                                break
                    current_string = ""
            
            return {
                'num_suspicious_strings': len(suspicious_strings),
                'suspicious_strings': suspicious_strings[:10]  # Limit to first 10
            }
            
        except Exception as e:
            logger.error(f"Error analyzing strings: {e}")
            return {
                'num_suspicious_strings': 0,
                'suspicious_strings': []
            }
