"""
Machine Learning Classifier Module
Trains and uses ML models for ransomware detection
"""

import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import logging

logger = logging.getLogger(__name__)


class RansomwareClassifier:
    """Train and use ML model for ransomware detection"""
    
    def __init__(self, model_path=None, scaler_path=None):
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.is_trained = False
        
        # Feature names for reference
        self.feature_names = [
            'size', 'entropy', 'num_sections', 'num_imports',
            'is_packed', 'is_dll', 'num_suspicious_apis',
            'is_exe', 'is_office_macro', 'is_archive',
            'is_high_entropy', 'num_suspicious_strings',
            'max_section_entropy'
        ]
        
        logger.info("ML Classifier initialized")
    
    def prepare_features(self, analysis_results):
        """Convert static analysis results to ML features"""
        try:
            features = []
            
            # Numerical features
            features.append(analysis_results.get('size', 0))
            features.append(analysis_results.get('entropy', 0))
            features.append(analysis_results.get('num_sections', 0))
            features.append(analysis_results.get('num_imports', 0))
            
            # Boolean features (convert to 0/1)
            features.append(1 if analysis_results.get('is_packed', False) else 0)
            features.append(1 if analysis_results.get('is_dll', False) else 0)
            features.append(analysis_results.get('num_suspicious_apis', 0))
            
            # Extension-based features
            ext = analysis_results.get('extension', '').lower()
            features.append(1 if ext == '.exe' else 0)
            features.append(1 if ext in ['.docm', '.xlsm', '.pptm'] else 0)
            features.append(1 if ext in ['.zip', '.rar', '.7z'] else 0)
            
            # Additional features
            features.append(1 if analysis_results.get('is_high_entropy', False) else 0)
            features.append(analysis_results.get('num_suspicious_strings', 0))
            features.append(analysis_results.get('max_section_entropy', 0))
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Error preparing features: {e}")
            # Return zero vector as fallback
            return np.zeros((1, len(self.feature_names)))
    
    def train(self, X_train, y_train, X_test=None, y_test=None):
        """Train the ML model"""
        try:
            logger.info(f"Training model with {len(X_train)} samples")
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            
            # Train model
            self.model.fit(X_train_scaled, y_train)
            
            # Cross-validation
            cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
            logger.info(f"Cross-validation scores: {cv_scores}")
            logger.info(f"Mean CV score: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
            
            # Test set evaluation
            if X_test is not None and y_test is not None:
                X_test_scaled = self.scaler.transform(X_test)
                y_pred = self.model.predict(X_test_scaled)
                
                accuracy = accuracy_score(y_test, y_pred)
                logger.info(f"Test accuracy: {accuracy:.3f}")
                logger.info(f"\nClassification Report:\n{classification_report(y_test, y_pred, target_names=['Benign', 'Ransomware'])}")
                logger.info(f"\nConfusion Matrix:\n{confusion_matrix(y_test, y_pred)}")
            
            # Feature importance
            feature_importance = pd.DataFrame({
                'feature': self.feature_names,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            logger.info(f"\nTop Features:\n{feature_importance.head(10)}")
            
            self.is_trained = True
            logger.info("✓ Model training complete")
            
            return True
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return False
    
    def predict(self, features):
        """Predict if file is ransomware"""
        try:
            if not self.is_trained:
                logger.warning("Model not trained, using default prediction")
                return {
                    'is_ransomware': False,
                    'confidence': 0.5,
                    'ransomware_probability': 0.5,
                    'benign_probability': 0.5
                }
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            result = {
                'is_ransomware': bool(prediction),
                'confidence': float(max(probabilities)),
                'ransomware_probability': float(probabilities[1]) if len(probabilities) > 1 else 0.0,
                'benign_probability': float(probabilities[0])
            }
            
            logger.debug(f"Prediction: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error making prediction: {e}")
            return {
                'is_ransomware': False,
                'confidence': 0.0,
                'ransomware_probability': 0.0,
                'benign_probability': 0.0,
                'error': str(e)
            }
    
    def save_model(self, model_path=None, scaler_path=None):
        """Save trained model and scaler"""
        try:
            model_path = model_path or self.model_path
            scaler_path = scaler_path or self.scaler_path
            
            if model_path:
                joblib.dump(self.model, model_path)
                logger.info(f"✓ Model saved to {model_path}")
            
            if scaler_path:
                joblib.dump(self.scaler, scaler_path)
                logger.info(f"✓ Scaler saved to {scaler_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def load_model(self, model_path=None, scaler_path=None):
        """Load pre-trained model and scaler"""
        try:
            model_path = model_path or self.model_path
            scaler_path = scaler_path or self.scaler_path
            
            if model_path and os.path.exists(model_path):
                self.model = joblib.load(model_path)
                self.is_trained = True
                logger.info(f"✓ Model loaded from {model_path}")
            else:
                logger.warning(f"Model file not found: {model_path}")
                return False
            
            if scaler_path and os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info(f"✓ Scaler loaded from {scaler_path}")
            else:
                logger.warning(f"Scaler file not found: {scaler_path}")
                # Create new scaler if not found
                self.scaler = StandardScaler()
            
            return True
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self.is_trained = False
            return False


def create_training_dataset():
    """Create synthetic training dataset for demonstration"""
    
    logger.info("Creating synthetic training dataset")
    
    # Ransomware characteristics (labeled as 1)
    # High entropy, packed, many crypto APIs, suspicious strings
    ransomware_samples = []
    
    for i in range(100):
        sample = [
            np.random.randint(100000, 2000000),      # size
            np.random.uniform(7.2, 7.9),             # high entropy
            np.random.randint(3, 8),                 # num_sections
            np.random.randint(50, 150),              # num_imports
            1,                                        # is_packed
            0,                                        # is_dll
            np.random.randint(5, 15),                # num_suspicious_apis
            1,                                        # is_exe
            0,                                        # is_office_macro
            0,                                        # is_archive
            1,                                        # is_high_entropy
            np.random.randint(3, 10),                # num_suspicious_strings
            np.random.uniform(7.0, 7.8)              # max_section_entropy
        ]
        ransomware_samples.append(sample)
    
    # Add some macro-based ransomware
    for i in range(20):
        sample = [
            np.random.randint(20000, 100000),        # size
            np.random.uniform(6.5, 7.2),             # entropy
            0,                                        # num_sections
            0,                                        # num_imports
            0,                                        # is_packed
            0,                                        # is_dll
            0,                                        # num_suspicious_apis
            0,                                        # is_exe
            1,                                        # is_office_macro
            0,                                        # is_archive
            1,                                        # is_high_entropy
            np.random.randint(2, 8),                 # num_suspicious_strings
            0                                         # max_section_entropy
        ]
        ransomware_samples.append(sample)
    
    # Benign software characteristics (labeled as 0)
    # Lower entropy, not packed, fewer crypto APIs
    benign_samples = []
    
    for i in range(100):
        sample = [
            np.random.randint(500000, 5000000),      # size (larger)
            np.random.uniform(4.5, 6.5),             # lower entropy
            np.random.randint(4, 12),                # num_sections
            np.random.randint(100, 300),             # more imports
            0,                                        # not packed
            np.random.choice([0, 1]),                # may be dll
            np.random.randint(0, 5),                 # fewer suspicious APIs
            1,                                        # is_exe
            0,                                        # is_office_macro
            0,                                        # is_archive
            0,                                        # not high entropy
            np.random.randint(0, 3),                 # few suspicious strings
            np.random.uniform(4.0, 6.5)              # lower section entropy
        ]
        benign_samples.append(sample)
    
    # Add some benign documents
    for i in range(30):
        sample = [
            np.random.randint(10000, 200000),        # size
            np.random.uniform(3.5, 5.5),             # low entropy
            0,                                        # num_sections
            0,                                        # num_imports
            0,                                        # is_packed
            0,                                        # is_dll
            0,                                        # num_suspicious_apis
            0,                                        # is_exe
            0,                                        # is_office_macro (normal doc)
            0,                                        # is_archive
            0,                                        # is_high_entropy
            0,                                        # num_suspicious_strings
            0                                         # max_section_entropy
        ]
        benign_samples.append(sample)
    
    # Combine datasets
    X = np.array(ransomware_samples + benign_samples)
    y = np.array([1] * len(ransomware_samples) + [0] * len(benign_samples))
    
    logger.info(f"Created dataset: {len(ransomware_samples)} ransomware, {len(benign_samples)} benign")
    
    return X, y


if __name__ == "__main__":
    """Train and save a model"""
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Create training data
    X, y = create_training_dataset()
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Initialize classifier
    classifier = RansomwareClassifier(
        model_path='models/ransomware_classifier.pkl',
        scaler_path='models/feature_scaler.pkl'
    )
    
    # Train model
    classifier.train(X_train, y_train, X_test, y_test)
    
    # Save model
    os.makedirs('models', exist_ok=True)
    classifier.save_model()
    
    print("\n✓ Model training complete and saved!")
