#!/usr/bin/env python3
"""
Train Machine Learning Model for Ransomware Detection
This script creates and trains the ML model used by RansomGuard Email Shield
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.ml_classifier import RansomwareClassifier, create_training_dataset
from sklearn.model_selection import train_test_split
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Train and save ransomware detection model"""
    
    print("="*60)
    print("RansomGuard Email Shield - Model Training")
    print("="*60)
    print()
    
    # Create models directory
    os.makedirs('models', exist_ok=True)
    
    # Create training dataset
    print("Creating synthetic training dataset...")
    X, y = create_training_dataset()
    print(f"✓ Dataset created: {len(X)} samples")
    print(f"  - Ransomware samples: {sum(y)}")
    print(f"  - Benign samples: {len(y) - sum(y)}")
    print()
    
    # Split data
    print("Splitting data into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, 
        test_size=0.2, 
        random_state=42,
        stratify=y
    )
    print(f"✓ Training set: {len(X_train)} samples")
    print(f"✓ Test set: {len(X_test)} samples")
    print()
    
    # Initialize classifier
    print("Initializing Random Forest classifier...")
    classifier = RansomwareClassifier(
        model_path='models/ransomware_classifier.pkl',
        scaler_path='models/feature_scaler.pkl'
    )
    print("✓ Classifier initialized")
    print()
    
    # Train model
    print("Training model...")
    print("-" * 60)
    success = classifier.train(X_train, y_train, X_test, y_test)
    print("-" * 60)
    
    if success:
        print()
        print("Saving model...")
        classifier.save_model()
        print()
        print("="*60)
        print("✓ Model training complete!")
        print("="*60)
        print()
        print("Model files saved:")
        print(f"  - models/ransomware_classifier.pkl")
        print(f"  - models/feature_scaler.pkl")
        print()
        print("You can now run the application with:")
        print("  python app.py")
        print()
    else:
        print()
        print("✗ Model training failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
