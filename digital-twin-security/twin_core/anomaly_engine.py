"""
ML-Based Anomaly Detection Engine
==================================
Purpose: Detect unknown/zero-day attacks using unsupervised machine learning.

Why Isolation Forest?
- Unsupervised: No labeled attack data required
- Efficient: O(n) complexity, handles large datasets
- Perfect for unknown attacks: Identifies outliers without prior knowledge
- Industry standard: Used in production SIEM systems

Model Output:
- 1: Normal behavior (inlier)
- -1: Anomalous behavior (outlier)
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Tuple, List


def anomaly_detection(df: pd.DataFrame, contamination: float = 0.05) -> pd.DataFrame:
    """
    Apply Isolation Forest anomaly detection on network traffic features.
    
    Args:
        df: DataFrame containing log entries with numeric features
        contamination: Expected proportion of anomalies (default 5%)
        
    Returns:
        DataFrame with 'anomaly' and 'anomaly_score' columns added
    """
    # Feature selection for anomaly detection
    feature_columns = ['packet_rate', 'bytes_sent']
    
    # Validate features exist
    missing_features = [col for col in feature_columns if col not in df.columns]
    if missing_features:
        raise ValueError(f"Missing required features: {missing_features}")
    
    features = df[feature_columns].copy()
    
    # Handle any remaining NaN values
    features = features.fillna(0)
    
    # Standardize features for better model performance
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    # Train Isolation Forest model
    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        n_jobs=-1  # Use all CPU cores
    )
    
    # Fit and predict
    df['anomaly'] = model.fit_predict(features_scaled)
    
    # Get anomaly scores (lower = more anomalous)
    df['anomaly_score'] = model.decision_function(features_scaled)
    
    # Convert to human-readable labels
    df['anomaly_label'] = df['anomaly'].map({1: 'Normal', -1: 'Anomaly'})
    
    # Log detection summary
    anomaly_count = (df['anomaly'] == -1).sum()
    normal_count = (df['anomaly'] == 1).sum()
    
    print("\n[ANOMALY ENGINE] ML Detection Summary:")
    print(f"  - Normal traffic: {normal_count}")
    print(f"  - Anomalies detected: {anomaly_count}")
    print(f"  - Contamination rate: {contamination*100:.1f}%")
    
    return df


def get_anomaly_details(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract detailed information about detected anomalies.
    
    Args:
        df: DataFrame with anomaly detection results
        
    Returns:
        DataFrame containing only anomalous entries with details
    """
    if 'anomaly' not in df.columns:
        raise ValueError("Run anomaly_detection() first")
    
    anomalies = df[df['anomaly'] == -1].copy()
    
    if len(anomalies) > 0:
        # Sort by anomaly score (most anomalous first)
        anomalies = anomalies.sort_values('anomaly_score', ascending=True)
    
    return anomalies


def get_model_info() -> dict:
    """
    Return model information for documentation/viva.
    
    Returns:
        Dictionary with model specifications
    """
    return {
        "model": "Isolation Forest",
        "type": "Unsupervised Anomaly Detection",
        "library": "scikit-learn",
        "features_used": ["packet_rate", "bytes_sent"],
        "contamination": "5% (configurable)",
        "why_isolation_forest": [
            "Unsupervised - no labeled data required",
            "Efficient O(n) complexity",
            "Perfect for unknown/zero-day attacks",
            "Industry standard in SIEM systems",
            "Handles high-dimensional data well"
        ],
        "output": {
            "1": "Normal (inlier)",
            "-1": "Anomaly (outlier)"
        }
    }
