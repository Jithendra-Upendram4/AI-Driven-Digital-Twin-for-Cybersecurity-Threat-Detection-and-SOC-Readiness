"""
Threat Intelligence Store
==========================
Purpose: Persist detected threats to database for SOC analysis and SIEM integration.

Database: SQLite (production-ready, zero configuration)
- Can be easily migrated to MongoDB, PostgreSQL, or Elasticsearch
- SIEM systems can query this database directly

Tables:
- incidents: All detected security incidents
- threat_summary: Aggregated threat statistics
"""

import sqlite3
import pandas as pd
import os
from datetime import datetime
from typing import List, Dict, Optional


# Database file path
DB_PATH = "threats.db"


def store_threats(df: pd.DataFrame, db_path: str = DB_PATH) -> None:
    """
    Store detected threats to SQLite database.
    
    Args:
        df: DataFrame containing threat detection results
        db_path: Path to SQLite database file
    """
    conn = sqlite3.connect(db_path)
    
    # Store all incidents
    df.to_sql("incidents", conn, if_exists="replace", index=False)
    
    # Create threat summary table
    summary = create_threat_summary(df)
    summary.to_sql("threat_summary", conn, if_exists="replace", index=False)
    
    # Log storage info
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM incidents")
    count = cursor.fetchone()[0]
    
    print(f"\n[THREAT STORE] Stored {count} incidents to {db_path}")
    print(f"[THREAT STORE] Tables created: incidents, threat_summary")
    
    conn.close()


def create_threat_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create aggregated threat summary for dashboard/reports.
    
    Args:
        df: DataFrame with detection results
        
    Returns:
        Summary DataFrame with threat counts and statistics
    """
    summary_data = []
    
    # Rule-based threat summary
    if 'rule_threat' in df.columns:
        for threat_type, count in df['rule_threat'].value_counts().items():
            summary_data.append({
                'threat_type': threat_type,
                'detection_method': 'Rule-Based',
                'count': count,
                'timestamp': datetime.now().isoformat()
            })
    
    # Anomaly-based summary
    if 'anomaly' in df.columns:
        anomaly_count = (df['anomaly'] == -1).sum()
        normal_count = (df['anomaly'] == 1).sum()
        summary_data.append({
            'threat_type': 'ML-Detected Anomaly',
            'detection_method': 'Isolation Forest',
            'count': anomaly_count,
            'timestamp': datetime.now().isoformat()
        })
        summary_data.append({
            'threat_type': 'Normal Traffic',
            'detection_method': 'Isolation Forest',
            'count': normal_count,
            'timestamp': datetime.now().isoformat()
        })
    
    return pd.DataFrame(summary_data)


def query_threats(db_path: str = DB_PATH, threat_type: Optional[str] = None) -> pd.DataFrame:
    """
    Query threats from database with optional filtering.
    
    Args:
        db_path: Path to SQLite database
        threat_type: Optional filter for specific threat type
        
    Returns:
        DataFrame with matching threats
    """
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database not found: {db_path}")
    
    conn = sqlite3.connect(db_path)
    
    if threat_type:
        query = f"SELECT * FROM incidents WHERE rule_threat = ?"
        df = pd.read_sql_query(query, conn, params=(threat_type,))
    else:
        df = pd.read_sql_query("SELECT * FROM incidents", conn)
    
    conn.close()
    return df


def get_threat_statistics(db_path: str = DB_PATH) -> Dict:
    """
    Get comprehensive threat statistics from database.
    
    Args:
        db_path: Path to SQLite database
        
    Returns:
        Dictionary with threat statistics
    """
    if not os.path.exists(db_path):
        return {"error": "Database not found"}
    
    conn = sqlite3.connect(db_path)
    
    stats = {}
    
    # Total incidents
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM incidents")
    stats['total_incidents'] = cursor.fetchone()[0]
    
    # Threat type breakdown
    df = pd.read_sql_query(
        "SELECT rule_threat, COUNT(*) as count FROM incidents GROUP BY rule_threat",
        conn
    )
    stats['threat_breakdown'] = df.to_dict('records')
    
    # Anomaly count
    try:
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE anomaly = -1")
        stats['ml_anomalies'] = cursor.fetchone()[0]
    except:
        stats['ml_anomalies'] = 0
    
    conn.close()
    return stats


def export_to_csv(db_path: str = DB_PATH, output_path: str = "exports/threats_export.csv") -> str:
    """
    Export threats from database to CSV for external analysis.
    
    Args:
        db_path: Path to SQLite database
        output_path: Path for output CSV file
        
    Returns:
        Path to exported CSV file
    """
    df = query_threats(db_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[THREAT STORE] Exported {len(df)} records to {output_path}")
    return output_path
