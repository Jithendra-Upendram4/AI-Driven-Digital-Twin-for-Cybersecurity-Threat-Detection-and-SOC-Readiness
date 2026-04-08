"""
Digital Twin Security System - Main Orchestrator
==================================================
AI-Driven Digital Twin for Cybersecurity Threat Detection and SOC Readiness

This is the main entry point that orchestrates:
1. Log Ingestion
2. Rule-Based Detection
3. ML-Based Anomaly Detection
4. Threat Storage
5. Report Generation

Run with: python main.py
Dashboard: streamlit run visualization/dashboard.py
"""

import os
import sys

# Ensure proper imports from project root
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from ingestion.log_ingestion import load_logs, validate_logs, save_processed_logs
from twin_core.rule_engine import rule_based_detection
from twin_core.anomaly_engine import anomaly_detection
from storage.threat_store import store_threats, get_threat_statistics
from reports.generate_report import generate_report, generate_quick_summary


def main():
    """
    Main orchestrator for the Digital Twin Security System.
    Executes the complete threat detection pipeline.
    """
    
    print("=" * 70)
    print("   AI-DRIVEN DIGITAL TWIN FOR CYBERSECURITY THREAT DETECTION")
    print("                    SOC READINESS SYSTEM")
    print("=" * 70)
    print()
    
    # Define paths
    raw_logs_path = os.path.join(PROJECT_ROOT, "data", "raw_logs.csv")
    processed_logs_path = os.path.join(PROJECT_ROOT, "data", "processed_logs.csv")
    reports_dir = os.path.join(PROJECT_ROOT, "reports")
    
    try:
        # =============================================
        # STEP 1: LOG INGESTION
        # =============================================
        print("\n[STEP 1] LOG INGESTION")
        print("-" * 40)
        
        df = load_logs(raw_logs_path)
        validate_logs(df)
        
        # =============================================
        # STEP 2: RULE-BASED DETECTION
        # =============================================
        print("\n[STEP 2] RULE-BASED THREAT DETECTION")
        print("-" * 40)
        
        df = rule_based_detection(df)
        
        # =============================================
        # STEP 3: ML-BASED ANOMALY DETECTION
        # =============================================
        print("\n[STEP 3] ML-BASED ANOMALY DETECTION")
        print("-" * 40)
        
        df = anomaly_detection(df, contamination=0.05)
        
        # =============================================
        # STEP 4: THREAT STORAGE
        # =============================================
        print("\n[STEP 4] PERSISTING THREATS TO DATABASE")
        print("-" * 40)
        
        db_path = os.path.join(PROJECT_ROOT, "threats.db")
        store_threats(df, db_path)
        
        # =============================================
        # STEP 5: SAVE PROCESSED LOGS
        # =============================================
        print("\n[STEP 5] SAVING PROCESSED LOGS")
        print("-" * 40)
        
        save_processed_logs(df, processed_logs_path)
        
        # =============================================
        # STEP 6: GENERATE REPORT
        # =============================================
        print("\n[STEP 6] GENERATING INCIDENT REPORT")
        print("-" * 40)
        
        generate_report(df, reports_dir)
        
        # =============================================
        # EXECUTION COMPLETE
        # =============================================
        print("\n" + "=" * 70)
        print("           DIGITAL TWIN EXECUTION COMPLETE")
        print("=" * 70)
        
        # Print quick summary
        print(generate_quick_summary(df))
        
        # Print statistics
        stats = get_threat_statistics(db_path)
        print(f"\n[DATABASE] Total incidents stored: {stats.get('total_incidents', 0)}")
        print(f"[DATABASE] ML-detected anomalies: {stats.get('ml_anomalies', 0)}")
        
        print("\n[NEXT STEPS]")
        print("  1. View dashboard: streamlit run visualization/dashboard.py")
        print("  2. Check reports folder for incident reports")
        print("  3. Query threats.db for detailed analysis")
        print()
        
        return True
        
    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}")
        print("Make sure raw_logs.csv exists in the data/ folder.")
        return False
        
    except Exception as e:
        print(f"\n[ERROR] Execution failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
