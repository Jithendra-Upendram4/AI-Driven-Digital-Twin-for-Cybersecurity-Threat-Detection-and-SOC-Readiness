"""
Security Incident Report Generator
====================================
Purpose: Generate SOC-ready incident reports for security analysts.

Report Types:
- Text summary report
- Detailed incident log
- Executive summary
"""

import pandas as pd
import os
from datetime import datetime
from typing import Optional


def generate_report(df: pd.DataFrame, output_dir: str = "reports") -> str:
    """
    Generate comprehensive security incident report.
    
    Args:
        df: DataFrame with threat detection results
        output_dir: Directory for report output
        
    Returns:
        Path to generated report file
    """
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(output_dir, f"incident_report_{timestamp}.txt")
    
    with open(report_path, "w") as f:
        # Header
        f.write("=" * 70 + "\n")
        f.write("         SECURITY INCIDENT REPORT - DIGITAL TWIN SYSTEM\n")
        f.write("=" * 70 + "\n\n")
        
        # Report metadata
        f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Log Entries Analyzed: {len(df)}\n")
        f.write("\n" + "-" * 70 + "\n\n")
        
        # Executive Summary
        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 40 + "\n")
        
        total_threats = len(df[df['rule_threat'] != 'Normal'])
        anomalies = len(df[df['anomaly'] == -1]) if 'anomaly' in df.columns else 0
        
        f.write(f"• Total Security Events: {len(df)}\n")
        f.write(f"• Rule-Based Threats Detected: {total_threats}\n")
        f.write(f"• ML-Detected Anomalies: {anomalies}\n")
        
        # Calculate threat percentage
        threat_pct = (total_threats / len(df) * 100) if len(df) > 0 else 0
        f.write(f"• Threat Percentage: {threat_pct:.2f}%\n")
        f.write("\n")
        
        # Threat Breakdown
        f.write("-" * 70 + "\n\n")
        f.write("THREAT DETECTION BREAKDOWN (RULE-BASED)\n")
        f.write("-" * 40 + "\n")
        
        threat_counts = df['rule_threat'].value_counts()
        for threat_type, count in threat_counts.items():
            percentage = (count / len(df) * 100)
            f.write(f"  {threat_type}: {count} ({percentage:.1f}%)\n")
        f.write("\n")
        
        # Severity Analysis
        if 'threat_severity' in df.columns:
            f.write("-" * 70 + "\n\n")
            f.write("THREAT SEVERITY ANALYSIS\n")
            f.write("-" * 40 + "\n")
            
            severity_counts = df['threat_severity'].value_counts()
            for severity, count in severity_counts.items():
                f.write(f"  {severity}: {count}\n")
            f.write("\n")
        
        # ML Anomaly Analysis
        if 'anomaly' in df.columns:
            f.write("-" * 70 + "\n\n")
            f.write("ML ANOMALY DETECTION (ISOLATION FOREST)\n")
            f.write("-" * 40 + "\n")
            
            normal_count = len(df[df['anomaly'] == 1])
            anomaly_count = len(df[df['anomaly'] == -1])
            
            f.write(f"  Normal Traffic: {normal_count}\n")
            f.write(f"  Anomalies Detected: {anomaly_count}\n")
            f.write("\n")
        
        # Top Threats Detail
        f.write("-" * 70 + "\n\n")
        f.write("TOP THREAT INCIDENTS\n")
        f.write("-" * 40 + "\n")
        
        threats_df = df[df['rule_threat'] != 'Normal'].head(10)
        if len(threats_df) > 0:
            for idx, row in threats_df.iterrows():
                f.write(f"\n  Incident #{idx + 1}:\n")
                f.write(f"    - Threat Type: {row.get('rule_threat', 'N/A')}\n")
                f.write(f"    - Source IP: {row.get('source_ip', 'N/A')}\n")
                f.write(f"    - Destination IP: {row.get('dest_ip', 'N/A')}\n")
                f.write(f"    - Severity: {row.get('threat_severity', 'N/A')}\n")
                f.write(f"    - Timestamp: {row.get('timestamp', 'N/A')}\n")
        else:
            f.write("  No threats detected.\n")
        
        # Recommendations
        f.write("\n" + "-" * 70 + "\n\n")
        f.write("RECOMMENDATIONS\n")
        f.write("-" * 40 + "\n")
        
        if total_threats > 0:
            if 'Brute Force Attack' in threat_counts.index:
                f.write("  • Implement account lockout policies\n")
                f.write("  • Enable multi-factor authentication\n")
            if 'DDoS Attack' in threat_counts.index:
                f.write("  • Configure rate limiting on firewalls\n")
                f.write("  • Consider DDoS mitigation services\n")
            if 'Data Exfiltration' in threat_counts.index:
                f.write("  • Review outbound traffic policies\n")
                f.write("  • Implement data loss prevention (DLP)\n")
        else:
            f.write("  • Continue monitoring - no immediate actions required\n")
        
        # Footer
        f.write("\n" + "=" * 70 + "\n")
        f.write("                    END OF REPORT\n")
        f.write("         Digital Twin Security System - SOC Ready\n")
        f.write("=" * 70 + "\n")
    
    print(f"\n[REPORT] Generated incident report: {report_path}")
    return report_path


def generate_quick_summary(df: pd.DataFrame) -> str:
    """
    Generate quick text summary for console output.
    
    Args:
        df: DataFrame with detection results
        
    Returns:
        Summary string
    """
    lines = [
        "\n" + "=" * 50,
        "QUICK THREAT SUMMARY",
        "=" * 50
    ]
    
    lines.append(f"Total Events: {len(df)}")
    lines.append(f"Threats: {len(df[df['rule_threat'] != 'Normal'])}")
    
    if 'anomaly' in df.columns:
        lines.append(f"ML Anomalies: {len(df[df['anomaly'] == -1])}")
    
    lines.append("\nBreakdown:")
    for threat, count in df['rule_threat'].value_counts().items():
        lines.append(f"  - {threat}: {count}")
    
    lines.append("=" * 50)
    
    return "\n".join(lines)


if __name__ == "__main__":
    # Test report generation
    test_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "processed_logs.csv"
    )
    
    if os.path.exists(test_path):
        df = pd.read_csv(test_path)
        report_dir = os.path.dirname(os.path.abspath(__file__))
        generate_report(df, report_dir)
        print(generate_quick_summary(df))
    else:
        print("No processed logs found. Run main.py first.")
