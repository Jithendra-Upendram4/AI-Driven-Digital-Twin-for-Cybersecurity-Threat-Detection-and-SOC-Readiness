"""
Matplotlib Fallback Dashboard
==============================
Purpose: Fallback visualization if Streamlit fails.
Generates static PNG charts for reports.

Run with: python visualization/matplotlib_dashboard.py
"""

import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def create_dashboard():
    """Generate static dashboard charts using matplotlib."""
    
    # Load data
    data_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "processed_logs.csv"
    )
    
    if not os.path.exists(data_path):
        print("ERROR: No processed data found. Run main.py first!")
        return
    
    df = pd.read_csv(data_path)
    
    # Create output directory
    output_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "reports",
        "charts"
    )
    os.makedirs(output_dir, exist_ok=True)
    
    # Create figure with subplots
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Security Digital Twin - Threat Analysis Dashboard', fontsize=16, fontweight='bold')
    
    # Chart 1: Rule-Based Detection
    ax1 = axes[0, 0]
    threat_counts = df['rule_threat'].value_counts()
    colors = ['green' if t == 'Normal' else 'red' for t in threat_counts.index]
    threat_counts.plot(kind='bar', ax=ax1, color=colors)
    ax1.set_title('Rule-Based Detection Results')
    ax1.set_xlabel('Threat Type')
    ax1.set_ylabel('Count')
    ax1.tick_params(axis='x', rotation=45)
    
    # Chart 2: ML Anomaly Detection
    ax2 = axes[0, 1]
    if 'anomaly_label' in df.columns:
        anomaly_counts = df['anomaly_label'].value_counts()
        colors = ['green' if a == 'Normal' else 'orange' for a in anomaly_counts.index]
        anomaly_counts.plot(kind='bar', ax=ax2, color=colors)
        ax2.set_title('ML Anomaly Detection (Isolation Forest)')
        ax2.set_xlabel('Classification')
        ax2.set_ylabel('Count')
    
    # Chart 3: Threat Severity
    ax3 = axes[1, 0]
    if 'threat_severity' in df.columns:
        severity_counts = df['threat_severity'].value_counts()
        severity_colors = {'LOW': 'green', 'MEDIUM': 'yellow', 'HIGH': 'orange', 'CRITICAL': 'red'}
        colors = [severity_colors.get(s, 'gray') for s in severity_counts.index]
        severity_counts.plot(kind='bar', ax=ax3, color=colors)
        ax3.set_title('Threat Severity Distribution')
        ax3.set_xlabel('Severity Level')
        ax3.set_ylabel('Count')
    
    # Chart 4: Packet Rate Distribution
    ax4 = axes[1, 1]
    ax4.hist(df['packet_rate'], bins=20, color='steelblue', edgecolor='black', alpha=0.7)
    ax4.axvline(x=1000, color='red', linestyle='--', label='DDoS Threshold (1000)')
    ax4.set_title('Packet Rate Distribution')
    ax4.set_xlabel('Packet Rate')
    ax4.set_ylabel('Frequency')
    ax4.legend()
    
    plt.tight_layout()
    
    # Save figure
    output_path = os.path.join(output_dir, 'dashboard.png')
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"[DASHBOARD] Saved chart to {output_path}")
    
    # Show plot
    plt.show()
    
    return output_path


if __name__ == "__main__":
    create_dashboard()
