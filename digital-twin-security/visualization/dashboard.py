"""
Security Digital Twin Dashboard
================================
Purpose: Real-time visualization of threat detection results.
Technology: Streamlit (fallback: matplotlib)

Run with: streamlit run visualization/dashboard.py
"""

import streamlit as st
import pandas as pd
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


KALI_VM_IP = "192.168.56.101"


def load_data():
    """Load processed logs from CSV."""
    data_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "processed_logs.csv"
    )
    
    if not os.path.exists(data_path):
        st.error("⚠️ No processed data found. Run main.py first!")
        st.stop()
    
    return pd.read_csv(data_path)


def main():
    """Main dashboard application."""
    
    # Page configuration
    st.set_page_config(
        page_title="Security Digital Twin",
        page_icon="🛡️",
        layout="wide"
    )
    
    # Title
    st.title("🛡️ AI-Driven Security Digital Twin Dashboard")
    st.markdown("**Real-time Threat Detection & SOC Readiness**")
    st.markdown(f"**Protected System:** Kali Linux VM | **Target IP:** {KALI_VM_IP}")
    st.divider()
    
    # Load data
    df = load_data()
    
    # Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    
    total_events = len(df)
    threats_detected = len(df[df['rule_threat'] != 'Normal'])
    anomalies = len(df[df['anomaly'] == -1]) if 'anomaly' in df.columns else 0
    critical_alerts = len(df[df['threat_severity'] == 'CRITICAL']) if 'threat_severity' in df.columns else 0
    
    col1.metric("📊 Total Events", total_events)
    col2.metric("🚨 Threats Detected", threats_detected, delta=f"{(threats_detected/total_events*100):.1f}%")
    col3.metric("🤖 ML Anomalies", anomalies)
    col4.metric("⚠️ Critical Alerts", critical_alerts)
    
    st.divider()
    
    # Charts Row
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.subheader("📈 Rule-Based Detection Results")
        threat_counts = df['rule_threat'].value_counts()
        st.bar_chart(threat_counts)
    
    with col_right:
        st.subheader("🔍 ML Anomaly Detection")
        if 'anomaly_label' in df.columns:
            anomaly_counts = df['anomaly_label'].value_counts()
            st.bar_chart(anomaly_counts)
        else:
            st.info("ML detection data not available")
    
    st.divider()
    
    # Threat Severity Distribution
    if 'threat_severity' in df.columns:
        st.subheader("⚡ Threat Severity Distribution")
        severity_counts = df['threat_severity'].value_counts()
        st.bar_chart(severity_counts)
    
    st.divider()
    
    # Detailed Threats Table
    st.subheader("📋 Detected Threats (Non-Normal)")
    threats_df = df[df['rule_threat'] != 'Normal']
    if len(threats_df) > 0:
        display_cols = ['timestamp', 'source_ip', 'dest_ip', 'rule_threat', 'response_action', 'threat_severity', 'anomaly_label']
        display_cols = [col for col in display_cols if col in threats_df.columns]
        st.dataframe(threats_df[display_cols], use_container_width=True)
    else:
        st.success("✅ No threats detected!")
    
    st.divider()
    
    # ML Anomalies Detail
    st.subheader("🤖 ML-Detected Anomalies")
    if 'anomaly' in df.columns:
        anomalies_df = df[df['anomaly'] == -1]
        if len(anomalies_df) > 0:
            display_cols = ['timestamp', 'source_ip', 'packet_rate', 'bytes_sent', 'anomaly_score']
            display_cols = [col for col in display_cols if col in anomalies_df.columns]
            st.dataframe(anomalies_df[display_cols].sort_values('anomaly_score'), use_container_width=True)
        else:
            st.success("✅ No anomalies detected by ML model!")
    
    st.divider()
    
    # Raw Data Explorer
    with st.expander("📊 View Raw Data"):
        st.dataframe(df, use_container_width=True)
    
    # Footer
    st.divider()
    st.markdown("""
    ---
    **Digital Twin Security System** | SOC-Ready | SIEM-Compatible  
    *Powered by Rule-Based Detection + Isolation Forest ML*
    """)


if __name__ == "__main__":
    main()
