"""
Log Ingestion Module
====================
Purpose: Simulate real-world enterprise log ingestion.
Handles loading raw network/web server logs from CSV and PCAP formats and preprocessing them for analysis.
"""

import pandas as pd
import os
try:
    from scapy.all import rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Protected target system (Kali VM)
KALI_VM_IP = "192.168.56.101"


def load_pcap(path: str) -> pd.DataFrame:
    """
    Load network packet data from PCAP file and convert to DataFrame.
    
    Args:
        path: Path to the PCAP file
        
    Returns:
        Preprocessed pandas DataFrame with packet information
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("scapy is required for PCAP parsing. Install it with: pip install scapy")
    
    if not os.path.exists(path):
        raise FileNotFoundError(f"PCAP file not found: {path}")
    
    packets = rdpcap(path)
    data = []
    
    print(f"[LOG INGESTION] Parsing PCAP file...")
    for idx, pkt in enumerate(packets):
        if idx % 10000 == 0:
            print(f"  Processing packet {idx}/{len(packets)}...")
        
        try:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = 'TCP' if TCP in pkt else ('UDP' if UDP in pkt else 'Other')
                
                # Extract port information
                port = 0
                if TCP in pkt:
                    port = pkt[TCP].dport
                elif UDP in pkt:
                    port = pkt[UDP].dport
                
                # Calculate packet size
                packet_size = len(pkt)
                
                data.append({
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'protocol': protocol,
                    'port': port,
                    'packet_rate': 1,  # Each packet = 1
                    'bytes_sent': packet_size,
                    'bytes_received': packet_size,
                    'failed_logins': 0,
                    'duration': 0,
                })
        except Exception as e:
            continue
    
    df = pd.DataFrame(data)
    print(f"[LOG INGESTION] Loaded {len(df)} packets from {path}")
    return df


def load_logs(path: str) -> pd.DataFrame:
    """
    Load and preprocess log data from CSV or PCAP file.
    
    Args:
        path: Path to the raw log file (CSV or PCAP)
        
    Returns:
        Preprocessed pandas DataFrame with missing values handled
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Log file not found: {path}")
    
    # Check file format
    if path.endswith('.pcap'):
        df = load_pcap(path)
    else:
        df = pd.read_csv(path)
    
    # Handle missing values - fill with 0 for numeric columns
    df.fillna(0, inplace=True)
    
    # Convert timestamp to datetime if present
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    # Process only traffic destined for the protected Kali VM.
    if 'dest_ip' in df.columns:
        before_count = len(df)
        df = df[df['dest_ip'] == KALI_VM_IP].copy()
        print(f"[LOG INGESTION] Target filter applied: {before_count} -> {len(df)} (dest_ip={KALI_VM_IP})")
    
    print(f"[LOG INGESTION] Loaded {len(df)} log entries from {path}")
    print(f"[LOG INGESTION] Columns: {list(df.columns)}")
    
    return df


def validate_logs(df: pd.DataFrame) -> bool:
    """
    Validate that required columns exist for threat detection.
    
    Args:
        df: DataFrame to validate
        
    Returns:
        True if valid, raises ValueError otherwise
    """
    required_columns = ['packet_rate', 'bytes_sent', 'failed_logins']
    missing = [col for col in required_columns if col not in df.columns]
    
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    
    print("[LOG INGESTION] Validation passed - all required columns present")
    return True


def save_processed_logs(df: pd.DataFrame, output_path: str) -> None:
    """
    Save processed logs to CSV file.
    
    Args:
        df: Processed DataFrame to save
        output_path: Path for output CSV file
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[LOG INGESTION] Saved processed logs to {output_path}")
