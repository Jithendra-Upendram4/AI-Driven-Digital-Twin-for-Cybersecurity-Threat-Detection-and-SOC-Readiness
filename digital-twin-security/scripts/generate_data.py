"""
Data Generator for Digital Twin Security System
Generates 100,000 synthetic log entries with 12 attack categories in PCAP format
"""

import pandas as pd
import random
from datetime import datetime, timedelta
import os
import sys
from scapy.all import IP, TCP, UDP, wrpcap, Packet
import struct

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

random.seed(42)

# Protected target system (Kali VM)
KALI_VM_IP = "192.168.56.101"

# Attack categories and their characteristics
attack_profiles = {
    'Normal': {
        'packet_rate': (50, 300), 
        'bytes_sent': (500, 5000), 
        'bytes_received': (200, 3000), 
        'failed_logins': (0, 2), 
        'ports': [80, 443, 8080, 3000, 5000], 
        'protocols': ['TCP', 'TCP', 'TCP', 'UDP'],
        'duration': (10, 120)
    },
    'DDoS Attack': {
        'packet_rate': (1500, 5000), 
        'bytes_sent': (50000, 200000), 
        'bytes_received': (25000, 100000), 
        'failed_logins': (0, 1), 
        'ports': [80, 443, 53], 
        'protocols': ['UDP', 'TCP', 'UDP'],
        'duration': (1, 10)
    },
    'Brute Force Attack': {
        'packet_rate': (80, 250), 
        'bytes_sent': (800, 2500), 
        'bytes_received': (400, 1500), 
        'failed_logins': (6, 50), 
        'ports': [22, 3389, 21, 23], 
        'protocols': ['TCP'],
        'duration': (60, 300)
    },
    'Port Scan': {
        'packet_rate': (300, 800), 
        'bytes_sent': (100, 500), 
        'bytes_received': (50, 300), 
        'failed_logins': (0, 1), 
        'ports': [22, 23, 80, 443, 3389, 445, 139, 8080, 21, 25, 110, 143], 
        'protocols': ['TCP'],
        'duration': (1, 5)
    },
    'SQL Injection': {
        'packet_rate': (100, 400), 
        'bytes_sent': (2000, 8000), 
        'bytes_received': (5000, 30000), 
        'failed_logins': (0, 3), 
        'ports': [80, 443, 3306, 1433, 5432, 8080], 
        'protocols': ['TCP'],
        'duration': (5, 30)
    },
    'Data Exfiltration': {
        'packet_rate': (200, 600), 
        'bytes_sent': (80000, 500000), 
        'bytes_received': (1000, 5000), 
        'failed_logins': (0, 1), 
        'ports': [443, 22, 21, 53, 8443], 
        'protocols': ['TCP', 'TCP', 'TCP', 'UDP'],
        'duration': (30, 180)
    },
    'Malware C2': {
        'packet_rate': (50, 150), 
        'bytes_sent': (1000, 5000), 
        'bytes_received': (2000, 10000), 
        'failed_logins': (0, 0), 
        'ports': [443, 8443, 4444, 6666, 31337, 1337, 9999], 
        'protocols': ['TCP'],
        'duration': (60, 600)
    },
    'DNS Tunneling': {
        'packet_rate': (400, 1200), 
        'bytes_sent': (3000, 15000), 
        'bytes_received': (4000, 20000), 
        'failed_logins': (0, 0), 
        'ports': [53], 
        'protocols': ['UDP'],
        'duration': (30, 300)
    },
    'Privilege Escalation': {
        'packet_rate': (80, 200), 
        'bytes_sent': (1500, 6000), 
        'bytes_received': (2000, 8000), 
        'failed_logins': (2, 5), 
        'ports': [445, 139, 135, 5985, 5986], 
        'protocols': ['TCP'],
        'duration': (10, 60)
    },
    'Ransomware Activity': {
        'packet_rate': (150, 500), 
        'bytes_sent': (10000, 50000), 
        'bytes_received': (500, 3000), 
        'failed_logins': (0, 2), 
        'ports': [445, 139, 443, 8080], 
        'protocols': ['TCP'],
        'duration': (30, 120)
    },
    'Cryptojacking': {
        'packet_rate': (100, 350), 
        'bytes_sent': (2000, 8000), 
        'bytes_received': (3000, 12000), 
        'failed_logins': (0, 0), 
        'ports': [3333, 4444, 8333, 443, 14444], 
        'protocols': ['TCP'],
        'duration': (300, 1800)
    },
    'Man-in-the-Middle': {
        'packet_rate': (200, 500), 
        'bytes_sent': (5000, 20000), 
        'bytes_received': (5000, 20000), 
        'failed_logins': (0, 1), 
        'ports': [80, 443, 25, 110, 143], 
        'protocols': ['TCP'],
        'duration': (60, 300)
    },
}

# Distribution weights - Total: 100,000 events (10x increased)
weights = {
    'Normal': 55000,
    'DDoS Attack': 8000,
    'Brute Force Attack': 7000,
    'Port Scan': 6000,
    'SQL Injection': 4500,
    'Data Exfiltration': 4000,
    'Malware C2': 3500,
    'DNS Tunneling': 3000,
    'Privilege Escalation': 3000,
    'Ransomware Activity': 2500,
    'Cryptojacking': 2000,
    'Man-in-the-Middle': 1500,
}


def generate_logs():
    """Generate synthetic log data with various attack patterns."""
    data = []
    base_time = datetime(2026, 1, 1, 0, 0, 0)
    
    print("Generating log entries...")
    
    for attack_type, count in weights.items():
        profile = attack_profiles[attack_type]
        for _ in range(count):
            # Random timestamp within 60 days
            timestamp = base_time + timedelta(seconds=random.randint(0, 5184000))
            
            # Generate realistic IPs
            src_ip = f'{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}'
            # All simulated attack traffic targets the protected Kali VM.
            dst_ip = KALI_VM_IP
            
            data.append({
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'packet_rate': random.randint(*profile['packet_rate']),
                'bytes_sent': random.randint(*profile['bytes_sent']),
                'bytes_received': random.randint(*profile['bytes_received']),
                'failed_logins': random.randint(*profile['failed_logins']),
                'protocol': random.choice(profile['protocols']),
                'port': random.choice(profile['ports']),
                'duration': random.randint(*profile['duration']),
                'attack_type': attack_type,
            })
    
    # Create DataFrame and sort by timestamp
    df = pd.DataFrame(data)
    df = df.sort_values('timestamp').reset_index(drop=True)
    
    return df


def generate_pcap_from_logs(df: pd.DataFrame, output_path: str):
    """
    Generate PCAP file from log data.
    Creates realistic network packets for each log entry.
    
    Args:
        df: DataFrame containing log entries
        output_path: Path to save PCAP file
    """
    print("Generating PCAP packets...")
    packets = []
    
    for idx, row in df.iterrows():
        if idx % 10000 == 0:
            print(f"  Processing packet {idx}/{len(df)}...")
        
        try:
            src_ip = row['source_ip']
            dst_ip = row['dest_ip']
            port = int(row['port'])
            packet_rate = int(row['packet_rate'])
            bytes_sent = int(row['bytes_sent'])
            protocol = row['protocol']
            
            # Create base IP packet
            ip_packet = IP(src=src_ip, dst=dst_ip)
            
            # Add transport layer based on protocol
            if protocol == 'TCP':
                transport = TCP(dport=port, sport=random.randint(1024, 65535))
            else:  # UDP
                transport = UDP(dport=port, sport=random.randint(1024, 65535))
            
            # Create payload with packet data
            payload = bytes([random.randint(0, 255) for _ in range(min(bytes_sent, 65000))])
            
            # Combine layers
            complete_packet = ip_packet / transport / payload
            packets.append(complete_packet)
        
        except Exception as e:
            # Skip problematic packets
            continue
    
    # Write PCAP file
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wrpcap(output_path, packets)
    print(f"✓ Generated {len(packets)} packets in PCAP format")


if __name__ == "__main__":
    print("=" * 70)
    print("  GENERATING 100,000 SYNTHETIC LOGS IN CSV + PCAP FORMAT")
    print("=" * 70)
    print()
    
    df = generate_logs()
    
    # Save to CSV
    csv_path = os.path.join(PROJECT_ROOT, 'data', 'raw_logs.csv')
    df.to_csv(csv_path, index=False)
    print(f"✓ Saved CSV to {csv_path}")
    
    # Generate PCAP
    pcap_path = os.path.join(PROJECT_ROOT, 'data', 'raw_logs.pcap')
    generate_pcap_from_logs(df, pcap_path)
    print(f"✓ Saved PCAP to {pcap_path}")
    
    print(f"\n{'='*70}")
    print(f"✓ Generated {len(df)} log entries")
    print(f"✓ CSV: {csv_path}")
    print(f"✓ PCAP: {pcap_path}")
    print(f"\nAttack Distribution:")
    print("-" * 70)
    total_attacks = sum(v for k, v in weights.items() if k != 'Normal')
    for attack, count in weights.items():
        pct = (count / len(df)) * 100
        bar = "█" * int(pct / 2)
        print(f"  {attack:25s}: {count:6d} ({pct:5.1f}%) {bar}")
    print("-" * 70)
    print(f"  {'Total Events':25s}: {len(df):6d}")
    print(f"  {'Total Attacks':25s}: {total_attacks:6d} ({(total_attacks/len(df))*100:.1f}%)")
    print(f"  {'Normal Traffic':25s}: {weights['Normal']:6d} ({(weights['Normal']/len(df))*100:.1f}%)")
    print("=" * 70)
