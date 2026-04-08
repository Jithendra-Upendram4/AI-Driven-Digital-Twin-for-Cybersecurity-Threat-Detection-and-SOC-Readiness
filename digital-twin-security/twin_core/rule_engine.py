"""
Rule-Based Detection Engine
============================
Purpose: Detect known attack patterns using predefined security rules.
This demonstrates domain knowledge and signature-based detection.

Attack Types Detected (12 Categories):
1. DDoS Attack: Abnormally high packet rates (>1000 packets/sec)
2. Brute Force Attack: Multiple failed login attempts (>5)
3. Port Scan: Low bytes with scanning port patterns
4. SQL Injection: Database ports with high response data
5. Data Exfiltration: High bytes sent with low received
6. Malware C2: Suspicious ports with regular beacon patterns
7. DNS Tunneling: High DNS traffic with unusual byte patterns
8. Privilege Escalation: SMB/WinRM ports with failed logins
9. Ransomware Activity: SMB ports with high write activity
10. Cryptojacking: Mining pool ports with sustained connections
11. Man-in-the-Middle: Symmetric traffic on mail/web ports
12. Normal: No rules triggered
"""

import pandas as pd
import os
from typing import List, Dict, Tuple


# Suspicious ports associated with specific attacks
MALWARE_C2_PORTS = {4444, 6666, 31337, 1337, 9999, 8443}
CRYPTO_MINING_PORTS = {3333, 4444, 8333, 14444, 14433}
SMB_PORTS = {445, 139, 135}
WINRM_PORTS = {5985, 5986}
DATABASE_PORTS = {3306, 1433, 5432, 27017, 6379}
MAIL_PORTS = {25, 110, 143, 993, 995}


def block_ip(ip: str) -> bool:
    """
    Block attacker IP using host firewall rule.

    For safety, command execution is disabled by default.
    Enable real firewall blocking by setting env var ENABLE_FIREWALL_BLOCK=true.
    """
    should_execute = os.getenv("ENABLE_FIREWALL_BLOCK", "false").lower() == "true"
    if not should_execute:
        return False

    rule_name = f"block_{ip.replace('.', '_')}"
    command = (
        f"netsh advfirewall firewall add rule "
        f"name={rule_name} dir=in action=block remoteip={ip}"
    )
    exit_code = os.system(command)
    return exit_code == 0


def respond_to_threat(src_ip: str, severity: str, blocked_ips: set) -> str:
    """Return response action for threat event and block high-risk sources."""
    if severity in {"HIGH", "CRITICAL"}:
        if src_ip in blocked_ips:
            return "Blocked"

        blocked = block_ip(src_ip)
        blocked_ips.add(src_ip)
        return "Blocked" if blocked else "Blocked (Simulated)"

    return "Monitored"


def rule_based_detection(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply rule-based threat detection on log data.
    
    Rules applied (in priority order):
    1. DDoS Attack: packet_rate > 1000
    2. Brute Force: failed_logins > 5
    3. Data Exfiltration: bytes_sent > 60000 with low bytes_received
    4. DNS Tunneling: port 53 with high packet rate and bytes
    5. Port Scan: low bytes_sent with short duration
    6. SQL Injection: database ports with high response
    7. Malware C2: suspicious ports with beacon pattern
    8. Cryptojacking: mining ports with long duration
    9. Ransomware Activity: SMB ports with high write
    10. Privilege Escalation: SMB/WinRM with failed logins
    11. Man-in-the-Middle: symmetric traffic pattern
    12. Normal: No rules triggered
    
    Args:
        df: DataFrame containing log entries
        
    Returns:
        DataFrame with 'rule_threat' and 'threat_severity' columns added
    """
    threats = []
    severities = []
    responses = []
    blocked_ips = set()
    
    for _, row in df.iterrows():
        threat, severity = apply_rules(row)
        response = respond_to_threat(str(row.get('source_ip', 'unknown')), severity, blocked_ips)
        threats.append(threat)
        severities.append(severity)
        responses.append(response)
    
    df['rule_threat'] = threats
    df['threat_severity'] = severities
    df['response_action'] = responses
    
    # Log detection summary
    threat_counts = df['rule_threat'].value_counts()
    print("\n[RULE ENGINE] Detection Summary:")
    for threat_type, count in threat_counts.items():
        print(f"  - {threat_type}: {count}")
    
    return df


def apply_rules(row: pd.Series) -> Tuple[str, str]:
    """
    Apply detection rules to a single log entry.
    Priority-based rule matching for accurate threat classification.
    
    Args:
        row: Single log entry as pandas Series
        
    Returns:
        Tuple of (threat_type, severity)
    """
    packet_rate = row.get('packet_rate', 0)
    bytes_sent = row.get('bytes_sent', 0)
    bytes_received = row.get('bytes_received', 0)
    failed_logins = row.get('failed_logins', 0)
    port = row.get('port', 0)
    protocol = row.get('protocol', 'TCP')
    duration = row.get('duration', 0)
    
    # Calculate ratios for pattern detection
    bytes_ratio = bytes_sent / max(bytes_received, 1)
    total_bytes = bytes_sent + bytes_received
    
    # Rule 1: DDoS Attack - Very high packet rates
    if packet_rate > 1000:
        if packet_rate > 3000:
            return ("DDoS Attack", "CRITICAL")
        elif packet_rate > 2000:
            return ("DDoS Attack", "HIGH")
        else:
            return ("DDoS Attack", "MEDIUM")
    
    # Rule 2: Brute Force Attack - Multiple failed logins
    if failed_logins > 5:
        if failed_logins > 20:
            return ("Brute Force Attack", "CRITICAL")
        elif failed_logins > 10:
            return ("Brute Force Attack", "HIGH")
        else:
            return ("Brute Force Attack", "MEDIUM")
    
    # Rule 3: Data Exfiltration - High outbound data
    if bytes_sent > 60000 and bytes_ratio > 10:
        if bytes_sent > 200000:
            return ("Data Exfiltration", "CRITICAL")
        elif bytes_sent > 100000:
            return ("Data Exfiltration", "HIGH")
        else:
            return ("Data Exfiltration", "MEDIUM")
    
    # Rule 4: DNS Tunneling - Suspicious DNS traffic
    if port == 53 and protocol == 'UDP':
        if packet_rate > 400 and total_bytes > 5000:
            if packet_rate > 800:
                return ("DNS Tunneling", "HIGH")
            else:
                return ("DNS Tunneling", "MEDIUM")
    
    # Rule 5: Port Scan - Low data, short duration, scanning pattern
    if bytes_sent < 600 and duration < 6 and packet_rate > 250:
        if packet_rate > 500:
            return ("Port Scan", "HIGH")
        else:
            return ("Port Scan", "MEDIUM")
    
    # Rule 6: SQL Injection - Database ports with high response
    if port in DATABASE_PORTS:
        if bytes_received > 5000 and bytes_sent > 1500:
            if bytes_received > 15000:
                return ("SQL Injection", "HIGH")
            else:
                return ("SQL Injection", "MEDIUM")
    
    # Rule 7: Malware C2 - Suspicious ports with beacon pattern
    if port in MALWARE_C2_PORTS:
        if 50 <= packet_rate <= 200 and duration > 50:
            if duration > 300:
                return ("Malware C2", "CRITICAL")
            else:
                return ("Malware C2", "HIGH")
    
    # Rule 8: Cryptojacking - Mining pool activity
    if port in CRYPTO_MINING_PORTS:
        if duration > 250 and 80 <= packet_rate <= 400:
            if duration > 1000:
                return ("Cryptojacking", "HIGH")
            else:
                return ("Cryptojacking", "MEDIUM")
    
    # Rule 9: Ransomware Activity - SMB with high write
    if port in SMB_PORTS:
        if bytes_sent > 8000 and bytes_ratio > 3 and duration < 150:
            if bytes_sent > 30000:
                return ("Ransomware Activity", "CRITICAL")
            else:
                return ("Ransomware Activity", "HIGH")
    
    # Rule 10: Privilege Escalation - SMB/WinRM with auth attempts
    if port in SMB_PORTS.union(WINRM_PORTS):
        if 2 <= failed_logins <= 5 and bytes_sent > 1000:
            return ("Privilege Escalation", "HIGH")
    
    # Rule 11: Man-in-the-Middle - Symmetric traffic
    if port in {80, 443}.union(MAIL_PORTS):
        if 0.7 <= bytes_ratio <= 1.4 and bytes_sent > 4000 and duration > 50:
            if total_bytes > 20000:
                return ("Man-in-the-Middle", "HIGH")
            else:
                return ("Man-in-the-Middle", "MEDIUM")
    
    # No threat detected
    return ("Normal", "LOW")


def get_rule_definitions() -> List[Dict]:
    """
    Return list of all detection rules for documentation.
    
    Returns:
        List of rule definitions with thresholds
    """
    return [
        {
            "rule_id": "R001",
            "name": "DDoS Detection",
            "condition": "packet_rate > 1000",
            "severity": "MEDIUM-CRITICAL",
            "description": "Detects Distributed Denial of Service attacks via packet flooding"
        },
        {
            "rule_id": "R002",
            "name": "Brute Force Detection",
            "condition": "failed_logins > 5",
            "severity": "MEDIUM-CRITICAL",
            "description": "Detects multiple failed authentication attempts"
        },
        {
            "rule_id": "R003",
            "name": "Data Exfiltration Detection",
            "condition": "bytes_sent > 60000 AND bytes_ratio > 10",
            "severity": "MEDIUM-CRITICAL",
            "description": "Detects unusual outbound data transfers"
        },
        {
            "rule_id": "R004",
            "name": "DNS Tunneling Detection",
            "condition": "port=53 AND packet_rate > 400 AND total_bytes > 5000",
            "severity": "MEDIUM-HIGH",
            "description": "Detects covert data exfiltration via DNS queries"
        },
        {
            "rule_id": "R005",
            "name": "Port Scan Detection",
            "condition": "bytes_sent < 600 AND duration < 6 AND packet_rate > 250",
            "severity": "MEDIUM-HIGH",
            "description": "Detects reconnaissance scanning activities"
        },
        {
            "rule_id": "R006",
            "name": "SQL Injection Detection",
            "condition": "database_port AND bytes_received > 5000",
            "severity": "MEDIUM-HIGH",
            "description": "Detects potential SQL injection attacks on databases"
        },
        {
            "rule_id": "R007",
            "name": "Malware C2 Detection",
            "condition": "suspicious_port AND beacon_pattern",
            "severity": "HIGH-CRITICAL",
            "description": "Detects Command & Control communication patterns"
        },
        {
            "rule_id": "R008",
            "name": "Cryptojacking Detection",
            "condition": "mining_port AND long_duration",
            "severity": "MEDIUM-HIGH",
            "description": "Detects unauthorized cryptocurrency mining"
        },
        {
            "rule_id": "R009",
            "name": "Ransomware Detection",
            "condition": "SMB_port AND high_write_ratio",
            "severity": "HIGH-CRITICAL",
            "description": "Detects ransomware file encryption activity"
        },
        {
            "rule_id": "R010",
            "name": "Privilege Escalation Detection",
            "condition": "SMB/WinRM_port AND failed_logins BETWEEN 2 AND 5",
            "severity": "HIGH",
            "description": "Detects lateral movement and privilege escalation attempts"
        },
        {
            "rule_id": "R011",
            "name": "Man-in-the-Middle Detection",
            "condition": "symmetric_traffic AND web/mail_port",
            "severity": "MEDIUM-HIGH",
            "description": "Detects traffic interception attacks"
        },
    ]


def get_threat_categories() -> List[str]:
    """Return list of all threat categories detected by the rule engine."""
    return [
        "Normal",
        "DDoS Attack",
        "Brute Force Attack",
        "Port Scan",
        "SQL Injection",
        "Data Exfiltration",
        "Malware C2",
        "DNS Tunneling",
        "Privilege Escalation",
        "Ransomware Activity",
        "Cryptojacking",
        "Man-in-the-Middle"
    ]
