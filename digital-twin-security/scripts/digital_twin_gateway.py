"""
Digital Twin Gateway Relay
==========================
Process all traffic through detection, block malicious packets, and forward only
allowed packets to the protected Kali VM.

This script also updates processed logs, threat DB, and incident reports so the
Streamlit dashboard continues to show full analytics.
"""

import argparse
import os
import sys
from typing import List

import pandas as pd
from scapy.all import IP, rdpcap, send


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from ingestion.log_ingestion import load_logs, save_processed_logs, validate_logs
from reports.generate_report import generate_quick_summary, generate_report
from storage.threat_store import store_threats
from twin_core.anomaly_engine import anomaly_detection
from twin_core.rule_engine import rule_based_detection


DEFAULT_KALI_IP = "192.168.56.101"
DATASET_TARGET_IP = "192.168.56.101"
DEFAULT_RAW_LOGS = os.path.join(PROJECT_ROOT, "data", "raw_logs.csv")
DEFAULT_PCAP = os.path.join(PROJECT_ROOT, "data", "raw_logs.pcap")
DEFAULT_PROCESSED = os.path.join(PROJECT_ROOT, "data", "processed_logs.csv")
DEFAULT_DB = os.path.join(PROJECT_ROOT, "threats.db")
DEFAULT_REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")


def build_detection_results(raw_logs_path: str, processed_logs_path: str) -> pd.DataFrame:
    """Run full digital twin detection and persist processed outputs."""
    df = load_logs(raw_logs_path)
    validate_logs(df)

    df = rule_based_detection(df)
    df = anomaly_detection(df, contamination=0.05)

    # Gateway decision: block known threats and ML anomalies.
    df["gateway_decision"] = "FORWARD"
    block_mask = (df["rule_threat"] != "Normal") | (df["anomaly"] == -1)
    df.loc[block_mask, "gateway_decision"] = "BLOCK"

    save_processed_logs(df, processed_logs_path)
    store_threats(df, DEFAULT_DB)
    generate_report(df, DEFAULT_REPORTS_DIR)

    return df


def load_gateway_decisions(processed_logs_path: str) -> pd.DataFrame:
    """Load saved detection results and ensure gateway decisions exist."""
    if not os.path.exists(processed_logs_path):
        raise FileNotFoundError(f"Processed logs not found: {processed_logs_path}")

    decisions_df = pd.read_csv(processed_logs_path)
    if "gateway_decision" not in decisions_df.columns:
        if "rule_threat" not in decisions_df.columns:
            raise ValueError("Processed logs missing gateway_decision and rule_threat columns.")

        decisions_df["gateway_decision"] = "FORWARD"
        block_mask = decisions_df["rule_threat"] != "Normal"
        if "anomaly" in decisions_df.columns:
            block_mask = block_mask | (decisions_df["anomaly"] == -1)
        decisions_df.loc[block_mask, "gateway_decision"] = "BLOCK"

    return decisions_df


def load_dataset_packets(pcap_path: str) -> List:
    """Load all IPv4 packets from dataset PCAP."""
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    packets = rdpcap(pcap_path)
    return [pkt for pkt in packets if IP in pkt]


def rewrite_destination_ip(packets: List, dst_ip: str) -> List:
    """Rewrite packet destination IP to reachable Kali interface IP."""
    rewritten = []
    for pkt in packets:
        pkt_copy = pkt.copy()
        pkt_copy[IP].dst = dst_ip
        if hasattr(pkt_copy[IP], "chksum"):
            del pkt_copy[IP].chksum
        # Recompute transport checksum when present.
        if pkt_copy.haslayer("TCP") and hasattr(pkt_copy["TCP"], "chksum"):
            del pkt_copy["TCP"].chksum
        if pkt_copy.haslayer("UDP") and hasattr(pkt_copy["UDP"], "chksum"):
            del pkt_copy["UDP"].chksum
        rewritten.append(pkt_copy)
    return rewritten


def select_forward_packets(packets: List, decisions_df: pd.DataFrame) -> List:
    """Align packets with detection decisions and keep only FORWARD traffic."""
    if "gateway_decision" not in decisions_df.columns:
        raise ValueError("Missing gateway_decision column.")

    if len(packets) != len(decisions_df):
        min_len = min(len(packets), len(decisions_df))
        print(
            "[GATEWAY] Warning: packet/result length mismatch "
            f"({len(packets)} vs {len(decisions_df)}). Using first {min_len}."
        )
        packets = packets[:min_len]
        decisions_df = decisions_df.iloc[:min_len]

    mask = decisions_df["gateway_decision"] == "FORWARD"
    allowed = [pkt for pkt, keep in zip(packets, mask.tolist()) if keep]
    return allowed


def prepare_forward_packets(
    pcap_path: str,
    decisions_df: pd.DataFrame,
    kali_ip: str,
    rewrite_dst: bool,
    count: int,
) -> tuple[List, int, int]:
    """Prepare the final packet list for transmission."""
    dataset_packets = load_dataset_packets(pcap_path)
    print(f"[GATEWAY] Dataset packets loaded: {len(dataset_packets)}")

    forward_packets = select_forward_packets(dataset_packets, decisions_df)
    blocked_count = len(dataset_packets) - len(forward_packets)

    should_rewrite = rewrite_dst or kali_ip != DATASET_TARGET_IP
    if should_rewrite:
        forward_packets = rewrite_destination_ip(forward_packets, kali_ip)
        print(f"[GATEWAY] Rewrote forwarded destination IP to {kali_ip}")

    if count > 0:
        forward_packets = forward_packets[:count]

    return forward_packets, blocked_count, len(dataset_packets)


def send_packets(packets: List, pps: int, iface: str | None, dry_run: bool) -> None:
    """Forward allowed packets to Kali VM."""
    if not packets:
        print("[GATEWAY] No allowed packets to forward.")
        return

    inter = 1.0 / pps if pps > 0 else 0
    if dry_run:
        print(f"[GATEWAY] Dry run: would forward {len(packets)} packets.")
        return

    print(f"[GATEWAY] Forwarding {len(packets)} packets at {pps} pps")
    if iface:
        print(f"[GATEWAY] Interface: {iface}")
    send(packets, inter=inter, iface=iface, verbose=False)
    print("[GATEWAY] Forwarding completed.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Digital Twin in-line packet gateway")
    parser.add_argument("--raw-logs", default=DEFAULT_RAW_LOGS, help="Path to raw_logs.csv")
    parser.add_argument("--pcap", default=DEFAULT_PCAP, help="Path to raw_logs.pcap")
    parser.add_argument("--processed", default=DEFAULT_PROCESSED, help="Path to processed logs output")
    parser.add_argument("--kali-ip", default=DEFAULT_KALI_IP, help="Reachable Kali VM IP to forward packets to")
    parser.add_argument(
        "--rewrite-dst",
        action="store_true",
        help="Rewrite packet destination IP to --kali-ip before forwarding",
    )
    parser.add_argument("--count", type=int, default=0, help="Max forwarded packets (0 = all allowed)")
    parser.add_argument("--pps", type=int, default=200, help="Forward rate in packets/sec")
    parser.add_argument("--iface", default=None, help="Optional NIC for packet send")
    parser.add_argument("--dry-run", action="store_true", help="Analyze and decide, but do not transmit")
    parser.add_argument(
        "--skip-send",
        action="store_true",
        help="Run detection and update dashboard data, but do not transmit packets",
    )
    parser.add_argument(
        "--send-only",
        action="store_true",
        help="Load previously processed decisions and only transmit allowed packets",
    )
    args = parser.parse_args()

    try:
        if args.send_only:
            print("[GATEWAY] Loading saved decisions for packet forwarding...")
            decisions_df = load_gateway_decisions(args.processed)
            forward_packets, blocked_count, total_packets = prepare_forward_packets(
                args.pcap,
                decisions_df,
                args.kali_ip,
                args.rewrite_dst,
                args.count,
            )

            print("\n[GATEWAY] Decision Summary")
            print(f"  - Total analyzed packets: {total_packets}")
            print(f"  - Blocked by digital twin: {blocked_count}")
            print(f"  - Allowed to Kali VM: {len(forward_packets)}")

            send_packets(forward_packets, pps=args.pps, iface=args.iface, dry_run=args.dry_run)
            return 0

        print("[GATEWAY] Running digital twin analysis on all traffic...")
        results_df = build_detection_results(args.raw_logs, args.processed)

        if args.skip_send:
            total_packets = len(results_df)
            blocked_count = int((results_df["gateway_decision"] == "BLOCK").sum())
            allowed_count = total_packets - blocked_count

            print("\n[GATEWAY] Decision Summary")
            print(f"  - Total analyzed packets: {total_packets}")
            print(f"  - Blocked by digital twin: {blocked_count}")
            print(f"  - Allowed to Kali VM: {allowed_count}")
            print(generate_quick_summary(results_df))
            print("[GATEWAY] Packet forwarding skipped by --skip-send.")
            print("[GATEWAY] Dashboard data updated at data/processed_logs.csv")
            return 0

        forward_packets, blocked_count, total_packets = prepare_forward_packets(
            args.pcap,
            results_df,
            args.kali_ip,
            args.rewrite_dst,
            args.count,
        )

        print("\n[GATEWAY] Decision Summary")
        print(f"  - Total analyzed packets: {total_packets}")
        print(f"  - Blocked by digital twin: {blocked_count}")
        print(f"  - Allowed to Kali VM: {len(forward_packets)}")
        print(generate_quick_summary(results_df))

        send_packets(forward_packets, pps=args.pps, iface=args.iface, dry_run=args.dry_run)
        print("[GATEWAY] Dashboard data updated at data/processed_logs.csv")
        return 0
    except PermissionError:
        print("[GATEWAY] Permission denied. Run terminal as Administrator/root.")
        return 1
    except Exception as exc:
        print(f"[GATEWAY] Failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
