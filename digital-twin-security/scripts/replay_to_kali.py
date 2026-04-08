"""
Replay generated PCAP packets toward Kali VM in a controlled lab setup.

Usage examples:
  python scripts/replay_to_kali.py
  python scripts/replay_to_kali.py --iface "Ethernet" --count 5000 --pps 200

Notes:
  - Requires administrator/root privileges for raw packet send.
  - On Windows, installing Npcap is typically required for packet operations.
"""

import argparse
import os
import sys
from typing import List

import pandas as pd
from scapy.all import IP, rdpcap, send


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PCAP_PATH = os.path.join(PROJECT_ROOT, "data", "raw_logs.pcap")
DEFAULT_PROCESSED_LOGS_PATH = os.path.join(PROJECT_ROOT, "data", "processed_logs.csv")
DEFAULT_KALI_IP = "192.168.56.101"


def load_packets(pcap_path: str, kali_ip: str) -> List:
    """Load packets from PCAP and keep only packets that target Kali IP."""
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    packets = rdpcap(pcap_path)
    filtered = [pkt for pkt in packets if IP in pkt and pkt[IP].dst == kali_ip]
    return filtered


def filter_packets_by_mode(packets: List, labels_path: str, mode: str) -> List:
    """
    Filter packets using processed detection results.

    Mode behavior:
      - all: keep all packets
      - normal: keep only rows where rule_threat == Normal
      - attack: keep only rows where rule_threat != Normal
    """
    if mode == "all":
        return packets

    if not os.path.exists(labels_path):
        raise FileNotFoundError(
            f"Processed logs not found for mode filtering: {labels_path}. Run main.py first."
        )

    labels_df = pd.read_csv(labels_path)
    if "rule_threat" not in labels_df.columns:
        raise ValueError("Processed logs missing 'rule_threat' column. Run main.py first.")

    if len(labels_df) != len(packets):
        # Keep deterministic alignment when lengths drift.
        min_len = min(len(labels_df), len(packets))
        print(
            "[REPLAY] Warning: labels/packets length mismatch "
            f"({len(labels_df)} vs {len(packets)}). Using first {min_len} entries."
        )
        labels_df = labels_df.iloc[:min_len]
        packets = packets[:min_len]

    if mode == "normal":
        keep_mask = labels_df["rule_threat"] == "Normal"
    else:  # mode == "attack"
        keep_mask = labels_df["rule_threat"] != "Normal"

    filtered = [pkt for pkt, keep in zip(packets, keep_mask.tolist()) if keep]
    print(f"[REPLAY] Mode filter '{mode}' retained {len(filtered)} packets")
    return filtered


def replay_packets(packets: List, pps: int, iface: str | None) -> None:
    """Send packets at a controlled pace."""
    if not packets:
        print("[REPLAY] No packets to send after filtering.")
        return

    inter = 1.0 / pps if pps > 0 else 0
    print(f"[REPLAY] Sending {len(packets)} packets...")
    print(f"[REPLAY] Rate: {pps} packets/sec")
    if iface:
        print(f"[REPLAY] Interface: {iface}")

    send(packets, inter=inter, iface=iface, verbose=False)
    print("[REPLAY] Packet replay completed.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay simulated packets to Kali VM")
    parser.add_argument("--pcap", default=DEFAULT_PCAP_PATH, help="Path to PCAP file")
    parser.add_argument(
        "--labels",
        default=DEFAULT_PROCESSED_LOGS_PATH,
        help="Path to processed_logs.csv used for normal/attack filtering",
    )
    parser.add_argument(
        "--mode",
        choices=["all", "normal", "attack"],
        default="normal",
        help="Traffic class to replay (default: normal)",
    )
    parser.add_argument("--kali-ip", default=DEFAULT_KALI_IP, help="Kali VM destination IP")
    parser.add_argument("--count", type=int, default=0, help="Max packets to send (0 = all)")
    parser.add_argument("--pps", type=int, default=200, help="Packets per second")
    parser.add_argument("--iface", default=None, help="Optional network interface name")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show replay stats without transmitting packets",
    )
    args = parser.parse_args()

    try:
        packets = load_packets(args.pcap, args.kali_ip)
        print(f"[REPLAY] Loaded {len(packets)} Kali-target packets from {args.pcap}")
        packets = filter_packets_by_mode(packets, args.labels, args.mode)

        if args.count > 0:
            packets = packets[: args.count]
            print(f"[REPLAY] Using first {len(packets)} packets due to --count={args.count}")

        if args.dry_run:
            print("[REPLAY] Dry run enabled. No packets transmitted.")
            return 0

        replay_packets(packets, pps=args.pps, iface=args.iface)
        return 0
    except PermissionError:
        print("[REPLAY] Permission denied. Run terminal as Administrator/root.")
        return 1
    except Exception as exc:
        print(f"[REPLAY] Failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
