"""
Fast end-to-end runner for the Digital Twin Security project.

Workflow:
1. Run analysis and update processed logs without sending packets.
2. Start the Streamlit dashboard.
3. Keep forwarding the allowed packets to the Kali VM in the background.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON = sys.executable
GATEWAY_SCRIPT = os.path.join(PROJECT_ROOT, "scripts", "digital_twin_gateway.py")
DASHBOARD_SCRIPT = os.path.join(PROJECT_ROOT, "visualization", "dashboard.py")
DASHBOARD_URL = "http://localhost:8501"
FAST_PPS = 2000
DEFAULT_KALI_IP = "192.168.56.101"


def run_analysis_only() -> None:
    """Build processed logs and reports before packet forwarding starts."""
    command = [
        PYTHON,
        GATEWAY_SCRIPT,
        "--kali-ip",
        DEFAULT_KALI_IP,
        "--rewrite-dst",
        "--skip-send",
    ]
    subprocess.run(command, cwd=PROJECT_ROOT, check=True)


def start_dashboard() -> subprocess.Popen:
    """Launch Streamlit in the background."""
    command = [PYTHON, "-m", "streamlit", "run", DASHBOARD_SCRIPT]
    return subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def start_packet_forwarding() -> subprocess.Popen:
    """Replay the approved packets to the Kali VM in the background."""
    command = [
        PYTHON,
        GATEWAY_SCRIPT,
        "--kali-ip",
        DEFAULT_KALI_IP,
        "--rewrite-dst",
        "--send-only",
        "--pps",
        str(FAST_PPS),
    ]
    return subprocess.Popen(command, cwd=PROJECT_ROOT)


def main() -> int:
    print("[RUNNER] Phase 1/3: running digital twin analysis only...")
    run_analysis_only()

    print("[RUNNER] Phase 2/3: starting dashboard...")
    dashboard_process = start_dashboard()
    time.sleep(3)
    print(f"[RUNNER] Dashboard should be available at {DASHBOARD_URL}")

    print("[RUNNER] Phase 3/3: forwarding allowed packets to the Kali VM...")
    sender_process = start_packet_forwarding()
    sender_exit = sender_process.wait()

    print(f"[RUNNER] Packet forwarding finished with exit code {sender_exit}")
    print(f"[RUNNER] Dashboard process id: {dashboard_process.pid}")
    return sender_exit


if __name__ == "__main__":
    sys.exit(main())
