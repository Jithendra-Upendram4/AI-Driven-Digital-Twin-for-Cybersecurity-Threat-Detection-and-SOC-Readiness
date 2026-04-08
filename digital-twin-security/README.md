# AI-Driven Digital Twin for Cybersecurity Threat Detection and SOC Readiness

Digital Twin Security is a Python-based cybersecurity simulation that ingests synthetic network logs, detects threats with rules plus machine learning, stores incidents in SQLite, and visualizes the results in a Streamlit dashboard. The workflow is designed for lab environments where traffic is analyzed by the digital twin first and only legitimate packets are forwarded to the Kali VM.

## Overview

This project models a security monitoring pipeline that behaves like a digital twin of a protected enterprise segment. It can:

- generate synthetic network logs and PCAP traffic for lab testing
- detect known threats with a rule engine
- detect unknown anomalies with Isolation Forest
- persist incidents into a local SQLite database
- generate SOC-style incident reports
- show results in a Streamlit dashboard
- replay only approved traffic to the Kali VM

## Workflow

The recommended end-to-end flow is:

1. Load or generate log and PCAP data.
2. Run the digital twin analysis.
3. Block malicious or anomalous traffic.
4. Forward only legitimate packets to the Kali VM.
5. Open the dashboard to review the processed results.

The current protected Kali VM destination IP is `192.168.56.101`.

## Features

| Feature | Description |
|---|---|
| Log ingestion | Loads CSV logs and validates the required fields |
| Rule-based detection | Flags brute force, DDoS, port scan, exfiltration, and other attacks |
| ML anomaly detection | Uses Isolation Forest for unknown or zero-day style behavior |
| Packet replay control | Forwards only allowed packets toward the Kali VM |
| Persistence | Stores incidents in SQLite for later analysis |
| Reporting | Generates incident summaries in the `reports/` folder |
| Visualization | Presents charts and tables through Streamlit |

## Architecture

```text
Log sources
   -> Ingestion layer
   -> Rule engine + anomaly engine
   -> Threat store (SQLite)
   -> Reports + Streamlit dashboard
   -> Approved packet replay to Kali VM
```

## Project Structure

```text
digital-twin-security/
├── data/
│   ├── raw_logs.csv
│   ├── raw_logs.pcap
│   └── processed_logs.csv
├── ingestion/
│   └── log_ingestion.py
├── scripts/
│   ├── generate_data.py
│   ├── digital_twin_gateway.py
│   ├── replay_to_kali.py
│   └── run_full_project.py
├── storage/
│   └── threat_store.py
├── twin_core/
│   ├── rule_engine.py
│   └── anomaly_engine.py
├── visualization/
│   ├── dashboard.py
│   └── matplotlib_dashboard.py
├── reports/
│   └── generate_report.py
├── main.py
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10+
- Windows, Linux, or macOS
- `pip` for dependency installation
- Optional: Npcap and administrator privileges for packet replay on Windows

## Installation

```bash
cd digital-twin-security
pip install -r requirements.txt
```

## Run the Project

### Fast end-to-end run

This is the best option when you want the full workflow:

```bash
python scripts/run_full_project.py
```

It will:

- run the analysis phase first
- update `data/processed_logs.csv`
- start the Streamlit dashboard
- continue forwarding only allowed packets to `192.168.56.101`

### Run the analysis only

```bash
python main.py
```

This processes logs, stores incidents, and generates the incident report.

### Start the dashboard only

```bash
streamlit run visualization/dashboard.py
```

### Generate fresh synthetic data

If you want to rebuild the CSV and PCAP files:

```bash
python scripts/generate_data.py
```

### Relay traffic through the digital twin

Analyze traffic first, then forward only approved packets:

```bash
python scripts/digital_twin_gateway.py --kali-ip 192.168.56.101 --rewrite-dst
```

Dry run:

```bash
python scripts/digital_twin_gateway.py --kali-ip 192.168.56.101 --rewrite-dst --dry-run
```

### Replay only the approved packets later

If you want to send packets after the analysis step has already finished:

```bash
python scripts/digital_twin_gateway.py --kali-ip 192.168.56.101 --rewrite-dst --send-only
```

## Detection Logic

### Rule-based examples

| Attack type | Example condition |
|---|---|
| Brute force | `failed_logins > 5` |
| DDoS | `packet_rate > 1000` |
| Data exfiltration | `bytes_sent > 50000` |

### ML detection

- Algorithm: Isolation Forest
- Purpose: detect unknown or unusual traffic patterns
- Contamination: 5%

## Output Files

After a successful run, the project generates:

- `data/processed_logs.csv`
- `threats.db`
- `reports/incident_report_*.txt`

## Why This Project Matters

- It is not just a dashboard; it simulates a security decision pipeline.
- It combines deterministic rules with anomaly detection.
- It is designed to mirror a SOC-style workflow.
- It supports packet forwarding control for a lab Kali VM.

## Troubleshooting

- If the dashboard says no data is available, run `python main.py` or `python scripts/run_full_project.py` first.
- If packet replay fails, run the terminal as administrator and ensure Npcap is installed on Windows.
- If the Kali VM does not receive traffic, confirm the target IP is `192.168.56.101` and that the VM is reachable from the host network.

## License

MIT License. Free for academic and commercial use.

## Author

Final Year Project: AI-Driven Digital Twin for Cybersecurity
