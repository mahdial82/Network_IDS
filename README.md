# Network Intrusion Detection System (NIDS)

A practical Network Intrusion Detection System implemented in Python for monitoring, feature extraction, attack detection, alert management, and web-based visualization in a controlled VMware laboratory environment.

## 1. Project Overview

The system captures network packets with Scapy, extracts relevant network features, detects predefined attack patterns, stores traffic and alerts in SQLite, exposes monitoring data through a FastAPI REST API, and presents the results through a web dashboard.

The project is designed as a practical laboratory implementation rather than a production-grade enterprise IDS.

### System Architecture

```text
Network Traffic
      |
      v
Scapy Packet Capture
      |
      v
Feature Extraction
      |
      v
Detection Engine
      |
      +---------> CSV Traffic Log
      |
      +---------> SQLite Database
                       |
                       v
                    FastAPI
                       |
                       v
                Web Dashboard
```

## 2. Laboratory Environment

The project was developed and tested using VMware virtual machines.

| Device | Role | IP Address | Interface |
|---|---|---|---|
| Kali Linux | Traffic generator / attacker | 192.168.100.10 | eth1 |
| Ubuntu | IDS server | 192.168.100.20 | ens37 |
| Windows | Target system | 192.168.100.130 | Ethernet |

The Ubuntu IDS machine also uses a NAT interface for general connectivity:

```text
ens33: 192.168.175.132/24
ens37: 192.168.100.20/24
```

The IDS monitors:

```text
ens37
```

## 3. Main Technologies

- Python 3
- Scapy
- SQLite
- FastAPI
- Uvicorn
- HTML, CSS and JavaScript
- VMware virtual machines
- Linux

## 4. Detection Capabilities

The IDS currently detects the following patterns.

| Detection | Description | Default Threshold |
|---|---|---|
| PORT SCAN | Multiple TCP SYN attempts toward different destination ports | 10 unique ports / 5 sec |
| SYN FLOOD | High-volume TCP SYN traffic | 50 SYN / 5 sec |
| ICMP FLOOD | High-volume ICMP traffic | 50 packets / 5 sec |
| UDP FLOOD | High-volume UDP traffic | 50 packets / 5 sec |
| SUSPICIOUS PORT | TCP SYN attempts toward configured sensitive services | Configurable |
| BRUTE FORCE | Repeated TCP connection attempts toward configured authentication-related ports | 10 attempts / 30 sec |

### Important Note About Brute Force Detection

The `BRUTE FORCE` detector identifies a repeated connection-attempt pattern. It does not inspect application authentication logs and therefore does not prove that password authentication actually failed.

## 5. Severity Classification

| Alert Type | Severity |
|---|---|
| PORT SCAN | MEDIUM |
| SUSPICIOUS PORT | MEDIUM |
| SYN FLOOD | HIGH |
| ICMP FLOOD | HIGH |
| UDP FLOOD | HIGH |
| BRUTE FORCE | HIGH |

Alert lifecycle states:

```text
NEW
ACKNOWLEDGED
RESOLVED
```

## 6. Data Storage

### SQLite

The main database is:

```text
ids_alerts.db
```

It stores:

- captured packet information
- generated security alerts
- alert type
- source and destination addresses
- counts
- detection details
- severity
- alert status

### CSV

Captured traffic is also recorded in:

```text
lab_traffic.csv
traffic.csv
```

### System Log

Rotating application logs are stored in:

```text
ids_system.log
```

## 7. Configuration

The main configuration file is:

```text
config.json
```

Important configuration parameters include:

```text
interface
csv_file
db_file
log_file
log_max_bytes
log_backup_count
time_window
port_scan_threshold
syn_flood_threshold
icmp_flood_threshold
udp_flood_threshold
alert_suppression_seconds
suspicious_port_suppression_seconds
brute_force_threshold
brute_force_window
brute_force_suppression_seconds
db_commit_interval
suspicious_ports
brute_force_ports
```

The project therefore allows thresholds, monitored interfaces, output files, suppression intervals and monitored ports to be adjusted without modifying the detection code.

## 8. Installation

Create a virtual environment:

```bash
python3 -m venv venv
```

Install project dependencies:

```bash
./venv/bin/pip install -r requirements.txt
```

The current environment uses the packages listed in `requirements.txt`, including:

```text
scapy
fastapi
uvicorn
```

## 9. Running the IDS

From the project directory:

```bash
cd ~/network-ids
sudo ./venv/bin/python packet_capture.py
```

The packet capture process requires elevated privileges because it accesses the network interface directly.

The configured capture interface is read from `config.json`.

## 10. Running the FastAPI Backend

Start the API server:

```bash
cd ~/network-ids
./venv/bin/uvicorn dashboard_api:app --host 0.0.0.0 --port 8000
```

The API will be available at:

```text
http://127.0.0.1:8000
```

Interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

## 11. Main API Endpoints

### Alert statistics

```http
GET /stats
```

Returns total alerts and counts for the supported attack types and severity levels.

### Traffic statistics

```http
GET /traffic/stats
```

Returns packet and byte totals together with protocol statistics.

### Latest alerts

```http
GET /alerts/latest
```

Returns recent security alerts.

### Alert filtering

```http
GET /alerts
```

Supported filters include:

```text
attack_type
severity
status
source_ip
limit
```

### Alert status management

```http
PATCH /alerts/{alert_id}/status
```

Supported status values:

```text
NEW
ACKNOWLEDGED
RESOLVED
```

### Recent network traffic

```http
GET /traffic/recent
```

### Top talkers

```http
GET /traffic/top-talkers
```

## 12. Running the Web Dashboard

The dashboard is located at:

```text
dashboard/index.html
```

Start the static web server:

```bash
cd ~/network-ids
./venv/bin/python -m http.server 8080 --directory dashboard
```

Open:

```text
http://127.0.0.1:8080
```

The dashboard includes:

- total alert statistics
- attack statistics
- protocol statistics
- traffic monitoring
- live traffic rate
- top source IPs
- top destination IPs
- recent network traffic
- recent security alerts
- attack/severity/status filters
- source-IP filtering
- alert status actions
- automatic refresh

## 13. Attack Test Scenarios

The following tests were used in the VMware laboratory.

### Port Scan

From Kali:

```bash
nmap -sS -p 1-100 192.168.100.130
```

### SYN Flood

```bash
sudo hping3 -S --flood -p 80 192.168.100.130
```

### ICMP Flood

```bash
sudo hping3 --icmp --flood 192.168.100.130
```

### UDP Flood

```bash
sudo hping3 --udp --flood -p 53 192.168.100.130
```

### Suspicious Port

Example using SSH:

```bash
sudo hping3 -S -p 22 -c 1 192.168.100.130
```

### Brute-Force Pattern

Example using repeated SSH connection attempts:

```bash
sudo hping3 -S -p 22 -c 12 -i u500000 192.168.100.130
```

### Normal Traffic / Negative Test

```bash
ping -c 5 192.168.100.130
```

These attack-generation commands are intended only for the isolated laboratory environment used for the project.

## 14. Evaluation

The project includes a controlled evaluation framework under:

```text
evaluation/
```

### Controlled Detection

Six positive attack scenarios were tested:

```text
PORT SCAN
SYN FLOOD
ICMP FLOOD
UDP FLOOD
SUSPICIOUS PORT
BRUTE FORCE
```

Observed result:

```text
Positive Tests : 6
Detected       : 6
Detection Rate : 100.00%
```

### Negative Test

A normal ping scenario was used as the negative test:

```text
Negative Tests       : 1
False Positive Tests : 0
Observed FPR         : 0.00%
```

These figures describe the specific controlled VMware scenarios that were tested. They should not be interpreted as a general accuracy or false-positive guarantee for arbitrary real-world traffic.

## 15. Operational Database Snapshot

The final evaluation snapshot contained:

```text
Total Packets : 208,994
Total Bytes   : 12,827,784
Total Alerts  : 74
```

### Attack Statistics

```text
PORT SCAN        : 5
SYN FLOOD        : 18
ICMP FLOOD       : 23
UDP FLOOD        : 5
SUSPICIOUS PORT  : 20
BRUTE FORCE      : 3
```

### Severity

```text
HIGH   : 49
MEDIUM : 25
LOW    : 0
```

### Alert Status

```text
NEW           : 73
ACKNOWLEDGED  : 1
RESOLVED      : 0
```

### Observed Protocol Distribution

```text
ICMP  : 81,975
UDP   : 76,399
TCP   : 49,027
ARP   : 1,113
OTHER : 369
IPv4  : 111
```

## 16. Performance Evaluation

Two controlled VMware performance runs were recorded.

### Run 1

```text
Duration          : 30.41 sec
Processed Packets : 26,633
Average PPS       : 875.93
Peak PPS          : 3178.71
Average CPU       : 39.91%
Peak CPU          : 63.23%
Average RAM       : 74.61 MB
Peak RAM          : 76.19 MB
Exit Code         : 0
```

### Load Test

```text
Duration          : 30.35 sec
Processed Packets : 29,199
Average PPS       : 962.21
Peak PPS          : 3070.31
Average CPU       : 43.14%
Peak CPU          : 66.98%
Average RAM       : 74.97 MB
Peak RAM          : 76.60 MB
Exit Code         : 0
```

These are measurements from the project's VMware laboratory runs. They are not presented as a maximum-capacity or production-throughput benchmark.

## 17. Evaluation Files

Important evaluation files include:

```text
evaluation/final_evaluation.py
evaluation/final_evaluation.txt
evaluation/final_evaluation.json
evaluation/ids_evaluation.py
evaluation/performance_test.py
evaluation/performance_report.txt
evaluation/performance_report.json
evaluation/performance_run_1.txt
evaluation/performance_run_1.json
evaluation/performance_load.txt
evaluation/performance_load.json
evaluation/test_tracker.py
evaluation/test_results.json
```

## 18. Project Structure

```text
network-ids/
├── config.json
├── packet_capture.py
├── dashboard_api.py
├── dashboard/
│   └── index.html
├── ids_alerts.db
├── lab_traffic.csv
├── traffic.csv
├── ids_system.log
├── requirements.txt
├── README.md
├── evaluation/
│   ├── baseline.json
│   ├── config_before_evaluation.json
│   ├── evaluation_report.txt
│   ├── final_evaluation.py
│   ├── final_evaluation.json
│   ├── final_evaluation.txt
│   ├── ids_alerts_before_evaluation.db
│   ├── ids_evaluation.py
│   ├── performance_capture.log
│   ├── performance_load.json
│   ├── performance_load.txt
│   ├── performance_report.json
│   ├── performance_report.txt
│   ├── performance_run_1.json
│   ├── performance_run_1.txt
│   ├── performance_test.py
│   ├── test_results.json
│   └── test_tracker.py
└── venv/
```

The local `venv/` directory is a development environment and does not need to be copied when transferring the source code. Dependencies can be recreated with `requirements.txt`.

## 19. End-to-End Workflow

```text
1. Capture network packets
           |
           v
2. Extract packet features
           |
           v
3. Apply detection rules
           |
           +------> Save traffic to CSV
           |
           +------> Save traffic and alerts to SQLite
                              |
                              v
4. FastAPI reads the database
                              |
                              v
5. Dashboard displays traffic and alerts
```

## 23. Machine Learning Extension

The project includes an optional machine-learning layer based on **Isolation Forest**. It is implemented as a complementary anomaly-detection component and does not replace the existing rule-based detection engine.

### ML Pipeline

```text
lab_traffic.csv
      |
      v
5-second windows grouped by source IP
      |
      v
Feature extraction
      |
      v
StandardScaler
      |
      v
Isolation Forest
      |
      +------> NORMAL
      |
      +------> ANOMALY
```

The model uses the following features:

```text
packet_count
total_bytes
average_packet_length
unique_destination_ips
unique_destination_ports
tcp_syn_count
tcp_ack_count
tcp_count
udp_count
icmp_count
```

The model was evaluated on the existing laboratory traffic dataset. The dataset contained 665,534 CSV rows and produced 3,383 five-second source-IP feature windows. The Isolation Forest model identified 205 anomaly windows, corresponding to an observed anomaly rate of 6.06%.

### ML / Rule-Based Overlap

The ML output was compared with the existing rule-based alert windows. This comparison is a window-overlap analysis, not a conventional classification accuracy measurement.

```text
ML feature windows        : 3383
ML anomaly windows        : 205
Rule alert windows        : 56
Overlapping windows       : 41
ML anomaly overlap       : 20.00%
Rule alert coverage by ML: 73.21%
```

Attack-type overlap in the current laboratory dataset:

| Attack Type | Matched / Total | Overlap |
|---|---:|---:|
| PORT SCAN | 5 / 5 | 100.00% |
| SYN FLOOD | 18 / 18 | 100.00% |
| UDP FLOOD | 5 / 5 | 100.00% |
| ICMP FLOOD | 17 / 23 | 73.91% |
| SUSPICIOUS PORT | 14 / 20 | 70.00% |
| BRUTE FORCE | 0 / 3 | 0.00% |

The current ML layer should be described as an anomaly-detection extension. The overlap figures should not be reported as accuracy, precision, recall, or F1-score because the current dataset does not provide independent ground-truth labels for supervised ML evaluation.

### ML Output Files

```text
evaluation/ml/ml_windows.csv
evaluation/ml/ml_anomalies.csv
evaluation/ml/ml_report.txt
evaluation/ml/ml_evaluation.py
evaluation/ml/ml_evaluation.txt
evaluation/ml/ml_api.py
```

### ML API

```http
GET /ml/stats
GET /ml/anomalies?limit=20
```

### ML Dashboard

A dedicated ML dashboard is available at:

```text
http://127.0.0.1:8080/ml.html
```

The main dashboard can also display a compact ML summary with a link to the full ML dashboard.

## 24. Project Validation

Before delivery, the project was checked by:

- compiling the Python source files with `py_compile`
- starting the FastAPI backend
- querying the statistics endpoint
- querying traffic statistics
- querying recent alerts
- starting the dashboard web server
- verifying dashboard updates
- running a normal ping as a negative traffic test
- running controlled attack scenarios
- running controlled performance tests

## 25. Scope and Limitations

This project is a laboratory implementation intended to demonstrate the design and implementation of a network intrusion detection system.

Important limitations include:

1. Detection is based on packet-level heuristics and configured thresholds.
2. The brute-force detector identifies repeated connection attempts rather than application-level authentication failures.
3. Evaluation results are limited to the tested VMware laboratory scenarios.
4. The measured packet rates are experimental observations, not guaranteed production throughput.
5. The system is not intended to replace mature enterprise IDS/IPS solutions.

## 26. Final Result

The implemented system provides an end-to-end NIDS workflow covering:

```text
Packet Capture
Feature Extraction
Attack Detection
Alert Generation
SQLite Storage
REST API
Web Dashboard
Controlled Evaluation
Performance Measurement
Machine Learning Anomaly Detection
```

The final controlled evaluation detected all six tested positive attack scenarios, while the single tested normal-traffic scenario generated no security alert.
