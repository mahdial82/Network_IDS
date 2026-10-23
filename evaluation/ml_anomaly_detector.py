import csv
import os
import sqlite3
from collections import defaultdict
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

CSV_FILE = "lab_traffic.csv"
DB_FILE = "ids_alerts.db"
OUTPUT_DIR = "evaluation/ml"
WINDOW_SECONDS = 5

os.makedirs(OUTPUT_DIR, exist_ok=True)

FEATURE_NAMES = [
    "packet_count",
    "total_bytes",
    "average_packet_length",
    "unique_destination_ips",
    "unique_destination_ports",
    "tcp_syn_count",
    "tcp_ack_count",
    "tcp_count",
    "udp_count",
    "icmp_count"
]

def parse_timestamp(value):
    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z"
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return None

def safe_int(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0

def get_window(timestamp):
    return timestamp.replace(
        second=(timestamp.second // WINDOW_SECONDS) * WINDOW_SECONDS,
        microsecond=0
    )

windows = defaultdict(lambda: {
    "packet_count": 0,
    "total_bytes": 0,
    "destination_ips": set(),
    "destination_ports": set(),
    "tcp_count": 0,
    "udp_count": 0,
    "icmp_count": 0,
    "tcp_syn_count": 0,
    "tcp_ack_count": 0,
    "lengths": []
})

total_rows = 0
invalid_rows = 0

with open(CSV_FILE, "r", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)

    for row in reader:
        total_rows += 1

        timestamp = parse_timestamp(row.get("timestamp", ""))
        src_ip = row.get("src_ip", "").strip()

        if timestamp is None or not src_ip:
            invalid_rows += 1
            continue

        key = (get_window(timestamp), src_ip)
        item = windows[key]

        length = safe_int(row.get("length"))
        dst_ip = row.get("dst_ip", "").strip()
        dst_port = row.get("dst_port", "").strip()
        protocol = row.get("protocol", "").strip().upper()
        flags = row.get("tcp_flags", "").strip().upper()

        item["packet_count"] += 1
        item["total_bytes"] += length
        item["lengths"].append(length)

        if dst_ip:
            item["destination_ips"].add(dst_ip)

        if dst_port and dst_port not in ("0", "-", "None"):
            item["destination_ports"].add(dst_port)

        if protocol == "TCP":
            item["tcp_count"] += 1

            if "S" in flags:
                item["tcp_syn_count"] += 1

            if "A" in flags:
                item["tcp_ack_count"] += 1

        elif protocol == "UDP":
            item["udp_count"] += 1

        elif protocol == "ICMP":
            item["icmp_count"] += 1

records = []

for (window_start, src_ip), item in windows.items():
    count = item["packet_count"]

    if count == 0:
        continue

    avg_length = item["total_bytes"] / count

    records.append({
        "window_start": window_start.isoformat(),
        "source_ip": src_ip,
        "packet_count": count,
        "total_bytes": item["total_bytes"],
        "average_packet_length": avg_length,
        "unique_destination_ips": len(item["destination_ips"]),
        "unique_destination_ports": len(item["destination_ports"]),
        "tcp_syn_count": item["tcp_syn_count"],
        "tcp_ack_count": item["tcp_ack_count"],
        "tcp_count": item["tcp_count"],
        "udp_count": item["udp_count"],
        "icmp_count": item["icmp_count"]
    })

records.sort(key=lambda x: (x["window_start"], x["source_ip"]))

if not records:
    raise SystemExit("No usable feature windows were generated.")

X = np.array([
    [record[name] for name in FEATURE_NAMES]
    for record in records
], dtype=float)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42,
    n_jobs=-1
)

model.fit(X_scaled)

decision_scores = model.decision_function(X_scaled)
predictions = model.predict(X_scaled)

for record, score, prediction in zip(records, decision_scores, predictions):
    record["anomaly_score"] = float(-score)
    record["prediction"] = "ANOMALY" if prediction == -1 else "NORMAL"

all_file = os.path.join(OUTPUT_DIR, "ml_windows.csv")
anomaly_file = os.path.join(OUTPUT_DIR, "ml_anomalies.csv")
report_file = os.path.join(OUTPUT_DIR, "ml_report.txt")

with open(all_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "window_start",
            "source_ip",
            *FEATURE_NAMES,
            "anomaly_score",
            "prediction"
        ]
    )
    writer.writeheader()
    writer.writerows(records)

anomalies = [
    record for record in records
    if record["prediction"] == "ANOMALY"
]

anomalies.sort(
    key=lambda x: x["anomaly_score"],
    reverse=True
)

with open(anomaly_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "window_start",
            "source_ip",
            *FEATURE_NAMES,
            "anomaly_score",
            "prediction"
        ]
    )
    writer.writeheader()
    writer.writerows(anomalies)

alert_window_keys = set()

if os.path.exists(DB_FILE):
    conn = sqlite3.connect(DB_FILE)

    try:
        cursor = conn.execute(
            "SELECT timestamp, source_ip FROM alerts"
        )

        for timestamp_value, source_ip in cursor.fetchall():
            parsed = parse_timestamp(timestamp_value)

            if parsed and source_ip:
                alert_window_keys.add(
                    (get_window(parsed).isoformat(), source_ip)
                )
    finally:
        conn.close()

matched_anomalies = 0

for record in anomalies:
    key = (
        record["window_start"],
        record["source_ip"]
    )

    if key in alert_window_keys:
        matched_anomalies += 1

anomaly_rate = (
    len(anomalies) / len(records) * 100
    if records
    else 0
)

alert_coverage = (
    matched_anomalies / len(anomalies) * 100
    if anomalies
    else 0
)

with open(report_file, "w", encoding="utf-8") as f:
    f.write("MACHINE LEARNING ANOMALY DETECTION REPORT\n")
    f.write("=" * 60 + "\n\n")
    f.write(f"Input CSV: {CSV_FILE}\n")
    f.write(f"Total CSV Rows: {total_rows}\n")
    f.write(f"Invalid Rows: {invalid_rows}\n")
    f.write(f"Feature Windows: {len(records)}\n")
    f.write(f"Window Size: {WINDOW_SECONDS} seconds\n")
    f.write(f"Anomaly Windows: {len(anomalies)}\n")
    f.write(f"Anomaly Rate: {anomaly_rate:.2f}%\n")
    f.write(f"Anomalies Matching Existing Alerts: {matched_anomalies}\n")
    f.write(f"Anomaly-to-Alert Window Coverage: {alert_coverage:.2f}%\n\n")

    f.write("FEATURES\n")
    f.write("-" * 60 + "\n")

    for name in FEATURE_NAMES:
        f.write(f"{name}\n")

    f.write("\nTOP ANOMALIES\n")
    f.write("-" * 60 + "\n")

    for record in anomalies[:20]:
        f.write(
            f'{record["window_start"]} | '
            f'{record["source_ip"]} | '
            f'score={record["anomaly_score"]:.6f} | '
            f'packets={record["packet_count"]} | '
            f'bytes={record["total_bytes"]} | '
            f'tcp_syn={record["tcp_syn_count"]} | '
            f'udp={record["udp_count"]} | '
            f'icmp={record["icmp_count"]} | '
            f'unique_ports={record["unique_destination_ports"]}\n'
        )

print("MACHINE LEARNING ANOMALY DETECTION")
print("=" * 60)
print(f"CSV rows: {total_rows}")
print(f"Invalid rows: {invalid_rows}")
print(f"Feature windows: {len(records)}")
print(f"Anomaly windows: {len(anomalies)}")
print(f"Anomaly rate: {anomaly_rate:.2f}%")
print(f"Matched with existing alert windows: {matched_anomalies}")
print(f"Anomaly-to-alert window coverage: {alert_coverage:.2f}%")
print()
print(f"Output: {all_file}")
print(f"Output: {anomaly_file}")
print(f"Report: {report_file}")
