import csv
import sqlite3
from collections import Counter
from datetime import datetime

ML_FILE = "evaluation/ml/ml_windows.csv"
DB_FILE = "ids_alerts.db"
OUTPUT_FILE = "evaluation/ml/ml_evaluation.txt"
WINDOW_SECONDS = 5

def parse_timestamp(value):
    if not value:
        return None

    value = value.strip()

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        pass

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

def normalize_window(value):
    timestamp = parse_timestamp(value)

    if timestamp is None:
        return None

    return timestamp.replace(
        second=(timestamp.second // WINDOW_SECONDS) * WINDOW_SECONDS,
        microsecond=0
    )

ml_records = []

with open(ML_FILE, "r", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)

    for row in reader:
        window = normalize_window(row.get("window_start", ""))

        if window is None:
            continue

        ml_records.append({
            "window": window,
            "source_ip": row.get("source_ip", ""),
            "prediction": row.get("prediction", ""),
            "anomaly_score": float(row.get("anomaly_score", 0)),
            "packet_count": int(row.get("packet_count", 0)),
            "tcp_syn_count": int(row.get("tcp_syn_count", 0)),
            "udp_count": int(row.get("udp_count", 0)),
            "icmp_count": int(row.get("icmp_count", 0)),
            "unique_destination_ports": int(
                row.get("unique_destination_ports", 0)
            )
        })

anomaly_records = [
    row for row in ml_records
    if row["prediction"] == "ANOMALY"
]

anomaly_keys = {
    (row["window"], row["source_ip"])
    for row in anomaly_records
}

conn = sqlite3.connect(DB_FILE)

try:
    rows = conn.execute(
        """
        SELECT timestamp, attack_type, source_ip, target_ip
        FROM alerts
        ORDER BY timestamp
        """
    ).fetchall()
finally:
    conn.close()

alert_records = []

for timestamp, attack_type, source_ip, target_ip in rows:
    window = normalize_window(timestamp)

    if window is None:
        continue

    alert_records.append({
        "window": window,
        "attack_type": attack_type,
        "source_ip": source_ip,
        "target_ip": target_ip
    })

alert_windows = {
    (row["window"], row["source_ip"])
    for row in alert_records
}

matched_keys = anomaly_keys.intersection(alert_windows)

anomaly_count = len(anomaly_keys)
alert_window_count = len(alert_windows)
matched_count = len(matched_keys)

anomaly_overlap_rate = (
    matched_count / anomaly_count * 100
    if anomaly_count
    else 0
)

alert_coverage_rate = (
    matched_count / alert_window_count * 100
    if alert_window_count
    else 0
)

attack_totals = Counter()
attack_matched = Counter()

for row in alert_records:
    key = (row["window"], row["source_ip"])
    attack_totals[row["attack_type"]] += 1

    if key in anomaly_keys:
        attack_matched[row["attack_type"]] += 1

feature_patterns = {
    "SYN-HEAVY": 0,
    "PORT-SCAN-LIKE": 0,
    "ICMP-HEAVY": 0,
    "UDP-HEAVY": 0,
    "OTHER-ANOMALY": 0
}

for row in anomaly_records:
    tcp_syn = row["tcp_syn_count"]
    udp = row["udp_count"]
    icmp = row["icmp_count"]
    ports = row["unique_destination_ports"]

    if tcp_syn >= 50 and ports <= 3:
        feature_patterns["SYN-HEAVY"] += 1
    elif ports >= 10:
        feature_patterns["PORT-SCAN-LIKE"] += 1
    elif icmp >= 50:
        feature_patterns["ICMP-HEAVY"] += 1
    elif udp >= 50:
        feature_patterns["UDP-HEAVY"] += 1
    else:
        feature_patterns["OTHER-ANOMALY"] += 1

matched_records = [
    row for row in anomaly_records
    if (row["window"], row["source_ip"]) in matched_keys
]

matched_records.sort(
    key=lambda row: row["anomaly_score"],
    reverse=True
)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("MACHINE LEARNING EVALUATION\n")
    f.write("=" * 60 + "\n\n")

    f.write("DATASET\n")
    f.write("-" * 60 + "\n")
    f.write(f"ML feature windows: {len(ml_records)}\n")
    f.write(f"ML anomaly windows: {anomaly_count}\n")
    f.write(f"Rule-based alert windows: {alert_window_count}\n")
    f.write(f"Overlapping windows: {matched_count}\n\n")

    f.write("OVERLAP ANALYSIS\n")
    f.write("-" * 60 + "\n")
    f.write(
        f"ML anomaly windows overlapping rule alerts: "
        f"{anomaly_overlap_rate:.2f}%\n"
    )
    f.write(
        f"Rule alert windows also identified by ML: "
        f"{alert_coverage_rate:.2f}%\n\n"
    )

    f.write("ATTACK TYPE OVERLAP\n")
    f.write("-" * 60 + "\n")

    for attack_type in sorted(attack_totals):
        total = attack_totals[attack_type]
        matched = attack_matched[attack_type]
        rate = matched / total * 100 if total else 0

        f.write(
            f"{attack_type}: "
            f"{matched}/{total} alert windows matched "
            f"({rate:.2f}%)\n"
        )

    f.write("\nANOMALY PATTERN ANALYSIS\n")
    f.write("-" * 60 + "\n")

    for pattern, count in feature_patterns.items():
        f.write(f"{pattern}: {count}\n")

    f.write("\nTOP MATCHED ANOMALIES\n")
    f.write("-" * 60 + "\n")

    for row in matched_records[:30]:
        f.write(
            f'{row["window"].isoformat()} | '
            f'{row["source_ip"]} | '
            f'score={row["anomaly_score"]:.6f} | '
            f'packets={row["packet_count"]} | '
            f'tcp_syn={row["tcp_syn_count"]} | '
            f'udp={row["udp_count"]} | '
            f'icmp={row["icmp_count"]} | '
            f'unique_ports={row["unique_destination_ports"]}\n'
        )

print("MACHINE LEARNING EVALUATION")
print("=" * 60)
print(f"ML feature windows: {len(ml_records)}")
print(f"ML anomaly windows: {anomaly_count}")
print(f"Rule alert windows: {alert_window_count}")
print(f"Overlapping windows: {matched_count}")
print(f"ML anomaly overlap: {anomaly_overlap_rate:.2f}%")
print(f"Rule alert coverage by ML: {alert_coverage_rate:.2f}%")
print()
print("Attack Type Overlap")

for attack_type in sorted(attack_totals):
    total = attack_totals[attack_type]
    matched = attack_matched[attack_type]
    rate = matched / total * 100 if total else 0
    print(f"{attack_type}: {matched}/{total} ({rate:.2f}%)")

print()
print("Anomaly Pattern Analysis")

for pattern, count in feature_patterns.items():
    print(f"{pattern}: {count}")

print()
print(f"Report: {OUTPUT_FILE}")
