import csv
import re
from pathlib import Path
from collections import Counter
from fastapi import APIRouter

router = APIRouter(prefix="/ml", tags=["Machine Learning"])

BASE_DIR = Path(__file__).resolve().parent
WINDOWS_FILE = BASE_DIR / "ml_windows.csv"
EVALUATION_FILE = BASE_DIR / "ml_evaluation.txt"

def load_windows():
    if not WINDOWS_FILE.exists():
        return []

    records = []

    with open(WINDOWS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)

        for row in reader:
            try:
                records.append({
                    "window_start": row["window_start"],
                    "source_ip": row["source_ip"],
                    "packet_count": int(row["packet_count"]),
                    "total_bytes": int(row["total_bytes"]),
                    "tcp_syn_count": int(row["tcp_syn_count"]),
                    "tcp_ack_count": int(row["tcp_ack_count"]),
                    "tcp_count": int(row["tcp_count"]),
                    "udp_count": int(row["udp_count"]),
                    "icmp_count": int(row["icmp_count"]),
                    "unique_destination_ports": int(
                        row["unique_destination_ports"]
                    ),
                    "anomaly_score": float(row["anomaly_score"]),
                    "prediction": row["prediction"]
                })
            except (KeyError, ValueError):
                continue

    return records

def load_evaluation():
    values = {
        "rule_alert_windows": 0,
        "overlapping_windows": 0,
        "anomaly_overlap_rate": 0.0,
        "alert_coverage_rate": 0.0,
        "attack_overlap": {}
    }

    if not EVALUATION_FILE.exists():
        return values

    text = EVALUATION_FILE.read_text(
        encoding="utf-8",
        errors="ignore"
    )

    patterns = {
        "rule_alert_windows": r"Rule-based alert windows: (\d+)",
        "overlapping_windows": r"Overlapping windows: (\d+)",
        "anomaly_overlap_rate": r"ML anomaly windows overlapping rule alerts: ([\d.]+)%",
        "alert_coverage_rate": r"Rule alert windows also identified by ML: ([\d.]+)%"
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, text)

        if match:
            values[key] = (
                float(match.group(1))
                if "." in match.group(1)
                else int(match.group(1))
            )

    section = re.search(
        r"ATTACK TYPE OVERLAP\s+-+\s+(.*?)(?:\n\n|\Z)",
        text,
        re.S
    )

    if section:
        for line in section.group(1).splitlines():
            match = re.match(
                r"(.+?):\s+(\d+)/(\d+) alert windows matched \(([\d.]+)%\)",
                line.strip()
            )

            if match:
                attack_type = match.group(1).strip()

                values["attack_overlap"][attack_type] = {
                    "matched": int(match.group(2)),
                    "total": int(match.group(3)),
                    "rate": float(match.group(4))
                }

    return values

@router.get("/stats")
def ml_stats():
    records = load_windows()
    evaluation = load_evaluation()

    anomalies = [
        record for record in records
        if record["prediction"] == "ANOMALY"
    ]

    patterns = Counter()

    for record in anomalies:
        syn = record["tcp_syn_count"]
        udp = record["udp_count"]
        icmp = record["icmp_count"]
        ports = record["unique_destination_ports"]

        if syn >= 50 and ports <= 3:
            patterns["SYN-HEAVY"] += 1
        elif ports >= 10:
            patterns["PORT-SCAN-LIKE"] += 1
        elif icmp >= 50:
            patterns["ICMP-HEAVY"] += 1
        elif udp >= 50:
            patterns["UDP-HEAVY"] += 1
        else:
            patterns["OTHER-ANOMALY"] += 1

    anomaly_rate = (
        len(anomalies) / len(records) * 100
        if records
        else 0
    )

    return {
        "feature_windows": len(records),
        "anomaly_windows": len(anomalies),
        "anomaly_rate": round(anomaly_rate, 2),
        "rule_alert_windows": evaluation["rule_alert_windows"],
        "overlapping_windows": evaluation["overlapping_windows"],
        "anomaly_overlap_rate": evaluation["anomaly_overlap_rate"],
        "alert_coverage_rate": evaluation["alert_coverage_rate"],
        "attack_overlap": evaluation["attack_overlap"],
        "anomaly_patterns": dict(patterns)
    }

@router.get("/anomalies")
def ml_anomalies(limit: int = 20):
    records = load_windows()

    anomalies = [
        record for record in records
        if record["prediction"] == "ANOMALY"
    ]

    anomalies.sort(
        key=lambda x: x["anomaly_score"],
        reverse=True
    )

    return anomalies[:max(1, min(limit, 100))]
