import sqlite3
import json
import os
import argparse
from datetime import datetime

DB_FILE = "ids_alerts.db"
OUTPUT_FILE = "evaluation/evaluation_report.txt"
BASELINE_FILE = "evaluation/baseline.json"

ATTACK_TYPES = [
    "PORT SCAN",
    "SYN FLOOD",
    "ICMP FLOOD",
    "UDP FLOOD",
    "SUSPICIOUS PORT",
    "BRUTE FORCE"
]

SEVERITIES = [
    "HIGH",
    "MEDIUM",
    "LOW"
]

STATUSES = [
    "NEW",
    "ACKNOWLEDGED",
    "RESOLVED"
]

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def collect_stats():
    conn = get_connection()

    total_packets = conn.execute(
        "SELECT COUNT(*) FROM packets"
    ).fetchone()[0]

    total_bytes = conn.execute(
        "SELECT COALESCE(SUM(length), 0) FROM packets"
    ).fetchone()[0]

    protocol_rows = conn.execute("""
        SELECT protocol, COUNT(*) AS count
        FROM packets
        GROUP BY protocol
        ORDER BY count DESC
    """).fetchall()

    alert_total = conn.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    attack_rows = conn.execute("""
        SELECT attack_type, COUNT(*) AS count
        FROM alerts
        GROUP BY attack_type
        ORDER BY count DESC
    """).fetchall()

    severity_rows = conn.execute("""
        SELECT severity, COUNT(*) AS count
        FROM alerts
        GROUP BY severity
        ORDER BY count DESC
    """).fetchall()

    status_rows = conn.execute("""
        SELECT status, COUNT(*) AS count
        FROM alerts
        GROUP BY status
        ORDER BY count DESC
    """).fetchall()

    first_packet = conn.execute("""
        SELECT timestamp
        FROM packets
        ORDER BY id ASC
        LIMIT 1
    """).fetchone()

    last_packet = conn.execute("""
        SELECT timestamp
        FROM packets
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    db_size = os.path.getsize(DB_FILE)

    conn.close()

    protocols = {
        row["protocol"]: row["count"]
        for row in protocol_rows
    }

    attacks = {
        row["attack_type"]: row["count"]
        for row in attack_rows
    }

    severities = {
        row["severity"]: row["count"]
        for row in severity_rows
    }

    statuses = {
        row["status"]: row["count"]
        for row in status_rows
    }

    packet_rate = 0

    if first_packet and last_packet:
        try:
            start = datetime.strptime(
                first_packet["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            end = datetime.strptime(
                last_packet["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            duration = (end - start).total_seconds()

            if duration > 0:
                packet_rate = total_packets / duration

        except ValueError:
            packet_rate = 0

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocols": protocols,
        "alert_total": alert_total,
        "attacks": attacks,
        "severities": severities,
        "statuses": statuses,
        "first_packet": first_packet["timestamp"] if first_packet else "",
        "last_packet": last_packet["timestamp"] if last_packet else "",
        "packet_rate": packet_rate,
        "db_size": db_size
    }

def print_report(stats):
    print()
    print("==============================================")
    print("NETWORK IDS EVALUATION")
    print("==============================================")
    print(f"Total Packets : {stats['total_packets']:,}")
    print(f"Total Bytes   : {stats['total_bytes']:,}")
    print(f"Average PPS   : {stats['packet_rate']:.2f}")
    print(f"Database Size : {stats['db_size']:,} bytes")
    print()

    print("Protocol Statistics")
    print("----------------------------------------------")

    for protocol, count in stats["protocols"].items():
        print(f"{protocol:10} : {count:,}")

    print()
    print("Alert Statistics")
    print("----------------------------------------------")
    print(f"Total Alerts : {stats['alert_total']:,}")

    for attack in ATTACK_TYPES:
        print(
            f"{attack:20} : "
            f"{stats['attacks'].get(attack, 0):,}"
        )

    print()
    print("Severity")
    print("----------------------------------------------")

    for severity in SEVERITIES:
        print(
            f"{severity:10} : "
            f"{stats['severities'].get(severity, 0):,}"
        )

    print()
    print("Status")
    print("----------------------------------------------")

    for status in STATUSES:
        print(
            f"{status:15} : "
            f"{stats['statuses'].get(status, 0):,}"
        )

    print()
    print(f"First Packet : {stats['first_packet']}")
    print(f"Last Packet  : {stats['last_packet']}")
    print("==============================================")
    print()

def save_report(stats):
    with open(OUTPUT_FILE, "w") as file:
        file.write("NETWORK IDS EVALUATION REPORT\n")
        file.write("=" * 50 + "\n\n")

        file.write(
            f"Total Packets : {stats['total_packets']:,}\n"
        )

        file.write(
            f"Total Bytes   : {stats['total_bytes']:,}\n"
        )

        file.write(
            f"Average PPS   : {stats['packet_rate']:.2f}\n"
        )

        file.write(
            f"Database Size : {stats['db_size']:,} bytes\n\n"
        )

        file.write("PROTOCOL STATISTICS\n")
        file.write("-" * 50 + "\n")

        for protocol, count in stats["protocols"].items():
            file.write(
                f"{protocol}: {count:,}\n"
            )

        file.write("\nALERT STATISTICS\n")
        file.write("-" * 50 + "\n")

        for attack in ATTACK_TYPES:
            file.write(
                f"{attack}: "
                f"{stats['attacks'].get(attack, 0):,}\n"
            )

        file.write("\nSEVERITY\n")
        file.write("-" * 50 + "\n")

        for severity in SEVERITIES:
            file.write(
                f"{severity}: "
                f"{stats['severities'].get(severity, 0):,}\n"
            )

        file.write("\nSTATUS\n")
        file.write("-" * 50 + "\n")

        for status in STATUSES:
            file.write(
                f"{status}: "
                f"{stats['statuses'].get(status, 0):,}\n"
            )

def save_baseline(stats):
    with open(BASELINE_FILE, "w") as file:
        json.dump(
            stats,
            file,
            indent=4
        )

    print(
        f"Baseline saved to {BASELINE_FILE}"
    )

def compare_baseline(stats):
    if not os.path.exists(BASELINE_FILE):
        print("Baseline file not found.")
        return

    with open(BASELINE_FILE) as file:
        baseline = json.load(file)

    print()
    print("==============================================")
    print("EVALUATION DELTA")
    print("==============================================")

    print(
        "New Packets : "
        f"{stats['total_packets'] - baseline['total_packets']:,}"
    )

    print(
        "New Alerts  : "
        f"{stats['alert_total'] - baseline['alert_total']:,}"
    )

    print()

    for attack in ATTACK_TYPES:

        before = baseline["attacks"].get(
            attack,
            0
        )

        after = stats["attacks"].get(
            attack,
            0
        )

        print(
            f"{attack:20} : "
            f"{after - before:+d}"
        )

    print("==============================================")
    print()

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--save-baseline",
        action="store_true"
    )

    parser.add_argument(
        "--compare",
        action="store_true"
    )

    args = parser.parse_args()

    stats = collect_stats()

    print_report(stats)
    save_report(stats)

    if args.save_baseline:
        save_baseline(stats)

    if args.compare:
        compare_baseline(stats)

if __name__ == "__main__":
    main()
