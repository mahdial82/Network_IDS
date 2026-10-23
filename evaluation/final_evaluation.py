import json
import os
import sqlite3
from datetime import datetime

TEST_RESULTS = "evaluation/test_results.json"
PERFORMANCE_RUN = "evaluation/performance_run_1.json"
PERFORMANCE_LOAD = "evaluation/performance_load.json"

DB_FILE = "ids_alerts.db"

OUTPUT_JSON = "evaluation/final_evaluation.json"
OUTPUT_TXT = "evaluation/final_evaluation.txt"

ATTACK_TYPES = [
    "PORT SCAN",
    "SYN FLOOD",
    "ICMP FLOOD",
    "UDP FLOOD",
    "SUSPICIOUS PORT",
    "BRUTE FORCE"
]

def load_json(path):
    if not os.path.exists(path):
        return None

    with open(path, "r") as file:
        return json.load(file)

def get_database_stats():
    conn = sqlite3.connect(DB_FILE)

    total_packets = conn.execute(
        "SELECT COUNT(*) FROM packets"
    ).fetchone()[0]

    total_bytes = conn.execute(
        "SELECT COALESCE(SUM(length), 0) FROM packets"
    ).fetchone()[0]

    total_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    attack_rows = conn.execute("""
        SELECT attack_type, COUNT(*)
        FROM alerts
        GROUP BY attack_type
    """).fetchall()

    severity_rows = conn.execute("""
        SELECT severity, COUNT(*)
        FROM alerts
        GROUP BY severity
    """).fetchall()

    status_rows = conn.execute("""
        SELECT status, COUNT(*)
        FROM alerts
        GROUP BY status
    """).fetchall()

    protocol_rows = conn.execute("""
        SELECT protocol, COUNT(*)
        FROM packets
        GROUP BY protocol
        ORDER BY COUNT(*) DESC
    """).fetchall()

    conn.close()

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "total_alerts": total_alerts,
        "attacks": dict(attack_rows),
        "severity": dict(severity_rows),
        "status": dict(status_rows),
        "protocols": dict(protocol_rows)
    }

def calculate_detection(test_results):

    if not test_results:
        return {
            "positive_tests": 0,
            "detected_tests": 0,
            "detection_rate": None,
            "negative_tests": 0,
            "false_positive_tests": 0,
            "false_positive_rate": None
        }

    positive = [
        test for test in test_results
        if test["attack_type"] != "NORMAL TRAFFIC"
    ]

    negative = [
        test for test in test_results
        if test["attack_type"] == "NORMAL TRAFFIC"
    ]

    detected = [
        test for test in positive
        if test.get("detected")
    ]

    false_positive = [
        test for test in negative
        if test.get("false_positive")
    ]

    detection_rate = None

    if positive:
        detection_rate = (
            len(detected)
            / len(positive)
            * 100
        )

    false_positive_rate = None

    if negative:
        false_positive_rate = (
            len(false_positive)
            / len(negative)
            * 100
        )

    return {
        "positive_tests": len(positive),
        "detected_tests": len(detected),
        "detection_rate": detection_rate,
        "negative_tests": len(negative),
        "false_positive_tests": len(false_positive),
        "false_positive_rate": false_positive_rate
    }

def build_performance(performance):
    if not performance:
        return None

    return {
        "duration_seconds": performance.get(
            "duration_seconds"
        ),
        "processed_packets": performance.get(
            "processed_packets"
        ),
        "average_pps": performance.get(
            "average_pps"
        ),
        "peak_pps": performance.get(
            "peak_pps"
        ),
        "average_cpu_percent": performance.get(
            "average_cpu_percent"
        ),
        "peak_cpu_percent": performance.get(
            "peak_cpu_percent"
        ),
        "average_ram_mb": performance.get(
            "average_ram_mb"
        ),
        "peak_ram_mb": performance.get(
            "peak_ram_mb"
        ),
        "database_size_bytes": performance.get(
            "database_size_bytes"
        ),
        "exit_code": performance.get(
            "exit_code"
        )
    }

def main():

    test_results = load_json(TEST_RESULTS)
    performance_run = load_json(PERFORMANCE_RUN)
    performance_load = load_json(PERFORMANCE_LOAD)

    db_stats = get_database_stats()

    evaluation = {
        "generated_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "controlled_detection": calculate_detection(
            test_results
        ),
        "database_snapshot": db_stats,
        "performance": {
            "run_1": build_performance(
                performance_run
            ),
            "load_test": build_performance(
                performance_load
            )
        }
    }

    with open(
        OUTPUT_JSON,
        "w"
    ) as file:
        json.dump(
            evaluation,
            file,
            indent=4
        )

    with open(
        OUTPUT_TXT,
        "w"
    ) as file:

        file.write(
            "NETWORK IDS FINAL EVALUATION REPORT\n"
        )

        file.write(
            "=" * 60 + "\n\n"
        )

        file.write(
            f"Generated: "
            f"{evaluation['generated_at']}\n\n"
        )

        detection = evaluation[
            "controlled_detection"
        ]

        file.write(
            "1. CONTROLLED DETECTION RESULTS\n"
        )

        file.write(
            "-" * 60 + "\n"
        )

        file.write(
            f"Positive Tests: "
            f"{detection['positive_tests']}\n"
        )

        file.write(
            f"Detected Tests: "
            f"{detection['detected_tests']}\n"
        )

        if detection["detection_rate"] is not None:
            file.write(
                f"Detection Rate: "
                f"{detection['detection_rate']:.2f}%\n"
            )

        file.write(
            f"Negative Tests: "
            f"{detection['negative_tests']}\n"
        )

        file.write(
            f"False Positive Tests: "
            f"{detection['false_positive_tests']}\n"
        )

        if detection["false_positive_rate"] is not None:
            file.write(
                f"False Positive Rate: "
                f"{detection['false_positive_rate']:.2f}%\n"
            )

        file.write("\n")

        snapshot = evaluation[
            "database_snapshot"
        ]

        file.write(
            "2. OPERATIONAL DATABASE SNAPSHOT\n"
        )

        file.write(
            "-" * 60 + "\n"
        )

        file.write(
            f"Total Packets: "
            f"{snapshot['total_packets']:,}\n"
        )

        file.write(
            f"Total Bytes: "
            f"{snapshot['total_bytes']:,}\n"
        )

        file.write(
            f"Total Alerts: "
            f"{snapshot['total_alerts']:,}\n"
        )

        file.write("\nAttack Types:\n")

        for attack in ATTACK_TYPES:
            file.write(
                f"  {attack}: "
                f"{snapshot['attacks'].get(attack, 0):,}\n"
            )

        file.write("\nSeverity:\n")

        for severity in [
            "HIGH",
            "MEDIUM",
            "LOW"
        ]:
            file.write(
                f"  {severity}: "
                f"{snapshot['severity'].get(severity, 0):,}\n"
            )

        file.write("\nStatus:\n")

        for status in [
            "NEW",
            "ACKNOWLEDGED",
            "RESOLVED"
        ]:
            file.write(
                f"  {status}: "
                f"{snapshot['status'].get(status, 0):,}\n"
            )

        file.write("\nProtocols:\n")

        for protocol, count in snapshot[
            "protocols"
        ].items():
            file.write(
                f"  {protocol}: {count:,}\n"
            )

        file.write("\n")

        file.write(
            "3. PERFORMANCE RESULTS\n"
        )

        file.write(
            "-" * 60 + "\n"
        )

        for label, performance in [
            ("Run 1", evaluation["performance"]["run_1"]),
            ("Load Test", evaluation["performance"]["load_test"])
        ]:

            file.write(
                f"\n{label}:\n"
            )

            if not performance:
                file.write(
                    "  NOT AVAILABLE\n"
                )
                continue

            file.write(
                f"  Duration: "
                f"{performance['duration_seconds']:.2f} sec\n"
            )

            file.write(
                f"  Processed Packets: "
                f"{performance['processed_packets']:,}\n"
            )

            file.write(
                f"  Average PPS: "
                f"{performance['average_pps']:.2f}\n"
            )

            file.write(
                f"  Peak PPS: "
                f"{performance['peak_pps']:.2f}\n"
            )

            file.write(
                f"  Average CPU: "
                f"{performance['average_cpu_percent']:.2f}%\n"
            )

            file.write(
                f"  Peak CPU: "
                f"{performance['peak_cpu_percent']:.2f}%\n"
            )

            file.write(
                f"  Average RAM: "
                f"{performance['average_ram_mb']:.2f} MB\n"
            )

            file.write(
                f"  Peak RAM: "
                f"{performance['peak_ram_mb']:.2f} MB\n"
            )

            file.write(
                f"  Database Size: "
                f"{performance['database_size_bytes']:,} bytes\n"
            )

            file.write(
                f"  Exit Code: "
                f"{performance['exit_code']}\n"
            )

        file.write("\n")

        file.write(
            "4. INTERPRETATION\n"
        )

        file.write(
            "-" * 60 + "\n"
        )

        if detection["detection_rate"] is not None:
            file.write(
                f"The controlled test set achieved a "
                f"detection rate of "
                f"{detection['detection_rate']:.2f}% "
                f"across "
                f"{detection['positive_tests']} "
                f"positive scenarios.\n"
            )

        if detection["false_positive_rate"] is not None:
            file.write(
                f"The observed false positive rate was "
                f"{detection['false_positive_rate']:.2f}% "
                f"across "
                f"{detection['negative_tests']} "
                f"negative scenarios.\n"
            )

        file.write(
            "These controlled results should be interpreted "
            "within the scope of the tested VMware laboratory "
            "scenarios and should not be generalized to "
            "unobserved traffic conditions.\n"
        )

    print(
        "=============================================="
    )
    print(
        "FINAL EVALUATION GENERATED"
    )
    print(
        "=============================================="
    )

    detection = evaluation[
        "controlled_detection"
    ]

    if detection["detection_rate"] is not None:
        print(
            f"Detection Rate: "
            f"{detection['detection_rate']:.2f}%"
        )

    if detection["false_positive_rate"] is not None:
        print(
            f"False Positive Rate: "
            f"{detection['false_positive_rate']:.2f}%"
        )

    print(
        f"Total Packets: "
        f"{db_stats['total_packets']:,}"
    )

    print(
        f"Total Alerts: "
        f"{db_stats['total_alerts']:,}"
    )

    print()
    print(
        f"TXT Report: {OUTPUT_TXT}"
    )

    print(
        f"JSON Report: {OUTPUT_JSON}"
    )

if __name__ == "__main__":
    main()
