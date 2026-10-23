import sqlite3
import json
import os
import sys
from datetime import datetime

DB_FILE = "ids_alerts.db"
RESULT_FILE = "evaluation/test_results.json"

ATTACK_TYPES = [
    "PORT SCAN",
    "SYN FLOOD",
    "ICMP FLOOD",
    "UDP FLOOD",
    "SUSPICIOUS PORT",
    "BRUTE FORCE",
    "NORMAL TRAFFIC"
]

def get_counts():
    conn = sqlite3.connect(DB_FILE)

    rows = conn.execute("""
        SELECT attack_type, COUNT(*)
        FROM alerts
        GROUP BY attack_type
    """).fetchall()

    conn.close()

    counts = {}

    for attack_type, count in rows:
        counts[attack_type] = count

    return counts

def load_results():
    if not os.path.exists(RESULT_FILE):
        return []

    with open(RESULT_FILE, "r") as file:
        return json.load(file)

def save_results(results):
    with open(RESULT_FILE, "w") as file:
        json.dump(results, file, indent=4)

def start_test(test_name, attack_type):
    counts = get_counts()

    test = {
        "test_name": test_name,
        "attack_type": attack_type,
        "start_time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "before_count": counts.get(
            attack_type,
            0
        )
    }

    with open(
        "evaluation/current_test.json",
        "w"
    ) as file:
        json.dump(test, file, indent=4)

    print("==============================================")
    print("TEST STARTED")
    print("==============================================")
    print(f"Test         : {test_name}")
    print(f"Attack Type  : {attack_type}")
    print(f"Before Count : {test['before_count']}")
    print(f"Start Time   : {test['start_time']}")
    print("==============================================")

def finish_test():
    if not os.path.exists(
        "evaluation/current_test.json"
    ):
        print("No active test found.")
        return

    with open(
        "evaluation/current_test.json"
    ) as file:
        test = json.load(file)

    counts = get_counts()

    after_count = counts.get(
        test["attack_type"],
        0
    )

    delta = (
        after_count -
        test["before_count"]
    )

    detected = delta > 0

    if test["attack_type"] == "NORMAL TRAFFIC":
        false_positive = delta > 0
    else:
        false_positive = False

    test["end_time"] = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    test["after_count"] = after_count
    test["new_alerts"] = delta
    test["detected"] = detected
    test["false_positive"] = false_positive

    results = load_results()

    results.append(test)

    save_results(results)

    os.remove(
        "evaluation/current_test.json"
    )

    print()
    print("==============================================")
    print("TEST FINISHED")
    print("==============================================")
    print(f"Test        : {test['test_name']}")
    print(f"Type        : {test['attack_type']}")
    print(f"New Alerts  : {delta}")
    print(f"Detected    : {detected}")
    print(
        f"False Pos.  : {false_positive}"
    )
    print("==============================================")

def report():
    results = load_results()

    if not results:
        print("No test results available.")
        return

    positive_tests = [
        test
        for test in results
        if test["attack_type"] != "NORMAL TRAFFIC"
    ]

    negative_tests = [
        test
        for test in results
        if test["attack_type"] == "NORMAL TRAFFIC"
    ]

    detected_tests = [
        test
        for test in positive_tests
        if test["detected"]
    ]

    false_positive_tests = [
        test
        for test in negative_tests
        if test["false_positive"]
    ]

    detection_rate = 0

    if positive_tests:
        detection_rate = (
            len(detected_tests)
            / len(positive_tests)
            * 100
        )

    false_positive_rate = 0

    if negative_tests:
        false_positive_rate = (
            len(false_positive_tests)
            / len(negative_tests)
            * 100
        )

    print()
    print("==============================================")
    print("CONTROLLED IDS TEST REPORT")
    print("==============================================")

    print()
    print("Positive Tests")
    print("----------------------------------------------")

    for test in positive_tests:
        print(
            f"{test['attack_type']:20} "
            f"alerts={test['new_alerts']:3} "
            f"detected={test['detected']}"
        )

    print()
    print("Negative Tests")
    print("----------------------------------------------")

    for test in negative_tests:
        print(
            f"{test['test_name']:20} "
            f"alerts={test['new_alerts']:3} "
            f"false_positive={test['false_positive']}"
        )

    print()
    print("Detection Rate")
    print("----------------------------------------------")
    print(
        f"{detection_rate:.2f}% "
        f"({len(detected_tests)}/{len(positive_tests)})"
    )

    print()
    print("False Positive Rate")
    print("----------------------------------------------")
    print(
        f"{false_positive_rate:.2f}% "
        f"({len(false_positive_tests)}/{len(negative_tests)})"
    )

    print("==============================================")

if len(sys.argv) < 2:
    print("Usage:")
    print("  start <test_name> <attack_type>")
    print("  finish")
    print("  report")
    sys.exit(1)

command = sys.argv[1]

if command == "start":

    if len(sys.argv) < 4:
        print(
            "Usage: start <test_name> <attack_type>"
        )
        sys.exit(1)

    start_test(
        sys.argv[2],
        sys.argv[3]
    )

elif command == "finish":

    finish_test()

elif command == "report":

    report()

else:

    print("Unknown command.")
