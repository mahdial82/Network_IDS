import os
import signal
import sqlite3
import subprocess
import time
import json
from datetime import datetime

DB_FILE = "ids_alerts.db"
REPORT_JSON = "evaluation/performance_report.json"
REPORT_TXT = "evaluation/performance_report.txt"
CAPTURE_LOG = "evaluation/performance_capture.log"

TEST_DURATION = 30
SAMPLE_INTERVAL = 1

def get_packet_count():
    conn = sqlite3.connect(DB_FILE)

    count = conn.execute(
        "SELECT COUNT(*) FROM packets"
    ).fetchone()[0]

    conn.close()

    return count

def get_cpu_ram(pid):
    try:
        with open(f"/proc/{pid}/stat") as file:
            data = file.read()

        end_comm = data.rfind(")")
        fields = data[end_comm + 2:].split()

        utime = int(fields[11])
        stime = int(fields[12])

        clock_ticks = os.sysconf(
            os.sysconf_names["SC_CLK_TCK"]
        )

        cpu_time = (
            utime + stime
        ) / clock_ticks

        with open(
            f"/proc/{pid}/status"
        ) as file:
            status = file.read()

        rss_kb = 0

        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                rss_kb = int(
                    line.split()[1]
                )
                break

        return cpu_time, rss_kb

    except Exception:
        return None, None

def main():

    if os.geteuid() != 0:
        print("Run this test with sudo.")
        return

    start_packet_count = get_packet_count()

    started_at = datetime.now()

    capture_log = open(
        CAPTURE_LOG,
        "w"
    )

    process = subprocess.Popen(
        [
            "./venv/bin/python",
            "packet_capture.py"
        ],
        stdout=capture_log,
        stderr=subprocess.STDOUT
    )

    pid = process.pid

    print("==============================================")
    print("NETWORK IDS PERFORMANCE TEST")
    print("==============================================")
    print(f"PID            : {pid}")
    print(f"Duration       : {TEST_DURATION} seconds")
    print(f"Start Packets  : {start_packet_count}")
    print("==============================================")
    print()

    samples = []

    last_packet_count = start_packet_count
    previous_time = time.time()

    test_start = time.time()

    while time.time() - test_start < TEST_DURATION:

        time.sleep(SAMPLE_INTERVAL)

        current_time = time.time()

        packet_count = get_packet_count()

        cpu_time, rss_kb = get_cpu_ram(pid)

        if cpu_time is not None:

            elapsed_since_start = (
                current_time - test_start
            )

            cpu_percent = (
                cpu_time /
                max(elapsed_since_start, 0.001)
                * 100
            )

        else:
            cpu_percent = None

        elapsed = current_time - previous_time

        packet_delta = (
            packet_count -
            last_packet_count
        )

        pps = (
            packet_delta /
            max(elapsed, 0.001)
        )

        samples.append(
            {
                "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "packets": packet_count,
                "pps": pps,
                "cpu": cpu_percent,
                "rss_kb": rss_kb
            }
        )

        last_packet_count = packet_count
        previous_time = current_time

        print(
            f"Packets={packet_count:,} | "
            f"PPS={pps:.2f} | "
            f"CPU={cpu_percent:.2f}% | "
            f"RAM={rss_kb / 1024:.2f} MB"
        )

    try:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()

    capture_log.close()

    end_packet_count = get_packet_count()

    finished_at = datetime.now()

    total_packets = (
        end_packet_count -
        start_packet_count
    )

    actual_duration = (
        finished_at - started_at
    ).total_seconds()

    average_pps = (
        total_packets /
        max(actual_duration, 0.001)
    )

    valid_pps = [
        sample["pps"]
        for sample in samples
    ]

    valid_cpu = [
        sample["cpu"]
        for sample in samples
        if sample["cpu"] is not None
    ]

    valid_ram = [
        sample["rss_kb"]
        for sample in samples
        if sample["rss_kb"] is not None
    ]

    peak_pps = (
        max(valid_pps)
        if valid_pps
        else 0
    )

    average_cpu = (
        sum(valid_cpu) /
        len(valid_cpu)
        if valid_cpu
        else 0
    )

    peak_cpu = (
        max(valid_cpu)
        if valid_cpu
        else 0
    )

    average_ram = (
        sum(valid_ram) /
        len(valid_ram)
        if valid_ram
        else 0
    )

    peak_ram = (
        max(valid_ram)
        if valid_ram
        else 0
    )

    db_size = os.path.getsize(DB_FILE)

    report = {
        "started_at": started_at.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "finished_at": finished_at.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "duration_seconds": actual_duration,
        "start_packets": start_packet_count,
        "end_packets": end_packet_count,
        "processed_packets": total_packets,
        "average_pps": average_pps,
        "peak_pps": peak_pps,
        "average_cpu_percent": average_cpu,
        "peak_cpu_percent": peak_cpu,
        "average_ram_mb": average_ram / 1024,
        "peak_ram_mb": peak_ram / 1024,
        "database_size_bytes": db_size,
        "exit_code": process.returncode,
        "samples": samples
    }

    with open(
        REPORT_JSON,
        "w"
    ) as file:
        json.dump(
            report,
            file,
            indent=4
        )

    with open(
        REPORT_TXT,
        "w"
    ) as file:

        file.write(
            "NETWORK IDS PERFORMANCE REPORT\n"
        )

        file.write(
            "=" * 50 + "\n\n"
        )

        file.write(
            f"Duration: {actual_duration:.2f} seconds\n"
        )

        file.write(
            f"Processed Packets: {total_packets:,}\n"
        )

        file.write(
            f"Average PPS: {average_pps:.2f}\n"
        )

        file.write(
            f"Peak PPS: {peak_pps:.2f}\n"
        )

        file.write(
            f"Average CPU: {average_cpu:.2f}%\n"
        )

        file.write(
            f"Peak CPU: {peak_cpu:.2f}%\n"
        )

        file.write(
            f"Average RAM: {average_ram / 1024:.2f} MB\n"
        )

        file.write(
            f"Peak RAM: {peak_ram / 1024:.2f} MB\n"
        )

        file.write(
            f"Database Size: {db_size:,} bytes\n"
        )

        file.write(
            f"Process Exit Code: {process.returncode}\n"
        )

    print()
    print("==============================================")
    print("PERFORMANCE TEST COMPLETE")
    print("==============================================")
    print(f"Processed Packets : {total_packets:,}")
    print(f"Average PPS       : {average_pps:.2f}")
    print(f"Peak PPS          : {peak_pps:.2f}")
    print(f"Average CPU       : {average_cpu:.2f}%")
    print(f"Peak CPU          : {peak_cpu:.2f}%")
    print(
        f"Average RAM       : "
        f"{average_ram / 1024:.2f} MB"
    )
    print(
        f"Peak RAM          : "
        f"{peak_ram / 1024:.2f} MB"
    )
    print(
        f"Database Size     : "
        f"{db_size:,} bytes"
    )
    print(f"Exit Code         : {process.returncode}")
    print()
    print(f"Report: {REPORT_TXT}")
    print("==============================================")

if __name__ == "__main__":
    main()
