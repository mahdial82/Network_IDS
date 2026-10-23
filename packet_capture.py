from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
from collections import defaultdict, deque
import csv
import os
import sqlite3
import json
import logging
from logging.handlers import RotatingFileHandler

CONFIG_FILE = "config.json"

with open(CONFIG_FILE, "r") as file:
    config = json.load(file)

INTERFACE = config["interface"]
CSV_FILE = config["csv_file"]
DB_FILE = config["db_file"]
LOG_FILE = config["log_file"]
LOG_MAX_BYTES = config["log_max_bytes"]
LOG_BACKUP_COUNT = config["log_backup_count"]
TIME_WINDOW = config["time_window"]
PORT_SCAN_THRESHOLD = config["port_scan_threshold"]
SYN_FLOOD_THRESHOLD = config["syn_flood_threshold"]
ICMP_FLOOD_THRESHOLD = config["icmp_flood_threshold"]
UDP_FLOOD_THRESHOLD = config["udp_flood_threshold"]
ALERT_SUPPRESSION_SECONDS = config["alert_suppression_seconds"]
SUSPICIOUS_PORT_SUPPRESSION_SECONDS = config["suspicious_port_suppression_seconds"]
BRUTE_FORCE_THRESHOLD = config["brute_force_threshold"]
BRUTE_FORCE_WINDOW = config["brute_force_window"]
BRUTE_FORCE_SUPPRESSION_SECONDS = config["brute_force_suppression_seconds"]
DB_COMMIT_INTERVAL = config["db_commit_interval"]

SUSPICIOUS_PORTS = {
    int(port): service
    for port, service in config["suspicious_ports"].items()
}

BRUTE_FORCE_PORTS = {
    int(port): service
    for port, service in config["brute_force_ports"].items()
}

if TIME_WINDOW <= 0:
    raise ValueError("time_window must be greater than 0")

if PORT_SCAN_THRESHOLD <= 0:
    raise ValueError("port_scan_threshold must be greater than 0")

if SYN_FLOOD_THRESHOLD <= 0:
    raise ValueError("syn_flood_threshold must be greater than 0")

if ICMP_FLOOD_THRESHOLD <= 0:
    raise ValueError("icmp_flood_threshold must be greater than 0")

if UDP_FLOOD_THRESHOLD <= 0:
    raise ValueError("udp_flood_threshold must be greater than 0")

if ALERT_SUPPRESSION_SECONDS < 0:
    raise ValueError("alert_suppression_seconds cannot be negative")

if SUSPICIOUS_PORT_SUPPRESSION_SECONDS < 0:
    raise ValueError("suspicious_port_suppression_seconds cannot be negative")

if BRUTE_FORCE_THRESHOLD <= 0:
    raise ValueError("brute_force_threshold must be greater than 0")

if BRUTE_FORCE_WINDOW <= 0:
    raise ValueError("brute_force_window must be greater than 0")

if BRUTE_FORCE_SUPPRESSION_SECONDS < 0:
    raise ValueError("brute_force_suppression_seconds cannot be negative")

if DB_COMMIT_INTERVAL <= 0:
    raise ValueError("db_commit_interval must be greater than 0")

logger = logging.getLogger("network_ids")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT
    )

    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

scan_tracker = defaultdict(deque)
syn_tracker = defaultdict(deque)
icmp_tracker = defaultdict(deque)
udp_tracker = defaultdict(deque)
brute_force_tracker = defaultdict(deque)

last_port_scan_alert = {}
last_suspicious_port_alert = {}
last_syn_flood_alert = {}
last_icmp_flood_alert = {}
last_udp_flood_alert = {}
last_brute_force_alert = {}

db_conn = None
db_packet_count = 0
csv_file = None
csv_writer = None

def init_database():
    global db_conn

    db_conn = sqlite3.connect(DB_FILE)

    cursor = db_conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            count INTEGER NOT NULL,
            details TEXT,
            severity TEXT,
            status TEXT DEFAULT 'NEW'
        )
    """)

    columns = [
        row[1]
        for row in cursor.execute(
            "PRAGMA table_info(alerts)"
        ).fetchall()
    ]

    if "severity" not in columns:
        cursor.execute(
            "ALTER TABLE alerts ADD COLUMN severity TEXT"
        )

    if "status" not in columns:
        cursor.execute(
            "ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'NEW'"
        )

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port TEXT,
            dst_port TEXT,
            tcp_flags TEXT,
            length INTEGER
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_packets_timestamp
        ON packets(timestamp)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_packets_src_ip
        ON packets(src_ip)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_packets_dst_ip
        ON packets(dst_ip)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_packets_protocol
        ON packets(protocol)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_attack_type
        ON alerts(attack_type)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
        ON alerts(source_ip)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
        ON alerts(timestamp)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_severity
        ON alerts(severity)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_status
        ON alerts(status)
    """)

    db_conn.commit()

def init_csv():
    global csv_file
    global csv_writer

    file_exists = os.path.exists(CSV_FILE)

    csv_file = open(CSV_FILE, "a", newline="")
    csv_writer = csv.writer(csv_file)

    if not file_exists:
        csv_writer.writerow([
            "timestamp",
            "src_ip",
            "dst_ip",
            "protocol",
            "src_port",
            "dst_port",
            "tcp_flags",
            "length"
        ])

        csv_file.flush()

def save_packet(row):
    global db_packet_count

    csv_writer.writerow(row)

    cursor = db_conn.cursor()

    cursor.execute(
        """
        INSERT INTO packets
        (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags, length)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            row[0],
            row[1],
            row[2],
            row[3],
            str(row[4]),
            str(row[5]),
            row[6],
            int(row[7])
        )
    )

    db_packet_count += 1

    if db_packet_count % DB_COMMIT_INTERVAL == 0:
        db_conn.commit()
        csv_file.flush()

def save_alert(
    attack_type,
    src_ip,
    dst_ip,
    count,
    details="",
    severity="HIGH"
):
    cursor = db_conn.cursor()

    cursor.execute(
        """
        INSERT INTO alerts
        (timestamp, attack_type, source_ip, target_ip, count, details, severity, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attack_type,
            src_ip,
            dst_ip,
            count,
            details,
            severity,
            "NEW"
        )
    )

    db_conn.commit()

    logger.warning(
        "DETECTION | type=%s | severity=%s | source=%s | target=%s | count=%s | details=%s",
        attack_type,
        severity,
        src_ip,
        dst_ip,
        count,
        details
    )

def detect_port_scan(
    src_ip,
    dst_ip,
    dst_port,
    tcp_flags
):
    if "S" not in tcp_flags or "A" in tcp_flags:
        return

    key = (src_ip, dst_ip)
    now = datetime.now().timestamp()

    scan_tracker[key].append(
        (now, dst_port)
    )

    while (
        scan_tracker[key]
        and now - scan_tracker[key][0][0]
        > TIME_WINDOW
    ):
        scan_tracker[key].popleft()

    ports = sorted(
        set(
            port
            for _, port in scan_tracker[key]
        )
    )

    if len(ports) >= PORT_SCAN_THRESHOLD:

        last_alert = last_port_scan_alert.get(
            key,
            0
        )

        if (
            now - last_alert
            >= ALERT_SUPPRESSION_SECONDS
        ):

            print()
            print("==============================================")
            print("🚨 PORT SCAN DETECTED")
            print(f"Source       : {src_ip}")
            print(f"Target       : {dst_ip}")
            print(f"Unique Ports : {len(ports)}")
            print("Severity     : MEDIUM")
            print(f"Ports        : {ports}")
            print("==============================================")
            print()

            details = (
                f"Ports: {ports} | "
                f"Window: {TIME_WINDOW} seconds"
            )

            save_alert(
                "PORT SCAN",
                src_ip,
                dst_ip,
                len(ports),
                details,
                "MEDIUM"
            )

            last_port_scan_alert[key] = now

def detect_suspicious_port(
    src_ip,
    dst_ip,
    dst_port,
    tcp_flags
):
    if "S" not in tcp_flags or "A" in tcp_flags:
        return

    if dst_port not in SUSPICIOUS_PORTS:
        return

    key = (
        src_ip,
        dst_ip,
        dst_port
    )

    now = datetime.now().timestamp()

    last_alert = last_suspicious_port_alert.get(
        key,
        0
    )

    if (
        now - last_alert
        < SUSPICIOUS_PORT_SUPPRESSION_SECONDS
    ):
        return

    service = SUSPICIOUS_PORTS[dst_port]

    print()
    print("==============================================")
    print("⚠️ SUSPICIOUS PORT ACCESS")
    print(f"Source    : {src_ip}")
    print(f"Target    : {dst_ip}")
    print(f"Port      : {dst_port}")
    print(f"Service   : {service}")
    print("Severity  : MEDIUM")
    print("==============================================")
    print()

    details = (
        f"Port: {dst_port} | "
        f"Service: {service} | "
        f"TCP SYN detected"
    )

    save_alert(
        "SUSPICIOUS PORT",
        src_ip,
        dst_ip,
        1,
        details,
        "MEDIUM"
    )

    last_suspicious_port_alert[key] = now

def detect_brute_force(
    src_ip,
    dst_ip,
    dst_port,
    tcp_flags
):
    if "S" not in tcp_flags or "A" in tcp_flags:
        return

    if dst_port not in BRUTE_FORCE_PORTS:
        return

    key = (
        src_ip,
        dst_ip,
        dst_port
    )

    now = datetime.now().timestamp()

    brute_force_tracker[key].append(now)

    while (
        brute_force_tracker[key]
        and now - brute_force_tracker[key][0]
        > BRUTE_FORCE_WINDOW
    ):
        brute_force_tracker[key].popleft()

    attempt_count = len(
        brute_force_tracker[key]
    )

    if attempt_count >= BRUTE_FORCE_THRESHOLD:

        last_alert = last_brute_force_alert.get(
            key,
            0
        )

        if (
            now - last_alert
            >= BRUTE_FORCE_SUPPRESSION_SECONDS
        ):

            service = BRUTE_FORCE_PORTS[dst_port]

            print()
            print("==============================================")
            print("🚨 BRUTE FORCE SUSPECTED")
            print(f"Source     : {src_ip}")
            print(f"Target     : {dst_ip}")
            print(f"Port       : {dst_port}")
            print(f"Service    : {service}")
            print(f"Attempts   : {attempt_count}")
            print("Severity   : HIGH")
            print(f"Window     : {BRUTE_FORCE_WINDOW} seconds")
            print("==============================================")
            print()

            details = (
                f"Port: {dst_port} | "
                f"Service: {service} | "
                f"Attempts: {attempt_count} | "
                f"Window: {BRUTE_FORCE_WINDOW} seconds"
            )

            save_alert(
                "BRUTE FORCE",
                src_ip,
                dst_ip,
                attempt_count,
                details,
                "HIGH"
            )

            last_brute_force_alert[key] = now

def detect_syn_flood(
    src_ip,
    dst_ip,
    tcp_flags
):
    if "S" not in tcp_flags or "A" in tcp_flags:
        return

    key = (src_ip, dst_ip)
    now = datetime.now().timestamp()

    syn_tracker[key].append(now)

    while (
        syn_tracker[key]
        and now - syn_tracker[key][0]
        > TIME_WINDOW
    ):
        syn_tracker[key].popleft()

    syn_count = len(
        syn_tracker[key]
    )

    if syn_count >= SYN_FLOOD_THRESHOLD:

        last_alert = last_syn_flood_alert.get(
            key,
            0
        )

        if (
            now - last_alert
            >= ALERT_SUPPRESSION_SECONDS
        ):

            print()
            print("==============================================")
            print("🚨 SYN FLOOD DETECTED")
            print(f"Source    : {src_ip}")
            print(f"Target    : {dst_ip}")
            print(f"SYN Count : {syn_count}")
            print("Severity  : HIGH")
            print(f"Window    : {TIME_WINDOW} seconds")
            print("==============================================")
            print()

            details = (
                f"Window: {TIME_WINDOW} seconds"
            )

            save_alert(
                "SYN FLOOD",
                src_ip,
                dst_ip,
                syn_count,
                details,
                "HIGH"
            )

            last_syn_flood_alert[key] = now

def detect_icmp_flood(
    src_ip,
    dst_ip
):
    key = (src_ip, dst_ip)
    now = datetime.now().timestamp()

    icmp_tracker[key].append(now)

    while (
        icmp_tracker[key]
        and now - icmp_tracker[key][0]
        > TIME_WINDOW
    ):
        icmp_tracker[key].popleft()

    icmp_count = len(
        icmp_tracker[key]
    )

    if icmp_count >= ICMP_FLOOD_THRESHOLD:

        last_alert = last_icmp_flood_alert.get(
            key,
            0
        )

        if (
            now - last_alert
            >= ALERT_SUPPRESSION_SECONDS
        ):

            print()
            print("==============================================")
            print("🚨 ICMP FLOOD DETECTED")
            print(f"Source     : {src_ip}")
            print(f"Target     : {dst_ip}")
            print(f"ICMP Count : {icmp_count}")
            print("Severity   : HIGH")
            print(f"Window     : {TIME_WINDOW} seconds")
            print("==============================================")
            print()

            details = (
                f"Window: {TIME_WINDOW} seconds"
            )

            save_alert(
                "ICMP FLOOD",
                src_ip,
                dst_ip,
                icmp_count,
                details,
                "HIGH"
            )

            last_icmp_flood_alert[key] = now

def detect_udp_flood(
    src_ip,
    dst_ip
):
    key = (src_ip, dst_ip)
    now = datetime.now().timestamp()

    udp_tracker[key].append(now)

    while (
        udp_tracker[key]
        and now - udp_tracker[key][0]
        > TIME_WINDOW
    ):
        udp_tracker[key].popleft()

    udp_count = len(
        udp_tracker[key]
    )

    if udp_count >= UDP_FLOOD_THRESHOLD:

        last_alert = last_udp_flood_alert.get(
            key,
            0
        )

        if (
            now - last_alert
            >= ALERT_SUPPRESSION_SECONDS
        ):

            print()
            print("==============================================")
            print("🚨 UDP FLOOD DETECTED")
            print(f"Source    : {src_ip}")
            print(f"Target    : {dst_ip}")
            print(f"UDP Count : {udp_count}")
            print("Severity  : HIGH")
            print(f"Window    : {TIME_WINDOW} seconds")
            print("==============================================")
            print()

            details = (
                f"Window: {TIME_WINDOW} seconds"
            )

            save_alert(
                "UDP FLOOD",
                src_ip,
                dst_ip,
                udp_count,
                details,
                "HIGH"
            )

            last_udp_flood_alert[key] = now

def packet_callback(packet):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    src_ip = ""
    dst_ip = ""
    protocol = "OTHER"
    src_port = ""
    dst_port = ""
    tcp_flags = ""
    length = len(packet)

    if packet.haslayer(ARP):

        arp = packet[ARP]

        src_ip = arp.psrc
        dst_ip = arp.pdst
        protocol = "ARP"

    elif packet.haslayer(IP):

        ip = packet[IP]

        src_ip = ip.src
        dst_ip = ip.dst

        if packet.haslayer(TCP):

            tcp = packet[TCP]

            protocol = "TCP"
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_flags = str(tcp.flags)

            detect_port_scan(
                src_ip,
                dst_ip,
                dst_port,
                tcp_flags
            )

            detect_suspicious_port(
                src_ip,
                dst_ip,
                dst_port,
                tcp_flags
            )

            detect_brute_force(
                src_ip,
                dst_ip,
                dst_port,
                tcp_flags
            )

            detect_syn_flood(
                src_ip,
                dst_ip,
                tcp_flags
            )

        elif packet.haslayer(UDP):

            udp = packet[UDP]

            protocol = "UDP"
            src_port = udp.sport
            dst_port = udp.dport

            detect_udp_flood(
                src_ip,
                dst_ip
            )

        elif packet.haslayer(ICMP):

            protocol = "ICMP"

            detect_icmp_flood(
                src_ip,
                dst_ip
            )

        else:

            protocol = "IPv4"

    row = [
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        tcp_flags,
        length
    ]

    save_packet(row)

    print(
        f"{timestamp} | "
        f"{src_ip} -> {dst_ip} | "
        f"{protocol} | "
        f"{src_port} -> {dst_port} | "
        f"Flags={tcp_flags} | "
        f"Length={length}"
    )

def main():

    global db_conn
    global csv_file

    logger.info(
        "SYSTEM START | Network IDS"
    )

    logger.info(
        "CONFIG | interface=%s | csv=%s | db=%s | log=%s",
        INTERFACE,
        CSV_FILE,
        DB_FILE,
        LOG_FILE
    )

    logger.info(
        "CONFIG | time_window=%s | port_scan_threshold=%s | syn_flood_threshold=%s | icmp_flood_threshold=%s | udp_flood_threshold=%s",
        TIME_WINDOW,
        PORT_SCAN_THRESHOLD,
        SYN_FLOOD_THRESHOLD,
        ICMP_FLOOD_THRESHOLD,
        UDP_FLOOD_THRESHOLD
    )

    logger.info(
        "CONFIG | suspicious_ports=%s",
        SUSPICIOUS_PORTS
    )

    logger.info(
        "CONFIG | brute_force_ports=%s | threshold=%s | window=%s | suppression=%s",
        BRUTE_FORCE_PORTS,
        BRUTE_FORCE_THRESHOLD,
        BRUTE_FORCE_WINDOW,
        BRUTE_FORCE_SUPPRESSION_SECONDS
    )

    try:

        init_database()
        init_csv()

        print("==============================================")
        print("NETWORK IDS - PACKET CAPTURE")
        print("==============================================")
        print(f"Interface                : {INTERFACE}")
        print(f"CSV File                 : {CSV_FILE}")
        print(f"Database                 : {DB_FILE}")
        print(f"Log File                 : {LOG_FILE}")
        print(f"Time Window              : {TIME_WINDOW} seconds")
        print(f"Port Scan Threshold      : {PORT_SCAN_THRESHOLD}")
        print(f"SYN Flood Threshold      : {SYN_FLOOD_THRESHOLD}")
        print(f"ICMP Flood Threshold     : {ICMP_FLOOD_THRESHOLD}")
        print(f"UDP Flood Threshold      : {UDP_FLOOD_THRESHOLD}")
        print(f"Brute Force Threshold    : {BRUTE_FORCE_THRESHOLD}")
        print(f"Brute Force Window       : {BRUTE_FORCE_WINDOW} seconds")
        print(
            "Brute Force Suppression  : "
            f"{BRUTE_FORCE_SUPPRESSION_SECONDS} seconds"
        )
        print(
            "Suspicious Ports         : "
            f"{len(SUSPICIOUS_PORTS)}"
        )
        print("Status                   : Listening...")
        print("==============================================")

        logger.info(
            "CAPTURE START | interface=%s",
            INTERFACE
        )

        sniff(
            iface=INTERFACE,
            prn=packet_callback,
            store=False
        )

    except KeyboardInterrupt:

        logger.info(
            "SYSTEM STOP | user interrupt | packets=%s",
            db_packet_count
        )

    except Exception:

        logger.exception(
            "SYSTEM ERROR | unexpected failure"
        )

    finally:

        try:

            if db_conn:
                db_conn.commit()
                db_conn.close()

        except Exception:

            logger.exception(
                "DATABASE ERROR | shutdown commit failed"
            )

        try:

            if csv_file:
                csv_file.flush()
                csv_file.close()

        except Exception:

            logger.exception(
                "CSV ERROR | shutdown flush failed"
            )

        logger.info(
            "SYSTEM STOP | final packets=%s",
            db_packet_count
        )

if __name__ == "__main__":
    main()
