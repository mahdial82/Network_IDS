from evaluation.ml.ml_api import router as ml_router
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import sqlite3

app = FastAPI(title="Network IDS Dashboard API")
app.include_router(ml_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

DB_FILE = "ids_alerts.db"

VALID_STATUSES = {
    "NEW",
    "ACKNOWLEDGED",
    "RESOLVED"
}

VALID_ATTACK_TYPES = {
    "PORT SCAN",
    "SYN FLOOD",
    "ICMP FLOOD",
    "UDP FLOOD",
    "SUSPICIOUS PORT",
    "BRUTE FORCE"
}


def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/")
def root():
    return {
        "status": "running",
        "service": "Network IDS Dashboard API"
    }

@app.get("/alerts")
def get_alerts(
    attack_type: str = "",
    severity: str = "",
    status: str = "",
    source_ip: str = "",
    limit: int = 100
):
    conn = get_connection()

    conditions = []
    params = []

    if attack_type:
        if attack_type not in VALID_ATTACK_TYPES:
            raise HTTPException(
                status_code=400,
                detail="Invalid attack type"
            )

        conditions.append("attack_type = ?")
        params.append(attack_type)

    if severity:
        severity = severity.upper()

        if severity not in VALID_SEVERITIES:
            raise HTTPException(
                status_code=400,
                detail="Invalid severity"
            )

        conditions.append("severity = ?")
        params.append(severity)

    if status:
        status = status.upper()

        if status not in VALID_STATUSES:
            raise HTTPException(
                status_code=400,
                detail="Invalid status"
            )

        conditions.append("status = ?")
        params.append(status)

    if source_ip:
        conditions.append("source_ip LIKE ?")
        params.append(f"%{source_ip}%")

    limit = max(1, min(limit, 500))

    query = """
        SELECT
            id,
            timestamp,
            attack_type,
            source_ip,
            target_ip,
            count,
            details,
            severity,
            status
        FROM alerts
    """

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += f"""
        ORDER BY id DESC
        LIMIT {limit}
    """

    rows = conn.execute(query, params).fetchall()

    conn.close()

    return [dict(row) for row in rows]

@app.get("/alerts/latest")
def get_latest_alerts():
    conn = get_connection()

    rows = conn.execute("""
        SELECT
            id,
            timestamp,
            attack_type,
            source_ip,
            target_ip,
            count,
            details,
            severity,
            status
        FROM alerts
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    conn.close()

    return [dict(row) for row in rows]

@app.patch("/alerts/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    status: str
):
    status = status.upper()

    if status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail="Invalid status"
        )

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE alerts
        SET status = ?
        WHERE id = ?
        """,
        (status, alert_id)
    )

    if cursor.rowcount == 0:
        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    conn.commit()

    row = cursor.execute(
        """
        SELECT
            id,
            timestamp,
            attack_type,
            source_ip,
            target_ip,
            count,
            details,
            severity,
            status
        FROM alerts
        WHERE id = ?
        """,
        (alert_id,)
    ).fetchone()

    conn.close()

    return dict(row)

@app.get("/alert-status")
def get_alert_status():
    conn = get_connection()

    rows = conn.execute("""
        SELECT
            status,
            COUNT(*) AS count
        FROM alerts
        GROUP BY status
    """).fetchall()

    result = {
        "NEW": 0,
        "ACKNOWLEDGED": 0,
        "RESOLVED": 0
    }

    for row in rows:
        if row["status"] in result:
            result[row["status"]] = row["count"]

    conn.close()

    return result

@app.get("/stats")
def get_stats():
    conn = get_connection()

    total = conn.execute("""
        SELECT COUNT(*) FROM alerts
    """).fetchone()[0]

    port_scan = conn.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE attack_type = 'PORT SCAN'
    """).fetchone()[0]

    syn_flood = conn.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE attack_type = 'SYN FLOOD'
    """).fetchone()[0]

    icmp_flood = conn.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE attack_type = 'ICMP FLOOD'
    """).fetchone()[0]

    udp_flood = conn.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE attack_type = 'UDP FLOOD'
    """).fetchone()[0]

    suspicious_port = conn.execute("""
    SELECT COUNT(*) FROM alerts
    WHERE attack_type = 'SUSPICIOUS PORT'
""").fetchone()[0]

    brute_force = conn.execute("""
    SELECT COUNT(*) FROM alerts
    WHERE attack_type = 'BRUTE FORCE'
""").fetchone()[0]

    high = conn.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE severity = 'HIGH'
    """).fetchone()[0]

    medium = conn.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE severity = 'MEDIUM'
    """).fetchone()[0]

    low = conn.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE severity = 'LOW'
    """).fetchone()[0]

    conn.close()

    return {
        "total_alerts": total,
        "port_scan": port_scan,
        "syn_flood": syn_flood,
        "icmp_flood": icmp_flood,
        "udp_flood": udp_flood,
        "suspicious_port": suspicious_port,
        "brute_force": brute_force,
        "high": high,
        "medium": medium,
        "low": low
    }

@app.get("/traffic/stats")
def get_traffic_stats():
    conn = get_connection()

    total_packets = conn.execute("""
        SELECT COUNT(*) FROM packets
    """).fetchone()[0]

    total_bytes = conn.execute("""
        SELECT COALESCE(SUM(length), 0)
        FROM packets
    """).fetchone()[0]

    tcp = conn.execute("""
        SELECT COUNT(*) FROM packets
        WHERE protocol = 'TCP'
    """).fetchone()[0]

    udp = conn.execute("""
        SELECT COUNT(*) FROM packets
        WHERE protocol = 'UDP'
    """).fetchone()[0]

    icmp = conn.execute("""
        SELECT COUNT(*) FROM packets
        WHERE protocol = 'ICMP'
    """).fetchone()[0]

    arp = conn.execute("""
        SELECT COUNT(*) FROM packets
        WHERE protocol = 'ARP'
    """).fetchone()[0]

    ipv4 = conn.execute("""
        SELECT COUNT(*) FROM packets
        WHERE protocol = 'IPv4'
    """).fetchone()[0]

    other = conn.execute("""
        SELECT COUNT(*) FROM packets
        WHERE protocol NOT IN ('TCP', 'UDP', 'ICMP', 'ARP', 'IPv4')
    """).fetchone()[0]

    unique_ips = conn.execute("""
        SELECT COUNT(*)
        FROM (
            SELECT src_ip AS ip
            FROM packets
            WHERE src_ip IS NOT NULL AND src_ip != ''

            UNION

            SELECT dst_ip AS ip
            FROM packets
            WHERE dst_ip IS NOT NULL AND dst_ip != ''
        )
    """).fetchone()[0]

    conn.close()

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "tcp": tcp,
        "udp": udp,
        "icmp": icmp,
        "arp": arp,
        "ipv4": ipv4,
        "other": other,
        "unique_ips": unique_ips
    }

@app.get("/traffic/recent")
def get_recent_traffic():
    conn = get_connection()

    rows = conn.execute("""
        SELECT
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            tcp_flags,
            length
        FROM packets
        ORDER BY id DESC
        LIMIT 15
    """).fetchall()

    conn.close()

    return [dict(row) for row in rows]

@app.get("/traffic/top-talkers")
def get_top_talkers():
    conn = get_connection()

    sources = conn.execute("""
        SELECT
            src_ip AS ip,
            COUNT(*) AS packets
        FROM packets
        WHERE src_ip IS NOT NULL AND src_ip != ''
        GROUP BY src_ip
        ORDER BY packets DESC
        LIMIT 10
    """).fetchall()

    destinations = conn.execute("""
        SELECT
            dst_ip AS ip,
            COUNT(*) AS packets
        FROM packets
        WHERE dst_ip IS NOT NULL AND dst_ip != ''
        GROUP BY dst_ip
        ORDER BY packets DESC
        LIMIT 10
    """).fetchall()

    bytes_data = conn.execute("""
        SELECT
            src_ip AS ip,
            COALESCE(SUM(length), 0) AS bytes
        FROM packets
        WHERE src_ip IS NOT NULL AND src_ip != ''
        GROUP BY src_ip
        ORDER BY bytes DESC
        LIMIT 10
    """).fetchall()

    conn.close()

    return {
        "sources": [dict(row) for row in sources],
        "destinations": [dict(row) for row in destinations],
        "bytes": [dict(row) for row in bytes_data]
    }
