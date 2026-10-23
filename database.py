
import sqlite3
from datetime import datetime


DATABASE_NAME = "firewall_monitor.db"


def create_database():

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # NETWORK CONNECTIONS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            protocol TEXT,
            local_address TEXT,
            remote_address TEXT,
            status TEXT,
            process TEXT
        )
    """)

    # SECURITY ALERTS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            message TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_connections(connections):

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for item in connections:

        cursor.execute("""
            INSERT INTO network_connections
            (timestamp, protocol, local_address,
             remote_address, status, process)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            item.get("protocol", ""),
            item.get("local", ""),
            item.get("remote", ""),
            item.get("status", ""),
            item.get("process", "")
        ))

    conn.commit()
    conn.close()


def save_alerts(alerts):

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for alert in alerts:

        cursor.execute("""
            INSERT INTO security_alerts
            (timestamp, ip_address, message)
            VALUES (?, ?, ?)
        """, (
            timestamp,
            alert.get("ip", ""),
            alert.get("message", "")
        ))

    conn.commit()
    conn.close()


def get_connection_history(limit=100):

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM network_connections
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    records = cursor.fetchall()
    conn.close()

    return records


def get_alert_history(limit=100):

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM security_alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    records = cursor.fetchall()
    conn.close()

    return records
