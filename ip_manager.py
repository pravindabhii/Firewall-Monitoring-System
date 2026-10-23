
import sqlite3
import ipaddress

DB_NAME = "firewall_monitor.db"


def create_ip_table():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            rule_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def add_ip(ip, rule_type):
    try:
        ip = str(ipaddress.ip_address(ip.strip()))

        if rule_type not in ("WHITELIST", "BLACKLIST"):
            return False, "Invalid rule type"

        create_ip_table()

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO ip_rules (ip, rule_type)
            VALUES (?, ?)
        """, (ip, rule_type))

        conn.commit()
        conn.close()

        return True, f"{ip} added to {rule_type}"

    except ValueError:
        return False, "Invalid IP address"


def remove_ip(ip):
    try:
        ip = str(ipaddress.ip_address(ip.strip()))

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM ip_rules WHERE ip = ?", (ip,))

        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        if deleted:
            return True, f"{ip} removed successfully"

        return False, "IP not found"

    except ValueError:
        return False, "Invalid IP address"


def get_all_ips():
    create_ip_table()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, ip, rule_type, created_at
        FROM ip_rules
        ORDER BY id DESC
    """)

    records = cursor.fetchall()
    conn.close()

    return records


def check_ip(ip):
    try:
        ip = str(ipaddress.ip_address(ip.strip()))

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT rule_type FROM ip_rules WHERE ip = ?",
            (ip,)
        )

        result = cursor.fetchone()
        conn.close()

        return result[0] if result else "UNKNOWN"

    except ValueError:
        return "INVALID"


create_ip_table()
