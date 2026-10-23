
import ipaddress


# Sensitive ports and their descriptions
HIGH_RISK_PORTS = {
    21: ("FTP", "Medium"),
    22: ("SSH", "Medium"),
    23: ("Telnet", "High"),
    445: ("SMB", "High"),
    3389: ("Remote Desktop (RDP)", "High"),
    5900: ("VNC", "High"),
    3306: ("MySQL", "Medium"),
    5432: ("PostgreSQL", "Medium"),
    6379: ("Redis", "High"),
    27017: ("MongoDB", "High"),
}


def check_suspicious_ip(ip):
    try:
        address = ipaddress.ip_address(ip)

        # Private IP addresses are not treated as suspicious
        if address.is_private:
            return False

        # Special-purpose IP addresses
        if (
            address.is_reserved
            or address.is_loopback
            or address.is_multicast
            or address.is_unspecified
            or address.is_link_local
            or not address.is_global
        ):
            return True

        return False

    except ValueError:
        return True


def extract_ip_port(remote):
    """
    Extract IP address and port from remote endpoint.
    Supports IPv4, IPv6 and tuple formats.
    """

    if not remote:
        return None, None

    if isinstance(remote, (tuple, list)):
        if len(remote) >= 2:
            return str(remote[0]), remote[1]
        return str(remote[0]), None

    remote = str(remote).strip()

    if remote in ("-", "N/A", ""):
        return None, None

    # IPv6 format: [2001:db8::1]:443
    if remote.startswith("[") and "]" in remote:
        ip = remote[1:remote.index("]")]
        remaining = remote[remote.index("]") + 1:]

        if remaining.startswith(":"):
            try:
                return ip, int(remaining[1:])
            except ValueError:
                return ip, None

        return ip, None

    # IPv4 format: 8.8.8.8:443
    if remote.count(":") == 1:
        ip, port = remote.rsplit(":", 1)

        try:
            return ip, int(port)
        except ValueError:
            return remote, None

    # Bare IPv6 or IPv4 address
    try:
        ipaddress.ip_address(remote)
        return remote, None
    except ValueError:
        return None, None


def analyze_connections(connections):

    alerts = []

    for item in connections:

        remote = item.get("remote", "")

        ip, port = extract_ip_port(remote)

        if not ip:
            continue

        # 1. Suspicious IP Detection
        if check_suspicious_ip(ip):

            alerts.append({
                "ip": ip,
                "message": "Unusual, reserved or invalid remote IP detected",
                "severity": "High",
                "type": "Suspicious IP"
            })

        # 2. High-Risk Port Detection
        if port in HIGH_RISK_PORTS:

            service, severity = HIGH_RISK_PORTS[port]

            alerts.append({
                "ip": ip,
                "message": f"Sensitive port detected: {port} ({service})",
                "severity": severity,
                "type": "High-Risk Port"
            })

    return alerts
