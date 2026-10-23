
import psutil
import socket
from datetime import datetime


def get_network_connections():

    connections = []

    for conn in psutil.net_connections(kind="inet"):

        if not conn.laddr:
            continue

        local_ip = conn.laddr.ip
        local_port = conn.laddr.port

        remote_ip = ""
        remote_port = ""

        if conn.raddr:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

        try:
            process_name = (
                psutil.Process(conn.pid).name()
                if conn.pid else "Unknown"
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_name = "Unknown"

        connections.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            "local": f"{local_ip}:{local_port}",
            "remote": f"{remote_ip}:{remote_port}",
            "status": conn.status,
            "process": process_name
        })

    return connections
