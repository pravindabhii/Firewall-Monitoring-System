
import os
import csv
import sqlite3
import socket
import subprocess
import ipaddress
import traceback

from datetime import datetime
from tkinter import messagebox, simpledialog, filedialog

import customtkinter as ctk
import psutil


# ==================================================
# FIREWALL MODULE
# ==================================================

try:
    from firewall_blocker import (
        block_ip,
        unblock_ip,
        get_blocked_ips
    )
except ImportError:
    block_ip = None
    unblock_ip = None
    get_blocked_ips = None


# ==================================================
# CONFIGURATION
# ==================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(
    BASE_DIR,
    "firewall_monitor.db"
)

BG = "#080E18"
SIDEBAR = "#0C1523"
CARD = "#111F30"
CARD2 = "#142438"
BORDER = "#26394F"

GREEN = "#00D68F"
GREEN_DARK = "#087A58"
WHITE = "#F1F5F9"
MUTED = "#8FA3B8"
RED = "#FF5263"
ORANGE = "#FFB454"
BLUE = "#47A8FF"


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")


# ==================================================
# MAIN APPLICATION
# ==================================================

class FirewallMonitor(ctk.CTk):

    def __init__(self):

        super().__init__()

        self.title(
            "FIREWALL | Security Operations Center"
        )

        self.geometry("1400x850")
        self.minsize(1100, 700)
        self.configure(fg_color=BG)

        self.monitoring = False
        self.after_id = None
        self.clock_id = None

        self.history_window = None
        self.blocked_window = None

        self.connections = []
        self.alerts = []

        self.init_database()
        self.create_dashboard()

        self.refresh_status()
        self.update_clock()

        self.protocol(
            "WM_DELETE_WINDOW",
            self.close_application
        )

    # ==================================================
    # DATABASE
    # ==================================================

    def init_database(self):

        with sqlite3.connect(DB_PATH) as conn:

            conn.execute("""
                CREATE TABLE IF NOT EXISTS activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS connection_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    local_address TEXT,
                    remote_address TEXT,
                    status TEXT,
                    pid INTEGER
                )
            """)

    def save_activity(self, event):

        with sqlite3.connect(DB_PATH) as conn:

            conn.execute(
                """
                INSERT INTO activity (timestamp, event)
                VALUES (?, ?)
                """,
                (
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    str(event)
                )
            )

    # ==================================================
    # ERROR HANDLING
    # ==================================================

    def safe_action(self, name, function):

        def execute():

            print(f"\n[CLICKED] {name}")

            try:

                function()

                print(f"[SUCCESS] {name}")

            except Exception as error:

                print(f"[ERROR] {name}: {error}")
                traceback.print_exc()

                messagebox.showerror(
                    "Function Error",
                    f"{name}\n\n{error}",
                    parent=self
                )

        return execute

    # ==================================================
    # UI HELPERS
    # ==================================================

    def make_label(
        self,
        parent,
        text,
        size=13,
        color=WHITE,
        weight="normal"
    ):

        return ctk.CTkLabel(
            parent,
            text=text,
            font=("Segoe UI", size, weight),
            text_color=color
        )

    def make_button(
        self,
        parent,
        text,
        command,
        color=GREEN_DARK,
        hover="#0A9B70",
        width=130
    ):

        return ctk.CTkButton(
            parent,
            text=text,
            command=self.safe_action(text, command),
            height=38,
            width=width,
            corner_radius=8,
            fg_color=color,
            hover_color=hover,
            text_color=WHITE,
            font=("Segoe UI", 12, "bold")
        )

    # ==================================================
    # DASHBOARD
    # ==================================================

    def create_dashboard(self):

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # SIDEBAR

        self.sidebar = ctk.CTkFrame(
            self,
            width=235,
            corner_radius=0,
            fg_color=SIDEBAR
        )

        self.sidebar.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        self.sidebar.grid_propagate(False)

        logo = ctk.CTkFrame(
            self.sidebar,
            fg_color="transparent"
        )

        logo.pack(
            fill="x",
            padx=18,
            pady=(25, 25)
        )

        self.make_label(
            logo,
            "🔐",
            28,
            GREEN,
            "bold"
        ).pack(anchor="w")

        self.make_label(
            logo,
            "FIREWALL SECURITY",
            11,
            MUTED,
            "bold"
        ).pack(anchor="w")

        ctk.CTkFrame(
            self.sidebar,
            height=1,
            fg_color=BORDER
        ).pack(fill="x", padx=15)

        self.make_label(
            self.sidebar,
            "MAIN MENU",
            10,
            MUTED,
            "bold"
        ).pack(
            anchor="w",
            padx=20,
            pady=(22, 10)
        )

        self.make_sidebar_button(
            "▦   Overview",
            self.show_dashboard
        )

        self.make_sidebar_button(
            "◉   Start Monitoring",
            self.start_monitoring
        )

        self.make_sidebar_button(
            "■   Stop Monitoring",
            self.stop_monitoring
        )

        self.make_sidebar_button(
            "▤   Activity History",
            self.open_history
        )

        self.make_sidebar_button(
            "⊘   Blocked IP Manager",
            self.open_blocked_dashboard
        )

        self.make_label(
            self.sidebar,
            "SECURITY TOOLS",
            10,
            MUTED,
            "bold"
        ).pack(
            anchor="w",
            padx=20,
            pady=(25, 10)
        )

        self.make_sidebar_button(
            "＋   Block IP Address",
            self.block_ip_dialog
        )

        self.make_sidebar_button(
            "−   Unblock IP Address",
            self.unblock_ip_dialog
        )

        self.make_sidebar_button(
            "⇩   Export CSV Report",
            self.export_csv
        )

        self.make_sidebar_button(
            "↻   Refresh Status",
            self.refresh_status
        )

        # SIDEBAR FOOTER

        footer = ctk.CTkFrame(
            self.sidebar,
            fg_color=CARD,
            corner_radius=10
        )

        footer.pack(
            side="bottom",
            fill="x",
            padx=14,
            pady=18
        )

        self.make_label(
            footer,
            "● SYSTEM ONLINE",
            12,
            GREEN,
            "bold"
        ).pack(
            anchor="w",
            padx=12,
            pady=(12, 3)
        )

        self.make_label(
            footer,
            "PRAVIN FIREWALL v2.1",
            10,
            MUTED
        ).pack(
            anchor="w",
            padx=12,
            pady=(0, 12)
        )

        # MAIN AREA

        self.main_area = ctk.CTkFrame(
            self,
            fg_color=BG,
            corner_radius=0
        )

        self.main_area.grid(
            row=0,
            column=1,
            sticky="nsew"
        )

        self.main_area.grid_columnconfigure(
            0,
            weight=1
        )

        self.main_area.grid_rowconfigure(
            3,
            weight=1
        )

        # TOP BAR

        topbar = ctk.CTkFrame(
            self.main_area,
            fg_color=SIDEBAR,
            corner_radius=0,
            height=75
        )

        topbar.grid(
            row=0,
            column=0,
            sticky="ew"
        )

        title_area = ctk.CTkFrame(
            topbar,
            fg_color="transparent"
        )

        title_area.pack(
            side="left",
            padx=25,
            pady=12
        )

        self.make_label(
            title_area,
            "Security Operations Center",
            21,
            WHITE,
            "bold"
        ).pack(anchor="w")

        self.make_label(
            title_area,
            "Network protection and threat monitoring",
            11,
            MUTED
        ).pack(anchor="w")

        clock_area = ctk.CTkFrame(
            topbar,
            fg_color="transparent"
        )

        clock_area.pack(
            side="right",
            padx=25
        )

        self.clock_label = self.make_label(
            clock_area,
            "--:--:--",
            16,
            GREEN,
            "bold"
        )

        self.clock_label.pack(anchor="e")

        self.date_label = self.make_label(
            clock_area,
            datetime.now().strftime("%d %B %Y"),
            10,
            MUTED
        )

        self.date_label.pack(anchor="e")

        # PAGE TITLE

        heading = ctk.CTkFrame(
            self.main_area,
            fg_color="transparent"
        )

        heading.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=25,
            pady=(20, 12)
        )

        self.make_label(
            heading,
            "Firewall Dashboard",
            25,
            WHITE,
            "bold"
        ).pack(side="left")

        self.status_label = self.make_label(
            heading,
            "● MONITORING STOPPED",
            12,
            ORANGE,
            "bold"
        )

        self.status_label.pack(side="right")

        # STATISTICS

        stats = ctk.CTkFrame(
            self.main_area,
            fg_color="transparent"
        )

        stats.grid(
            row=2,
            column=0,
            sticky="ew",
            padx=20,
            pady=8
        )

        for col in range(4):
            stats.grid_columnconfigure(
                col,
                weight=1
            )

        self.connection_value = self.make_stat(
            stats,
            0,
            "NETWORK CONNECTIONS",
            "0",
            GREEN,
            "Current connections"
        )

        self.alert_value = self.make_stat(
            stats,
            1,
            "SECURITY NOTICES",
            "0",
            ORANGE,
            "Listening-port notices"
        )

        self.firewall_value = self.make_stat(
            stats,
            2,
            "WINDOWS FIREWALL",
            "Checking",
            BLUE,
            "Protection status"
        )

        self.ip_value = self.make_stat(
            stats,
            3,
            "LOCAL IP ADDRESS",
            "Checking",
            GREEN,
            "Network interface"
        )

        # CONTENT

        content = ctk.CTkFrame(
            self.main_area,
            fg_color="transparent"
        )

        content.grid(
            row=3,
            column=0,
            sticky="nsew",
            padx=20,
            pady=10
        )

        content.grid_columnconfigure(0, weight=3)
        content.grid_columnconfigure(1, weight=2)
        content.grid_rowconfigure(0, weight=1)

        # CONNECTION PANEL

        network_panel = ctk.CTkFrame(
            content,
            fg_color=CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER
        )

        network_panel.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 8)
        )

        network_panel.grid_rowconfigure(1, weight=1)
        network_panel.grid_columnconfigure(0, weight=1)

        self.make_label(
            network_panel,
            "LIVE NETWORK CONNECTIONS",
            14,
            GREEN,
            "bold"
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=15,
            pady=13
        )

        self.connection_box = ctk.CTkTextbox(
            network_panel,
            fg_color="#0B1421",
            text_color="#C5D4E3",
            font=("Consolas", 11),
            corner_radius=8,
            wrap="none"
        )

        self.connection_box.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=12,
            pady=(0, 12)
        )

        # RIGHT PANELS

        right = ctk.CTkFrame(
            content,
            fg_color="transparent"
        )

        right.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(8, 0)
        )

        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(0, weight=1)
        right.grid_rowconfigure(1, weight=1)

        alert_panel = ctk.CTkFrame(
            right,
            fg_color=CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER
        )

        alert_panel.grid(
            row=0,
            column=0,
            sticky="nsew",
            pady=(0, 8)
        )

        alert_panel.grid_columnconfigure(0, weight=1)
        alert_panel.grid_rowconfigure(1, weight=1)

        self.make_label(
            alert_panel,
            "SECURITY EVENTS",
            14,
            ORANGE,
            "bold"
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=15,
            pady=12
        )

        self.alert_box = ctk.CTkTextbox(
            alert_panel,
            fg_color="#0B1421",
            text_color="#FFCA83",
            font=("Consolas", 11)
        )

        self.alert_box.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=12,
            pady=(0, 12)
        )

        log_panel = ctk.CTkFrame(
            right,
            fg_color=CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER
        )

        log_panel.grid(
            row=1,
            column=0,
            sticky="nsew",
            pady=(8, 0)
        )

        log_panel.grid_columnconfigure(0, weight=1)
        log_panel.grid_rowconfigure(1, weight=1)

        self.make_label(
            log_panel,
            "SYSTEM ACTIVITY LOG",
            14,
            GREEN,
            "bold"
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=15,
            pady=12
        )

        self.log_box = ctk.CTkTextbox(
            log_panel,
            fg_color="#0B1421",
            text_color="#A9C0D4",
            font=("Consolas", 11)
        )

        self.log_box.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=12,
            pady=(0, 12)
        )

        # BOTTOM ACTION BAR

        actionbar = ctk.CTkFrame(
            self.main_area,
            fg_color=SIDEBAR,
            corner_radius=10
        )

        actionbar.grid(
            row=4,
            column=0,
            sticky="ew",
            padx=20,
            pady=(5, 15)
        )

        self.make_button(
            actionbar,
            "▶ START",
            self.start_monitoring,
            GREEN_DARK
        ).pack(side="left", padx=8, pady=10)

        self.make_button(
            actionbar,
            "■ STOP",
            self.stop_monitoring,
            "#773342",
            "#A83A50"
        ).pack(side="left", padx=8, pady=10)

        self.make_button(
            actionbar,
            "↻ REFRESH",
            self.refresh_status,
            "#23466B",
            "#32699D"
        ).pack(side="left", padx=8, pady=10)

        self.make_button(
            actionbar,
            "BLOCKED IPs",
            self.open_blocked_dashboard,
            "#5B477A",
            "#795EA5"
        ).pack(side="right", padx=10, pady=10)

    # ==================================================
    # SIDEBAR BUTTON
    # ==================================================

    def make_sidebar_button(self, text, command):

        button = ctk.CTkButton(
            self.sidebar,
            text=text,
            command=self.safe_action(text, command),
            height=43,
            corner_radius=8,
            fg_color="transparent",
            hover_color=CARD2,
            text_color="#C5D4E3",
            anchor="w",
            font=("Segoe UI", 12)
        )

        button.pack(
            fill="x",
            padx=12,
            pady=3
        )

    def show_dashboard(self):

        self.main_area.tkraise()

        self.log("Dashboard selected.")

    # ==================================================
    # STAT CARD
    # ==================================================

    def make_stat(
        self,
        parent,
        column,
        title,
        value,
        color,
        subtitle
    ):

        card = ctk.CTkFrame(
            parent,
            fg_color=CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER
        )

        card.grid(
            row=0,
            column=column,
            sticky="nsew",
            padx=5,
            pady=5
        )

        self.make_label(
            card,
            title,
            10,
            MUTED,
            "bold"
        ).pack(
            anchor="w",
            padx=15,
            pady=(15, 5)
        )

        value_label = self.make_label(
            card,
            value,
            22,
            color,
            "bold"
        )

        value_label.pack(
            anchor="w",
            padx=15,
            pady=2
        )

        self.make_label(
            card,
            subtitle,
            10,
            MUTED
        ).pack(
            anchor="w",
            padx=15,
            pady=(2, 15)
        )

        return value_label

    # ==================================================
    # CLOCK
    # ==================================================

    def update_clock(self):

        if not self.winfo_exists():
            return

        now = datetime.now()

        self.clock_label.configure(
            text=now.strftime("%H:%M:%S")
        )

        self.date_label.configure(
            text=now.strftime("%d %B %Y")
        )

        self.clock_id = self.after(
            1000,
            self.update_clock
        )

    # ==================================================
    # LOGGING
    # ==================================================

    def log(self, message):

        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )

        self.log_box.insert(
            "end",
            f"[{timestamp}] {message}\n"
        )

        self.log_box.see("end")

        try:
            self.save_activity(message)
        except sqlite3.Error as error:
            print("Database log error:", error)

    # ==================================================
    # SYSTEM STATUS
    # ==================================================

    def get_local_ip(self):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]

        except OSError:
            return "Unavailable"

        finally:
            sock.close()

    def get_firewall_status(self):

        if os.name != "nt":
            return "Windows only"

        try:

            result = subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "show",
                    "allprofiles",
                    "state"
                ],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return "Unknown"

            states = []

            for line in result.stdout.splitlines():

                parts = line.strip().split()

                if (
                    len(parts) >= 2
                    and parts[0].lower() == "state"
                ):
                    states.append(parts[-1].upper())

            if not states:
                return "Unknown"

            if all(state == "ON" for state in states):
                return "ON"

            if all(state == "OFF" for state in states):
                return "OFF"

            return "MIXED"

        except (OSError, subprocess.SubprocessError):
            return "Unavailable"

    def refresh_status(self):

        firewall = self.get_firewall_status()

        self.firewall_value.configure(
            text=firewall,
            text_color=(
                GREEN if firewall == "ON" else RED
            )
        )

        local_ip = self.get_local_ip()

        self.ip_value.configure(
            text=local_ip
        )

        self.log(
            f"Status refreshed | Firewall: {firewall} | IP: {local_ip}"
        )

    # ==================================================
    # MONITORING
    # ==================================================

    def start_monitoring(self):

        if self.monitoring:
            print("Monitoring is already running.")
            return

        self.monitoring = True

        self.status_label.configure(
            text="● LIVE MONITORING ACTIVE",
            text_color=GREEN
        )

        self.log("Monitoring started.")

        self.update_connections()

    def stop_monitoring(self):

        self.monitoring = False

        if self.after_id is not None:

            try:
                self.after_cancel(self.after_id)
            except tk.TclError:
                pass

            self.after_id = None

        self.status_label.configure(
            text="● MONITORING STOPPED",
            text_color=ORANGE
        )

        self.log("Monitoring stopped.")

    def update_connections(self):

        if not self.monitoring:
            return

        try:

            connections = psutil.net_connections(
                kind="inet"
            )

            self.connections = connections

            lines = []
            alerts = []

            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            with sqlite3.connect(DB_PATH) as conn:

                for item in connections:

                    local = (
                        f"{item.laddr.ip}:{item.laddr.port}"
                        if item.laddr else "-"
                    )

                    remote = (
                        f"{item.raddr.ip}:{item.raddr.port}"
                        if item.raddr else "-"
                    )

                    status = item.status or "UNKNOWN"

                    lines.append(
                        f"{status:<13} LOCAL: {local:<25} "
                        f"REMOTE: {remote:<25} PID: {item.pid}"
                    )

                    conn.execute(
                        """
                        INSERT INTO connection_history
                        (
                            timestamp,
                            local_address,
                            remote_address,
                            status,
                            pid
                        )
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            timestamp,
                            local,
                            remote,
                            status,
                            item.pid
                        )
                    )

                    if status == psutil.CONN_LISTEN:

                        alerts.append(
                            f"[LISTENING] {local}"
                        )

            self.alerts = alerts

            self.connection_value.configure(
                text=str(len(connections))
            )

            self.alert_value.configure(
                text=str(len(alerts))
            )

            self.connection_box.delete(
                "1.0",
                "end"
            )

            self.connection_box.insert(
                "end",
                "\n".join(lines[:250])
                if lines else "No connections found."
            )

            self.alert_box.delete(
                "1.0",
                "end"
            )

            self.alert_box.insert(
                "end",
                "\n".join(alerts[:100])
                if alerts else "No listening-port notices."
            )

            print(
                f"[MONITORING] Connections: {len(connections)}"
            )

        except (sqlite3.Error, psutil.Error) as error:

            self.log(
                f"Monitoring error: {error}"
            )

        except Exception as error:

            self.log(
                f"Unexpected monitoring error: {error}"
            )

        if self.monitoring:

            self.after_id = self.after(
                3000,
                self.update_connections
            )

    # ==================================================
    # HISTORY
    # ==================================================

    def open_history(self):

        if self.history_window is not None:

            try:
                if self.history_window.winfo_exists():
                    self.history_window.lift()
                    return
            except tk.TclError:
                self.history_window = None

        self.history_window = ctk.CTkToplevel(self)

        self.history_window.title(
            "PRAVIN FIREWALL | Activity History"
        )

        self.history_window.geometry("950x600")
        self.history_window.configure(fg_color=BG)

        self.make_label(
            self.history_window,
            "SYSTEM ACTIVITY HISTORY",
            21,
            GREEN,
            "bold"
        ).pack(pady=15)

        box = ctk.CTkTextbox(
            self.history_window,
            fg_color=CARD,
            text_color=WHITE,
            font=("Consolas", 11)
        )

        box.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=15
        )

        with sqlite3.connect(DB_PATH) as conn:

            rows = conn.execute(
                """
                SELECT timestamp, event
                FROM activity
                ORDER BY id DESC
                LIMIT 500
                """
            ).fetchall()

        if not rows:
            box.insert("end", "No activity history found.\n")

        for timestamp, event in rows:

            box.insert(
                "end",
                f"{timestamp} | {event}\n"
            )

        self.history_window.protocol(
            "WM_DELETE_WINDOW",
            self.close_history
        )

    def close_history(self):

        if self.history_window is not None:

            try:
                self.history_window.destroy()
            except tk.TclError:
                pass

            self.history_window = None

    # ==================================================
    # IP VALIDATION
    # ==================================================

    def validate_ip(self, ip):

        try:

            return str(
                ipaddress.ip_address(ip.strip())
            )

        except ValueError:

            messagebox.showerror(
                "Invalid IP",
                "Enter a valid IPv4 or IPv6 address.",
                parent=self
            )

            return None

    # ==================================================
    # BLOCK IP
    # ==================================================

    def block_ip_dialog(self):

        if block_ip is None:

            messagebox.showerror(
                "Module Error",
                "firewall_blocker.py or block_ip function is missing.",
                parent=self
            )

            return

        ip = simpledialog.askstring(
            "Block IP",
            "Enter IP address:",
            parent=self
        )

        if not ip:
            return

        ip = self.validate_ip(ip)

        if not ip:
            return

        try:

            result = block_ip(ip)

            self.log(
                f"Block IP: {ip} | {result}"
            )

            messagebox.showinfo(
                "Block IP Result",
                str(result),
                parent=self
            )

        except Exception as error:

            self.log(
                f"Block IP failed: {error}"
            )

            messagebox.showerror(
                "Block Error",
                str(error),
                parent=self
            )

    # ==================================================
    # UNBLOCK IP
    # ==================================================

    def unblock_ip_dialog(self):

        if unblock_ip is None:

            messagebox.showerror(
                "Module Error",
                "firewall_blocker.py or unblock_ip function is missing.",
                parent=self
            )

            return

        ip = simpledialog.askstring(
            "Unblock IP",
            "Enter IP address:",
            parent=self
        )

        if not ip:
            return

        ip = self.validate_ip(ip)

        if not ip:
            return

        try:

            result = unblock_ip(ip)

            self.log(
                f"Unblock IP: {ip} | {result}"
            )

            messagebox.showinfo(
                "Unblock IP Result",
                str(result),
                parent=self
            )

        except Exception as error:

            self.log(
                f"Unblock IP failed: {error}"
            )

            messagebox.showerror(
                "Unblock Error",
                str(error),
                parent=self
            )

    # ==================================================
    # BLOCKED IP DASHBOARD
    # ==================================================

    def open_blocked_dashboard(self):

        if self.blocked_window is not None:

            try:
                if self.blocked_window.winfo_exists():
                    self.blocked_window.lift()
                    return
            except tk.TclError:
                self.blocked_window = None

        self.blocked_window = ctk.CTkToplevel(self)

        self.blocked_window.title(
            "PRAVIN FIREWALL | Blocked IP Manager"
        )

        self.blocked_window.geometry("700x500")
        self.blocked_window.configure(fg_color=BG)

        self.make_label(
            self.blocked_window,
            "BLOCKED IP ADDRESSES",
            21,
            GREEN,
            "bold"
        ).pack(pady=15)

        box = ctk.CTkTextbox(
            self.blocked_window,
            fg_color=CARD,
            text_color=WHITE,
            font=("Consolas", 12)
        )

        box.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=10
        )

        def refresh_blocked():

            box.delete(
                "1.0",
                "end"
            )

            if get_blocked_ips is None:

                box.insert(
                    "end",
                    "get_blocked_ips() function is unavailable."
                )

                return

            try:

                ips = get_blocked_ips()

                if not ips:
                    box.insert(
                        "end",
                        "No PRAVIN blocked IP rules found."
                    )

                else:

                    for ip in ips:
                        box.insert(
                            "end",
                            str(ip) + "\n"
                        )

                self.log(
                    "Blocked IP list refreshed."
                )

            except Exception as error:

                box.insert(
                    "end",
                    f"Error: {error}"
                )

                self.log(
                    f"Blocked IP refresh error: {error}"
                )

        self.make_button(
            self.blocked_window,
            "REFRESH BLOCKED IPs",
            refresh_blocked
        ).pack(pady=12)

        refresh_blocked()

        self.blocked_window.protocol(
            "WM_DELETE_WINDOW",
            self.close_blocked_window
        )

    def close_blocked_window(self):

        if self.blocked_window is not None:

            try:
                self.blocked_window.destroy()
            except tk.TclError:
                pass

            self.blocked_window = None

    # ==================================================
    # CSV EXPORT
    # ==================================================

    def export_csv(self):

        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv")
            ],
            initialfile="PRAVIN_FIREWALL_Report.csv"
        )

        if not path:
            return

        try:

            with sqlite3.connect(DB_PATH) as conn:

                rows = conn.execute(
                    """
                    SELECT
                        timestamp,
                        local_address,
                        remote_address,
                        status,
                        pid
                    FROM connection_history
                    ORDER BY id DESC
                    """
                ).fetchall()

            with open(
                path,
                "w",
                newline="",
                encoding="utf-8-sig"
            ) as file:

                writer = csv.writer(file)

                writer.writerow([
                    "Timestamp",
                    "Local Address",
                    "Remote Address",
                    "Status",
                    "PID"
                ])

                writer.writerows(rows)

            self.log(
                f"CSV exported successfully: {path}"
            )

            messagebox.showinfo(
                "Export Complete",
                f"CSV report saved successfully.\n\n{path}",
                parent=self
            )

        except Exception as error:

            self.log(
                f"CSV export error: {error}"
            )

            messagebox.showerror(
                "Export Error",
                str(error),
                parent=self
            )

    # ==================================================
    # CLOSE APPLICATION
    # ==================================================

    def close_application(self):

        self.monitoring = False

        if self.after_id is not None:

            try:
                self.after_cancel(self.after_id)
            except tk.TclError:
                pass

            self.after_id = None

        if self.clock_id is not None:

            try:
                self.after_cancel(self.clock_id)
            except tk.TclError:
                pass

            self.clock_id = None

        self.close_history()
        self.close_blocked_window()

        self.destroy()


# ==================================================
# START APPLICATION
# ==================================================

if __name__ == "__main__":

    app = FirewallMonitor()

    app.mainloop()
