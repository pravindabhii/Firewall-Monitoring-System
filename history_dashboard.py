
import customtkinter as ctk
import sqlite3
import csv
import os

from tkinter import ttk, messagebox, filedialog
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, A4
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
)
from reportlab.lib.styles import getSampleStyleSheet


DATABASE_NAME = "firewall_monitor.db"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")


class HistoryDashboard(ctk.CTkToplevel):

    def __init__(self, master=None):
        super().__init__(master)

        self.title("PRAVIN FIREWALL - HISTORY DASHBOARD")
        self.geometry("1350x800")
        self.configure(fg_color="#080D0B")

        self.create_ui()
        self.load_connections()
        self.load_alerts()

    # ---------------- CREATE UI ----------------

    def create_ui(self):

        title = ctk.CTkLabel(
            self,
            text="FIREWALL HISTORY DASHBOARD",
            font=("Arial", 28, "bold"),
            text_color="#00FF88"
        )
        title.pack(pady=20)

        subtitle = ctk.CTkLabel(
            self,
            text="NETWORK CONNECTIONS | SECURITY ALERTS | DATABASE",
            text_color="#A0A0A0",
            font=("Arial", 13)
        )
        subtitle.pack(pady=(0, 15))

        # SEARCH SECTION
        search_frame = ctk.CTkFrame(
            self, fg_color="#101814"
        )
        search_frame.pack(fill="x", padx=20, pady=10)

        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="Search IP, Protocol, Process...",
            width=350,
            height=40
        )
        self.search_entry.pack(side="left", padx=10, pady=10)

        ctk.CTkButton(
            search_frame,
            text="SEARCH",
            command=self.search_history,
            fg_color="#008F55"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            search_frame,
            text="RESET",
            command=self.refresh_history,
            fg_color="#333333"
        ).pack(side="left", padx=5)

        self.search_entry.bind(
            "<Return>",
            lambda event: self.search_history()
        )

        # TABS
        self.tabs = ctk.CTkTabview(
            self,
            fg_color="#101814",
            segmented_button_selected_color="#00AA66"
        )
        self.tabs.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=10
        )

        self.connection_tab = self.tabs.add("Network History")
        self.alert_tab = self.tabs.add("Security Alerts")

        self.create_connection_table()
        self.create_alert_table()

        # ACTION BUTTONS
        buttons = ctk.CTkFrame(
            self, fg_color="transparent"
        )
        buttons.pack(pady=12)

        button_data = [
            ("REFRESH", self.refresh_history, "#008F55"),
            ("DELETE CONNECTION", self.delete_connection, "#CC3333"),
            ("DELETE ALERT", self.delete_alert, "#CC3333"),
            ("EXPORT CSV", self.export_csv, "#006699"),
            ("EXPORT PDF", self.export_pdf, "#7952A3"),
            ("CLOSE", self.destroy, "#333333")
        ]

        for text, command, color in button_data:
            ctk.CTkButton(
                buttons,
                text=text,
                command=command,
                fg_color=color,
                hover_color="#222222",
                width=145
            ).pack(side="left", padx=5)

        self.status_label = ctk.CTkLabel(
            self,
            text="DATABASE HISTORY READY",
            text_color="#00FF88"
        )
        self.status_label.pack(pady=(0, 10))

    # ---------------- CONNECTION TABLE ----------------

    def create_connection_table(self):

        columns = (
            "ID", "Timestamp", "Protocol",
            "Local Address", "Remote Address",
            "Status", "Process"
        )

        self.connection_table = ttk.Treeview(
            self.connection_tab,
            columns=columns,
            show="headings",
            selectmode="extended"
        )

        for column in columns:
            self.connection_table.heading(
                column, text=column
            )
            self.connection_table.column(
                column,
                width=150,
                minwidth=100,
                anchor="center"
            )

        scrollbar = ttk.Scrollbar(
            self.connection_tab,
            orient="vertical",
            command=self.connection_table.yview
        )

        self.connection_table.configure(
            yscrollcommand=scrollbar.set
        )

        self.connection_table.pack(
            side="left",
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        scrollbar.pack(
            side="right",
            fill="y",
            pady=10
        )

    # ---------------- ALERT TABLE ----------------

    def create_alert_table(self):

        columns = ("ID", "Timestamp", "IP Address", "Message")

        self.alert_table = ttk.Treeview(
            self.alert_tab,
            columns=columns,
            show="headings",
            selectmode="extended"
        )

        for column in columns:
            self.alert_table.heading(
                column, text=column
            )
            self.alert_table.column(
                column,
                width=200,
                minwidth=120,
                anchor="center"
            )

        scrollbar = ttk.Scrollbar(
            self.alert_tab,
            orient="vertical",
            command=self.alert_table.yview
        )

        self.alert_table.configure(
            yscrollcommand=scrollbar.set
        )

        self.alert_table.pack(
            side="left",
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        scrollbar.pack(
            side="right",
            fill="y",
            pady=10
        )

    # ---------------- LOAD CONNECTIONS ----------------

    def load_connections(self):

        for item in self.connection_table.get_children():
            self.connection_table.delete(item)

        try:
            with sqlite3.connect(DATABASE_NAME) as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT id, timestamp, protocol,
                           local_address, remote_address,
                           status, process
                    FROM network_connections
                    ORDER BY id DESC
                """)

                records = cursor.fetchall()

            for record in records:
                self.connection_table.insert(
                    "", "end", values=record
                )

            self.status_label.configure(
                text=f"NETWORK RECORDS: {len(records)}"
            )

        except sqlite3.Error as error:
            messagebox.showerror(
                "Database Error", str(error)
            )

    # ---------------- LOAD ALERTS ----------------

    def load_alerts(self):

        for item in self.alert_table.get_children():
            self.alert_table.delete(item)

        try:
            with sqlite3.connect(DATABASE_NAME) as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT id, timestamp, ip_address, message
                    FROM security_alerts
                    ORDER BY id DESC
                """)

                records = cursor.fetchall()

            for record in records:
                self.alert_table.insert(
                    "", "end", values=record
                )

        except sqlite3.Error as error:
            messagebox.showerror(
                "Database Error", str(error)
            )

    # ---------------- SEARCH ----------------

    def search_history(self):

        keyword = self.search_entry.get().strip()

        if not keyword:
            self.refresh_history()
            return

        search = f"%{keyword}%"

        try:
            with sqlite3.connect(DATABASE_NAME) as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT id, timestamp, protocol,
                           local_address, remote_address,
                           status, process
                    FROM network_connections
                    WHERE CAST(id AS TEXT) LIKE ?
                    OR timestamp LIKE ?
                    OR protocol LIKE ?
                    OR local_address LIKE ?
                    OR remote_address LIKE ?
                    OR status LIKE ?
                    OR process LIKE ?
                    ORDER BY id DESC
                """, (search,) * 7)

                connections = cursor.fetchall()

                cursor.execute("""
                    SELECT id, timestamp, ip_address, message
                    FROM security_alerts
                    WHERE CAST(id AS TEXT) LIKE ?
                    OR timestamp LIKE ?
                    OR ip_address LIKE ?
                    OR message LIKE ?
                    ORDER BY id DESC
                """, (search,) * 4)

                alerts = cursor.fetchall()

            self.clear_tables()

            for record in connections:
                self.connection_table.insert(
                    "", "end", values=record
                )

            for record in alerts:
                self.alert_table.insert(
                    "", "end", values=record
                )

            self.status_label.configure(
                text=f"SEARCH: {len(connections)} CONNECTIONS | {len(alerts)} ALERTS"
            )

        except sqlite3.Error as error:
            messagebox.showerror("Search Error", str(error))

    # ---------------- CLEAR TABLES ----------------

    def clear_tables(self):

        for item in self.connection_table.get_children():
            self.connection_table.delete(item)

        for item in self.alert_table.get_children():
            self.alert_table.delete(item)

    # ---------------- REFRESH ----------------

    def refresh_history(self):

        self.search_entry.delete(0, "end")
        self.load_connections()
        self.load_alerts()

        self.status_label.configure(
            text="HISTORY REFRESHED SUCCESSFULLY"
        )

    # ---------------- DELETE CONNECTION ----------------

    def delete_connection(self):

        selected = self.connection_table.selection()

        if not selected:
            messagebox.showwarning(
                "Warning", "Select a connection first!"
            )
            return

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Delete {len(selected)} selected connection(s)?"
        )

        if not confirm:
            return

        try:
            with sqlite3.connect(DATABASE_NAME) as conn:
                cursor = conn.cursor()

                for item in selected:
                    record_id = self.connection_table.item(
                        item, "values"
                    )[0]

                    cursor.execute(
                        "DELETE FROM network_connections WHERE id=?",
                        (record_id,)
                    )

            self.refresh_history()

            messagebox.showinfo(
                "Success", "Connection deleted successfully!"
            )

        except sqlite3.Error as error:
            messagebox.showerror("Delete Error", str(error))

    # ---------------- DELETE ALERT ----------------

    def delete_alert(self):

        selected = self.alert_table.selection()

        if not selected:
            messagebox.showwarning(
                "Warning", "Select an alert first!"
            )
            return

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Delete {len(selected)} selected alert(s)?"
        )

        if not confirm:
            return

        try:
            with sqlite3.connect(DATABASE_NAME) as conn:
                cursor = conn.cursor()

                for item in selected:
                    record_id = self.alert_table.item(
                        item, "values"
                    )[0]

                    cursor.execute(
                        "DELETE FROM security_alerts WHERE id=?",
                        (record_id,)
                    )

            self.refresh_history()

            messagebox.showinfo(
                "Success", "Alert deleted successfully!"
            )

        except sqlite3.Error as error:
            messagebox.showerror("Delete Error", str(error))

    # ---------------- GET EXPORT DATA ----------------

    def get_export_data(self):

        tab = self.tabs.get()

        if tab == "Network History":
            table = self.connection_table
            columns = (
                "ID", "Timestamp", "Protocol",
                "Local Address", "Remote Address",
                "Status", "Process"
            )
        else:
            table = self.alert_table
            columns = (
                "ID", "Timestamp", "IP Address", "Message"
            )

        records = [
            table.item(item, "values")
            for item in table.get_children()
        ]

        return columns, records, tab

    # ---------------- EXPORT CSV ----------------

    def export_csv(self):

        columns, records, tab = self.get_export_data()

        if not records:
            messagebox.showwarning(
                "No Data", "No records available to export!"
            )
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            initialfile="firewall_history.csv"
        )

        if not filepath:
            return

        try:
            with open(
                filepath, "w", newline="", encoding="utf-8-sig"
            ) as file:

                writer = csv.writer(file)
                writer.writerow(columns)
                writer.writerows(records)

            messagebox.showinfo(
                "Export Success",
                f"{tab} exported successfully!\n{filepath}"
            )

        except (OSError, csv.Error) as error:
            messagebox.showerror("CSV Error", str(error))

    # ---------------- EXPORT PDF ----------------

    def export_pdf(self):

        columns, records, tab = self.get_export_data()

        if not records:
            messagebox.showwarning(
                "No Data", "No records available to export!"
            )
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")],
            initialfile="firewall_history.pdf"
        )

        if not filepath:
            return

        try:
            document = SimpleDocTemplate(
                filepath,
                pagesize=landscape(A4)
            )

            styles = getSampleStyleSheet()

            elements = [
                Paragraph(
                    "FIREWALL MONITORING SYSTEM",
                    styles["Title"]
                ),
                Spacer(1, 15),
                Paragraph(
                    tab + " Report",
                    styles["Heading2"]
                ),
                Spacer(1, 15)
            ]

            data = [columns]

            for record in records:
                data.append([
                    str(value) if value is not None else ""
                    for value in record
                ])

            table = Table(data, repeatRows=1)

            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0),
                 colors.HexColor("#008F55")),
                ("TEXTCOLOR", (0, 0), (-1, 0),
                 colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5,
                 colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#E8F5E9")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))

            elements.append(table)
            document.build(elements)

            messagebox.showinfo(
                "Export Success",
                f"PDF exported successfully!\n{filepath}"
            )

        except Exception as error:
            messagebox.showerror("PDF Error", str(error))


if __name__ == "__main__":

    app = ctk.CTk()
    app.withdraw()

    history = HistoryDashboard(app)

    app.mainloop()
