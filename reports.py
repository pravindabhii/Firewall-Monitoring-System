
import csv
from datetime import datetime
from tkinter import filedialog, messagebox
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def export_csv(connections):
    if not connections:
        messagebox.showwarning(
            "No Data",
            "No connection data available."
        )
        return

    filename = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv")],
        initialfile=f"firewall_report_{datetime.now():%Y%m%d_%H%M%S}.csv"
    )

    if not filename:
        return

    try:
        with open(filename, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "time", "protocol", "local",
                    "remote", "status", "process"
                ]
            )
            writer.writeheader()
            writer.writerows(connections)

        messagebox.showinfo("Success", "CSV Report Saved Successfully!")

    except Exception as error:
        messagebox.showerror("Export Error", str(error))


def export_pdf(connections, alerts=None):
    if not connections:
        messagebox.showwarning(
            "No Data",
            "No connection data available."
        )
        return

    filename = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF Files", "*.pdf")],
        initialfile=f"firewall_report_{datetime.now():%Y%m%d_%H%M%S}.pdf"
    )

    if not filename:
        return

    try:
        pdf = canvas.Canvas(filename, pagesize=A4)
        width, height = A4
        y = height - 50

        def write_line(value):
            nonlocal y
            if y < 50:
                pdf.showPage()
                y = height - 50
            pdf.drawString(40, y, str(value)[:105])
            y -= 18

        pdf.setTitle("Firewall Security Report")

        write_line("PRAVIN - FIREWALL MONITORING SYSTEM")
        write_line("NETWORK SECURITY REPORT")
        write_line(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}")
        write_line("-" * 75)
        write_line(f"Total Connections: {len(connections)}")
        write_line("")
        write_line("NETWORK CONNECTION DETAILS")
        write_line("-" * 75)

        for item in connections:
            write_line(
                f"{item.get('time', '')} | "
                f"{item.get('protocol', '')} | "
                f"{item.get('local', '')} | "
                f"{item.get('remote', '')}"
            )
            write_line(
                f"Status: {item.get('status', '')} | "
                f"Process: {item.get('process', '')}"
            )

        write_line("")
        write_line("SECURITY ALERTS")
        write_line("-" * 75)

        if alerts:
            for alert in alerts:
                write_line(
                    f"{alert.get('ip', '')}: "
                    f"{alert.get('message', '')}"
                )
        else:
            write_line("No unusual IP addresses detected.")

        pdf.save()

        messagebox.showinfo("Success", "PDF Report Saved Successfully!")

    except Exception as error:
        messagebox.showerror("PDF Export Error", str(error))
