
import customtkinter as ctk
from tkinter import messagebox

from firewall_blocker import get_blocked_ips, unblock_ip


class BlockedIPDashboard(ctk.CTkToplevel):

    def __init__(self, master):
        super().__init__(master)

        self.title("PRAVIN - Blocked IP Dashboard")
        self.geometry("750x550")
        self.configure(fg_color="#080d0b")

        self.selected_ip = None
        self.blocked_ips = []

        # HEADER
        header = ctk.CTkLabel(
            self,
            text="🛡 PRAVIN BLOCKED IP MANAGER",
            font=("Arial", 25, "bold"),
            text_color="#00ff88"
        )
        header.pack(pady=(25, 10))

        subtitle = ctk.CTkLabel(
            self,
            text="WINDOWS FIREWALL SECURITY MANAGEMENT",
            font=("Arial", 12),
            text_color="gray"
        )
        subtitle.pack(pady=(0, 20))

        # COUNTER CARD
        self.counter_label = ctk.CTkLabel(
            self,
            text="TOTAL BLOCKED IPs: 0",
            font=("Arial", 18, "bold"),
            text_color="#00ff88",
            fg_color="#12251c",
            corner_radius=10,
            height=55
        )
        self.counter_label.pack(fill="x", padx=30, pady=10)

        # IP LIST TITLE
        ctk.CTkLabel(
            self,
            text="BLOCKED IP ADDRESS LIST",
            font=("Arial", 16, "bold"),
            text_color="white"
        ).pack(pady=(15, 8))

        # SCROLLABLE IP LIST
        self.ip_frame = ctk.CTkScrollableFrame(
            self,
            fg_color="#101815",
            corner_radius=10
        )
        self.ip_frame.pack(fill="both", expand=True, padx=30, pady=10)

        # SELECTED IP
        self.selected_label = ctk.CTkLabel(
            self,
            text="Selected IP: None",
            font=("Arial", 13, "bold"),
            text_color="#00ff88"
        )
        self.selected_label.pack(pady=8)

        # BUTTON FRAME
        button_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        button_frame.pack(pady=15)

        self.refresh_button = ctk.CTkButton(
            button_frame,
            text="⟳ REFRESH",
            width=150,
            height=40,
            fg_color="#087f46",
            hover_color="#00aa60",
            command=self.refresh_list
        )
        self.refresh_button.grid(row=0, column=0, padx=10)

        self.unblock_button = ctk.CTkButton(
            button_frame,
            text="UNBLOCK SELECTED",
            width=190,
            height=40,
            fg_color="#b3261e",
            hover_color="#e53935",
            command=self.unblock_selected
        )
        self.unblock_button.grid(row=0, column=1, padx=10)

        self.refresh_list()

    # =====================================
    # REFRESH BLOCKED IP LIST
    # =====================================

    def refresh_list(self):

        self.selected_ip = None
        self.selected_label.configure(text="Selected IP: None")

        for widget in self.ip_frame.winfo_children():
            widget.destroy()

        self.blocked_ips = get_blocked_ips()

        self.counter_label.configure(
            text=f"TOTAL BLOCKED IPs: {len(self.blocked_ips)}"
        )

        if not self.blocked_ips:
            ctk.CTkLabel(
                self.ip_frame,
                text="No PRAVIN blocked IPs found.\nRun this application as Administrator.",
                font=("Arial", 14),
                text_color="gray"
            ).pack(pady=40)

            return

        for ip in self.blocked_ips:

            row = ctk.CTkFrame(
                self.ip_frame,
                fg_color="#17251e",
                corner_radius=8
            )
            row.pack(fill="x", padx=8, pady=6)

            ctk.CTkLabel(
                row,
                text="●  " + ip,
                font=("Arial", 14, "bold"),
                text_color="#00ff88"
            ).pack(side="left", padx=15, pady=12)

            ctk.CTkButton(
                row,
                text="SELECT",
                width=90,
                height=30,
                fg_color="#087f46",
                hover_color="#00aa60",
                command=lambda address=ip: self.select_ip(address)
            ).pack(side="right", padx=12, pady=8)

    # =====================================
    # SELECT IP
    # =====================================

    def select_ip(self, ip):

        self.selected_ip = ip

        self.selected_label.configure(
            text=f"Selected IP: {ip}"
        )

    # =====================================
    # UNBLOCK SELECTED IP
    # =====================================

    def unblock_selected(self):

        if not self.selected_ip:
            messagebox.showwarning(
                "Select IP",
                "Please select an IP address first.",
                parent=self
            )
            return

        confirm = messagebox.askyesno(
            "Confirm Unblock",
            f"Are you sure you want to unblock {self.selected_ip}?",
            parent=self
        )

        if not confirm:
            return

        success, message = unblock_ip(self.selected_ip)

        if success:
            messagebox.showinfo(
                "Success",
                message,
                parent=self
            )
            self.refresh_list()

        else:
            messagebox.showerror(
                "Error",
                message,
                parent=self
            )


# =====================================
# TEST THIS DASHBOARD DIRECTLY
# =====================================

if __name__ == "__main__":

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("green")

    app = ctk.CTk()
    app.withdraw()

    dashboard = BlockedIPDashboard(app)

    app.mainloop()
