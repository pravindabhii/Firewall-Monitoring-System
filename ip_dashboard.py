
import customtkinter as ctk
from tkinter import messagebox
from ip_manager import add_ip, remove_ip, get_all_ips


class IPDashboard(ctk.CTkToplevel):

    def __init__(self, master=None):
        super().__init__(master)

        self.title("Firewall - IP Manager")
        self.geometry("850x600")
        self.configure(fg_color="#080D12")

        self.title_label = ctk.CTkLabel(
            self,
            text="IP WHITELIST & BLACKLIST MANAGER",
            font=("Consolas", 23, "bold"),
            text_color="#00FF66"
        )
        self.title_label.pack(pady=20)

        self.ip_entry = ctk.CTkEntry(
            self,
            placeholder_text="Enter IP Address",
            width=350,
            height=40
        )
        self.ip_entry.pack(pady=10)

        self.button_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        self.button_frame.pack(pady=10)

        ctk.CTkButton(
            self.button_frame,
            text="ADD WHITELIST",
            fg_color="#008F45",
            hover_color="#00AA55",
            command=lambda: self.add_new_ip("WHITELIST")
        ).grid(row=0, column=0, padx=10)

        ctk.CTkButton(
            self.button_frame,
            text="ADD BLACKLIST",
            fg_color="#B22222",
            hover_color="#E00000",
            command=lambda: self.add_new_ip("BLACKLIST")
        ).grid(row=0, column=1, padx=10)

        ctk.CTkButton(
            self.button_frame,
            text="REMOVE IP",
            fg_color="#444444",
            hover_color="#666666",
            command=self.delete_ip
        ).grid(row=0, column=2, padx=10)

        ctk.CTkButton(
            self.button_frame,
            text="REFRESH",
            fg_color="#006B75",
            hover_color="#008C99",
            command=self.load_ips
        ).grid(row=0, column=3, padx=10)

        self.ip_list = ctk.CTkTextbox(
            self,
            width=780,
            height=350,
            font=("Consolas", 14),
            fg_color="#101820",
            text_color="#00FF66"
        )
        self.ip_list.pack(pady=20)

        self.load_ips()

    def add_new_ip(self, rule_type):
        ip = self.ip_entry.get().strip()

        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address")
            return

        success, message = add_ip(ip, rule_type)

        if success:
            messagebox.showinfo("Success", message)
            self.ip_entry.delete(0, "end")
            self.load_ips()
        else:
            messagebox.showerror("Error", message)

    def delete_ip(self):
        ip = self.ip_entry.get().strip()

        if not ip:
            messagebox.showwarning("Warning", "Enter IP address to remove")
            return

        success, message = remove_ip(ip)

        if success:
            messagebox.showinfo("Success", message)
            self.ip_entry.delete(0, "end")
            self.load_ips()
        else:
            messagebox.showerror("Error", message)

    def load_ips(self):
        records = get_all_ips()

        self.ip_list.configure(state="normal")
        self.ip_list.delete("1.0", "end")

        self.ip_list.insert(
            "end",
            "ID       IP ADDRESS              RULE TYPE             CREATED AT\n"
        )
        self.ip_list.insert("end", "-" * 85 + "\n")

        for record in records:
            record_id, ip, rule_type, created_at = record

            self.ip_list.insert(
                "end",
                f"{record_id:<8} {ip:<24} {rule_type:<21} {created_at}\n"
            )

        if not records:
            self.ip_list.insert("end", "\nNo IP records found.")

        self.ip_list.configure(state="disabled")
