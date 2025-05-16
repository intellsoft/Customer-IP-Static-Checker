import tkinter as tk
from tkinter import ttk, messagebox, font, filedialog
import json
import socket
import subprocess
import threading
import time
from cryptography.fernet import Fernet
import winsound
import webbrowser
import os
import csv

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Customer IP Static Checker")
        self.state('zoomed')
        self.configure_fonts()
        
        # Initialize cryptography
        self.load_or_generate_key()
        
        # Configuration
        self.load_config()
        self.muted_ips = set()
        self.first_run = True
        
        # Create tabs
        self.notebook = ttk.Notebook(self)
        self.tab1 = ttk.Frame(self.notebook)
        self.tab2 = ttk.Frame(self.notebook)
        self.tab3 = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab1, text="Customer IP Static")
        self.notebook.add(self.tab2, text="Status")
        self.notebook.add(self.tab3, text="About")
        self.notebook.pack(expand=True, fill="both")
        
        # Initialize tabs
        self.create_input_tab()
        self.create_status_tab()
        self.create_about_tab()
        
        # Load data
        self.load_data()
        
        # Start monitoring
        self.start_monitoring()

    def configure_fonts(self):
        default_font = font.nametofont("TkDefaultFont")
        default_font.configure(size=12)
        text_font = ('Arial', 12)
        self.option_add("*Font", text_font)
        self.option_add("*TCombobox*Listbox*Font", text_font)

    def load_or_generate_key(self):
        key_file = "secret.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(self.key)
        self.cipher = Fernet(self.key)

    def load_config(self):
        try:
            with open("config.json") as f:
                self.config = json.load(f)
        except:
            self.config = {"ping_interval": 7200}
            with open("config.json", "w") as f:
                json.dump(self.config, f)

    def create_input_tab(self):
        container = ttk.Frame(self.tab1)
        container.pack(fill="both", expand=True)

        # Search Box
        search_frame = ttk.Frame(self.tab1)
        search_frame.pack(pady=5, fill="x")
        
        self.search_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.search_var, width=30).pack(side="left", padx=5)
        ttk.Button(search_frame, text="Search", command=self.search_customer).pack(side="left", padx=5)
        ttk.Button(search_frame, text="Clear", command=self.clear_search).pack(side="left", padx=5)

        self.input_table = ttk.Treeview(container, 
                                      columns=("Name", "IP", "Port"), 
                                      show="headings")
        self.input_table.heading("Name", text="Name")
        self.input_table.heading("IP", text="IP Address")
        self.input_table.heading("Port", text="Port")
        self.input_table.tag_configure("highlight", background="yellow")
        
        self.input_table.bind("<Double-1>", self.on_double_click)
        self.input_table.bind("<<TreeviewOpen>>", self.auto_save_check)
        
        vsb = ttk.Scrollbar(container, orient="vertical", command=self.input_table.yview)
        hsb = ttk.Scrollbar(container, orient="horizontal", command=self.input_table.xview)
        self.input_table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.input_table.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)
        
        btn_frame = ttk.Frame(self.tab1)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Add Row", command=self.add_row).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_selected).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Import CSV", command=self.import_csv).pack(side="left", padx=5)

    def search_customer(self):
        query = self.search_var.get().lower()
        for item in self.input_table.get_children():
            values = self.input_table.item(item, "values")
            if len(values) >= 1 and query in values[0].lower():
                self.input_table.item(item, tags=("highlight",))
                self.input_table.see(item)
            else:
                self.input_table.item(item, tags=())

    def clear_search(self):
        self.search_var.set("")
        for item in self.input_table.get_children():
            self.input_table.item(item, tags=())

    def import_csv(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("CSV Files", "*.csv")]
        )
        if not file_path:
            return
        
        try:
            with open(file_path, newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) != 3:
                        raise ValueError("CSV must have exactly 3 columns")
                    
                    name, ip, port = row
                    port = port.strip()
                    
                    if not all([name, ip, port]):
                        raise ValueError("All fields are required")
                    if not self.validate_ip(ip):
                        raise ValueError(f"Invalid IP: {ip}")
                    if not self.validate_port(port):
                        raise ValueError(f"Invalid Port: {port}")
                    
                    self.input_table.insert("", "end", values=(name, ip, port))
            
            self.auto_save_check()
            messagebox.showinfo("Success", "CSV imported successfully")
        
        except Exception as e:
            messagebox.showerror("Import Error", f"Error: {str(e)}")

    # بقیه توابع بدون تغییر باقی میمانند (فقط کپی کنید) #

    def add_row(self):
        new_id = self.input_table.insert("", "end", values=("", "", ""))
        self.on_double_click(None, new_id)
        self.auto_save_check()

    def on_double_click(self, event, item_id=None):
        if not item_id:
            region = self.input_table.identify("region", event.x, event.y)
            if region != "cell":
                return
            item = self.input_table.selection()[0]
            column = self.input_table.identify_column(event.x)
        else:
            item = item_id
            column = "#1"

        col_index = int(column[1:]) - 1
        cell_value = self.input_table.item(item, "values")[col_index]

        x, y, width, height = self.input_table.bbox(item, column)
        entry = ttk.Entry(self.input_table)
        entry.place(x=x, y=y, width=width, height=height)
        entry.insert(0, cell_value)
        entry.focus()

        if cell_value in ["New Customer", "0.0.0.0", "0"]:
            entry.delete(0, tk.END)

        def save_edit(event=None):
            new_value = entry.get()
            current_values = list(self.input_table.item(item, "values"))
            current_values[col_index] = new_value
            self.input_table.item(item, values=current_values)
            entry.destroy()
            self.auto_save_check()

        entry.bind("<FocusOut>", save_edit)
        entry.bind("<Return>", save_edit)

    def delete_selected(self):
        selected_items = self.input_table.selection()
        if not selected_items:
            return
        
        confirm = messagebox.askyesno(
            "Delete Confirmation",
            "Are you sure you want to delete selected items?",
            parent=self
        )
        
        if confirm:
            for item in selected_items:
                self.input_table.delete(item)
            self.auto_save_check()

    def auto_save_check(self, event=None):
        all_valid = True
        for child in self.input_table.get_children():
            values = self.input_table.item(child)["values"]
            if len(values) != 3 or not all(values):
                all_valid = False
                break
            if not self.validate_ip(values[1]) or not self.validate_port(values[2]):
                all_valid = False
                break
        
        if all_valid and self.input_table.get_children():
            self.save_data(silent=True)
            self.update_status()

    def save_data(self, silent=False):
        data = []
        for child in self.input_table.get_children():
            values = self.input_table.item(child)["values"]
            if len(values) != 3:
                continue
                
            name, ip, port = values
            port = str(port)
            
            if not all([name, ip, port]):
                if not silent:
                    messagebox.showerror("Error", "All fields are required")
                return
                
            if not self.validate_ip(ip):
                if not silent:
                    messagebox.showerror("Error", f"Invalid IP address: {ip}")
                return
                
            if not self.validate_port(port):
                if not silent:
                    messagebox.showerror("Error", f"Invalid Port: {port}")
                return
                
            data.append({"name": name, "ip": ip, "port": port})
        
        encrypted = self.cipher.encrypt(json.dumps(data).encode())
        with open("data.enc", "wb") as f:
            f.write(encrypted)
        if not silent:
            messagebox.showinfo("Success", "Data saved successfully")
        self.update_status()

    def validate_ip(self, ip):
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            return False

    def validate_port(self, port):
        return str(port).isdigit() and 1 <= int(port) <= 65535

    def load_data(self):
        try:
            with open("data.enc", "rb") as f:
                encrypted = f.read()
                data = json.loads(self.cipher.decrypt(encrypted).decode())
                for item in data:
                    self.input_table.insert("", "end", values=(item["name"], item["ip"], item["port"]))
        except Exception as e:
            pass

    def create_status_tab(self):
        container = ttk.Frame(self.tab2)
        container.pack(fill="both", expand=True, padx=10, pady=10)

        self.status_tree = ttk.Treeview(container, 
                                      columns=("Name", "IP", "Port", "Status"), 
                                      show="headings")
        
        for col in ["Name", "IP", "Port", "Status"]:
            self.status_tree.heading(col, text=col, anchor="center")
            self.status_tree.column(col, width=120, anchor="center", stretch=True)
        
        hsb = ttk.Scrollbar(container, orient="horizontal", command=self.status_tree.xview)
        self.status_tree.configure(xscrollcommand=hsb.set)
        
        self.status_tree.pack(side="top", fill="both", expand=True)
        hsb.pack(side="bottom", fill="x")

        self.status_tree.tag_configure("Offline", background="#ffcccc")
        self.status_tree.tag_configure("Online", background="#ccffcc")

    def update_status(self):
        self.status_tree.delete(*self.status_tree.get_children())
        
        children = self.input_table.get_children()
        entries = [self.input_table.item(child)["values"] for child in children]
        
        offline = []
        online = []
        
        for entry in entries:
            if len(entry) != 3:
                continue
            name, ip, port = entry
            status = self.check_status(ip, port)
            
            if status == "Offline":
                offline.append((name, ip, port, status))
            else:
                online.append((name, ip, port, status))
        
        for item in offline + online:
            name, ip, port, status = item
            self.status_tree.insert("", "end", 
                                  values=(name, ip, port, status), 
                                  tags=(status,))
            
            if status == "Offline" and ip not in self.muted_ips and not self.first_run:
                threading.Thread(target=self.play_alert).start()
        
        self.first_run = False

    def check_status(self, ip, port):
        try:
            param = '-n' if os.name == 'nt' else '-c'
            subprocess.check_output(
                ["ping", param, "1", ip],
                stderr=subprocess.STDOUT,
                timeout=2
            )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, int(port)))
            return "Online"
        except:
            return "Offline"

    def play_alert(self):
        winsound.Beep(1000, 1000)

    def start_monitoring(self):
        def monitoring_loop():
            self.update_status()
            self.after(self.config["ping_interval"] * 1000, monitoring_loop)
        
        monitoring_loop()

    def create_about_tab(self):
        about_text = """I am Ali Abbaspour\n
Transforming CCTV cameras into creative tools ✨ I help you use specialized software 
to do amazing things with CCTV camera images and get the most out of your camera."""
        
        text_frame = ttk.Frame(self.tab3)
        text_frame.pack(pady=20, padx=20)
        
        label = ttk.Label(text_frame, text=about_text, wraplength=600)
        label.pack()
        
        website = ttk.Label(text_frame, text="https://intellsoft.ir", foreground="blue", cursor="hand2")
        website.pack(pady=10)
        website.bind("<Button-1>", lambda e: webbrowser.open("https://intellsoft.ir"))

if __name__ == "__main__":
    app = Application()
    app.mainloop()