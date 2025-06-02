import threading
import logging
import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime
from telnet_honeypot import TelnetHoneypot

class HoneypotGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Telnet Honeypot")
        self.root.geometry("600x400")
        self.honeypot = None
        self.server_thread = None
        self.initialize_gui()

    def initialize_gui(self):
        self.control_frame = ttk.Frame(self.root)
        self.control_frame.pack(pady=5)

        self.start_button = ttk.Button(self.control_frame, text="Start Honeypot", command=self.start_honeypot)
        self.start_button.grid(row=0, column=0, padx=5)
        self.stop_button = ttk.Button(self.control_frame, text="Stop Honeypot", command=self.stop_honeypot, state='disabled')
        self.stop_button.grid(row=0, column=1, padx=5)

        self.status_frame = ttk.LabelFrame(self.root, text="Status")
        self.status_frame.pack(pady=5, padx=10, fill="x")
        self.status_label = ttk.Label(self.status_frame, text="Stopped", foreground="red")
        self.status_label.pack(pady=5)

        self.log_text = scrolledtext.ScrolledText(self.root, width=70, height=20)
        self.log_text.pack(pady=10)

        logging.basicConfig(
            filename='telnet_honeypot.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )

        self.configure_tags()
        self.update_logs()

    def start_honeypot(self):
        if not self.server_thread or not self.server_thread.is_alive():
            try:
                self.log_text.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Attempting to start honeypot\n")
                self.honeypot = TelnetHoneypot(host='0.0.0.0', port=8023)
                self.server_thread = threading.Thread(target=self.honeypot.start)
                self.server_thread.daemon = True
                self.server_thread.start()
                self.start_button.config(state='disabled')
                self.stop_button.config(state='normal')
                self.update_status("Running", "green")
            except Exception as e:
                self.log_text.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Failed to start server: {e}\n", "error")
                self.update_status("Stopped", "red")

    def stop_honeypot(self):
        try:
            if self.honeypot:
                self.honeypot.stop()
                self.log_text.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Stopping honeypot\n")
            if self.server_thread:
                self.server_thread.join(timeout=15)  # Increased timeout
                if self.server_thread.is_alive():
                    self.log_text.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Warning: Server thread did not terminate\n", "error")
                self.server_thread = None
            self.honeypot = None
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
            self.update_status("Stopped", "red")
            self.log_text.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Honeypot stopped\n")
        except Exception as e:
            self.log_text.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Failed to stop server: {e}\n", "error")

    def update_status(self, status, color):
        self.status_label.config(text=status, foreground=color)

    def update_logs(self):
        if self.honeypot:
            log_queue = self.honeypot.get_log_queue()
            while not log_queue.empty():
                entry = log_queue.get()
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if isinstance(entry, tuple):
                    log_type, message = entry
                    if log_type == "scan":
                        self.log_text.insert(tk.END, f"{timestamp} - {message}\n", "scan")
                        self.log_text.config(background="red")
                        self.root.after(500, lambda: self.log_text.config(background="white"))
                    elif log_type == "error":
                        self.log_text.insert(tk.END, f"{timestamp} - {message}\n", "error")
                    elif log_type == "ddos":
                        self.log_text.insert(tk.END, f"{timestamp} - {message}\n", "ddos")
                    else:
                        self.log_text.insert(tk.END, f"{timestamp} - {message}\n")
                else:
                    self.log_text.insert(tk.END, f"{timestamp} - {entry}\n")
                logging.info(message if isinstance(entry, tuple) else entry)
                self.log_text.see(tk.END)
        self.root.after(100, self.update_logs)

    def configure_tags(self):
        self.log_text.tag_configure("scan", foreground="red", font=("Arial", 10, "bold"))
        self.log_text.tag_configure("error", foreground="orange")
        self.log_text.tag_configure("ddos", foreground="purple", font=("Arial", 10, "bold"))

def main():
    root = tk.Tk()
    app = HoneypotGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
