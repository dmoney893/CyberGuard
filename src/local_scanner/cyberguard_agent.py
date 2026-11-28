
import os
import socket
import threading
import tkinter as tk
from tkinter import messagebox
import webbrowser

import uvicorn

from scanner_server import app, create_pairing_code

WEBSITE_URL = "https://cyberguard-omega-sable.vercel.app"


class CyberGuardAgent:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberGuard Agent")
        self.root.geometry("480x480")
        self.root.resizable(False, False)
        self.root.configure(bg="#101827")

        self.server = None
        self.server_thread = None
        self.pairing_code = None
        self.port = None
        self.listener = None

        tk.Label(
            root,
            text="CyberGuard",
            font=("Segoe UI", 23, "bold"),
            fg="#FFFFFF",
            bg="#101827",
        ).pack(pady=(25, 5))

        tk.Label(
            root,
            text="Local Security Agent",
            font=("Segoe UI", 11),
            fg="#94A3B8",
            bg="#101827",
        ).pack()

        self.status_label = tk.Label(
            root,
            text="Starting agent...",
            font=("Segoe UI", 11),
            fg="#FBBF24",
            bg="#101827",
        )
        self.status_label.pack(pady=(20, 10))

        tk.Label(
            root,
            text="YOUR PAIRING CODE",
            font=("Segoe UI", 10, "bold"),
            fg="#94A3B8",
            bg="#101827",
        ).pack()

        self.code_label = tk.Label(
            root,
            text="Generating...",
            font=("Consolas", 15, "bold"),
            fg="#38BDF8",
            bg="#101827",
        )
        self.code_label.pack(pady=12)

        self.copy_button = tk.Button(
            root,
            text="Copy Pairing Code",
            command=self.copy_code,
            width=25,
        )
        self.copy_button.pack(pady=5)

        tk.Button(
            root,
            text="Generate New Code",
            command=self.generate_code,
            width=25,
        ).pack(pady=5)

        tk.Button(
            root,
            text="Open CyberGuard Website",
            command=self.open_website,
            width=25,
        ).pack(pady=5)

        self.root.protocol("WM_DELETE_WINDOW", self.close_agent)

        self.start_agent()

    def start_agent(self):
        configured = os.environ.get("CYBERGUARD_AGENT_PORT")
        ports = [int(configured)] if configured else range(8765, 8776)
        for port in ports:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.bind(("127.0.0.1", port))
                listener.listen(128)
            except OSError:
                listener.close()
                continue
            self.listener = listener
            self.port = port
            break
        if self.listener is None:
            self.status_label.config(text="No available agent port", fg="#EF4444")
            messagebox.showerror("CyberGuard Agent", "Agent ports are already in use. Close another CyberGuard Agent and try again.")
            return
        self.generate_code()

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=self.port,
            log_level="warning",
            log_config=None,
            access_log=False,
        )

        self.server = uvicorn.Server(config)

        self.server_thread = threading.Thread(
            target=self.server.run,
            kwargs={"sockets": [self.listener]},
            daemon=True,
        )
        self.server_thread.start()

        self.check_server()

    def check_server(self):
        if self.server and self.server.started:
            self.status_label.config(
                text=f"Agent Running — Port {self.port}",
                fg="#22C55E",
            )
        elif self.server_thread and not self.server_thread.is_alive():
            self.status_label.config(
                text="Agent Failed to Start",
                fg="#EF4444",
            )
            messagebox.showerror(
                "CyberGuard Agent",
                "Unable to start the scanner. "
                "Check whether another scanner is already running.",
            )
        else:
            self.root.after(300, self.check_server)

    def open_website(self):
        if self.port is not None:
            webbrowser.open(f"{WEBSITE_URL}/device-scanner?agentPort={self.port}")

    def copy_code(self):
        if not self.pairing_code:
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(self.pairing_code)
        self.root.update()

        self.copy_button.config(text="Copied!")

        self.root.after(
            2000,
            lambda: self.copy_button.config(text="Copy Pairing Code")
        )

    def generate_code(self):
        self.pairing_code = create_pairing_code()
        self.code_label.config(text=self.pairing_code)

    def close_agent(self):
        if self.server:
            self.server.should_exit = True
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    CyberGuardAgent(root)
    root.mainloop()
