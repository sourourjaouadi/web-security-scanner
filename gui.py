import threading
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from web_vul import WebSecurityScanner
import tkinter as tk
from PIL import Image, ImageTk

class SecurityScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ CyberSec Web Scanner")
        self.root.geometry("900x650")
        self.root.resizable(False, False)

        # Load and set background image
        self.bg_image_orig = Image.open("background.jpg").resize((900, 650))
        self.bg_image_tk = ImageTk.PhotoImage(self.bg_image_orig)
        self.bg_label = tk.Label(root, image=self.bg_image_tk)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Semi-transparent dark overlay using transparent image
        overlay_img = Image.new('RGBA', (900, 650), (0, 0, 0, 130))  # black with alpha
        self.overlay_img_tk = ImageTk.PhotoImage(overlay_img)
        self.overlay_label = tk.Label(root, image=self.overlay_img_tk)
        self.overlay_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Panel for UI widgets
        self.panel = tk.Frame(root, bg="#1b1b2f")
        self.panel.place(relx=0.5, rely=0.5, anchor="center", width=860, height=600)

        self.style = ttk.Style("cyborg")
        self.style.configure("Custom.TEntry", font=("Segoe UI", 14))
        self.style.configure("Custom.TLabel", font=("Segoe UI", 18), foreground="#c8a2c8", background="#1b1b2f")
        self.style.configure("Result.TLabel", font=("Consolas", 12), background="#1b1b2f", foreground="#ddd")
        self.style.configure("Custom.TButton", font=("Segoe UI Semibold", 14), padding=10, relief="raised", borderwidth=4)
        self.style.map("Custom.TButton",
            relief=[('pressed', 'sunken'), ('active', 'raised')],
            background=[('active', '#8a2be2'), ('!active', '#5a2bc8')],
            foreground=[('disabled', '#555555'), ('!disabled', '#ffffff')],
        )

        self.create_widgets()

    def create_widgets(self):
        # Load icons
        self.shield_icon = Image.open("shield_icon.jpg").resize((40, 40))
        self.shield_icon_tk = ImageTk.PhotoImage(self.shield_icon)

        self.scan_icon = Image.open("scan_icon.png").resize((20, 20))
        self.scan_icon_tk = ImageTk.PhotoImage(self.scan_icon)

        # Title with icon
        title_frame = tk.Frame(self.panel, bg="#1b1b2f")
        title_frame.pack(pady=(25, 15))
        shield_label = tk.Label(title_frame, image=self.shield_icon_tk, bg="#1b1b2f")
        shield_label.pack(side="left", padx=(0, 10))
        title_label = ttk.Label(title_frame, text="CyberSec Web Scanner", style="Custom.TLabel")
        title_label.pack(side="left")

        # URL entry
        self.url_entry = ttk.Entry(self.panel, style="Custom.TEntry", width=50)
        self.url_entry.pack(pady=10)
        self.url_entry.insert(0, "https://example.com")
        self.url_entry.bind("<FocusIn>", self.clear_placeholder)
        self.url_entry.bind("<FocusOut>", self.add_placeholder)

        # Start Scan button
        self.scan_btn = ttk.Button(
            self.panel,
            text=" Start Scan",
            style="Custom.TButton",
            bootstyle="success-outline",
            command=self.start_scan,
            compound="left",
            image=self.scan_icon_tk
        )
        self.scan_btn.pack(pady=15)

        # Progress bar
        self.progress = ttk.Progressbar(self.panel, mode="indeterminate", bootstyle="success")
        self.progress.pack(fill="x", padx=40, pady=(0, 15))

        # Status label
        self.status_label = ttk.Label(self.panel, text="", style="Result.TLabel")
        self.status_label.pack(pady=5)

        # Result box
        self.result_box = ttk.ScrolledText(
            self.panel,
            height=22,
            font=("Consolas", 11),
            wrap="word",
            background="#12122a",
            foreground="#d4d4dc",
            insertbackground="white"
        )
        self.result_box.pack(padx=20, pady=10, fill=BOTH, expand=True)

    def clear_placeholder(self, event):
        if self.url_entry.get() == "https://example.com":
            self.url_entry.delete(0, "end")
            self.url_entry.config(foreground="#fff")

    def add_placeholder(self, event):
        if not self.url_entry.get():
            self.url_entry.insert(0, "https://example.com")
            self.url_entry.config(foreground="#777")

    def start_scan(self):
        url = self.url_entry.get()
        if url.strip() == "" or url.strip() == "https://example.com":
            self.status_label.config(text="Please enter a valid URL.", foreground="#ff5555")
            return

        self.result_box.delete("1.0", "end")
        self.status_label.config(text="Scanning in progress...", foreground="#a0ffa0")
        self.progress.start(10)
        self.scan_btn.state(["disabled"])
        threading.Thread(target=self.run_scan, args=(url,), daemon=True).start()

    def run_scan(self, url):
        try:
            scanner = WebSecurityScanner(url)
            vulnerabilities = scanner.scan()
        except Exception as e:
            self.root.after(0, lambda: self.show_error(e))
            return

        def update_ui():
            self.progress.stop()
            self.scan_btn.state(["!disabled"])
            self.status_label.config(text="Scan Complete.", foreground="#a0ffa0")

            self.result_box.insert("end", f"Scanned {len(scanner.visited_urls)} pages.\n")
            self.result_box.insert("end", f"Vulnerabilities found: {len(vulnerabilities)}\n\n")

            for vuln in vulnerabilities:
                self.result_box.insert("end", f"[{vuln['type']}] on {vuln['url']}\n")
                for key, value in vuln.items():
                    if key not in ("url", "type"):
                        self.result_box.insert("end", f" - {key}: {value}\n")
                self.result_box.insert("end", "\n")

        self.root.after(0, update_ui)

    def show_error(self, error):
        self.progress.stop()
        self.scan_btn.state(["!disabled"])
        self.status_label.config(text=f"Error during scan: {error}", foreground="#ff5555")


if __name__ == "__main__":
    root = ttk.Window(themename="cyborg")
    app = SecurityScannerGUI(root)
    root.mainloop()
