import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import threading
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import queue


class DirectoryScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Directory Scanner")
        self.root.geometry("900x650")
        self.root.configure(bg="#1a1a1a")  # Dark background

        # Create main frame
        main_frame = ttk.Frame(root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.configure(style="MainFrame.TFrame")

        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')  # Use 'clam' theme for better dark mode support

        # Define colors
        bg_color = "#1a1a1a"  # Dark background
        fg_color = "#e6e6e6"  # Light foreground
        accent_color = "#9acd32"  # Hack The Box green
        entry_bg_color = "#333333"  # Darker entry background
        entry_fg_color = "#e6e6e6"  # Light entry foreground

        # Frame style
        style.configure("MainFrame.TFrame", background=bg_color)

        # Label style
        style.configure("TLabel", background=bg_color, foreground=fg_color, font=("Arial", 12))

        # Button style
        style.configure("TButton", background=accent_color, foreground=bg_color, font=("Arial", 12), padding=5)
        style.map("TButton", background=[("active", "#7fbf00")])  # Slightly lighter green on hover

        # Entry style
        style.configure("TEntry", fieldbackground=entry_bg_color, foreground=entry_fg_color, font=("Arial", 12),
                        padding=5)

        # URL input
        ttk.Label(main_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(main_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=10, pady=5, sticky=(tk.W, tk.E))

        # Scan button
        self.scan_button = ttk.Button(main_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=2, padx=10, pady=5)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100, length=600)
        self.progress_bar.grid(row=1, column=0, columnspan=3, pady=10)

        # Results
        ttk.Label(main_frame, text="Results:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.results_text = scrolledtext.ScrolledText(main_frame, width=90, height=25, bg=entry_bg_color,
                                                      fg=entry_fg_color, font=("Arial", 12),
                                                      insertbackground=entry_fg_color)
        self.results_text.grid(row=3, column=0, columnspan=3, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Search functionality
        ttk.Label(main_frame, text="Search:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.search_entry = ttk.Entry(main_frame, width=50)
        self.search_entry.grid(row=4, column=1, padx=10, pady=5, sticky=(tk.W, tk.E))
        self.search_button = ttk.Button(main_frame, text="Search", command=self.search_results)
        self.search_button.grid(row=4, column=2, padx=10, pady=5)

        self.scanning = False
        self.visited_urls = set()
        self.queued_urls = set()
        self.url_queue = queue.Queue()
        self.target_directories = []

        # Configure grid weights for resizing
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_rowconfigure(3, weight=1)

    def validate_url(self, url):
        if not url.startswith(("http://", "https://")):
            return "https://" + url
        return url

    def scan_directory(self, base_url, path="", depth=0):
        if not self.scanning:
            return

        full_url = urljoin(base_url, path)
        if full_url in self.visited_urls:
            return
        self.visited_urls.add(full_url)

        self.results_text.insert(tk.END, f"{'  ' * depth}Checking: {full_url}\n")
        self.results_text.see(tk.END)

        try:
            response = requests.get(full_url, allow_redirects=False, verify=False)
            if response.status_code != 404:
                self.results_text.insert(tk.END, f"{'  ' * depth}Found: {full_url} (Status: {response.status_code})\n")
                self.results_text.see(tk.END)

                soup = BeautifulSoup(response.content, "html.parser")
                links = soup.find_all("a")
                for link in links:
                    href = link.get("href")
                    if href:
                        absolute_href = urljoin(full_url, href)
                        parsed_href = urlparse(absolute_href)
                        if parsed_href.netloc == urlparse(base_url).netloc and parsed_href.path not in self.queued_urls:
                            self.url_queue.put(parsed_href.path)
                            self.queued_urls.add(parsed_href.path)
                            self.results_text.insert(tk.END, f"{'  ' * (depth + 1)}Queued: {parsed_href.path}\n")
                            self.results_text.see(tk.END)
        except requests.RequestException as e:
            self.results_text.insert(tk.END, f"{'  ' * depth}Error: {full_url} - {str(e)}\n")
            self.results_text.see(tk.END)

    def process_queue(self, base_url):
        while not self.url_queue.empty() and self.scanning:
            path = self.url_queue.get()
            self.scan_directory(base_url, path)
            self.url_queue.task_done()

    def start_scan(self):
        if not self.scanning:
            self.scanning = True
            self.scan_button.config(text="Stop Scan")
            self.results_text.delete("1.0", tk.END)
            threading.Thread(target=self.initiate_scan, daemon=True).start()
        else:
            self.scanning = False
            self.scan_button.config(text="Start Scan")

    def initiate_scan(self):
        base_url = self.validate_url(self.url_entry.get().strip())
        if not base_url:
            messagebox.showerror("Error", "Please enter a valid URL")
            return

        self.results_text.insert(tk.END, f"Starting scan of {base_url}\n\n")

        try:
            self.url_queue.put("")  # Start with the base
            self.process_queue(base_url)
        finally:
            self.scanning = False
            self.scan_button.config(text="Start Scan")
            self.progress_var.set(0)
            self.results_text.insert(tk.END, "\nScan completed!\n")
            self.results_text.see(tk.END)

    def search_results(self):
        search_term = self.search_entry.get().strip()
        if not search_term:
            messagebox.showwarning("Warning", "Please enter a search term")
            return

        self.results_text.tag_remove("highlight", "1.0", tk.END)
        start_pos = "1.0"
        while True:
            start_pos = self.results_text.search(search_term, start_pos, tk.END, nocase=True)
            if not start_pos:
                break
            end_pos = f"{start_pos}+{len(search_term)}c"
            self.results_text.tag_add("highlight", start_pos, end_pos)
            start_pos = end_pos

        self.results_text.tag_config("highlight", background="yellow")


if __name__ == "__main__":
    root = tk.Tk()
    app = DirectoryScanner(root)
    root.mainloop()
