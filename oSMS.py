import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext, ttk
import requests
from urllib.parse import urljoin, urlparse
import socket
import threading
import time
import datetime
import re

stop_scan_flag = False
log_lines = []
common_ports = [21, 22, 23, 80, 443, 8080, 8443, 3306, 5432, 6379]
default_creds = [("admin", "admin"), ("admin", "password"), ("user", "user"), ("root", "root")]

# ------------------------------------------
# Logging
# ------------------------------------------
def log_output(text, color):
    prefix = {
        "green": "[INFO]",
        "red": "[ERROR]",
        "orange": "[WARNING]",
        "blue": "[INFO]"
    }.get(color, "[INFO]")
    output_box.tag_config(color, foreground=color)
    output_box.insert(tk.END, text + "\n", color)
    output_box.see(tk.END)
    log_lines.append(f"{prefix} {text}")

# ------------------------------------------
# Vulnerability test functions
# ------------------------------------------
def check_http_headers(url):
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers
        missing = [h for h in [
            'Content-Security-Policy', 'Strict-Transport-Security',
            'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection'
        ] if h not in headers]
        if missing:
            return ("Missing Security Headers: " + ", ".join(missing), "red")
        return ("All recommended headers are present.", "green")
    except Exception as e:
        return (f"[Header Check] Error: {e}", "orange")

def check_directory_listing(url):
    try:
        res = requests.get(url, timeout=5)
        if "Index of /" in res.text:
            return ("Possible Directory Listing Enabled.", "red")
        return ("No directory listing found.", "green")
    except Exception as e:
        return (f"[Directory Check] Error: {e}", "orange")

def check_error_messages(url):
    try:
        res = requests.get(urljoin(url, "/nonexistent404page"), timeout=5)
        if any(e in res.text.lower() for e in ["exception", "traceback", "error", "warning"]):
            return ("Verbose error message detected.", "red")
        return ("Error messages appear generic.", "green")
    except Exception as e:
        return (f"[Error Check] Error: {e}", "orange")

def check_tech_exposure(url):
    try:
        res = requests.get(url, timeout=5)
        exposed = []
        if "x-powered-by" in res.headers:
            exposed.append(f"X-Powered-By: {res.headers['x-powered-by']}")
        if "server" in res.headers:
            exposed.append(f"Server: {res.headers['server']}")
        if any(tag in res.text.lower() for tag in ["php", ".aspx", "wordpress", "drupal", "django"]):
            exposed.append("HTML indicates potential tech stack.")
        if exposed:
            return ("Tech Exposure: " + ", ".join(exposed), "red")
        return ("No obvious tech stack exposure.", "green")
    except Exception as e:
        return (f"[Tech Stack Check] Error: {e}", "orange")

def check_default_credentials(url):
    login_url = urljoin(url, "/login")
    results = []
    for user, pwd in default_creds:
        try:
            res = requests.post(login_url, data={"username": user, "password": pwd}, timeout=5)
            if res.status_code == 200 and "logout" in res.text.lower():
                results.append(f"Default creds work: {user}/{pwd}")
        except:
            continue
    if results:
        return ("\n".join(results), "red")
    return ("No working default credentials found.", "green")

def check_xxe(url):
    payload = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"""
    headers = {'Content-Type': 'application/xml'}
    try:
        res = requests.post(url, data=payload, headers=headers, timeout=5)
        if "root:" in res.text:
            return ("XXE vulnerability detected!", "red")
        return ("No XXE vulnerability detected.", "green")
    except Exception as e:
        return (f"[XXE Test] Error: {e}", "orange")

def check_open_ports(url):
    results = []
    try:
        ip = socket.gethostbyname(urlparse(url).hostname)
        for port in common_ports:
            if stop_scan_flag: break
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                results.append(f"Port {port} is open.")
            s.close()
        if results:
            return ("\n".join(results), "red")
        return ("No common open ports detected.", "green")
    except Exception as e:
        return (f"[Port Scan] Error: {e}", "orange")

def check_s3_buckets(url):
    try:
        domain = urlparse(url).hostname.replace("www.", "")
        buckets = [f"http://{domain}.s3.amazonaws.com", f"http://s3.amazonaws.com/{domain}"]
        for bucket in buckets:
            res = requests.get(bucket, timeout=5)
            if "<ListBucketResult" in res.text:
                return (f"Open S3 bucket found: {bucket}", "red")
        return ("No open S3 buckets found.", "green")
    except Exception as e:
        return (f"[S3 Check] Error: {e}", "orange")

def detect_waf(url):
    try:
        res = requests.get(url, timeout=5)
        waf_headers = ["server", "x-cdn", "via", "x-firewall", "cf-ray"]
        detected = [f"{h}: {res.headers[h]}" for h in waf_headers if h in res.headers]
        if any("cloudflare" in h.lower() or "akamai" in h.lower() or "sucuri" in h.lower() for h in detected):
            return ("WAF/CDN detected: " + ", ".join(detected), "orange")
        return ("No obvious WAF/CDN detected.", "green")
    except Exception as e:
        return (f"[WAF Detection] Error: {e}", "orange")

# ------------------------------------------
# Scanner Execution
# ------------------------------------------
def perform_tests(url):
    global stop_scan_flag
    stop_scan_flag = False
    progress_bar["value"] = 0
    progress_step = 100 / 9
    tests = [
        ("HTTP Header Check", check_http_headers),
        ("Directory Listing", check_directory_listing),
        ("Error Message Exposure", check_error_messages),
        ("Tech Stack Exposure", check_tech_exposure),
        ("Default Credentials", check_default_credentials),
        ("XXE Injection", check_xxe),
        ("Open Ports", check_open_ports),
        ("S3 Buckets", check_s3_buckets),
        ("WAF/CDN Detection", detect_waf)
    ]
    for label, func in tests:
        if stop_scan_flag:
            log_output("Scan stopped by user.", "orange")
            return
        log_output(f"[{label}]", "blue")
        result, color = func(url)
        log_output(result, color)
        progress_bar["value"] += progress_step
        time.sleep(0.1)
    log_output("Scan complete.", "blue")
    progress_bar["value"] = 100
    save_log_file()

def threaded_scan():
    url = url_entry.get().strip()
    if not url.startswith("http"):
        messagebox.showerror("Invalid URL", "Please enter a valid URL starting with http:// or https://")
        return
    output_box.delete(1.0, tk.END)
    log_lines.clear()
    scan_button["state"] = "disabled"
    stop_button["state"] = "normal"
    threading.Thread(target=lambda: perform_tests(url)).start()

def stop_scan():
    global stop_scan_flag
    stop_scan_flag = True
    stop_button["state"] = "disabled"
    scan_button["state"] = "normal"

def save_as_html():
    html = "<html><head><style>body{font-family:Arial;} .green{color:green;} .red{color:red;} .orange{color:orange;} .blue{color:blue;}</style></head><body>"
    html += f"<h2>Security Misconfiguration Report - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2><pre>"
    text = output_box.get("1.0", tk.END)
    for line in text.splitlines():
        color = "blue"
        if "[ERROR]" in line:
            color = "red"
        elif "[WARNING]" in line:
            color = "orange"
        elif "[INFO]" in line:
            color = "green"
        html += f"<span class='{color}'>{line}</span><br>"
    html += "</pre></body></html>"
    path = filedialog.asksaveasfilename(defaultextension=".html")
    if path:
        with open(path, "w") as f:
            f.write(html)
        messagebox.showinfo("Saved", "HTML report saved.")

def save_log_file():
    filename = f"scan_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write("\n".join(log_lines))

# ------------------------------------------
# GUI Setup
# ------------------------------------------
root = tk.Tk()
root.title("OWASP A05:2021 Security Misconfiguration Scanner")

tk.Label(root, text="Enter Target URL:").pack(pady=5)
url_entry = tk.Entry(root, width=60)
url_entry.pack(pady=5)

frame = tk.Frame(root)
frame.pack(pady=5)

scan_button = tk.Button(frame, text="Start Scan", command=threaded_scan)
scan_button.pack(side="left", padx=5)

stop_button = tk.Button(frame, text="Stop Scan", command=stop_scan, state="disabled")
stop_button.pack(side="left", padx=5)

export_button = tk.Button(frame, text="Export to HTML", command=save_as_html)
export_button.pack(side="left", padx=5)

progress_bar = ttk.Progressbar(root, orient="horizontal", mode="determinate", length=500)
progress_bar.pack(pady=5)

output_box = scrolledtext.ScrolledText(root, width=100, height=30)
output_box.pack(padx=10, pady=10)

root.mainloop()
