# Security Misconfiguration Scanner

**Beginner-friendly Python tool with a graphical user interface (GUI) built using Tkinter. It helps identify OWASP A05:2021 – Security Misconfiguration issues in web applications.**

## Overview

This scanner is designed for beginners and provides a simple way to check for common security misconfigurations in web applications. It leverages a user-friendly GUI built with Tkinter, making it accessible to those without extensive command-line experience.

The scanner performs tests for:

*   **Default credentials:** Probing for common default usernames and passwords.
*   **XML External Entities (XXE):** Checking for XXE vulnerabilities with basic XML payload injection.
*   **Open ports and exposed services:** Identifying open network ports and potentially exposed services.
*   **Misconfigured Amazon S3 buckets:** Checking for common S3 bucket misconfigurations.
*   **Tech stack exposure through HTTP headers:** Analyzing HTTP headers for information leakage about the server and technologies used.
*   **Web Application Firewall (WAF) or CDN detection:** Attempting to identify the presence of WAFs or CDNs.
*   **Missing or misconfigured security headers:** Checking for important security headers like `Content-Security-Policy`, `X-Content-Type-Options`, etc.
*   **CAPTCHA and bot protection detection:** Identifying the presence of CAPTCHA or other bot protection mechanisms.

## Features

*   **User-friendly interface:** Intuitive GUI built with Tkinter (no command-line knowledge required).
*   **Default credential testing:** Probes for common default credentials via login form analysis.
*   **Basic open port and service scan:** Uses sockets to perform a basic scan for open ports and services.
*   **XXE vulnerability test:** Includes a basic test for XXE vulnerabilities using XML payload injection.
*   **S3 bucket misconfiguration check:** Checks for common S3 bucket misconfigurations.
*   **Server fingerprinting:** Identifies server and technology information via HTTP headers.
*   **WAF/CDN detection:** Attempts to detect the presence of WAFs or CDNs.
*   **CAPTCHA and bot protection identification:** Identifies the presence of CAPTCHA or other bot protection mechanisms.
*   **Stop scan button:** Allows cancellation of an in-progress scan.
*   **Visual dashboard:** Provides a progress bar and color-coded output for scan status.
*   **Export results:** Generates an HTML report of the scan results.
*   **Logging:** Saves detailed logs to a plain text file (`scan_log.txt`).

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/TheOSuite/oSMS.git
cd oSMS 
```

### 2. Install Dependencies

Make sure you are using **Python 3.8 or newer**.

```bash
pip install -r requirements.txt
```

### 3. Run the Application

```bash
python oSMS.py
```

## How to Use

1.  Launch the script to open the GUI.
2.  Enter the target domain or IP address in the input field.
3.  Click the "Start Scan" button to begin scanning.
4.  Monitor the scan progress through the dashboard.
5.  Click "Export Report" to save the results as an HTML file.
6.  Review detailed logs in `scan_log.txt` for more information.

## Legal Disclaimer

**This tool is intended for educational use and authorized testing only. Do not use it to scan targets without explicit permission from the owner. Unauthorized scanning is illegal and unethical. The developer is not responsible for any misuse of this tool.**

## Roadmap

*   Add command-line interface (CLI) mode for scripting and automation.
*   Implement email report delivery functionality.
*   Add support for authenticated scans (e.g., login to a web application).
*   Develop a plugin system for modular scanning capabilities.
```
