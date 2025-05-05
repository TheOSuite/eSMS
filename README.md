Security Misconfiguration Scanner (OWASP A05:2021)
This is a beginner-friendly Python tool with a graphical user interface (GUI) built using Tkinter. It helps identify OWASP A05:2021 – Security Misconfiguration issues in web applications.

The scanner performs tests for:

Default credentials

XML External Entities (XXE)

Open ports and exposed services

Misconfigured Amazon S3 buckets

Tech stack exposure through HTTP headers

Web Application Firewall (WAF) or CDN detection

Missing or misconfigured security headers

CAPTCHA and bot protection detection

Features
User-friendly interface with Tkinter (no command-line knowledge required)

Default credential testing via login form probing

Basic open port and service scan using sockets

XXE vulnerability test with XML payload injection

S3 bucket misconfiguration check

Server fingerprinting via headers

WAF/CDN presence detection

CAPTCHA and bot protection identification

Stop scan button to cancel an in-progress scan

Visual dashboard with progress bar and color-coded output

Export results to an HTML report

Saves logs to a plain text file (scan_log.txt)

Getting Started
1. Clone the Repository
bash
Copy
Edit
git clone https://github.com/TheOSuite/eSMS
cd security-misconfig-scanner
2. Install Dependencies
Make sure you are using Python 3.8 or newer.

bash
Copy
Edit
pip install -r requirements.txt
3. Run the Application
bash
Copy
Edit
python eSMS.py
How to Use
Launch the script to open the GUI.

Enter the target domain or IP address in the input field.

Click the "Start Scan" button to begin scanning.

Monitor the scan progress through the dashboard.

Click "Export Report" to save the results as an HTML file.

Review detailed logs in scan_log.txt.

Legal Disclaimer
This tool is intended for educational use and authorized testing only. Do not use it to scan targets without explicit permission. Unauthorized scanning is illegal and unethical.

Roadmap
Add command-line interface (CLI) mode

Email report delivery

Authenticated scan support

Plugin system for modular scanning
