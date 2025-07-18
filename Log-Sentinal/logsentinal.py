#!/usr/bin/env python3

import time

def scan_logs():
    print("[*] LogSentinel: Simulated log scan initiated...")
    time.sleep(1)
    print("[+] Analyzing access.log for web anomalies...")
    time.sleep(1)
    print("[!] Found repeated 404 errors from IP: 192.168.56.101")
    print("[+] Flagged as possible reconnaissance scan")
    time.sleep(1)
    print("[+] Analyzing auth.log for login anomalies...")
    print("[!] Multiple failed logins for user 'annie' from unknown host")
    print("[✓] Log review complete — alerts generated")

if __name__ == "__main__":
    scan_logs()
