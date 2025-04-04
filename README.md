# url_scanner

A simple Python script that analyzes a given URL and detects common signs of phishing or suspicious behavior.

## ✅ Features

- Checks if the URL uses HTTPS
- Detects IP addresses used as domain
- Flags overly long URLs
- Identifies suspicious symbols (e.g. `@`, `//`, `-`)
- Analyzes number of subdomains

## 🖥️ Example

```bash
Enter URL to scan: http://192.168.0.1/login.php

Analysis result: URL is likely malicious ❌
Potential issues:
 - Does not use HTTPS.
 - Uses IP address instead of domain name.
