# 🛡️ Phishing URL Scanner – Brainwave Matrix Internship (Task 1)

This project is part of the internship program offered by **Brainwave Matrix Solutions**. The goal of Task 1 was to build a basic **Phishing URL Scanner** using Python that can assess a URL for potential phishing behavior through static analysis.

---

## 🔍 Features

- ✅ Extracts and parses domain from a given URL
- 🌐 Checks if the URL is reachable (HTTP 200 OK)
- 🧠 Analyzes HTML content for common phishing indicators:
  - Suspicious keywords (e.g., `login`, `password`, `secure`)
  - Forms that may be trying to collect credentials
- 📅 Attempts WHOIS lookup for domain age and registrar data (currently throws an exception due to a module bug — see below)

---

## 📸 Example Output

```bash
🔍 Scanning URL: https://www.google.com
[✓] Domain Extracted: google.com
✅ URL is reachable (HTTP 200)
⚠️ Could not retrieve WHOIS info.
✅ HTML content looks clean.
✔️ Scan complete.

🔍 Scanning URL: https://secure-bank-login.com
[✓] Domain Extracted: secure-bank-login.com
❌ Could not reach the URL.

How to run
git clone https://github.com/capalotk/Brainwave_Matrix_Intern.git
cd Brainwave_Matrix_Intern/phishing-scanner-env
pip install -r requirements.txt
python phishing_scanner.py

