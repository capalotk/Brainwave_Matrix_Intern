import requests
import validators
import tldextract
import whois
from bs4 import BeautifulSoup
from datetime import datetime

# Suspicious keywords often used in phishing URLs
suspicious_url_keywords = ['login', 'verify', 'account', 'update', 'secure', 'bank', 'billing']
suspicious_html_keywords = ['password', 'credit card', 'login', 'signin', 'verify your identity']

def is_suspicious_url(url):
    return any(word in url.lower() for word in suspicious_url_keywords)

def fetch_whois_info(domain):
    try:
        w = whois.whois(domain)
        print("[DEBUG] Raw WHOIS data:", w)  # debug print to inspect raw data
        if w.domain_name:
            return w
        else:
            return None
    except Exception as e:
        print(f"[DEBUG] WHOIS exception: {e}")
        return None

def get_domain_age(whois_data):
    creation_date = whois_data.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if creation_date and isinstance(creation_date, datetime):
        age = (datetime.now() - creation_date).days
        return age
    return None

def fetch_html_content(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=5)
        return response.text if response.status_code == 200 else None
    except:
        return None

def scan_for_html_keywords(html):
    if not html:
        return []
    soup = BeautifulSoup(html, 'html.parser')
    text = soup.get_text().lower()
    return [kw for kw in suspicious_html_keywords if kw in text]

def display_whois_info(w):
    def safe_str(value):
        if value is None:
            return "N/A"
        if isinstance(value, list):
            return ', '.join(str(v) for v in value)
        return str(value)

    print("\n--- WHOIS Information ---")
    print(f"Domain Name    : {safe_str(w.domain_name)}")
    print(f"Registrar      : {safe_str(w.registrar)}")
    print(f"Creation Date  : {safe_str(w.creation_date)}")
    print(f"Expiration Date: {safe_str(w.expiration_date)}")
    print(f"Name Servers   : {safe_str(w.name_servers)}")
    print(f"Status         : {safe_str(w.status)}")

def scan_url(url):
    print(f"\n🔍 Scanning URL: {url}")

    if not validators.url(url):
        print("❌ Invalid URL.")
        return

    domain_info = tldextract.extract(url)
    domain = f"{domain_info.domain}.{domain_info.suffix}"
    print(f"[✓] Domain Extracted: {domain}")

    # Check reachability
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print("✅ URL is reachable (HTTP 200).")
        else:
            print(f"⚠️ URL returned status code: {response.status_code}")
            return
    except Exception:
        print("❌ Could not reach the URL.")
        return

    # Suspicious keyword in URL
    if is_suspicious_url(url):
        print("⚠️ URL contains suspicious keywords.")

    # Fetch WHOIS info once and reuse
    whois_data = fetch_whois_info(domain)
    if whois_data is None:
        print("⚠️ Could not retrieve WHOIS info.")
    else:
        # Domain age check
        age = get_domain_age(whois_data)
        if age is None:
            print("⚠️ Could not determine domain age.")
        elif age < 90:
            print(f"⚠️ Domain is newly registered ({age} days old).")
        else:
            print(f"ℹ️ Domain is {age} days old.")

        # Display WHOIS details
        display_whois_info(whois_data)

    # HTML content analysis
    html = fetch_html_content(url)
    suspicious_terms = scan_for_html_keywords(html)
    if suspicious_terms:
        print(f"⚠️ HTML contains suspicious terms: {', '.join(suspicious_terms)}")
    else:
        print("✅ HTML content looks clean.")

    print("\n✅ Scan complete.\n")

if __name__ == "__main__":
    user_url = input("Enter a URL to scan: ").strip()
    scan_url(user_url)
