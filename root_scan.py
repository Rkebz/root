import os
import time
import requests
from tqdm import tqdm
from termcolor import colored
from prettytable import PrettyTable
from colorama import init
import pyfiglet
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

# Initialize colorama
init(autoreset=True)

# Display welcome message using pyfiglet for large text
def show_welcome_message():
    os.system('clear' if os.name == 'posix' else 'cls')  # Clear terminal screen

    # Create the banner with pyfiglet
    welcome_message = pyfiglet.figlet_format("Tools Mr.root", font="slant")
    print(colored(welcome_message, "cyan"))

    # Wait for 5 seconds before starting
    time.sleep(5)

    # Clear the screen
    os.system('clear' if os.name == 'posix' else 'cls')

# Load data from file
def load_file(filename):
    if not os.path.exists(filename):
        print(colored(f"File '{filename}' not found!", "red"))
        return []
    with open(filename, "r") as file:
        return [line.strip() for line in file if line.strip()]

# Inject payload into a URL
def inject_payload(url, param, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if param in query_params:
        query_params[param] = payload
    modified_query = urlencode(query_params, doseq=True)
    modified_url = urlunparse(parsed_url._replace(query=modified_query))
    return modified_url

# Test a URL with a payload
def test_vulnerability(url, payload):
    test_url = url + payload if '?' not in url else inject_payload(url, list(parse_qs(urlparse(url).query).keys())[0], payload)
    try:
        response = requests.get(test_url, timeout=5)
        if response.status_code == 200 and (
            "sql" in response.text.lower() or 
            "syntax error" in response.text.lower() or
            "alert" in response.text.lower()
        ):
            return True, test_url
    except Exception:
        pass
    return False, None

# Scan for vulnerabilities
def scan_vulnerabilities(base_url, paths, payloads):
    results_table = PrettyTable()
    results_table.field_names = ["URL", "Payload", "Status"]
    results_table.align = "l"

    for path in paths:
        full_url = urljoin(base_url, path)
        for payload in payloads:
            is_vulnerable, vulnerable_url = test_vulnerability(full_url, payload)
            if is_vulnerable:
                results_table.add_row([colored(full_url, "green"), payload, colored("Vulnerable", "green")])
                print(colored(f"[+] Found vulnerability: {vulnerable_url} (Payload: {payload})", "green"))
            else:
                results_table.add_row([full_url, payload, colored("Not Vulnerable", "red")])

    return results_table

# Main function
def main():
    show_welcome_message()

    # Request base URL
    base_url = input("Enter the base URL (e.g., https://example.com): ").strip()
    if not base_url.startswith("http"):
        print(colored("Invalid URL. Please include http:// or https://", "red"))
        return

    # Load paths and payloads
    paths_sql = load_file("paths_sql.txt")
    paths_xss = load_file("paths_xxss.txt")
    sql_payloads = load_file("payloads_sql.txt")
    xss_payloads = load_file("payloads_xss.txt")

    if not paths_sql or not paths_xss or not sql_payloads or not xss_payloads:
        print(colored("One or more files are missing. Make sure paths and payloads are in the correct files.", "red"))
        return

    # Scan for SQL Injection vulnerabilities
    print("\n[+] Scanning for SQL Injection...")
    sql_results = scan_vulnerabilities(base_url, paths_sql, sql_payloads)

    # Scan for XSS vulnerabilities
    print("\n[+] Scanning for XSS...")
    xss_results = scan_vulnerabilities(base_url, paths_xss, xss_payloads)

    # Display results
    print("\nSQL Injection Results:")
    print(sql_results)
    print("\nXSS Results:")
    print(xss_results)

if __name__ == "__main__":
    main()
