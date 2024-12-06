import requests
import pyfiglet
from termcolor import colored
from tabulate import tabulate

# Define payloads for the vulnerabilities
sql_injection_payloads = ["' OR 1=1 --", "' OR 'a'='a", "1' OR 'a'='a", "1' OR 1=1"]
xss_payloads = ['<script>alert(1)</script>', '<img src="x" onerror="alert(1)">']
idor_payloads = ['/admin', '/config', '/user/profile']

# Function to print the Mr.root banner
def print_banner():
    ascii_banner = pyfiglet.figlet_format("Mr.root")
    print(colored(ascii_banner, 'cyan'))

# Function to test SQL Injection
def test_sql_injection(url):
    results = []
    for payload in sql_injection_payloads:
        response = requests.get(url + payload)
        if "error" in response.text or "syntax" in response.text or response.status_code == 500:
            results.append(("SQL Injection", url, payload, url + payload))
    return results

# Function to test XSS
def test_xss(url):
    results = []
    for payload in xss_payloads:
        response = requests.get(url + payload)
        if payload in response.text:
            results.append(("XSS", url, payload, url + payload))
    return results

# Function to test IDOR
def test_idor(url):
    results = []
    for payload in idor_payloads:
        response = requests.get(url + payload)
        if response.status_code == 200:
            results.append(("IDOR", url, payload, url + payload))
    return results

# Function to scan the website
def scan_website(url):
    results = []
    print(colored(f"Scanning {url}...", 'blue'))
    results.extend(test_sql_injection(url))
    results.extend(test_xss(url))
    results.extend(test_idor(url))
    return results

# Main function to scan websites from the list
def main():
    print_banner()
    # Ask for the name of the list file
    list_filename = input(colored("Enter the name of the list file (e.g., list.txt): ", 'yellow'))

    try:
        with open(list_filename, "r") as file:
            urls = file.readlines()

        all_results = []
        for url in urls:
            url = url.strip()
            # Ensure the URL starts with http:// or https://
            if not url.startswith("http"):
                url = "http://" + url
            results = scan_website(url)
            all_results.extend(results)

        if all_results:
            # Print results in a table
            headers = ["Vulnerability", "Website", "Payload", "Path"]
            table = tabulate(all_results, headers, tablefmt="grid", numalign="center", stralign="center")
            print(colored(table, 'green'))
        else:
            print(colored("No vulnerabilities found.", 'green'))
    except FileNotFoundError:
        print(colored(f"Error: The file '{list_filename}' was not found!", 'red'))

# Run the script
if __name__ == "__main__":
    main()
