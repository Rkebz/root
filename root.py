import os
import requests
import pyfiglet
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Print the banner with pyfiglet
ascii_banner = pyfiglet.figlet_format("Mr.root Tools")
print(Fore.CYAN + ascii_banner)

# Function to check for IDOR vulnerability
def check_idor(url):
    print(Fore.YELLOW + "[*] Checking for IDOR on the URL:", url)
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(Fore.GREEN + f"[+] IDOR vulnerability found in: {url}")
        else:
            print(Fore.RED + "[-] No IDOR found")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + "[-] Connection failed:", e)

# Function to check for SQL Injection vulnerability
def check_sql_injection(url):
    print(Fore.YELLOW + "[*] Checking for SQL Injection on the URL:", url)
    payloads = ["' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT null--"]
    for payload in payloads:
        try:
            test_url = url + payload
            response = requests.get(test_url)
            if "error" in response.text or "SQL syntax" in response.text:
                print(Fore.GREEN + f"[+] SQL Injection found in {url} with payload: {payload}")
                print(Fore.GREEN + f"Vulnerable path: {test_url}")
                return
        except requests.exceptions.RequestException as e:
            print(Fore.RED + "[-] Connection failed:", e)
    print(Fore.RED + "[-] No SQL Injection found")

# Function to check for XSS vulnerability
def check_xss(url):
    print(Fore.YELLOW + "[*] Checking for XSS on the URL:", url)
    payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(1)">']
    for payload in payloads:
        try:
            test_url = url + payload
            response = requests.get(test_url)
            if payload in response.text:
                print(Fore.GREEN + f"[+] XSS found in {url} with payload: {payload}")
                print(Fore.GREEN + f"Vulnerable path: {test_url}")
                return
        except requests.exceptions.RequestException as e:
            print(Fore.RED + "[-] Connection failed:", e)
    print(Fore.RED + "[-] No XSS found")

# Main function to read the URLs from the file and scan them
def main():
    file_path = input(Fore.CYAN + "Enter the path to the list file (list.txt): ").strip()
    if not os.path.exists(file_path):
        print(Fore.RED + "The file does not exist!")
        return

    with open(file_path, "r") as file:
        urls = file.readlines()
        
    print(Fore.CYAN + "[*] Starting the scan for all sites in the list...")
    
    for url in urls:
        url = url.strip()
        if url:
            print(Fore.CYAN + f"\n[*] Scanning site: {url}")
            check_idor(url)
            check_sql_injection(url)
            check_xss(url)

if __name__ == "__main__":
    main()
