import os
import subprocess
import pyfiglet
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Function to check if the script is running as root
def check_root():
    if os.geteuid() != 0:
        print(Fore.RED + "[*] This script requires root privileges. Please run it as root (sudo).")
        exit(1)
    else:
        print(Fore.GREEN + "[*] Running with root privileges...")

# Function to check for SQL Injection using SQLMap
def check_sql_injection(url):
    print(Fore.YELLOW + "[*] Checking for SQL Injection on the URL:", url)
    try:
        result = subprocess.run(['sqlmap', '-u', url, '--batch', '--risk=3', '--level=5'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "available databases" in result.stdout:
            print(Fore.GREEN + f"[+] SQL Injection vulnerability found in {url}")
            print(Fore.GREEN + f"Vulnerable path: {url}")
            print(Fore.GREEN + "Result:\n" + result.stdout)
        else:
            print(Fore.RED + "[-] No SQL Injection found")
    except Exception as e:
        print(Fore.RED + "[-] Error with SQLMap:", e)

# Function to check for XSS using XSSer
def check_xss(url):
    print(Fore.YELLOW + "[*] Checking for XSS on the URL:", url)
    try:
        result = subprocess.run(['xsser', '--url', url, '--batch'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "XSS payloads" in result.stdout:
            print(Fore.GREEN + f"[+] XSS vulnerability found in {url}")
            print(Fore.GREEN + f"Vulnerable path: {url}")
            print(Fore.GREEN + "Result:\n" + result.stdout)
        else:
            print(Fore.RED + "[-] No XSS found")
    except Exception as e:
        print(Fore.RED + "[-] Error with XSSer:", e)

# Function to check for Directory Traversal (IDOR) using DirBuster
def check_idor(url):
    print(Fore.YELLOW + "[*] Checking for IDOR on the URL:", url)
    try:
        result = subprocess.run(['dirbuster', '-u', url, '-t', '100', '-w', '/path/to/wordlist'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "found" in result.stdout:
            print(Fore.GREEN + f"[+] IDOR vulnerability found in {url}")
            print(Fore.GREEN + f"Vulnerable path: {url}")
            print(Fore.GREEN + "Result:\n" + result.stdout)
        else:
            print(Fore.RED + "[-] No IDOR found")
    except Exception as e:
        print(Fore.RED + "[-] Error with DirBuster:", e)

# Main function to read the URLs from the file and scan them
def main():
    check_root()  # Check if the script is running as root

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
            check_sql_injection(url)
            check_xss(url)
            check_idor(url)

if __name__ == "__main__":
    main()
