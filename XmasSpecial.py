import requests
import socket
import dns.resolver
import ssl
import subprocess
from urllib.parse import urlparse
from datetime import datetime
from colorama import Fore, Style
import pyfiglet
import ascii_magic
import os
from playsound import playsound
from pwn import *
import nmap


def display_banner():
    """Display Christmas-themed ASCII art banner"""
    banner = pyfiglet.figlet_format("Merry Pentesting!")
    print(Fore.RED + banner + Style.RESET_ALL)
    print(Fore.GREEN + "⛄ Welcome to the Christmas Edition of the Advanced Pentesting Tool! 🎄" + Style.RESET_ALL)
    print(Fore.YELLOW + "Let's unwrap vulnerabilities! 🎁" + Style.RESET_ALL)


def play_christmas_sound():
    """Play a Christmas jingle"""
    try:
        playsound("jingle_bells.mp3")
    except Exception:
        print(Fore.RED + "[!] Unable to play sound. Ensure the file 'jingle_bells.mp3' is in the same directory." + Style.RESET_ALL)


def get_headers(url):
    """Retrieve and display HTTP headers"""
    try:
        response = requests.head(url, allow_redirects=True)
        headers = response.headers
        print(Fore.GREEN + "\n🎄 [HTTP Headers] 🎄" + Style.RESET_ALL)
        for header, value in headers.items():
            print(f"{Fore.CYAN}{header}: {value}{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[-] Error fetching headers: {e}{Style.RESET_ALL}")


def get_ip_from_url(url):
    """Resolve the IP address of the given URL"""
    try:
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"\n🎁 IP Address of {url}: {ip}" + Style.RESET_ALL)
        return ip
    except socket.gaierror as e:
        print(Fore.RED + f"[-] Error resolving IP: {e}" + Style.RESET_ALL)
        return None


def dns_lookup(url):
    """Perform DNS lookup"""
    try:
        domain = urlparse(url).netloc
        result = dns.resolver.resolve(domain, 'A')
        print(Fore.GREEN + f"\n🎄 DNS A Record for {url}: 🎄" + Style.RESET_ALL)
        for ip in result:
            print(f"{Fore.CYAN}{ip.to_text()}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] DNS lookup error: {e}{Style.RESET_ALL}")


def nmap_scan(target_ip, custom_args):
    """Perform an Nmap scan"""
    try:
        print(Fore.GREEN + f"\n🎁 Running Nmap Scan on {target_ip}... 🎁" + Style.RESET_ALL)
        nmap_output = subprocess.run(["nmap", target_ip] + custom_args.split(), capture_output=True, text=True)
        print(Fore.CYAN + nmap_output.stdout + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Nmap scan error: {e}{Style.RESET_ALL}")


def detect_waf(url):
    """Detect Web Application Firewall"""
    try:
        print(Fore.GREEN + f"\n🎄 Checking for WAF... 🎄" + Style.RESET_ALL)
        waf_output = subprocess.run(["wafw00f", url], capture_output=True, text=True)
        print(Fore.CYAN + waf_output.stdout + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Error detecting WAF: {e}{Style.RESET_ALL}")


def generate_html_report(url, headers, ip, dns_records):
    """Generate a Christmas-themed HTML report"""
    report = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>🎄 Christmas Pentesting Report 🎄</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f9; color: #333; }}
            h1, h2 {{ color: #d9534f; }}
            h1 {{ text-align: center; }}
            .header {{ background-color: #5bc0de; padding: 20px; text-align: center; }}
            .content {{ margin: 20px; padding: 10px; }}
            .section {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🎄 Christmas Pentesting Report 🎄</h1>
            <p>Generated for: {url}</p>
            <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        <div class="content">
            <div class="section">
                <h2>HTTP Headers</h2>
                <pre>{headers}</pre>
            </div>
            <div class="section">
                <h2>IP Address</h2>
                <p>{ip}</p>
            </div>
            <div class="section">
                <h2>DNS Records</h2>
                <pre>{dns_records}</pre>
            </div>
        </div>
    </body>
    </html>
    """
    with open("pentest_report.html", "w") as f:
        f.write(report)
    print(Fore.GREEN + "\n🎄 Report saved as 'pentest_report.html' 🎄" + Style.RESET_ALL)


def main():
    """Main pentesting function with Christmas effects"""
    display_banner()
    play_christmas_sound()
    
    url = input("Enter the website URL to scan (e.g., https://example.com): ")
    custom_nmap_args = input("Enter custom Nmap switches (e.g., -sV --script=vuln): ")

    # HTTP Headers
    get_headers(url)
    
    # Resolve IP
    ip = get_ip_from_url(url)
    
    # DNS Lookup
    dns_lookup(url)
    
    # WAF Detection
    detect_waf(url)
    
    # Nmap Scan
    if ip:
        nmap_scan(ip, custom_nmap_args)

    # Generate HTML Report
    headers = "See terminal output"
    dns_records = "See terminal output"
    generate_html_report(url, headers, ip, dns_records)


if __name__ == "__main__":
    main()