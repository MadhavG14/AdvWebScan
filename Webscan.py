import requests
import socket
import dns.resolver
import ssl
import nmap
import subprocess
import os
from urllib.parse import urlparse
from datetime import datetime


# Function to get HTTP Headers
def get_headers(url):
    try:
        response = requests.head(url, allow_redirects=True)
        headers = response.headers
        print("\n[+] HTTP Headers:")
        for header, value in headers.items():
            print(f"{header}: {value}")
    except requests.RequestException as e:
        print(f"[-] Error fetching headers: {e}")


# Function to get IP address of the website
def get_ip_from_url(url):
    try:
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        print(f"\n[+] IP Address of {url}: {ip}")
    except socket.gaierror as e:
        print(f"[-] Error resolving IP: {e}")


# DNS Lookup function
def dns_lookup(url):
    try:
        domain = urlparse(url).netloc
        result = dns.resolver.resolve(domain, 'A')
        print(f"\n[+] DNS A Record for {url}:")
        for ip in result:
            print(ip.to_text())
    except dns.resolver.NoAnswer as e:
        print(f"[-] DNS lookup failed: No A record found.")
    except dns.resolver.NXDOMAIN as e:
        print(f"[-] DNS lookup failed: Domain not found.")
    except Exception as e:
        print(f"[-] DNS lookup error: {e}")


# Function to check HTTPS status
def check_https(url):
    if url.startswith("https://"):
        print("\n[+] HTTPS is enabled on this website.")
    else:
        print("\n[-] HTTPS is not enabled on this website.")


# Function to get SSL/TLS Certificate details
def get_ssl_info(url):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.connect((host, 443))
            cert = s.getpeercert()
            print("\n[+] SSL Certificate Information:")
            print(f"Issuer: {cert['issuer']}")
            print(f"Subject: {cert['subject']}")
            print(f"Certificate Expiry: {cert['notAfter']}")
            print(f"SSL Protocol: {ssl.get_protocol_name(s.version())}")
            print(f"Cipher Suite: {s.cipher()}")
    except Exception as e:
        print(f"[-] Error retrieving SSL certificate info: {e}")


# Function to check for common HTTP security headers
def check_security_headers(url):
    required_headers = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "X-XSS-Protection"
    ]
    
    try:
        response = requests.get(url)
        print("\n[+] HTTP Security Headers:")
        for header in required_headers:
            if header in response.headers:
                print(f"{header}: {response.headers[header]}")
            else:
                print(f"[-] Missing {header} header.")
    except requests.RequestException as e:
        print(f"[-] Error fetching security headers: {e}")


# Subdomain Enumeration using Sublist3r
def subdomain_enum(domain):
    try:
        print("\n[+] Starting subdomain enumeration...")
        result = subprocess.run(["sublist3r", "-d", domain], capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        else:
            print("[-] No subdomains found.")
    except Exception as e:
        print(f"[-] Error running subdomain enumeration: {e}")


# Function to run Nmap scan with customizable switches
def run_nmap_scan(url, custom_switches):
    print("\n[+] Running Nmap Scan...")
    nm = nmap.PortScanner()
    domain = urlparse(url).netloc
    
    try:
        # Perform Nmap scan with custom switches
        nm.scan(domain, '1-1024', arguments=custom_switches)
        print(f"\n[+] Nmap Scan Results for {url}:")
        for proto in nm[domain].all_protocols():
            print(f"\nProtocol: {proto}")
            lport = nm[domain][proto].keys()
            for port in lport:
                print(f"Port: {port} is {nm[domain][proto][port]['state']}")
                print(f"Service: {nm[domain][proto][port]['name']}")
                print(f"Version: {nm[domain][proto][port].get('version', 'N/A')}")
                print(f"Product: {nm[domain][proto][port].get('product', 'N/A')}")
        
        # Run NSE scripts related to exploits or vulnerabilities
        print("\n[+] Running NSE Scripts for Exploits and Vulnerabilities...")
        nm.scan(domain, '1-1024', arguments=f'--script vuln {custom_switches}')
        if 'hostscript' in nm[domain]:
            for script in nm[domain]['hostscript']:
                print(f"Script: {script['id']}")
                print(f"Output: {script['output']}")
    except Exception as e:
        print(f"[-] Error running Nmap scan: {e}")


# Function to perform SQL Injection test
def check_sql_injection(url):
    payload = "' OR '1'='1'; --"
    try:
        response = requests.get(url + f"?id={payload}")
        if "error" in response.text.lower():
            print("\n[-] Potential SQL Injection detected!")
        else:
            print("\n[+] No SQL Injection vulnerability detected.")
    except requests.RequestException as e:
        print(f"[-] Error checking SQL Injection: {e}")


# Function to detect Web Application Firewall (WAF)
def detect_waf(url):
    try:
        result = subprocess.run(["wafw00f", url], capture_output=True, text=True)
        if result.stdout:
            print(f"\n[+] WAF Detected: {result.stdout}")
        else:
            print("\n[-] No WAF detected.")
    except Exception as e:
        print(f"[-] Error detecting WAF: {e}")


# Function to check for Heartbleed vulnerability
def check_heartbleed(url):
    try:
        domain = urlparse(url).netloc
        result = subprocess.run(["testssl.sh", "--heartbleed", f"https://{domain}"], capture_output=True, text=True)
        if "VULNERABLE" in result.stdout:
            print("\n[+] Heartbleed vulnerability detected!")
        else:
            print("\n[+] No Heartbleed vulnerability detected.")
    except Exception as e:
        print(f"[-] Error checking Heartbleed: {e}")


# Main scan function
def run_scan(url, custom_nmap_switches):
    print(f"\n[+] Starting scan for: {url}")
    
    # Header check
    get_headers(url)
    
    # IP address check
    get_ip_from_url(url)
    
    # DNS lookup
    dns_lookup(url)
    
    # HTTPS check
    check_https(url)
    
    # SSL/TLS certificate check
    get_ssl_info(url)
    
    # HTTP Security Headers check
    check_security_headers(url)
    
    # Subdomain enumeration
    domain = urlparse(url).netloc
    subdomain_enum(domain)
    
    # Run Nmap scan with custom switches
    run_nmap_scan(url, custom_nmap_switches)
    
    # SQL Injection test
    check_sql_injection(url)
    
    # Detect WAF
    detect_waf(url)
    
    # Heartbleed test
    check_heartbleed(url)


# Driver code
if __name__ == "__main__":
    url = input("Enter the website URL to scan (e.g., https://example.com): ")
    custom_nmap_switches = input("Enter custom Nmap switches (e.g., -sV --script=vuln): ")

    if not url.startswith("http"):
        url = "http://" + url  # Default to HTTP if no scheme is provided
    
    run_scan(url, custom_nmap_switches)
