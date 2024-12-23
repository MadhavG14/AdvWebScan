# AdvWebScan

<B>THIS IS HIGHLY ADVANCED TOOL FOR WEB SCANNING (PORTS, VULNERABLITIES, EXPLOITS, ETC.)</B>

<B> INSTALL DEPENDENCIES WITH THE FOLLOWING COMMANDS:

pip install requests dnspython ssl nmap subprocess WAFW00F </B>

<b> IF U FIND ERROR WHILE INSTALLING USE sudo apt install <module_name> </b> 

USE IT FOR RESEARCH PURPOSES ONLY !!!

<b> EXAMPLE </b>

Enter the website URL to scan (e.g., https://example.com): https://example.com
Enter custom Nmap switches (e.g., -sV --script=vuln): -sV --script=vuln

[+] Starting scan for: https://example.com

[+] HTTP Headers:
Server: Apache
Content-Type: text/html; charset=UTF-8
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-XSS-Protection: 1; mode=block

[+] IP Address of https://example.com: 93.184.216.34

[+] DNS A Record for https://example.com:
93.184.216.34

[+] HTTPS is enabled on this website.

[+] SSL Certificate Information:
Issuer: /C=US/O=Let's Encrypt/CN=R3
Subject: /CN=example.com
Certificate Expiry: Dec 30 23:59:59 2024 GMT
SSL Protocol: TLSv1.3
Cipher Suite: ('TLS_AES_128_GCM_SHA256',)
 
[+] HTTP Security Headers:
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
X-XSS-Protection: 1; mode=block

[+] Starting subdomain enumeration...
www.example.com
mail.example.com
api.example.com

[+] Running Nmap Scan...

Protocol: tcp
Port: 80 is open
Service: http
Version: Apache httpd 2.4.41
Product: Apache httpd
Port: 443 is open
Service: https
Version: Apache httpd 2.4.41
Product: Apache httpd

[+] Running NSE Scripts for Exploits and Vulnerabilities...
Script: http-vuln-cve2014-0224
Output: Vulnerable to CVE-2014-0224: SSL/TLS padding oracle attack
Script: ssl-heartbleed
Output: No vulnerability found for Heartbleed.

[+] SQL Injection Test:
[-] Potential SQL Injection detected!

[+] Detecting WAF...
[+] WAF Detected: Cloudflare WAF

[+] Heartbleed Test:
[+] No Heartbleed vulnerability detected.

[+] Nmap Scan Completed
