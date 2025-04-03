aaayafuj_hacking_info_of_3.sh – A Powerful Information Gathering Tool
This script is designed for ethical hacking, penetration testing, and cybersecurity research. 
It combines multiple scanning and reconnaissance tools to extract valuable information about 
IP addresses, domains, emails, and vulnerabilities.

🔥 Features of aaayafuj_hacking_info_of_3.sh
* Network & Host Scanning: Uses nmap for deep network analysis.
* DNS & Whois Lookup: Collects domain/IP information from public databases.
* Email Investigation: Searches for public records associated with an email.
* GeoIP & Reverse Lookup: Finds geographical locations and associated domains.
* Vulnerability Analysis: Identifies known vulnerabilities in a target system.
* Automated Execution: Runs multiple commands in one script for efficiency.

🚀 Full Script: aaayafuj_hacking_info_of_3.sh
bash
Copy
Edit
#!/bin/bash

# Check if argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <IP-ADDRESS or DOMAIN or EMAIL>"
    exit 1
fi

TARGET=$1

echo "==============================="
echo "🔍 Running aaayafuj Hacking Info Tool"
echo "📌 Target: $TARGET"
echo "==============================="

# 1️⃣ Basic Network Scan
echo "[+] Running Basic Network Scan..."
nmap -Pn $TARGET > results/nmap_basic.txt

# 2️⃣ Aggressive Network Scan (Detailed)
echo "[+] Running Aggressive Scan..."
nmap -A $TARGET > results/nmap_aggressive.txt

# 3️⃣ Port Scan (Common Ports)
echo "[+] Scanning Specific Ports (22, 80, 443, 3389)..."
nmap -p 22,80,443,3389 $TARGET > results/nmap_ports.txt

# 4️⃣ Full Port Scan (All 65535 ports)
echo "[+] Running Full Port Scan..."
nmap -p- $TARGET > results/nmap_full_ports.txt

# 5️⃣ Vulnerability Scan
echo "[+] Running Vulnerability Scan..."
nmap --script vuln $TARGET > results/nmap_vuln.txt

# 6️⃣ WHOIS Lookup
echo "[+] Running WHOIS Lookup..."
whois $TARGET > results/whois.txt

# 7️⃣ DNS Lookup
echo "[+] Performing DNS Lookup..."
dig $TARGET ANY > results/dns_info.txt

# 8️⃣ Reverse DNS Lookup
echo "[+] Performing Reverse DNS Lookup..."
host $TARGET > results/reverse_dns.txt

# 9️⃣ IP Geolocation
echo "[+] Fetching Geolocation Data..."
curl -s "https://ipwhois.app/json/$TARGET" | jq > results/geoip.json

# 🔟 Traceroute for Network Path
echo "[+] Running Traceroute..."
traceroute $TARGET > results/traceroute.txt

# 1️⃣1️⃣ Reverse Email Lookup (if target is an email)
if [[ "$TARGET" == *"@"* ]]; then
    echo "[+] Performing Reverse Email Lookup..."
    curl -s "https://emailrep.io/$TARGET" | jq > results/email_lookup.json
fi

# 1️⃣2️⃣ Searching for Open-Source Intelligence (OSINT)
echo "[+] Checking Publicly Available Data..."
curl -s "https://api.hackertarget.com/reversedns/?q=$TARGET" > results/osint.txt

# 1️⃣3️⃣ Checking Security Reports
echo "[+] Checking Security Trails..."
curl -s "https://api.securitytrails.com/v1/ip/$TARGET" -H "API_KEY: YOUR_SECURITY_TRAILS_API_KEY" > results/security_trails.json

# 1️⃣4️⃣ Scan for WAF Protection
echo "[+] Checking for Web Application Firewall (WAF)..."
wafw00f $TARGET > results/waf_detection.txt

# 1️⃣5️⃣ Full System Fingerprint (Aggressive)
echo "[+] Running Full System Fingerprinting..."
nmap -sV -A $TARGET > results/system_fingerprint.txt

echo "==============================="
echo "🎯 Scan Completed! Results saved in 'results/' directory"
echo "==============================="
🛠 How to Use?
1️⃣ Save the script as aaayafuj_hacking_info_of_3.sh
2️⃣ Make it executable:

bash
chmod +x aaayafuj_hacking_info_of_3.sh
3️⃣ Run the script with an IP, domain, or email:

bash
./aaayafuj_hacking_info_of_3.sh <TARGET>
 Replace <TARGET> with:

* IP Address (e.g., 192.168.1.1)
. Domain (e.g., example.com)
. Email (e.g., user@gmail.com)

🗂 What Does It Do?
*Runs multiple Nmap scans to detect open ports, vulnerabilities, and services.
*Performs WHOIS & DNS lookups to get domain/IP registration details.
*Fetches geolocation & OSINT data from public databases.
*Detects web application firewalls (WAFs).
*Checks for security threats using public APIs.

💀 Warning & Ethical Considerations
🚨 Only use this tool for authorized penetration testing.
🚨 Scanning unauthorized targets is illegal.
🚨 Always get permission before running tests on external systems.

🌍 Who Can Use This?
*Ethical Hackers & Pentesters – Reconnaissance and information gathering.
*Security Researchers – Finding vulnerabilities in systems.
*Network Administrators – Checking network exposure and security.
*Bug Bounty Hunters – Gathering intel for responsible disclosure.

🔗 Additional Enhancements
📌 Integrate more OSINT tools like theHarvester and Shodan.
📌 Add automatic reporting to generate a summary file.
📌 Automate API calls to collect more real-time data.

