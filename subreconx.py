import os
import requests
import shutil
import dns.resolver
from colorama import Fore, Style, init
import pyfiglet
import subprocess

# Initialize Colorama
init(autoreset=True)

# Replace with your actual API keys
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
SECURITYTRAILS_API_KEY = "your_securitytrails_api_key"
SHODAN_API_KEY = "your_shodan_api_key"
CERTSPOTTER_API_KEY = "your_certs"

# Tools to check
TOOLS = {
    "amass": "apt-get install amass -y",
    "subfinder": "apt-get install subfinder -y",
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "subzy": "go install github.com/LukaSikic/subzy@latest"
}

# Banner using pyfiglet
def print_banner():
    banner = pyfiglet.figlet_format("SubReconX")
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print(Fore.YELLOW + "                Created by Mr. Pyth0n\n" + Style.RESET_ALL)

# Check and install missing tools
def check_and_install_tools():
    missing_tools = [tool for tool in TOOLS if not shutil.which(tool)]
    if missing_tools:
        print(Fore.RED + "[!] Missing tools: " + ", ".join(missing_tools) + Style.RESET_ALL)
        for tool in missing_tools:
            print(Fore.YELLOW + f"[*] Installing {tool}..." + Style.RESET_ALL)
            try:
                command = TOOLS[tool]
                subprocess.run(command, shell=True, check=True)
                print(Fore.GREEN + f"[+] Successfully installed {tool}." + Style.RESET_ALL)
            except subprocess.CalledProcessError:
                print(Fore.RED + f"[!] Failed to install {tool}. Please install it manually." + Style.RESET_ALL)
        print(Fore.YELLOW + "Please verify installation of missing tools before re-running the script." + Style.RESET_ALL)
        exit(1)

# VirusTotal API
def passive_enum_virustotal(domain):
    print(Fore.CYAN + "[*] Enumerating subdomains via VirusTotal..." + Style.RESET_ALL)
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    subdomains = []
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            subdomains = [item["id"] for item in data.get("data", [])]
            print(Fore.GREEN + f"[+] VirusTotal found {len(subdomains)} subdomains." + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[!] VirusTotal API error: {response.status_code}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Error connecting to VirusTotal: {e}" + Style.RESET_ALL)
    return subdomains

# SecurityTrails API
def passive_enum_securitytrails(domain):
    print(Fore.CYAN + "[*] Enumerating subdomains via SecurityTrails..." + Style.RESET_ALL)
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    subdomains = []
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            subdomains = [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
            print(Fore.GREEN + f"[+] SecurityTrails found {len(subdomains)} subdomains." + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[!] SecurityTrails API error: {response.status_code}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Error connecting to SecurityTrails: {e}" + Style.RESET_ALL)
    return subdomains

# Shodan API
def passive_enum_shodan(domain):
    print(Fore.CYAN + "[*] Enumerating subdomains via Shodan..." + Style.RESET_ALL)
    url = f"https://api.shodan.io/dns/domain/{domain}?key={SHODAN_API_KEY}"
    subdomains = []
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if "subdomains" in data:
                subdomains = [f"{sub}.{domain}" for sub in data["subdomains"]]
                print(Fore.GREEN + f"[+] Shodan found {len(subdomains)} subdomains." + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "[!] No subdomains found in Shodan response." + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[!] Shodan API error: {response.status_code}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Error connecting to Shodan: {e}" + Style.RESET_ALL)
    return subdomains

# CertSpotter API
def passive_enum_certspotter(domain):
    print(Fore.CYAN + "[*] Enumerating subdomains via CertSpotter..." + Style.RESET_ALL)
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true"
    headers = {"Authorization": f"Bearer {CERTSPOTTER_API_KEY}"}
    subdomains = []
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                dns_names = entry.get("dns_names", [])
                if dns_names:
                    subdomains.extend(dns_names)
            print(Fore.GREEN + f"[+] CertSpotter found {len(subdomains)} subdomains." + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[!] CertSpotter API error: {response.status_code}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Error connecting to CertSpotter: {e}" + Style.RESET_ALL)
    return subdomains

# Check if subdomains are live
def check_live_subdomains(subdomains):
    print(Fore.MAGENTA + "\n[***] Checking live subdomains..." + Style.RESET_ALL)
    live_subdomains = []
    for subdomain in subdomains:
        try:
            response = requests.get(f"http://{subdomain}", timeout=5)
            if response.status_code == 200:
                print(Fore.GREEN + f"[+] Live: {subdomain}" + Style.RESET_ALL)
                live_subdomains.append(subdomain)
        except requests.RequestException:
            print(Fore.RED + f"[-] Dead: {subdomain}" + Style.RESET_ALL)
    return live_subdomains

# Check for subdomain takeover vulnerabilities using Subzy
def check_subdomain_takeover(live_subdomains):
    print(Fore.MAGENTA + "\n[***] Checking for Subdomain Takeover Vulnerabilities..." + Style.RESET_ALL)
    takeover_vulnerabilities = []
    try:
        with open("live_subdomains.txt", "w") as f:
            f.write("\n".join(live_subdomains))
        command = "subzy --targets live_subdomains.txt --verify"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout
        if "Vulnerable:" in output:
            vulnerabilities = [line for line in output.splitlines() if "Vulnerable:" in line]
            takeover_vulnerabilities.extend(vulnerabilities)
            print(Fore.GREEN + f"[+] Found {len(vulnerabilities)} subdomains vulnerable to takeover." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[+] No subdomain takeover vulnerabilities found." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Error running Subzy: {e}" + Style.RESET_ALL)
    return takeover_vulnerabilities

# Main function
def main():
    os.system("clear")  # Clear terminal screen
    print_banner()
    check_and_install_tools()

    print(Fore.YELLOW + "=== Welcome to SubReconX ===" + Style.RESET_ALL)
    domain = input(Fore.BLUE + "Enter the target domain (e.g., example.com): " + Style.RESET_ALL).strip()
    all_subdomains = set()

    # Passive enumeration
    print(Fore.MAGENTA + "\n[***] Starting Passive Enumeration..." + Style.RESET_ALL)
    all_subdomains.update(passive_enum_virustotal(domain))
    all_subdomains.update(passive_enum_securitytrails(domain))
    all_subdomains.update(passive_enum_shodan(domain))  # No TypeError
    all_subdomains.update(passive_enum_certspotter(domain))

    # Active enumeration tools
    print(Fore.MAGENTA + "\n[***] Running Active Subdomain Enumeration Tools..." + Style.RESET_ALL)
    commands = {
        "amass": f"amass enum -d {domain} -o amass.txt",
        "subfinder": f"subfinder -d {domain} -o subfinder.txt >/dev/null 2>&1",
        "assetfinder": f"assetfinder {domain} > assetfinder.txt"
    }

    for tool, command in commands.items():
        print(Fore.CYAN + f"[*] Running {tool}..." + Style.RESET_ALL)
        try:
            subprocess.run(command, shell=True, check=True)
            with open(f"{tool}.txt", "r") as f:
                all_subdomains.update(f.read().splitlines())
            os.remove(f"{tool}.txt")
        except subprocess.CalledProcessError:
            print(Fore.RED + f"[!] {tool} failed. Please check your installation." + Style.RESET_ALL)

    # Save results
    output_file = f"{domain}_subdomains.txt"
    with open(output_file, "w") as f:
        f.write("\n".join(sorted(all_subdomains)))

    print(Fore.CYAN + f"\n[+] Subdomain enumeration completed. Results saved to: {output_file}" + Style.RESET_ALL)

    # Check live subdomains
    live_subdomains = check_live_subdomains(all_subdomains)
    live_output_file = f"{domain}_live_subdomains.txt"
    with open(live_output_file, "w") as f:
        f.write("\n".join(sorted(live_subdomains)))

    print(Fore.CYAN + f"\n[+] Live subdomains saved to: {live_output_file}" + Style.RESET_ALL)

    # Check for subdomain takeover
    check_subdomain_takeover(live_subdomains)

if __name__ == "__main__":
    main()
