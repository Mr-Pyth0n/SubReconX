# SubReconX

SubReconX is a powerful Python-based subdomain enumeration and reconnaissance tool designed for bug bounty hunters, penetration testers, and security researchers. It integrates passive and active enumeration techniques to provide a comprehensive list of subdomains, including checks for live subdomains and potential subdomain takeover vulnerabilities.

```
 ____        _     ____                     __  __
/ ___| _   _| |__ |  _ \ ___  ___ ___  _ __ \ \/ /
\___ \| | | | '_ \| |_) / _ \/ __/ _ \| '_ \ \  /
 ___) | |_| | |_) |  _ <  __/ (_| (_) | | | |/  \
|____/ \__,_|_.__/|_| \_\___|\___\___/|_| |_/_/\_\


                Created by Mr. Pyth0n

=== Welcome to SubReconX ===
Enter the target domain (e.g., example.com): hackertarget.com
```


## Features

### 1. **Passive Subdomain Enumeration**
   - **VirusTotal**: Utilizes the VirusTotal API to enumerate subdomains.
   - **SecurityTrails**: Leverages the SecurityTrails API for subdomain discovery.
   - **Shodan**: Extracts subdomains using Shodan's DNS domain search API.
   - **CertSpotter**: Identifies subdomains by querying SSL certificate transparency logs.
   - Automatically handles API errors, rate limits, and invalid API key issues.

### 2. **Active Subdomain Enumeration**
   - Uses multiple tools for active subdomain discovery:
     - **Amass**: Performs OSINT-based reconnaissance and DNS enumeration.
     - **Subfinder**: Efficiently discovers subdomains from various sources.
     - **Assetfinder**: Gathers subdomains using a variety of passive sources.
   - Aggregates the results from all tools into one final subdomain list.

### 3. **Live Subdomain Detection**
   - Verifies which discovered subdomains are live by sending HTTP requests.
   - Filters out dead subdomains to focus on active targets.

### 4. **Subdomain Takeover Detection**
   - Integrates with **Subzy** to check for subdomain takeover vulnerabilities.
   - Identifies subdomains that may be vulnerable to takeover and provides detailed output.

### 5. **Automated Tool Installation**
   - Automatically checks for missing tools (`amass`, `subfinder`, `assetfinder`, `subzy`).
   - Installs missing dependencies using package managers or Go install commands.

### 6. **Customizable**
   - Allows integration of API keys for VirusTotal, SecurityTrails, Shodan, and CertSpotter.
   - Customizable timeout settings and configuration options for tools.

### 7. **Clean and Organized Output**
   - Outputs discovered subdomains to a file (`<domain>_subdomains.txt`).
   - Generates a separate file for live subdomains (`<domain>_live_subdomains.txt`).
   - Color-coded output in the terminal for easy identification of results.

### 8. **Beginner-Friendly**
   - Easy-to-use prompts for user input.
   - Well-documented code to help beginners understand the functionality.

### 9. **Error Handling and Notifications**
   - Provides detailed error messages for failed API calls or tool execution.
   - Recommends manual steps to resolve issues when automatic installation fails.

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/SubReconX.git
```
### 2. Navigate to the project directory
```bash
cd SubReconX
```
### 3. Install dependencies
```bash
pip install -r requirements.txt
```
### 4. Run the script
```bash
python subreconx.py
```
Alternatively, if you face permission issues:
```bash
sudo python subreconx.py
```

### Usage
After running the script, you'll be prompted to enter a target domain for reconnaissance. Example input:
```bash
Enter the target domain (e.g., example.com): example.com
```
The script will perform both passive and active subdomain enumeration, identify live subdomains, and check for potential subdomain takeover vulnerabilities.

All subdomains will be saved in the example.com_subdomains.txt file, and live subdomains will be stored in the example.com_live_subdomains.txt file.

### Contributing
Contributions are welcome! Feel free to fork the repository and submit pull requests. To contribute:

Fork the repository.
Create a new branch for your feature or bug fix.
Submit a pull request with a clear description of your changes.

### License
SubReconX is licensed under the MIT License. See LICENSE for more information.

# Acknowledgments
Amass - For subdomain enumeration.

Subfinder - For passive subdomain discovery.

Assetfinder - For identifying subdomains.

Subzy - For subdomain takeover vulnerability detection.

VirusTotal, SecurityTrails, Shodan, and CertSpotter - For passive subdomain enumeration via APIs.

# Support
If you encounter any issues or need help, feel free to open an issue on GitHub or contact the project maintainer.
### Key Sections Explained:
- **Introduction**: Brief overview of the project.
- **Features**: Detailed explanation of what the script does, from passive and active enumeration to takeover detection.
- **Installation**: Steps to clone, install dependencies, and run the script.
- **Usage**: How to use the tool for reconnaissance, including example prompts.
- **Contributing**: Instructions on how others can contribute to the project.
- **License**: MIT License or your preferred license.
- **Acknowledgments**: Credits to the tools and services used in the project.
- **Support**: Information on how to get help if needed.

This structure ensures that your `README.md` is informative, easy to follow, and provides all the necessary details for users and contributors.
