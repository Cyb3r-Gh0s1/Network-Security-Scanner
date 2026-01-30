# 🔐 Automated Network Security Scanner v2.0

A professional, modular network security scanner with **plugin-based architecture**. Core scanning works independently—CVE and Shodan plugins enhance functionality without affecting reliability.

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)

## ⚡ Quick Start (Kali Linux)

```bash
git clone https://github.com/Cyb3r-Gh0s1/network-security-scanner.git
cd network-security-scanner
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python network_scanner.py -t scanme.nmap.org
```

## 🎯 Key Features

###Core Scanner (Always Works)
- ✅ **Port Scanning**: Nmap integration with customizable port ranges
- ✅ **Service Detection**: Identifies services, products, and versions
- ✅ **OS Fingerprinting**: Operating system detection
- ✅ **Hostname Resolution**: Supports both IP addresses and domains
- ✅ **Offline Capability**: Core functionality works without internet

### Optional Plugins (Fail Gracefully)
- 🔌 **CVE Plugin**: Automated vulnerability lookup from NIST NVD
- 🔌 **Shodan Plugin**: Passive intelligence gathering
- 🔌 **Modular Design**: Plugins never break core scanning

## 🏗️ Architecture

```
Core Scanner (Always Works)
    ↓
    ├── CVE Plugin (Optional)
    └── Shodan Plugin (Optional)
```

**One-way dependency**: Core scanner is completely independent. Plugins depend on core results but never affect core functionality.

## 📋 Requirements

- Python 3.8+
- Nmap
- Internet (optional, for plugins only)

## 🚀 Installation

### Option 1: Automated Setup (Recommended)
```bash
# Clone repository
git clone https://github.com/Cyb3r-Gh0s1/network-security-scanner.git
cd network-security-scanner

# Run automated setup script
chmod +x setup.sh
./setup.sh
```

### Option 2: Manual Installation (Kali / Debian / Ubuntu)

**⚠️ Important for Kali Linux users**: Kali uses an externally managed Python environment (PEP 668). You **must** use a virtual environment:

```bash
# 1. Clone repository
git clone https://github.com/Cyb3r-Gh0s1/network-security-scanner.git
cd network-security-scanner

# 2. Install Nmap (if not already installed)
sudo apt-get update && sudo apt-get install nmap -y

# 3. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Verify installation
python network_scanner.py --help
```

**Every time you use the scanner**, activate the virtual environment first:
```bash
cd network-security-scanner
source venv/bin/activate
python network_scanner.py -t <target>
```

**💡 Pro Tip**: Use the convenient `scan.sh` wrapper script (auto-activates venv):
```bash
chmod +x scan.sh
./scan.sh -t scanme.nmap.org
# No need to manually activate venv!
```

## 💻 Usage

**📝 Note**: For Kali/Debian users, always activate your virtual environment first:

**Method 1: Manual activation**
```bash
source venv/bin/activate  # On Linux/Mac/Kali
python network_scanner.py -t <target>
```

**Method 2: Use the wrapper script** (easier, recommended)
```bash
./scan.sh -t <target>
# Automatically activates venv for you!
```

### Basic Scanning

```bash
# Scan IP address
python network_scanner.py -t 192.168.1.1
# OR
./scan.sh -t 192.168.1.1

# Scan domain
python network_scanner.py -t scanme.nmap.org

# Scan specific ports
python network_scanner.py -t 10.0.0.1 -p 22,80,443
```

### Scan Modes

```bash
# Quick scan (fastest)
python network_scanner.py -t example.com -p 1-100 --quick

# Default scan (balanced)
python network_scanner.py -t 192.168.1.1 -p 1-1000

# Thorough scan (most detailed)
python network_scanner.py -t scanme.nmap.org --thorough
```

### Using Plugins

```bash
# With CVE lookup
python network_scanner.py -t scanme.nmap.org --cve

# With Shodan
python network_scanner.py -t 8.8.8.8 --shodan -s YOUR_API_KEY

# Full assessment
python network_scanner.py -t example.com -p 1-5000 --cve --shodan --thorough
```

## 📊 Sample Output

```
[*] Resolving target: scanme.nmap.org
[+] Resolved scanme.nmap.org → 45.33.32.156

============================================================
  Port Scanning: scanme.nmap.org (45.33.32.156)
============================================================

[+] 22/tcp      open    ssh     OpenSSH 6.6.1p1
[+] 80/tcp      open    http    Apache httpd 2.4.7
[+] 443/tcp     open    https   Apache httpd 2.4.7

[CVE Plugin] CVE-2017-15715 - HIGH (CVSS: 8.1)
[CVE Plugin] CVE-2017-9788 - CRITICAL (CVSS: 9.8)

============================================================
  SCAN SUMMARY
============================================================
Target: scanme.nmap.org (45.33.32.156)
Open ports: 3
CVEs found: 2
```

## 🔌 Plugin Details

### CVE Plugin (`--cve`)
- Queries NIST National Vulnerability Database
- Returns CVE IDs, CVSS scores, and severity
- Fails gracefully if offline or API unavailable

### Shodan Plugin (`--shodan`)
- Provides passive intelligence
- Requires API key (free at [shodan.io](https://account.shodan.io/register))
- Returns geolocation, ISP, known vulnerabilities

## 🛡️ Security & Legal

**⚠️ For authorized testing only!**

- ✅ Only scan systems you own or have permission to test
- ❌ Unauthorized scanning is illegal
- 📜 Always comply with local laws
- 🎓 Educational and authorized testing only

Safe targets: `scanme.nmap.org`, your own systems

## 🐛 Troubleshooting

**Kali Linux "externally-managed-environment":**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Permission denied:**
```bash
sudo python network_scanner.py -t target --thorough
```

**No ports found:**
```bash
# Try thorough mode
python network_scanner.py -t target --thorough
```

## 👨‍💻 Author

**Faiz Ahemad**
- GitHub: [@Cyb3r-Gh0s1](https://github.com/Cyb3r-Gh0s1)
- LinkedIn: [faiz-ahemad](https://linkedin.com/in/faiz-ahemad)

## 📜 License

MIT License - see [LICENSE](LICENSE) file

---

⭐ **Star this repo if you find it useful!**
