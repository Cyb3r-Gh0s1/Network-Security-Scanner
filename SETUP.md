# 🚀 Quick Setup Guide

## Step-by-Step Installation

### 1. System Requirements Check

**Verify Python version:**
```bash
python3 --version
# Should be 3.8 or higher
```

**Check if Nmap is installed:**
```bash
nmap --version
```

### 2. Install Nmap (if not already installed)

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nmap -y
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
1. Download from: https://nmap.org/download.html
2. Run installer
3. Add to PATH: `C:\Program Files (x86)\Nmap`

### 3. Clone Repository

```bash
git clone https://github.com/Cyb3r-Gh0s1/network-security-scanner.git
cd network-security-scanner
```

### 4. Set Up Virtual Environment (Recommended)

**⚠️ IMPORTANT for Kali Linux users:** Kali requires virtual environments for pip installations.

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS/Kali:
source venv/bin/activate

# On Windows:
venv\Scripts\activate

# Your prompt should now show (venv) prefix
```

**For Kali Linux - If you get "externally-managed-environment" error:**
```bash
# Option 1: Use virtual environment (RECOMMENDED - see above)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Option 2: Install system-wide with flag (NOT RECOMMENDED)
pip install -r requirements.txt --break-system-packages
```

### 5. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 6. Get Shodan API Key (Optional but Recommended)

1. Visit: https://account.shodan.io/register
2. Create a free account
3. Go to: https://account.shodan.io/
4. Copy your API key

**Set environment variable:**

**Linux/macOS:**
```bash
export SHODAN_API_KEY="your_api_key_here"

# To make it permanent, add to ~/.bashrc or ~/.zshrc:
echo 'export SHODAN_API_KEY="your_api_key_here"' >> ~/.bashrc
source ~/.bashrc
```

**Windows (Command Prompt):**
```cmd
set SHODAN_API_KEY=your_api_key_here
```

**Windows (PowerShell):**
```powershell
$env:SHODAN_API_KEY="your_api_key_here"
```

### 7. Test Installation

```bash
# Test basic functionality
python network_scanner.py --help

# Run a safe test scan
python network_scanner.py -t scanme.nmap.org -p 1-100
```

## 🎯 First Scan

### Basic Scan (No Shodan)
```bash
python network_scanner.py -t scanme.nmap.org -p 1-1000
```

### With Shodan Integration
```bash
python network_scanner.py -t scanme.nmap.org -p 1-1000 -s YOUR_SHODAN_KEY
```

### Save Results
```bash
python network_scanner.py -t scanme.nmap.org -o my_first_scan.json
```

## ⚠️ Common Issues & Solutions

### Issue: "externally-managed-environment" error (Kali Linux)

**Solution:** Kali Linux protects system Python - use virtual environment

**Quick Fix:**
```bash
cd ~/network-security-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Alternative (not recommended):**
```bash
pip install -r requirements.txt --break-system-packages
```

**Permanent Solution:** Always work in virtual environments:
```bash
# Every time you start working
cd ~/network-security-scanner
source venv/bin/activate

# When done
deactivate
```

### Issue: "Permission denied" when scanning

**Solution:** Some scan types require elevated privileges

**Linux/macOS:**
```bash
sudo python network_scanner.py -t scanme.nmap.org
```

**Windows:**
Run Command Prompt or PowerShell as Administrator

### Issue: "nmap: command not found"

**Solution:** Nmap is not installed or not in PATH

**Verify installation:**
```bash
which nmap  # Linux/macOS
where nmap  # Windows
```

**Install if missing (see Step 2 above)**

### Issue: "ModuleNotFoundError: No module named 'nmap'"

**Solution:** Python dependencies not installed

```bash
pip install -r requirements.txt
```

### Issue: Shodan API rate limiting

**Solution:** Free Shodan accounts have rate limits

- Wait a few minutes between scans
- Upgrade to paid Shodan account for higher limits
- Use without Shodan for unlimited local scanning

### Issue: CVE lookup timeout

**Solution:** NVD API can be slow or rate-limited

- The scanner will continue even if CVE lookup fails
- Wait a few seconds between scans
- Check your internet connection

## 🔧 Configuration Tips

### Scan Speed vs Stealth

**Fast scan (less stealthy):**
```bash
python network_scanner.py -t target -p 1-100
```

**Comprehensive scan:**
```bash
python network_scanner.py -t target -p 1-65535
```

### Running in Background

**Linux/macOS:**
```bash
nohup python network_scanner.py -t target -p 1-1000 > scan.log 2>&1 &
```

**Check progress:**
```bash
tail -f scan.log
```

## 📊 Understanding Reports

The JSON report contains:

```json
{
    "scan_time": "When the scan was performed",
    "targets": [
        {
            "host": "Scanned IP/hostname",
            "open_ports": [
                {
                    "port": "Port number",
                    "service": "Service name (http, ssh, etc.)",
                    "version": "Service version",
                    "cves": "Associated vulnerabilities"
                }
            ]
        }
    ],
    "vulnerabilities": "All CVEs found"
}
```

## 🎓 Next Steps

1. **Practice** on authorized targets (scanme.nmap.org, your own systems)
2. **Customize** the scanner for your specific needs
3. **Analyze** the reports to understand vulnerabilities
4. **Learn** about each CVE found using the CVE IDs
5. **Contribute** improvements back to the project

## 📚 Additional Resources

- **Nmap Tutorial:** https://nmap.org/book/man.html
- **Shodan Guide:** https://help.shodan.io/
- **CVE Database:** https://cve.mitre.org/
- **Ethical Hacking:** https://www.offensive-security.com/

## ✅ Installation Checklist

- [ ] Python 3.8+ installed
- [ ] Nmap installed and in PATH
- [ ] Virtual environment created and activated
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Shodan API key obtained (optional)
- [ ] Test scan completed successfully
- [ ] Permission to scan target systems confirmed

---

**Need help?** Open an issue on GitHub or check the main README.md

**Ready to scan?** Run: `python network_scanner.py -t scanme.nmap.org`
