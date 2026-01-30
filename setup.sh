#!/bin/bash
# Quick Setup Script for Kali Linux
# Automated Network Security Scanner Setup

echo "================================================"
echo "  Network Security Scanner - Kali Linux Setup"
echo "================================================"
echo ""

# Check if running on Kali
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" == "kali" ]]; then
        echo "[✓] Detected Kali Linux"
    else
        echo "[!] Not Kali Linux, but continuing anyway..."
    fi
fi

# Check Python version
echo ""
echo "[*] Checking Python version..."
python3 --version

if [ $? -ne 0 ]; then
    echo "[✗] Python 3 not found. Please install it first."
    exit 1
fi

# Check if Nmap is installed
echo ""
echo "[*] Checking for Nmap..."
if command -v nmap &> /dev/null; then
    echo "[✓] Nmap is installed"
    nmap --version | head -n 1
else
    echo "[!] Nmap not found. Installing..."
    sudo apt update
    sudo apt install nmap -y
    if [ $? -eq 0 ]; then
        echo "[✓] Nmap installed successfully"
    else
        echo "[✗] Failed to install Nmap"
        exit 1
    fi
fi

# Create virtual environment
echo ""
echo "[*] Setting up virtual environment..."

if [ -d "venv" ]; then
    echo "[!] Virtual environment already exists"
    read -p "Remove and recreate? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf venv
        python3 -m venv venv
    fi
else
    python3 -m venv venv
fi

if [ -d "venv" ]; then
    echo "[✓] Virtual environment created"
else
    echo "[✗] Failed to create virtual environment"
    exit 1
fi

# Activate virtual environment
echo ""
echo "[*] Activating virtual environment..."
source venv/bin/activate

if [ $? -eq 0 ]; then
    echo "[✓] Virtual environment activated"
else
    echo "[✗] Failed to activate virtual environment"
    exit 1
fi

# Upgrade pip
echo ""
echo "[*] Upgrading pip..."
pip install --upgrade pip -q

# Install requirements
echo ""
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "[✓] All dependencies installed successfully"
else
    echo "[✗] Failed to install dependencies"
    exit 1
fi

# Test installation
echo ""
echo "[*] Testing installation..."
python network_scanner.py --help > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "[✓] Scanner is working correctly!"
else
    echo "[✗] Scanner test failed"
    exit 1
fi

# Success message
echo ""
echo "================================================"
echo "  ✓ Setup Complete!"
echo "================================================"
echo ""
echo "To run the scanner:"
echo "  1. Activate virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run scanner:"
echo "     python network_scanner.py -t scanme.nmap.org -p 1-100"
echo ""
echo "  3. When done, deactivate:"
echo "     deactivate"
echo ""
echo "Example commands:"
echo "  python network_scanner.py -t scanme.nmap.org"
echo "  python network_scanner.py -t scanme.nmap.org -p 1-1000 -o report.json"
echo ""
echo "For Shodan integration:"
echo "  export SHODAN_API_KEY='your_key_here'"
echo "  python network_scanner.py -t 8.8.8.8 -s \$SHODAN_API_KEY"
echo ""
echo "================================================"
