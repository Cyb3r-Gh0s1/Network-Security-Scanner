# 🧪 Testing Guide - Network Security Scanner v2.0

## Quick Test Commands

### Test 1: Basic IP Scan (Core Only)
```bash
python network_scanner.py -t 8.8.8.8 -p 1-100 --quick
```
**Expected**: Should scan Google DNS and show results even without internet for plugins

### Test 2: Domain Name Scan
```bash
python network_scanner.py -t scanme.nmap.org -p 1-1000
```
**Expected**: 
- Resolves domain to IP
- Shows open ports (22, 80, 443 typically)
- Service detection works

### Test 3: With CVE Plugin
```bash
python network_scanner.py -t scanme.nmap.org -p 1-1000 --cve
```
**Expected**:
- Core scan completes first
- CVE plugin runs after
- If offline: CVE fails gracefully with warning, core results still shown

### Test 4: Help Command
```bash
python network_scanner.py --help
```
**Expected**: Shows comprehensive help with examples for both IP and domain scanning

### Test 5: Quick Mode
```bash
python network_scanner.py -t 192.168.1.1 -p 1-100 --quick
```
**Expected**: Fast scan, no version detection

### Test 6: Thorough Mode (requires sudo)
```bash
sudo python network_scanner.py -t scanme.nmap.org -p 1-100 --thorough
```
**Expected**: 
- Service versions
- OS detection
- More detailed results

## Verification Checklist

### ✅ Core Functionality
- [ ] IP addresses work
- [ ] Domain names work
- [ ] Open ports are detected
- [ ] Service versions shown
- [ ] JSON report generated

### ✅ Plugin Architecture
- [ ] Scanner works without `--cve` flag
- [ ] Scanner works without `--shodan` flag
- [ ] CVE failures don't crash scanner
- [ ] Shodan failures don't crash scanner
- [ ] Core scan completes before plugins

### ✅ Error Handling
- [ ] Invalid IP shows clear error
- [ ] Invalid domain shows resolution failure
- [ ] Down hosts show "host_down" status
- [ ] Missing Nmap shows clear error message

## Common Test Scenarios

### Scenario 1: Offline Testing
```bash
# Disconnect internet
python network_scanner.py -t 127.0.0.1 -p 1-100
```
**Result**: Should work perfectly (core scanner is offline-capable)

### Scenario 2: Plugin Failure (No API Key)
```bash
python network_scanner.py -t 8.8.8.8 --shodan
```
**Result**: 
```
[Shodan Plugin] No API key provided - skipping
```
Core scan still completes successfully

### Scenario 3: Invalid Target
```bash
python network_scanner.py -t invalid.domain.that.does.not.exist
```
**Result**:
```
[!] Failed to resolve hostname: invalid.domain.that.does.not.exist
[!] Core scan failed. Exiting.
```

### Scenario 4: Host Down
```bash
python network_scanner.py -t 192.168.255.255
```
**Result**:
```
[!] Host appears to be down or unreachable
```

## Performance Comparison

| Scan Mode | Speed | Detail Level | Use Case |
|-----------|-------|--------------|----------|
| `--quick` | ⚡ Fastest | Basic | Quick recon |
| default | ⚡⚡ Balanced | Medium | General use |
| `--thorough` | ⚡⚡⚡ Slowest | Detailed | Full assessment |

## Expected Output Structure

### Console Output
```
[Banner]
[Disclaimer]
[*] Starting core network scan...
[*] Resolving target...
[+] Resolved/Validated
[Port Scan Section]
  [+] Port results
[CVE Plugin Section] (if --cve)
  [CVE Plugin] Results
[Shodan Plugin Section] (if --shodan)
  [Shodan Plugin] Results
[Summary]
[Report Saved]
[Completion Message]
```

### JSON Report Structure
```json
{
  "scan_time": "...",
  "scanner_version": "2.0.0",
  "target": "...",
  "target_ip": "...",
  "scan_status": "completed",
  "open_ports": [...],
  "os_detection": [...],
  "cve_data": {...},      // Only if --cve used
  "shodan_data": {...}    // Only if --shodan used
}
```

## Debugging Tips

### Enable verbose Nmap output
Modify line in scanner:
```python
self.nm.scan(hosts=target_ip, ports=port_range, arguments=scan_args + ' -v')
```

### Check if Nmap is working
```bash
nmap -version
nmap -p 80 scanme.nmap.org
```

### Test Python imports
```bash
python3 -c "import nmap; import requests; import colorama; print('All imports OK')"
```

### Check network connectivity
```bash
ping 8.8.8.8
curl https://api.shodan.io
curl https://services.nvd.nist.gov
```

## Known Behaviors

### ✅ Expected (Not Bugs)
- Empty results if host is down
- Fewer ports in `--quick` mode
- No OS detection without `sudo`
- Plugin warnings when offline
- CVE lookups slow (NVD API rate limiting)

### ⚠️ Platform-Specific
| Platform | Note |
|----------|------|
| Kali Linux | Use venv for pip installs |
| Windows | May need admin for SYN scans |
| macOS | May need sudo for some features |

## Success Indicators

Your scanner is working correctly if:

1. ✅ Core scan completes even without flags
2. ✅ Domain names resolve properly
3. ✅ Open ports are detected
4. ✅ JSON report is generated
5. ✅ Plugins can be enabled/disabled independently
6. ✅ Plugin failures don't crash the program

## Troubleshooting

### No ports found but Nmap shows ports
```bash
# Try thorough mode
sudo python network_scanner.py -t target --thorough

# Or test with known-good target
python network_scanner.py -t scanme.nmap.org
```

### "Nmap not found"
```bash
# Install Nmap
sudo apt-get install nmap

# Verify
which nmap
```

### Scanner hangs
```bash
# Use Ctrl+C to interrupt
# Check target is reachable first
ping target
```

## Report Issues

If you find bugs, please report with:
1. Full command used
2. Console output
3. System info (OS, Python version)
4. Nmap version

Example:
```
Command: python network_scanner.py -t example.com --cve
Error: [paste error here]
OS: Kali Linux 2024.1
Python: 3.11.2
Nmap: 7.94
```

---

## Quick Verification Script

Save as `test_scanner.sh`:
```bash
#!/bin/bash
echo "Testing Network Scanner v2.0..."

echo "Test 1: Help"
python network_scanner.py --help > /dev/null && echo "✓" || echo "✗"

echo "Test 2: Version"
python network_scanner.py --version > /dev/null && echo "✓" || echo "✗"

echo "Test 3: Quick scan"
python network_scanner.py -t scanme.nmap.org -p 80 --quick -o test1.json > /dev/null && echo "✓" || echo "✗"

echo "Test 4: Domain resolution"
python network_scanner.py -t scanme.nmap.org -p 80 -o test2.json 2>&1 | grep -q "Resolved" && echo "✓" || echo "✗"

echo "All basic tests completed!"
```

Run with: `chmod +x test_scanner.sh && ./test_scanner.sh`
