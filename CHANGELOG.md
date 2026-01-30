# Changelog

All notable changes to the Automated Network Security Scanner will be documented in this file.

## [2.0.0] - 2024-01-30

### 🎉 Major Release - Plugin Architecture

#### Added
- **Plugin-based architecture** - Core scanner now completely independent
- **Hostname resolution** - Support for both IP addresses and domain names
- **CVE Plugin** - Optional, fails gracefully without breaking core scan
- **Shodan Plugin** - Optional, requires API key, fails gracefully
- **Three scan modes**: `--quick`, `--thorough`, and default balanced mode
- **Comprehensive --help** with detailed examples for IPs and domains
- **Better error handling** - Distinguishes between hostname resolution, scan, and plugin failures
- **Improved Nmap arguments** - More reliable port detection

#### Changed
- **Complete rewrite** of core scanning logic
- **Modular design** - Separated CoreScanner, CVEPlugin, ShodanPlugin classes
- **Better output formatting** - Clearer section separators and plugin indicators
- **Enhanced reporting** - More structured JSON output

#### Fixed
- **Empty scan results bug** - Improved Nmap scan reliability
- **Domain name scanning** - Now properly resolves hostnames before scanning
- **Plugin dependency issues** - CVE and Shodan failures no longer affect core scanning
- **Error messages** - More descriptive and actionable error reporting

#### Technical Improvements
- One-way dependency architecture (plugins depend on core, not vice versa)
- Socket-based hostname resolution before Nmap scan
- Graceful failure handling for all optional components
- Better separation of concerns between scanning and enrichment

### Breaking Changes from 1.0
- Command-line interface remains mostly compatible
- `--cve` and `--shodan` are now explicit opt-in flags (plugins disabled by default)
- Scan modes (`--quick`, `--thorough`) replace old scan type argument
- Report structure updated with clearer separation of core vs plugin data

---

## [1.0.0] - 2024-01-29

### Initial Release

#### Features
- Basic port scanning with Nmap
- Service version detection
- Shodan API integration (always-on)
- CVE lookups (always-on)
- JSON report generation
- OS detection
- Color-coded terminal output

#### Known Issues (Fixed in 2.0)
- Empty scan results with some targets
- Domain names caused errors
- Plugin failures could crash the scanner
- Hard dependencies on CVE and Shodan APIs

---

## Version Comparison

| Feature | v1.0 | v2.0 |
|---------|------|------|
| Core Scanning | ✓ | ✓ Improved |
| Hostname Support | ✗ | ✓ |
| CVE Lookup | Always-on | Optional Plugin |
| Shodan | Always-on | Optional Plugin |
| Offline Mode | ✗ | ✓ |
| Graceful Failures | ✗ | ✓ |
| Scan Modes | ✗ | ✓ |
| Plugin Architecture | ✗ | ✓ |

---

## Upgrade Guide (1.0 → 2.0)

### Old Command (v1.0)
```bash
python network_scanner.py -t 192.168.1.1 -s SHODAN_KEY
```

### New Command (v2.0)
```bash
# Core scan only (faster, works offline)
python network_scanner.py -t 192.168.1.1

# With all plugins (same as v1.0 behavior)
python network_scanner.py -t 192.168.1.1 --cve --shodan -s SHODAN_KEY
```

### What Changed
1. **Plugins are now opt-in**: Use `--cve` and `--shodan` flags explicitly
2. **Domain names now work**: `python network_scanner.py -t example.com`
3. **New scan modes**: `--quick` for fast scans, `--thorough` for deep scans
4. **Better reliability**: Core scan works even if plugins fail

---

## Future Roadmap

### Planned for 2.1
- [ ] Web-based dashboard
- [ ] Scan scheduling
- [ ] Database storage for historical scans
- [ ] Additional plugins (VirusTotal, threat feeds)

### Planned for 2.2
- [ ] Multi-threading for faster scans
- [ ] Scan profiles/templates
- [ ] Email notifications
- [ ] PDF report generation

### Planned for 3.0
- [ ] Machine learning for anomaly detection
- [ ] Automated remediation suggestions
- [ ] API endpoint for integration
- [ ] Docker container packaging

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute to this project.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.
