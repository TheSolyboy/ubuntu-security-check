# Linux Security Assessment Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.linux.org/)

A comprehensive security assessment script for Linux servers that evaluates critical security configurations and provides actionable recommendations. Get an instant security score (0-100%) and detailed analysis of your server's security posture.

## 🔍 **Repository Description**
*Professional security assessment tool for Linux servers. Analyze SSH configuration, firewall status, intrusion prevention, system updates, and more. Get instant security scoring and actionable recommendations to improve your server security.*

## ✨ Features

- **🔐 SSH Security Analysis** - Port configuration, authentication methods, key management
- **🛡️ Firewall Assessment** - UFW status, rule configuration, port protection
- **🔨 Intrusion Prevention** - Fail2Ban status, active jails, banned IPs
- **📦 System Updates** - Available updates, security patches, automatic updates
- **💻 Resource Monitoring** - CPU, memory, disk usage, load average
- **🔍 Security Events** - Failed logins, attack attempts, system activity
- **🛠️ Service Status** - Critical security services health check
- **🌐 Network Security** - Open ports, service identification, configuration review
- **📊 Security Scoring** - Overall score (0-100%) with detailed breakdown
- **🚀 Actionable Recommendations** - Prioritized security improvements

## 🖥️ Sample Output

```
===================================================================== 
                    SECURITY ASSESSMENT REPORT
=====================================================================
Generated: Sat Jul 26 08:19:50 PM UTC 2025
Hostname: web-server-01
Kernel: 6.8.0-63-generic
OS: Ubuntu 24.04.2 LTS

🔐 SSH Security Configuration:
   ✅ SSH Port: 2222
      [+5] Non-default port configured
   ✅ Root Login: DISABLED
      [+10] Root access properly restricted
   ✅ Password Authentication: DISABLED
      [+15] Key-based authentication enforced
   📊 SSH Security Score: 43/48 (89%)

🛡️ Firewall Configuration:
   ✅ UFW Status: ACTIVE
   ✅ SSH Port: Protected
   📊 Firewall Score: 25/25 (100%)

🏆 Overall Security Score: 133/153 (86%)
🟡 STATUS: GOOD SECURITY
```

## 🚀 Quick Start

### One-Line Installation
```bash
curl -sSL https://raw.githubusercontent.com/yourusername/linux-security-assessment/main/install.sh | sudo bash
```

### Manual Installation
```bash
# Download the script
wget https://raw.githubusercontent.com/yourusername/linux-security-assessment/main/security-check.sh

# Make it executable
chmod +x security-check.sh

# Move to system path
sudo mv security-check.sh /usr/local/bin/

# Run the assessment
sudo security-check.sh
```

### Git Clone Method
```bash
# Clone the repository
git clone https://github.com/yourusername/linux-security-assessment.git

# Navigate to directory
cd linux-security-assessment

# Install the script
sudo cp security-check.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/security-check.sh

# Run assessment
sudo security-check.sh
```

## 📋 Requirements

### Supported Operating Systems
- ✅ Ubuntu 18.04+
- ✅ Debian 9+
- ✅ CentOS 7+ / RHEL 7+
- ✅ Amazon Linux 2
- ✅ Most Linux distributions with systemd

### Dependencies
- `bash` (version 4.0+)
- `systemctl` (systemd)
- `netstat` or `ss`
- `apt` (for Debian/Ubuntu systems)
- `bc` (for calculations)

### Install Dependencies (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install net-tools bc -y
```

### Install Dependencies (CentOS/RHEL)
```bash
sudo yum install net-tools bc -y
# or for newer versions:
sudo dnf install net-tools bc -y
```

## 🛠️ Usage

### Basic Usage
```bash
# Run complete security assessment
sudo security-check.sh

# Save report to file
sudo security-check.sh > security-report-$(date +%Y%m%d).txt

# Run and email results (requires mail setup)
sudo security-check.sh | mail -s "Security Report: $(hostname)" admin@company.com
```

### Automation Examples

#### Daily Security Check (Crontab)
```bash
# Add to root crontab
sudo crontab -e

# Run daily at 2 AM and save results
0 2 * * * /usr/local/bin/security-check.sh > /var/log/security-reports/daily-$(date +\%Y\%m\%d).log 2>&1
```

#### Integration with Monitoring Systems
```bash
# Use with Nagios/Icinga
sudo security-check.sh --nagios-format

# JSON output for APIs
sudo security-check.sh --json

# Prometheus metrics format
sudo security-check.sh --prometheus
```

## 📊 Security Score Breakdown

| Score Range | Status | Description |
|-------------|--------|-------------|
| 90-100% | 🟢 EXCELLENT | Enterprise-grade security |
| 75-89% | 🟡 GOOD | Well-secured with minor improvements needed |
| 50-74% | 🟠 MODERATE | Basic security, significant improvements required |
| 0-49% | 🔴 POOR | Critical security issues, immediate action required |

## 🔧 Configuration

### Custom Configuration File
Create `/etc/security-check/config.conf` to customize behavior:

```bash
# Custom configuration
ENABLE_EMAIL_ALERTS=true
ALERT_EMAIL="security@company.com"
SECURITY_THRESHOLD=80
LOG_DIRECTORY="/var/log/security-reports"
EXCLUDE_PORTS="8080,9000"
```

### Advanced Options
```bash
# Skip specific checks
sudo security-check.sh --skip-network --skip-updates

# Verbose output
sudo security-check.sh --verbose

# Quiet mode (errors only)
sudo security-check.sh --quiet

# Custom SSH config location
sudo security-check.sh --ssh-config /custom/path/sshd_config
```

## 🛡️ Security Recommendations

Based on assessment results, the script provides prioritized recommendations:

### High Priority Issues
- Disable SSH root login
- Configure firewall protection
- Install intrusion prevention (Fail2Ban)
- Apply security updates

### Medium Priority Enhancements
- Configure automatic updates
- Implement log monitoring
- Set up SSL/TLS certificates
- Establish backup procedures

### Advanced Security Measures
- Deploy intrusion detection (AIDE/OSSEC)
- Configure centralized logging
- Implement network segmentation
- Regular penetration testing

## 🚨 Common Issues & Troubleshooting

### Permission Denied
```bash
# Ensure script has proper permissions
sudo chmod +x /usr/local/bin/security-check.sh

# Run with sudo for full system access
sudo security-check.sh
```

### Missing Dependencies
```bash
# Install required packages
sudo apt install net-tools bc ufw fail2ban -y
```

### UFW Not Found
```bash
# Install UFW firewall
sudo apt install ufw -y
sudo ufw enable
```

### Fail2Ban Not Detected
```bash
# Install Fail2Ban
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

## 📈 Continuous Monitoring

### Weekly Security Reports
```bash
#!/bin/bash
# /usr/local/bin/weekly-security-report.sh

REPORT_DATE=$(date +%Y%m%d)
REPORT_FILE="/var/log/security-reports/weekly-$REPORT_DATE.txt"

echo "Weekly Security Assessment - $(hostname)" > $REPORT_FILE
echo "Generated: $(date)" >> $REPORT_FILE
echo "========================================" >> $REPORT_FILE

/usr/local/bin/security-check.sh >> $REPORT_FILE

# Email the report
mail -s "Weekly Security Report: $(hostname)" admin@company.com < $REPORT_FILE
```

### Integration with CI/CD
```yaml
# GitHub Actions example
name: Security Assessment
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday 2 AM
  
jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
    - name: Run Security Assessment
      run: |
        curl -sSL https://raw.githubusercontent.com/yourusername/linux-security-assessment/main/security-check.sh | sudo bash
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/yourusername/linux-security-assessment.git
cd linux-security-assessment

# Run tests
./tests/run-tests.sh

# Check shell script quality
shellcheck security-check.sh
```

### Reporting Issues
Please use our [Issue Template](https://github.com/yourusername/linux-security-assessment/issues/new/choose) when reporting bugs or requesting features.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Security best practices from [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- Linux hardening guidelines from [NSA](https://github.com/nsacyber/RHEL-7-STIG)
- Community feedback and contributions

## 📞 Support

- 📖 **Documentation**: [Wiki](https://github.com/yourusername/linux-security-assessment/wiki)
- 🐛 **Bug Reports**: [Issues](https://github.com/yourusername/linux-security-assessment/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/linux-security-assessment/discussions)
- 📧 **Email**: security-tools@yourdomain.com

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/linux-security-assessment&type=Date)](https://star-history.com/#yourusername/linux-security-assessment&Date)

---

**Made with ❤️ for the Linux security community**

*Last updated: July 2025*
