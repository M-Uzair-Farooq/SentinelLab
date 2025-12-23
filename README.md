```markdown
# SentinelLab 

SentinelLab is a GUI-based Attack and Defence  framework for demonstrating the complete cybersecurity assessment lifecycle in controlled lab environments. It performs reconnaissance, vulnerability analysis, controlled exploitation demonstrations, and provides defensive hardening recommendations.

##  Features

- **Active Reconnaissance**: Port scanning and service enumeration
- **Vulnerability Mapping**: Automated vulnerability identification
- **Controlled Exploitation**: Safe demonstration of common attack vectors
- **Defense Recommendations**: Actionable hardening suggestions
- **Interactive GUI**: Built with PyQt5 for intuitive workflow
- **Report Generation**: PDF and HTML reporting capabilities

## Prerequisites

- Python 3.8+
- Nmap installed and in system PATH
- Isolated lab network (recommended)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sentinelab.git
cd sentinelab
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```
### Lab Configuration:
- **Attacker Machine**: Kali Linux
- **Target Machine**: Metasploitable 2
- **Network**: Host-only/NAT isolated network

## ⚠️ Important Notice

**This tool is for educational and authorized testing purposes only.** Always ensure you have explicit permission before scanning or testing any system. Use only in isolated lab environments.
