# 🛡️ SentinelLab – A GUI-Based Attack and Defense Framework

**SentinelLab** is a GUI-based Attack and Defence framework for demonstrating the complete cybersecurity assessment lifecycle in controlled lab environments. It performs reconnaissance, vulnerability analysis, controlled exploitation demonstrations, and provides defensive hardening recommendations.

---

## 🔍 Key Features

### 🕵️ Active Reconnaissance
- Port scanning and service enumeration

### 🗺️ Vulnerability Mapping
- Automated vulnerability identification

### ⚔️ Controlled Exploitation
- Safe demonstration of common attack vectors

### 🛡️ Defense Recommendations
- Actionable hardening suggestions

### 🖥️ Interactive GUI
- Built with PyQt5 for intuitive workflow

### 📄 Report Generation
- PDF and HTML reporting capabilities

---

## 🛠️ Tech Stack

| Layer        | Technology Used                     |
|--------------|-------------------------------------|
| Backend      | Python 3.8+, Nmap                   |
| Frontend     | PyQt5 GUI                           |
| Analysis     | Vulnerability scanners, Exploitation tools |
| Reporting    | PDF/HTML generators                 |
| Environment  | Isolated lab network (Kali Linux, Metasploitable 2) |

---

## 🚀 How to Run Locally

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/SentinelLab.git
   cd SentinelLab
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Ensure prerequisites**:
   - Python 3.8+
   - Nmap installed and in system PATH
   - Isolated lab network (recommended)

4. **Configure lab environment**:
   - **Attacker Machine**: Kali Linux
   - **Target Machine**: Metasploitable 2
   - **Network**: Host-only/NAT isolated network


---

## ⚠️ Important Notice

**This tool is for educational and authorized testing purposes only.** Always ensure you have explicit permission before scanning or testing any system. Use only in isolated lab environments.

---
