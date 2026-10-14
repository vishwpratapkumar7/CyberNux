# 🛡️ CyberNux
### Advanced Cybersecurity Toolkit

**One Platform. Multiple Security Capabilities.**

CyberNux is a modular cybersecurity toolkit built with Python, designed to bring digital forensics, threat detection, website security assessment, communication, and network analysis into one unified platform.

## 🚀 Features

### 🔬 1. Advanced Metadata Analyzer
A powerful file-analysis module designed to uncover embedded technical information across supported file formats.

- Multi-format metadata extraction
- Image EXIF and document property analysis
- Media and archive inspection
- Timestamp and file-attribute analysis
- AI-generation marker identification
- Structured, readable analysis results

### 🛡️ 2. Web Vulnerability Scanner
An automated website security assessment module for identifying potential weaknesses and configuration issues.

- Website response analysis
- Security-header inspection
- TLS security checks
- Page and resource discovery
- Suspicious error-pattern identification
- Security findings and risk-oriented reporting

### 🎯 3. URL & Phishing Detector
A threat-detection module designed to analyze suspicious links and identify phishing-related indicators.

- URL structure analysis
- Suspicious domain and redirect indicators
- Brand-impersonation detection rules
- HTML form inspection
- Server-log analysis
- Risk scoring and categorized findings
- Optional threat-intelligence checks

### 💬 4. Anonymous Chat
An integrated browser-based communication module featuring a streamlined chat interface.

- Browser-based messaging interface
- Nickname and channel interaction
- WebSocket-based communication
- Real-time message exchange
- Lightweight, user-friendly design

### 📱 5. Digital Information Intelligence
A structured information-lookup module designed to process queries and present available results in a readable format.

- Multi-source lookup workflow
- Automated fallback handling
- Structured information display
- JSON-formatted output
- Request timeout handling

### 📊 6. Network Traffic Analyzer
A network-performance testing module for examining HTTP request behavior in controlled environments.

- Concurrent request processing
- Response-time measurement
- Success and failure statistics
- Timeout monitoring
- Latency analysis
- Performance summaries

## 🧰 Technology Stack

- **Language:** Python
- **Networking:** Requests and aiohttp
- **Concurrency:** asyncio and threading
- **Frontend:** HTML, CSS, JavaScript
- **Communication:** WebSocket
- **Version Control:** Git and GitHub

## 📂 Project Structure

```text
CyberNux/
├── app.py
├── requirements.txt
├── .gitignore
├── anonymous_chat/
│   ├── main.py
│   ├── server.py
│   └── index.html
├── metadata/
│   ├── metadata.py
│   └── metadata.html
└── tools/
    ├── detector.py
    ├── phoneinfo.py
    ├── scan.py
    └── trafficcheck.py
```

## ⚙️ Installation

### Requirements
- Python 3
- Git
- Dependencies listed in `requirements.txt`

### 1. Clone the repository

```bash
git clone https://github.com/vishwpratapkumar7/CyberNux.git
cd CyberNux
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Launch CyberNux

```bash
python app.py
```

Follow the interactive menu to select a module.

## 🔐 Application Access

**Demo password:** `CyberSquad`

For production use, configure an appropriate authentication mechanism and keep credentials secure.

## 🎯 Project Objectives

- Combine multiple security utilities in one application.
- Simplify digital-file and website analysis.
- Support phishing investigation and threat awareness.
- Provide readable outputs for practical demonstrations.
- Encourage modular development and future expansion.

## 🚀 Future Scope

- Enhanced detection rules
- Expanded file-format support
- Improved security reporting
- Automated testing and quality assurance
- Additional defensive analysis capabilities
- Enhanced performance monitoring

## 👨‍💻 Developer

**Vishw Pratap Kumar**

GitHub: [@vishwpratapkumar7](https://github.com/vishwpratapkumar7)

Project: [CyberNux Repository](https://github.com/vishwpratapkumar7/CyberNux)

## ⚖️ Responsible Use

CyberNux is intended for educational purposes, defensive cybersecurity analysis, and authorized testing. Use security-assessment and traffic-testing features only on systems you own or have permission to test.

---

**CyberNux — Analyze. Detect. Defend.**
