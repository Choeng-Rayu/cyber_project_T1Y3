# Cyber Security Project Report

## Malware Attack & Defence Simulation System

---

**Team Members:**
- Choeng Rayu
- Tep Somnang
- Lon Mengheng
- Tet Elite
- Ratana Asinike
- Sophal Taingchhay

**School of Computer Science**  
Cambodia Academy of Digital Technology  
{rayu.choeng, somnang.tep, mengheng.lon, elite.tet, asinike.ratana, taingchhay.sophal}@student.cadt.edu.kh

**Submit By:** Group 4  
**Under the Advisory of:** Mr. Pich Reatrey  
**Date of Presentation:** Dec 12, 2025

---

## Acknowledgement

We extend our heartfelt thanks to our lecturer, Mr. Pich Reatrey, for his invaluable guidance and unwavering support throughout the development of this cybersecurity project. His expertise in security concepts and hands-on approach to teaching were instrumental in shaping our understanding of both offensive and defensive security techniques.

---

## Abstract

This project presents a comprehensive Malware Attack and Defence Simulation System designed for educational purposes in cybersecurity research. The system demonstrates real-world attack vectors including credential harvesting, data exfiltration, malicious delivery techniques, and persistence mechanisms, while simultaneously providing defensive countermeasures to detect and mitigate such threats.

The project is divided into two main components: an **Attacker Module** that simulates sophisticated malware behaviour (including sensitive data collection from Windows systems, browser credential extraction, Wi-Fi password harvesting, and registry manipulation) and a **Defender Module** that provides protection mechanisms against these attack vectors.

Built using Python for malware simulation, Node.js/Express for command-and-control (C&C) backend infrastructure, and web technologies for social engineering demonstration, this project provides students with practical, hands-on experience in understanding both sides of the cybersecurity landscape.

> ⚠️ **DISCLAIMER:** All implementations are designed strictly for controlled educational environments with proper authorization.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Presentation of the Project](#2-presentation-of-the-project)
3. [Project Analysis and Concepts](#3-project-analysis-and-concepts)
4. [Detail Concept](#4-detail-concept)
5. [Implementation](#5-implementation)
6. [Conclusion](#6-conclusion)

---

## 1. Introduction

Cybersecurity is one of the most critical fields in modern computer science, yet students often struggle to grasp abstract threat concepts without practical exposure. This project, **Malware Attack & Defence Simulation System**, aims to bridge this gap by providing a safe, controlled environment where students can study real-world attack techniques and develop corresponding defence strategies.

Deployed as a comprehensive simulation framework, the system covers the complete attack lifecycle from initial delivery through phishing websites, to data collection and exfiltration via C&C servers, to persistence mechanisms that ensure continued access. Simultaneously, it provides defensive modules that detect, prevent, and remediate these threats.

This project combines malware analysis, network security, social engineering awareness, and security tool development to provide a holistic understanding of cybersecurity principles.

---

## 2. Presentation of the Project

### 2.1 General Presentation

We developed this Malware Attack & Defence Simulation System as part of our cybersecurity coursework under the guidance of Mr. Pich Reatrey. This educational project allows students to explore various attack vectors and defence mechanisms in a controlled laboratory environment.

**The project consists of multiple integrated components:**
- Sensitive Data Collector
- Command & Control Backend (server.js)
- Phishing Website Simulation
- Defence Modules

### 2.2 Problematic

Understanding cyber security threats and defenses can be challenging for students due to the abstract nature of attacks and the lack of safe environments for hands-on learning. Common issues include:

- Limited practical exposure to real-world attack techniques in academic settings
- Difficulty understanding how malware operates at a technical level
- Lack of safe environments to study offensive security techniques
- Disconnect between theory and practice in security education
- Insufficient awareness of social engineering attack vectors
- Limited understanding of how data exfiltration actually works
- Inadequate knowledge of persistence mechanisms used by malware

### 2.3 Objectives

The primary objectives of this Cyber Security Malware Simulation project include:

1. Demonstrating real-world attack vectors including credential theft, data exfiltration, and social engineering
2. Providing hands-on experience with malware development techniques for educational understanding
3. Implementing C&C (Command & Control) infrastructure to understand how attackers manage compromised systems
4. Developing defense mechanisms that detect and prevent the demonstrated attacks
5. Creating a phishing simulation to demonstrate social engineering awareness
6. Building modular, extensible code that can be adapted for various security research scenarios
7. Documenting attack and defense techniques for educational reference
8. Emphasizing ethical considerations and the importance of authorized security testing

---

## 3. Project Analysis and Concepts

### 3.1 Functional Requirements

**Attacker Team:**
- Collect sensitive system information from victim machines
- Extract browser credentials and session cookies
- Harvest Wi-Fi passwords and SSH keys
- Exfiltrate data to C&C server
- Deliver malware through phishing emails and fake websites

**Defender Team:**
- Detect unauthorized data access and exfiltration
- Monitor suspicious file system activity
- Block malicious network connections
- Prevent persistence mechanism installation
- Alert on social engineering attempts

### 3.2 Non-Functional Requirements

| Requirement | Description |
|-------------|-------------|
| Performance | Scripts execute within reasonable time limits |
| Portability | Cross-platform support (Windows primary, macOS/Linux secondary) |
| Modularity | Each component can function independently |
| Documentation | Clear code comments and usage instructions |
| Safety | Built-in safeguards to prevent accidental misuse |

---

## 4. Detail Concept

### 4.1 Tools and Technologies

| Technology | Purpose |
|------------|---------|
| **Python 3.10+** | Core malware simulation language |
| **Node.js/Express.js** | C&C backend server |
| **MySQL** | Data storage (Aiven Cloud) |
| **EJS** | Template engine for web pages |
| **HTML/CSS** | Phishing website design |
| **Git/GitHub** | Version control and collaboration |
| **VS Code** | Development environment |

### 4.2 Methodology

This project was developed using the **Security Development Lifecycle (SDL)** methodology:

1. **Threat Modeling** - Identified attack vectors and high-value targets
2. **Attack Design** - Constructed realistic malware behaviors
3. **Defense Design** - Created countermeasures for each attack technique
4. **Implementation** - Developed both offensive and defensive modules
5. **Testing** - Verified functionality in isolated environment
6. **Documentation** - Produced comprehensive explanations

**Ethical Considerations:** All components were developed strictly for educational purposes. Testing was performed only on isolated machines with full authorization.

---

## 5. Implementation

### 5.1 Project Setup

**Prerequisites:**
- Python 3.10+
- Node.js v16+
- npm
- Git

**Installation:**
```bash
# Clone repository
git clone https://github.com/Choeng-Rayu/cyber_project_T1Y3.git
cd cyber_project_T1Y3

# Install backend dependencies
cd flowChart/somnang_attack_website
npm install

# Start phishing server
npm start

# Run email campaign (separate terminal)
cd src/Attacker/MaliciousDeliveryTechnique/technique2
python3 auto_sending_email.py
```

### 5.2 Project Structure

```
cyber_project_T1Y3/
├── README.md
├── flowChart/
│   └── somnang_attack_website/    # Phishing Website (Technique 1)
│       ├── server.js              # Express.js server
│       ├── views/                 # EJS templates
│       ├── public/                # Static assets
│       └── payload.zip            # Malicious payload
│
├── src/
│   └── Attacker/
│       ├── MaliciousDeliveryTechnique/
│       │   ├── technique1/        # Website-based delivery
│       │   └── technique2/        # Email-based delivery
│       │       ├── auto_sending_email.py
│       │       └── email_dataset.csv
│       │
│       └── malicious/             # Core malware modules
│           ├── sendDataOS.py      # Data exfiltration
│           ├── encrypData.py      # File encryption
│           └── folderMonitor.py   # Directory monitoring
│
└── Victim/                        # Victim-side simulation
```

### 5.3 Feature Implementation

#### 5.3.1 Sensitive Data Collection

The sensitive data collection module (`sendDataOS.py`) is the core malware component responsible for gathering critical information from victim systems.

**Data Categories Collected:**

| Category | Data Type | Purpose |
|----------|-----------|---------|
| System Information | OS version, hostname, username, IP address | Victim identification |
| Browser Credentials | Saved passwords, cookies, history | Account compromise |
| Wi-Fi Passwords | Stored network credentials | Network infiltration |
| SSH Keys | Private keys from `~/.ssh/` | Remote server access |
| Cloud Credentials | AWS, Azure, GCP configs | Cloud infrastructure access |
| Sensitive Documents | PDF, DOC, XLS files | Data theft |

**Implementation Architecture:**

```
sendDataOS.py
├── System Profiling      → OS, hardware, network information
├── Credential Harvesting → Browser data, Wi-Fi, SSH keys
├── File Collection       → Documents, cloud configs
└── Exfiltration          → JSON packaging, HTTPS transmission to C&C
```

**Operational Flow:**

1. **System Profiling**: Collects OS details using Python's `os`, `platform`, and `socket` modules
2. **Credential Extraction**: Targets browser SQLite databases for passwords and cookies
3. **Network Harvesting**: Extracts Wi-Fi passwords using system commands
4. **Key Discovery**: Scans for SSH keys and cloud configuration files
5. **Data Packaging**: Serializes all data into structured JSON format
6. **Exfiltration**: Transmits to C&C server via encrypted HTTPS POST

**Supporting Modules:**

| Module | Function |
|--------|----------|
| `encrypData.py` | Demonstrates ransomware-style file encryption using AES |
| `folderMonitor.py` | Real-time file system monitoring for new sensitive files |

---

#### 5.3.2 C&C Backend Endpoints

The Command & Control backend (`server.js`) serves as the central hub for managing compromised systems and storing exfiltrated data.

**Server Configuration:**

| Setting | Value |
|---------|-------|
| Framework | Express.js |
| Port | 3000 |
| Template Engine | EJS |
| Static Files | `/public` |

**API Endpoints:**

**Public-Facing (Phishing):**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Serves fake Adobe Photoshop download page |
| `/download` | GET | Delivers malicious payload (`Photoshop_Setup_Demo.zip`) |
| `/install-sim` | GET | Displays fake installation progress |

**Data Collection (C&C):**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/submit` | POST | Receives exfiltrated system data (JSON) |
| `/api/upload` | POST | Accepts stolen file uploads |
| `/api/heartbeat` | POST | Receives malware check-in signals |

**Administrative:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin` | GET | Dashboard for viewing collected data |
| `/api/victims` | GET | Returns list of compromised systems |
| `/api/logs` | GET | Returns activity logs |

**Data Submission Format:**

```json
{
  "victim_id": "unique_identifier",
  "timestamp": "2025-12-10T10:30:00Z",
  "system_info": { "os": "...", "hostname": "...", "ip": "..." },
  "collected_data": { "browsers": [...], "wifi": [...], "ssh_keys": [...] }
}
```

---

#### 5.3.3 Phishing Website

The phishing website (Technique 1) is a fake Adobe Photoshop download page designed to trick victims into downloading malware.

**Design Principles:**

| Principle | Implementation |
|-----------|----------------|
| **Authority** | Adobe branding and professional design |
| **Scarcity** | "Limited Time Offer", "Student Exclusive" |
| **Reciprocity** | Free premium software ($22.99 value) |
| **Urgency** | Time-limited messaging |

**Website Structure:**

```
flowChart/somnang_attack_website/
├── server.js                 # Express.js server
├── views/
│   ├── index.ejs            # Main phishing page
│   └── install.ejs          # Fake installation page
├── public/
│   ├── css/styles.css       # Professional styling
│   └── images/photoshop-logo.png
├── payload.zip              # Malicious download
└── payload_content/         # Payload source files
```

**Page Components:**

**Homepage (`index.ejs`):**
- Adobe Photoshop CC 2025 branding with logo
- "Get Photoshop FREE for CADT Students" headline
- Feature list: Photo Editing, AI Features, Cloud Storage, Free Updates
- Prominent "DOWNLOAD NOW" button
- Fake trust indicators and security badges

**Fake Installer (`install.ejs`):**
- Animated progress bar (0% to 100%)
- Changing status messages ("Extracting files...", "Installing...")
- Distracts victim while malware executes

**Attack Flow Integration:**

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Email Campaign │     │ Phishing Website│     │ Payload Download│
│  (Technique 2)  │────▶│  (Technique 1)  │────▶│   & Execution   │
│                 │     │                 │     │                 │
│ auto_sending_   │     │ Fake Adobe page │     │ payload.zip     │
│ email.py        │     │ with download   │     │ extracts &      │
│                 │     │ button          │     │ runs malware    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                      │                       │
         ▼                      ▼                       ▼
   Victim receives        Victim clicks           Data collected
   phishing email         "Download Now"          & sent to C&C
```

**Red Flags for Defense Training:**

| Warning Sign | Description |
|--------------|-------------|
| URL Mismatch | Domain is not `adobe.com` |
| Too Good to Be True | Premium software offered free |
| Urgency Tactics | "Limited time" pressure |
| Unusual Source | Download not from official servers |

---

## 6. Conclusion

The Malware Attack & Defense Simulation Project successfully demonstrates the full lifecycle of contemporary cyber threats by integrating both offensive and defensive cybersecurity techniques into a unified, educational framework.

**Key Achievements:**

- ✅ Implemented sensitive data collection simulating real malware behavior
- ✅ Built C&C infrastructure for managing compromised systems
- ✅ Created convincing phishing website for social engineering demonstration
- ✅ Developed email-based malware delivery system
- ✅ Documented attack techniques for educational reference

**Educational Value:**

Students gain hands-on experience with:
- Data exfiltration techniques
- Credential harvesting methods
- Phishing and social engineering
- Command-and-control communication
- Defense detection strategies

**Future Enhancements:**

- Ransomware encryption simulation
- Keylogger module
- Network traffic analysis
- Privilege escalation techniques
- Real-time security dashboard

---

## References

1. MITRE ATT&CK Framework - https://attack.mitre.org/
2. OWASP Testing Guide - https://owasp.org/
3. Python Documentation - https://docs.python.org/3/
4. Node.js Documentation - https://nodejs.org/docs/
5. Express.js Guide - https://expressjs.com/

---

## License

This project is for **educational purposes only**. Do not use any components for malicious activities. All testing must be performed in controlled environments with proper authorization.

---

**GitHub Repository:** https://github.com/Choeng-Rayu/cyber_project_T1Y3
