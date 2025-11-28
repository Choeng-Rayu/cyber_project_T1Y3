# 📤 How to Send Python File to Laptop 2 - Complete Guide

## 🎯 Overview
This guide shows you **5 different ways** to send your `main.py` file to Laptop 2 and get it working.

---

## ✅ Method 1: Using Git (Recommended - Easiest)

### Prerequisites:
- Git installed on both laptops
- GitHub account (or use any Git repo)

### Step 1: On Laptop A (Your Current Laptop)
Your files are already committed to Git. Just provide the repo URL to Laptop 2.

### Step 2: On Laptop 2
```powershell
# Clone the entire project
git clone https://github.com/Choeng-Rayu/cyber_project_T1Y3.git

# Or if already cloned, pull latest updates
cd cyber_project_T1Y3
git pull origin main
```

**Result:** All files automatically downloaded to Laptop 2

---

## ✅ Method 2: USB Drive (Physical - No Network Needed)

### Step 1: On Laptop A
```powershell
# Copy the project folder to USB drive
$USBPath = "E:\"  # Replace with your USB drive letter
Copy-Item -Path "E:\cadt\y3-term1\cyber-Security\cyber-project\cyber_project_T1Y3" `
          -Destination "$USBPath\cyber_project_T1Y3" `
          -Recurse -Force
```

### Step 2: On Laptop 2
- Insert USB drive
- Copy the `cyber_project_T1Y3` folder to Laptop 2
- Done!

---

## ✅ Method 3: Email / Cloud Storage (Google Drive, OneDrive, Dropbox)

### Using Google Drive:
```
1. Go to https://drive.google.com
2. Create a folder "cyber_project_T1Y3"
3. Upload entire project folder
4. Share with email address of Laptop 2 user
5. On Laptop 2, download from Google Drive
```

### Using OneDrive:
```
1. Upload project to OneDrive
2. Share link
3. On Laptop 2, download from link
```

**Pros:** No setup needed, works anywhere
**Cons:** Internet required, slower for large files

---

## ✅ Method 4: Windows File Sharing (Network Share)

### Step 1: On Laptop A - Share the Folder
```powershell
# Right-click folder → Properties → Sharing tab → Share
# Or use PowerShell:

# Enable Network Discovery
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Share the folder
$FolderPath = "E:\cadt\y3-term1\cyber-Security\cyber-project\cyber_project_T1Y3"
Grant-SmbShareAccess -Name "cyber_project" -AccountName "Everyone" -AccessRight Change -Force
```

### Step 2: On Laptop 2 - Access the Share
```powershell
# Find Laptop A on the network
Get-ChildItem -Path "\\<LAPTOP_A_IP_OR_NAME>\cyber_project"

# Copy the files
Copy-Item -Path "\\192.168.1.100\cyber_project\*" `
          -Destination "C:\cyber_project_T1Y3" `
          -Recurse -Force
```

---

## ✅ Method 5: Direct File Transfer (Python - Simple Server)

### Step 1: On Laptop A - Create Simple HTTP Server
```powershell
cd "E:\cadt\y3-term1\cyber-Security\cyber-project\cyber_project_T1Y3"

# Start simple Python HTTP server
python -m http.server 8888
```

**Output:**
```
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

### Step 2: On Laptop 2 - Download Files
```powershell
# Download the main.py file
$url = "http://192.168.1.100:8888/source/Attacker/main.py"
$output = "C:\cyber_project\main.py"
Invoke-WebRequest -Uri $url -OutFile $output

# Or download entire project (zip it first)
$url = "http://192.168.1.100:8888/"
# Open in browser: http://192.168.1.100:8888/
```

**Or in browser on Laptop 2:**
```
http://192.168.1.100:8888/source/Attacker/main.py
```

---

## 🚀 Step-by-Step for Each Method

### **FASTEST: Method 1 (Git)**

**On Laptop 2:**
```powershell
# Create a workspace folder
mkdir "D:\Projects"
cd "D:\Projects"

# Clone the project
git clone https://github.com/Choeng-Rayu/cyber_project_T1Y3.git

# Navigate to project
cd cyber_project_T1Y3

# Install Python dependencies
pip install requests cryptography

# You're done! All files are ready
dir
```

---

### **SIMPLEST: Method 3 (USB Drive)**

**On Laptop A:**
```powershell
# Just copy to USB
Copy-Item -Recurse "E:\cadt\y3-term1\cyber-Security\cyber-project\cyber_project_T1Y3" "F:\"
```

**On Laptop 2:**
```powershell
# Copy from USB to local folder
Copy-Item -Recurse "F:\cyber_project_T1Y3" "D:\Projects\"
```

---

### **MOST FLEXIBLE: Method 5 (HTTP Server)**

**On Laptop A:**
```powershell
cd "E:\cadt\y3-term1\cyber-Security\cyber-project\cyber_project_T1Y3"
python -m http.server 8888
```

**On Laptop 2 (Browser):**
```
Open: http://192.168.1.100:8888/source/Attacker/main.py
Click download button
Or right-click → Save as
```

---

## ✨ After Sending File - Setup on Laptop 2

### Important Steps:
```powershell
# 1. Install Python packages
pip install requests cryptography

# 2. Create victim files directory
mkdir "C:\MalwareLab\VictimFiles"

# 3. Create authorization file
New-Item "C:\MalwareLab\VictimFiles\ALLOW_SIMULATION.txt" -Force

# 4. Create sample files
@"
Sensitive Data 1
"@ | Out-File "C:\MalwareLab\VictimFiles\document1.txt"

@"
Sensitive Data 2
"@ | Out-File "C:\MalwareLab\VictimFiles\document2.txt"

# 5. Update SERVER_IP in main.py
# Edit main.py and change:
# SERVER_IP = "192.168.1.100"  to your laptop A's IP

# 6. Run the script
python main.py
```

---

## 📋 Comparison Table

| Method | Speed | Complexity | Network Required | Best For |
|--------|-------|-----------|-----------------|----------|
| **Git** | ⚡⚡⚡ Fast | ⭐ Simple | ✅ Yes | Team projects |
| **USB** | ⚡⚡ Medium | ⭐ Simple | ❌ No | Air-gapped networks |
| **Email/Cloud** | ⚡ Slow | ⭐ Simple | ✅ Yes | One-time transfer |
| **File Share** | ⚡⚡⚡ Fast | ⭐⭐ Medium | ✅ Yes | Local network |
| **HTTP Server** | ⚡⚡⚡ Fast | ⭐ Simple | ✅ Yes | Quick file access |

---

## 🎓 My Recommendation

### **For Your Project:**

**Step 1:** On Laptop A - Start server (keeps running)
```powershell
cd source\Attacker
node server.js
```

**Step 2:** On Laptop 2 - Clone via Git (easiest)
```powershell
git clone https://github.com/Choeng-Rayu/cyber_project_T1Y3.git
cd cyber_project_T1Y3\source\Attacker
```

**Step 3:** On Laptop 2 - Update IP and run
```powershell
# Edit main.py: change SERVER_IP to your Laptop A's IP
python main.py
```

---

## ⚡ Quick Command Reference

### Git Method (Fastest for Projects):
```powershell
git clone https://github.com/Choeng-Rayu/cyber_project_T1Y3.git
cd cyber_project_T1Y3
pip install requests cryptography
```

### USB Method (No Network):
```powershell
# Copy entire folder to USB, then copy on Laptop 2
```

### HTTP Server Method (Browser Download):
```powershell
# On Laptop A:
python -m http.server 8888

# On Laptop 2 (browser):
http://192.168.1.100:8888/source/Attacker/main.py
```

---

## 🔧 Troubleshooting

### Problem: "Connection refused" on Laptop 2
**Solution:** Make sure Laptop A's server is running:
```powershell
# On Laptop A
node server.js
```

### Problem: "File not found" on Laptop 2
**Solution:** Check if you copied the `VictimFiles` folder:
```powershell
mkdir C:\MalwareLab\VictimFiles
New-Item C:\MalwareLab\VictimFiles\ALLOW_SIMULATION.txt -Force
```

### Problem: "requests module not found"
**Solution:** Install Python packages on Laptop 2:
```powershell
pip install requests cryptography
```

### Problem: Can't access Laptop A via network
**Solution:** Check firewall on Laptop A:
```powershell
# Allow Port 5000 through firewall
New-NetFirewallRule -DisplayName "Allow Port 5000" `
                     -Direction Inbound `
                     -LocalPort 5000 `
                     -Protocol TCP `
                     -Action Allow
```

---

## 📝 Final Checklist

### Before Running on Laptop 2:
- [ ] Python file copied to Laptop 2
- [ ] Dependencies installed: `pip install requests cryptography`
- [ ] `VictimFiles` directory created
- [ ] `ALLOW_SIMULATION.txt` file created
- [ ] Sample victim files created
- [ ] `SERVER_IP` updated to Laptop A's IP
- [ ] Laptop A server (`node server.js`) is running

### To Start Experiment:
- [ ] Run `python main.py` on Laptop 2
- [ ] Check Laptop A server console for upload confirmations
- [ ] Verify files in `uploads/` directory on Laptop A

---

**Choose the method that works best for your network setup! 🚀**
