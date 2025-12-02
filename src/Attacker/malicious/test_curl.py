#!/usr/bin/env python3
"""Test backend with curl equivalent"""

import subprocess
import json
from datetime import datetime

test_data = {
    'test': 'hello',
    'timestamp': datetime.now().isoformat(),
    'number': 123
}

url = 'https://clownfish-app-5kdkx.ondigitalocean.app/api/receive?type=test'

print("[*] Testing with requests library...")
try:
    import requests
    resp = requests.post(url, json=test_data, verify=False, timeout=10)
    print(f"Status: {resp.status_code}")
    print(f"Response: {resp.text}")
except Exception as e:
    print(f"Error: {e}")

print("\n[*] Testing with curl...")
try:
    json_data = json.dumps(test_data)
    result = subprocess.run(
        ['curl', '-X', 'POST', 
         '-H', 'Content-Type: application/json',
         '-d', json_data,
         '-k',  # insecure
         url],
        capture_output=True,
        text=True,
        timeout=10
    )
    print(f"Return code: {result.returncode}")
    print(f"Output: {result.stdout}")
    if result.stderr:
        print(f"Error: {result.stderr}")
except Exception as e:
    print(f"Error: {e}")
