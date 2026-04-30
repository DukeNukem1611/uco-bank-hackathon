import requests
import json

# The URL where your FastAPI server is running
url = "http://localhost:8000/scan"

# Dummy code that contains security vulnerabilities:
# 1. Hardcoded secret (api_key = "...")
# 2. Insecure default (debug=True)
# 3. Weak cryptography (hashlib.md5)
dummy_code = """import hashlib

# Vulnerability 1: Hardcoded Secret
api_key = "super_secret_key_12345"

# Vulnerability 2: Insecure Defaults
def start_server():
    app.run(debug=True)

# Vulnerability 3: Weak Crypto
def hash_data(data):
    return hashlib.md5(data.encode())
"""

# Dummy requirements.txt content containing vulnerable packages
dummy_dependencies = """requests==2.20.0
urllib3==1.24.1
"""

# Construct the payload
payload = {
    "source_code": dummy_code,
    "dependencies": dummy_dependencies,
    "file_name": "vulnerable_app.py"
}

# Send the POST request to the API
print(f"Sending scan request to {url}...\n")
response = requests.post(url, json=payload)

# Print the beautifully formatted JSON response
if response.status_code == 200:
    print("Scan Results:")
    print(json.dumps(response.json(), indent=2))
else:
    print(f"Failed with status code: {response.status_code}")
    print(response.text)
