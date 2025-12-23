#!/bin/bash
echo "Setting up Metasploit Integration..."
echo "====================================="

# Install Python module for Metasploit RPC
pip3 install pymetasploit3

# Start Metasploit RPC daemon (in background)
echo "[*] Starting Metasploit RPC daemon..."
msfrpcd -P password -S -f &

# Wait for it to start
sleep 5

echo "[+] Metasploit RPC daemon running on port 55553"
echo "[+] Username: msf"
echo "[+] Password: password"

# Create test script
echo "[*] Creating test script..."
cat > test_msf.py << 'EOF'
#!/usr/bin/env python3
from pymetasploit3.msfrpc import MsfRpcClient

# Connect to MSF RPC
client = MsfRpcClient('password', port=55553)

# List exploits
print("Available exploits:", len(client.modules.exploits))

# List payloads
print("Available payloads:", len(client.modules.payloads))

print("[+] Metasploit RPC connection successful!")
EOF

chmod +x test_msf.py
python3 test_msf.py

echo ""
echo "Setup complete! Run your framework with: python3 main.py"
