#!/usr/bin/env python3
from pymetasploit3.msfrpc import MsfRpcClient

# Connect to MSF RPC
client = MsfRpcClient('password', port=55553)

# List exploits
print("Available exploits:", len(client.modules.exploits))

# List payloads
print("Available payloads:", len(client.modules.payloads))

print("[+] Metasploit RPC connection successful!")
