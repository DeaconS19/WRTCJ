import hashlib
import time
import sys

# Configuration
MINING_SPEED = 1000000  # Mining speed in hashes per second
DIFFICULTY = 4  # Target difficulty for mining (number of leading zeros in hash)

# Bitcoin wallet address (replace with your own)
WALLET_ADDRESS = 'bc1q7zqs0v6l4heep4d6kmarqn876xzawmedn30z5q'

def mine():
    nonce = 0
    while True:
        block_data = f'Block Data: {nonce}'
        block_data += f' Wallet Address: {WALLET_ADDRESS}'
        
        # Attempt to find a valid hash that meets the difficulty target
        while True:
            data = f'{block_data}-{nonce}'
            hash_result = hashlib.sha256(data.encode()).hexdigest()
            
            # Check if hash meets the difficulty target
            if hash_result.startswith('0' * DIFFICULTY):
                print(f'Mined a Bitcoin block! Nonce: {nonce}, Hash: {hash_result}')
                break
            
            nonce += 1
            time.sleep(1 / MINING_SPEED)

        time.sleep(0.1)  # Pause briefly before starting the next mining attempt

if __name__ == '__main__':
    try:
        print('Starting Bitcoin mining...')
        mine()
    except KeyboardInterrupt:
        print('\nMining interrupted. Exiting...')
        sys.exit(0)
