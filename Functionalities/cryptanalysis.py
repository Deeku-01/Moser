import os
from collections import Counter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import matplotlib.pyplot as plt
import numpy as np
import json

def rc4_bruteforce_demo(encrypted_data, known_plaintext):
    print("Brute-forcing 1-byte RC4 key...")
    for k in range(256):
        key = bytes([k])
        cipher = Cipher(algorithms.ARC4(key), mode=None)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        if known_plaintext in decrypted:
            print(f"Key found: {key.hex()}\nDecrypted: {decrypted}")
            return key, decrypted
    print("Key not found.")
    return None, None

def aes_ecb_pattern_analysis(encrypted_data, block_size=16):
    print("Analyzing ciphertext for block repetition (AES-ECB pattern)...")
    blocks = [encrypted_data[i:i+block_size] for i in range(0, len(encrypted_data), block_size)]
    counter = Counter(blocks)
    repeated = {block: count for block, count in counter.items() if count > 1}
    if repeated:
        print(f"Repeated blocks detected: {len(repeated)}")
        for block, count in repeated.items():
            print(f"Block: {block.hex()} | Count: {count}")
    else:
        print("No repeated blocks detected.")

def load_ransomware_config():
    with open('ransom.json', 'r') as f:
        return json.load(f)

def detect_family_by_extension(file_path, configs):
    for cfg in configs:
        if file_path.endswith(cfg['extension']):
            return cfg['ransomware'], cfg
    return None, None

def block_repetition_map(data, block_size=16):
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    counter = Counter(blocks)
    repeated = {block: count for block, count in counter.items() if count > 1}
    return repeated, len(blocks)

def entropy(data, window=256):
    # Sliding window entropy
    ent = []
    for i in range(0, len(data), window):
        chunk = data[i:i+window]
        if not chunk:
            continue
        counts = np.array(list(Counter(chunk).values()))
        probs = counts / counts.sum()
        ent.append(-np.sum(probs * np.log2(probs)))
    return ent

def analyze_encrypted_file(file_path, configs):
    print(f"\n--- Analyzing: {file_path} ---")
    with open(file_path, 'rb') as f:
        data = f.read()
    family, cfg = detect_family_by_extension(file_path, configs)
    if family:
        print(f"Detected ransomware family: {family}")
        print(f"Encryption type: {cfg['enc-type']}")
    else:
        print("Ransomware family: Unknown (extension not recognized)")
        cfg = None
    # Block repetition analysis (for AES-ECB, etc.)
    repeated, total_blocks = block_repetition_map(data)
    if repeated:
        print(f"[!] Repeated blocks detected: {len(repeated)} out of {total_blocks} blocks (possible ECB mode)")
    else:
        print("No repeated blocks detected (likely not ECB mode)")
    # Entropy visualization
    try:
        ent = entropy(data)
        plt.figure(figsize=(8,3))
        plt.plot(ent)
        plt.title('Sliding Window Entropy')
        plt.xlabel('Window #')
        plt.ylabel('Entropy (bits)')
        plt.tight_layout()
        plt.show()
    except Exception as e:
        print(f"[!] Could not plot entropy: {e}")
    print("--- Analysis complete ---\n")

def main():
    print("Cryptanalysis Tools:")
    print("1. RC4 1-byte key brute-force demo")
    print("2. AES-ECB block repetition analysis")
    print("3. Ransomware Sample Analyzer")
    choice = input("Select tool (1/2/3): ")
    file_path = input("Enter path to encrypted file: ")
    if choice == '1':
        known = input("Enter known plaintext (ASCII): ").encode()
        rc4_bruteforce_demo(data, known)
    elif choice == '2':
        aes_ecb_pattern_analysis(data)
    elif choice == '3':
        configs = load_ransomware_config()
        analyze_encrypted_file(file_path, configs)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main() 