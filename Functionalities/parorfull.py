from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

# Helper function to pad data for AES block size (16 bytes)
def pad(data):
    padding_len = AES.block_size - len(data) % AES.block_size
    return data + (bytes([padding_len]) * padding_len)

# Function for full encryption
def full_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.iv + cipher.encrypt(pad(data))
    return ciphertext

# Function for partial encryption (first 64KB)
def partial_encrypt(data, key):
    size_to_encrypt = 64 * 1024  # 64KB
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_part = cipher.iv + cipher.encrypt(pad(data[:size_to_encrypt]))
    return encrypted_part + data[size_to_encrypt:]  # Combine encrypted part with rest of file

# Encryption function based on file size
def encrypt_file(file_path):
    file_size = os.path.getsize(file_path)
    
    with open(file_path, 'rb') as f:
        file_data = f.read()

    key = get_random_bytes(32)  # AES-256 key
    
    # If the file is less than or equal to 64KB, perform full encryption
    if file_size <= (64 * 1024):  # Less than or equal to 64KB
        print(f"Full encryption for file: {file_path} (size: {file_size} bytes)")
        encrypted_data = full_encrypt(file_data, key)
    
    # If the file is between 64KB and 1MB, perform partial encryption (first 64KB)
    elif (64 * 1024) < file_size <= (1 * 1024 * 1024):  # Between 64KB and 1MB
        print(f"Partial encryption for file: {file_path} (size: {file_size} bytes)")
        encrypted_data = partial_encrypt(file_data, key)
    
    else:
        print(f"File too large for this scheme: {file_path} (size: {file_size} bytes)")
        encrypted_data = full_encrypt(file_data, key)  # You can customize this for larger files
    
    # Save the encrypted file
    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)
    
    print(f"Encryption complete. Encrypted file saved as: {encrypted_file_path}")
    return key, encrypted_file_path

# Test encryption
file_path = 'test_file.txt'  # Replace with the path to your file
key, encrypted_file_path = encrypt_file(file_path)
