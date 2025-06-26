import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

def load_ransomware_config():
    with open('ransom.json', 'r') as f:
        return json.load(f)

def generate_key(enc_type):
    if "AES" in enc_type:
        return os.urandom(32)
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
    return iv, encrypted_data

def chacha20_encrypt(data, key):
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    encrypted_data = cipher.encrypt(nonce, data, None)
    return nonce, encrypted_data

def rc4_encrypt(data, key):
    cipher = Cipher(algorithms.ARC4(key), mode=None)
    encryptor = cipher.encryptor()
    return b"", encryptor.update(data) + encryptor.finalize()

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
    return private_key, public_key

def playground():
    configs = load_ransomware_config()
    print("\nAvailable Ransomware Configs:")
    for idx, cfg in enumerate(configs, 1):
        print(f"{idx}. {cfg['ransomware']} ({cfg['enc-algo']})")
    choice = int(input("\nSelect ransomware number: ")) - 1
    if not (0 <= choice < len(configs)):
        print("Invalid choice.")
        return
    cfg = configs[choice]
    enc_type = cfg['enc-type']
    print(f"\nSelected: {cfg['ransomware']} | Encryption: {enc_type}")
    print("\n1. Enter a message\n2. Encrypt a file")
    mode = input("Choose input mode (1/2): ")
    if mode == '1':
        msg = input("Enter your message: ").encode()
        data = msg
        filename = None
    elif mode == '2':
        filename = input("Enter path to file: ")
        with open(filename, 'rb') as f:
            data = f.read()
    else:
        print("Invalid mode.")
        return
    print("\n--- Encryption Process ---")
    print("[INFO] A symmetric key is used for fast, efficient encryption of the data. Symmetric ciphers are much faster than asymmetric (RSA) and are suitable for large files.")
    key = generate_key(enc_type)
    print(f"Symmetric key: {key.hex()} (keep this secret!)")
    if 'RSA' in enc_type:
        print("[INFO] In hybrid encryption, the symmetric key is itself encrypted with the recipient's RSA public key. This allows secure key exchange: only the holder of the private key can decrypt the symmetric key and thus the data.")
        priv, pub = ensure_rsa_keys()
        print("RSA public key loaded.")
    else:
        priv = pub = None
    if enc_type == 'AES':
        print("[INFO] AES in CBC mode requires an IV (Initialization Vector) to ensure that encrypting the same data twice produces different ciphertexts. The IV should be random and unique for each encryption.")
        iv, encrypted = aes_encrypt(data, key)
        print(f"IV: {iv.hex()} (must be provided for decryption)")
        print(f"Ciphertext (IV + encrypted data, base64): {base64.b64encode(iv+encrypted).decode()}")
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(padded) + unpadder.finalize()
    elif enc_type == 'ChaCha20':
        print("[INFO] ChaCha20 is a modern stream cipher. It uses a nonce (number used once) to ensure unique encryption for each message. The nonce must be unique for each encryption with the same key.")
        nonce, encrypted = chacha20_encrypt(data, key)
        print(f"Nonce: {nonce.hex()} (must be provided for decryption)")
        print(f"Ciphertext (nonce + encrypted data, base64): {base64.b64encode(nonce+encrypted).decode()}")
        cipher = ChaCha20Poly1305(key)
        decrypted = cipher.decrypt(nonce, encrypted, None)
    elif enc_type == 'RC4':
        print("[INFO] RC4 is a legacy stream cipher. It does not use an IV or nonce, but is considered insecure for most uses today.")
        _, encrypted = rc4_encrypt(data, key)
        print(f"Ciphertext (base64): {base64.b64encode(encrypted).decode()}")
        cipher = Cipher(algorithms.ARC4(key), mode=None)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
    elif enc_type == 'AES + RSA':
        print("[INFO] Hybrid encryption: AES encrypts the data, and the AES key is encrypted with RSA. This combines the speed of symmetric encryption with the secure key exchange of asymmetric encryption.")
        iv, encrypted = aes_encrypt(data, key)
        encrypted_key = rsa_encrypt(key, pub)
        print(f"IV: {iv.hex()} (must be provided for decryption)")
        print(f"Encrypted symmetric key (RSA, base64): {base64.b64encode(encrypted_key).decode()}")
        print(f"Ciphertext (IV + encrypted data, base64): {base64.b64encode(iv+encrypted).decode()}")
        # Decrypt
        file_key = priv.decrypt(
            encrypted_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cipher = Cipher(algorithms.AES(file_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(padded) + unpadder.finalize()
    elif enc_type == 'ChaCha20 + RSA':
        print("[INFO] Hybrid encryption: ChaCha20 encrypts the data, and the ChaCha20 key is encrypted with RSA. The nonce is also needed for decryption.")
        nonce, encrypted = chacha20_encrypt(data, key)
        encrypted_key = rsa_encrypt(key, pub)
        print(f"Nonce: {nonce.hex()} (must be provided for decryption)")
        print(f"Encrypted symmetric key (RSA, base64): {base64.b64encode(encrypted_key).decode()}")
        print(f"Ciphertext (nonce + encrypted data, base64): {base64.b64encode(nonce+encrypted).decode()}")
        file_key = priv.decrypt(
            encrypted_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cipher = ChaCha20Poly1305(file_key)
        decrypted = cipher.decrypt(nonce, encrypted, None)
    elif enc_type == 'RC4 + RSA':
        print("[INFO] Hybrid encryption: RC4 encrypts the data, and the RC4 key is encrypted with RSA. This is not recommended for modern use.")
        _, encrypted = rc4_encrypt(data, key)
        encrypted_key = rsa_encrypt(key, pub)
        print(f"Encrypted symmetric key (RSA, base64): {base64.b64encode(encrypted_key).decode()}")
        print(f"Ciphertext (base64): {base64.b64encode(encrypted).decode()}")
        file_key = priv.decrypt(
            encrypted_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cipher = Cipher(algorithms.ARC4(file_key), mode=None)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
    else:
        print("Unsupported encryption type for playground.")
        return
    print(f"\n[INFO] Decryption uses the same key (and IV/nonce if needed) to recover the original data.")
    print(f"Decrypted output: {decrypted.decode(errors='replace')}")
    print("\n--- Encryption/Decryption round-trip complete! ---")

if __name__ == "__main__":
    playground() 