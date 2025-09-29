import argparse
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path, password, key_file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Input file '{file_path}' not found.")
    
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    encrypted = fernet.encrypt(data)
    
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted)
    
    with open(key_file_path, 'wb') as f:
        f.write(base64.b64encode(salt))
    
    print(f"File encrypted and saved as: {encrypted_file_path}")
    print(f"Salt saved to: {key_file_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt a file using password-based key derivation.")
    parser.add_argument("--file", required=True, help="Path to the file to encrypt.")
    parser.add_argument("--password", required=True, help="Password for key derivation.")
    parser.add_argument("--key-file", default="key.salt", help="Path to save the salt (default: key.salt).")
    args = parser.parse_args()
    
    try:
        encrypt_file(args.file, args.password, args.key_file)
        print("Encryption completed successfully.")
    except Exception as e:
        print(f"Error during encryption: {e}")
