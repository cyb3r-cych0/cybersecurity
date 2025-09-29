import argparse
import os
import base64
from cryptography.fernet import Fernet, InvalidToken
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

def decrypt_file(encrypted_file_path, password, key_file_path, output_file_path):
    if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError(f"Encrypted file '{encrypted_file_path}' not found.")
    if not os.path.exists(key_file_path):
        raise FileNotFoundError(f"Key file '{key_file_path}' not found.")
    
    with open(key_file_path, 'rb') as f:
        salt = base64.b64decode(f.read())
    
    key = derive_key(password, salt)
    fernet = Fernet(key)
    
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except InvalidToken:
        raise ValueError("Invalid password or corrupted file.")
    
    with open(output_file_path, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"File decrypted and saved as: {output_file_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt a file using password-based key derivation.")
    parser.add_argument("--file", required=True, help="Path to the encrypted file.")
    parser.add_argument("--password", required=True, help="Password for key derivation.")
    parser.add_argument("--key-file", default="key.salt", help="Path to the salt file (default: key.salt).")
    parser.add_argument("--output", help="Path for the decrypted output file (default: {encrypted}.dec).")
    args = parser.parse_args()
    
    if not args.output:
        args.output = args.file.replace(".enc", ".dec")
    
    try:
        decrypt_file(args.file, args.password, args.key_file, args.output)
        print("Decryption completed successfully.")
    except Exception as e:
        print(f"Error during decryption: {e}")
