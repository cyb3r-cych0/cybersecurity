from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def encrypt_file(file_path, key):
    """Encrypts a file using AES in CBC mode."""
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(file_path, 'rb') as f_in:
        plaintext = f_in.read()
    
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f_out:
        f_out.write(iv)
        f_out.write(ciphertext)
    print(f"File encrypted and saved as: {encrypted_file_path}")

def save_key(key, key_file_path):
    with open(key_file_path, 'w') as f:
        f.write(key.hex())
    print(f"Encryption key saved to: {key_file_path}")

if __name__ == "__main__":
    encryption_key = get_random_bytes(16) 

    original_file = "secret.txt"
    with open(original_file, 'w') as f:
        f.write("This is a very secret message!")

    encrypt_file(original_file, encryption_key)
    save_key(encryption_key, "key.pom")
    print(f"Encryption completed.")