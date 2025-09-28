from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def load_key(key_file_path):
    with open(key_file_path, 'r') as f:
        return bytes.fromhex(f.read().strip())

def decrypt_file(encrypted_file_path, key):
    with open(encrypted_file_path, 'rb') as f_in:
        iv = f_in.read(16)
        ciphertext = f_in.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
    
    with open(decrypted_file_path, 'wb') as f_out:
        f_out.write(plaintext)
    print(f"File decrypted and saved as: {decrypted_file_path}")

if __name__ == "__main__":
    key_file = "key.pom"
    encrypted_file = "secret.txt.enc"
    encryption_key = load_key(key_file)
    decrypt_file(encrypted_file, encryption_key)
    print(f"Decryption completed.")