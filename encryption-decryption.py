# Encryption_Decryption_Tool
import os
import sys
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from getpass import getpass

def generate_keys():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization, rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    os.makedirs("keys", exist_ok=True)

    with open("keys/private_key.pem", "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    public_key = private_key.public_key()

    with open("keys/public_key.pem", "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("RSA key pair generated and saved in 'keys/' directory.")

def aes_encrypt(file_path, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()

    with open(file_path, 'rb') as f:
        data = f.read()
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    with open(f"{file_path}.aes", 'wb') as f:
        f.write(iv + encrypted)
    print(f"File encrypted successfully as {file_path}.aes")

def aes_decrypt(file_path, key):
    backend = default_backend()
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        encrypted = f.read()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    original_file = file_path.replace('.aes', '')
    with open(original_file, 'wb') as f:
        f.write(decrypted)
    print(f"File decrypted successfully as {original_file}")

def rsa_encrypt(file_path, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(f"{file_path}.rsa", 'wb') as f:
        f.write(encrypted)
    print(f"File encrypted successfully as {file_path}.rsa")

def rsa_decrypt(file_path, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    with open(file_path, 'rb') as f:
        encrypted = f.read()
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    original_file = file_path.replace('.rsa', '')
    with open(original_file, 'wb') as f:
        f.write(decrypted)
    print(f"File decrypted successfully as {original_file}")

def main():
    print("=== Encryption & Decryption Tool ===")
    print("Select an option:")
    print("1. Generate RSA Key Pair")
    print("2. Encrypt a file with AES")
    print("3. Decrypt a file with AES")
    print("4. Encrypt a file with RSA")
    print("5. Decrypt a file with RSA")
    print("6. Exit")
    
    choice = input("Enter choice (1-6): ")
    
    if choice == '1':
        generate_keys()
    elif choice == '2':
        file_path = input("Enter the file path to encrypt: ")
        key = getpass("Enter encryption key (32 bytes for AES-256): ").encode()
        if len(key) != 32:
            print("Key must be 32 bytes for AES-256.")
            sys.exit(1)
        iv = os.urandom(16)
        aes_encrypt(file_path, key, iv)
    elif choice == '3':
        file_path = input("Enter the AES-encrypted file path (.aes): ")
        key = getpass("Enter decryption key (32 bytes for AES-256): ").encode()
        if len(key) != 32:
            print("Key must be 32 bytes for AES-256.")
            sys.exit(1)
        aes_decrypt(file_path, key)
    elif choice == '4':
        file_path = input("Enter the file path to encrypt: ")
        public_key_path = input("Enter the path to the public key (keys/public_key.pem): ")
        rsa_encrypt(file_path, public_key_path)
    elif choice == '5':
        file_path = input("Enter the RSA-encrypted file path (.rsa): ")
        private_key_path = input("Enter the path to the private key (keys/private_key.pem): ")
        rsa_decrypt(file_path, private_key_path)
    elif choice == '6':
        print("Exiting...")
        sys.exit(0)
    else:
        print("Invalid choice. Please select a valid option.")
        sys.exit(1)

if __name__ == "__main__":
    main()
