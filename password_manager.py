# Password_Manager
import json
import os
import getpass
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import string
import sys

DATA_FILE = 'passwords.enc'
SALT_FILE = 'salt.bin'

def generate_salt():
    return os.urandom(16)

def load_salt():
    if not os.path.exists(SALT_FILE):
        salt = generate_salt()
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    else:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
    return salt

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted

def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

def load_data(key):
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'rb') as f:
        encrypted_data = f.read()
    try:
        decrypted_data = decrypt_data(encrypted_data, key)
        return json.loads(decrypted_data)
    except:
        print("Invalid master password or corrupted data.")
        return None

def save_data(data, key):
    json_data = json.dumps(data)
    encrypted_data = encrypt_data(json_data, key)
    with open(DATA_FILE, 'wb') as f:
        f.write(encrypted_data)

def set_master_password():
    password = getpass.getpass("Set master password: ")
    confirm_password = getpass.getpass("Confirm master password: ")
    if password != confirm_password:
        print("Passwords do not match.")
        return None, None
    salt = load_salt()
    key = derive_key(password, salt)
    return key, password

def verify_master_password(salt):
    password = getpass.getpass("Enter master password: ")
    key = derive_key(password, salt)
    return key, password

def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def add_entry(data, key):
    service = input("Enter service name: ")
    username = input("Enter username: ")
    choice = input("Generate password? (y/n): ").lower()
    if choice == 'y':
        password = generate_password()
        print(f"Generated password: {password}")
    else:
        password = getpass.getpass("Enter password: ")
    data[service] = {'username': username, 'password': password}
    print(f"Entry for {service} added.")

def get_entry(data):
    service = input("Enter service name to retrieve: ")
    if service in data:
        print(f"Service: {service}")
        print(f"Username: {data[service]['username']}")
        print(f"Password: {data[service]['password']}")
    else:
        print("Service not found.")

def delete_entry(data):
    service = input("Enter service name to delete: ")
    if service in data:
        del data[service]
        print(f"Entry for {service} deleted.")
    else:
        print("Service not found.")

def list_entries(data):
    if not data:
        print("No entries found.")
        return
    print("Stored services:")
    for service in data:
        print(f"- {service}")

def main():
    salt = load_salt()
    if not os.path.exists(DATA_FILE):
        print("No existing data found. Setting up new Password Manager.")
        key, _ = set_master_password()
        if key is None:
            return
        data = {}
    else:
        key, _ = verify_master_password(salt)
        if key is None:
            return
        data = load_data(key)
        if data is None:
            return

    while True:
        print("\nPassword Manager")
        print("1. Add entry")
        print("2. Get entry")
        print("3. Delete entry")
        print("4. List entries")
        print("5. Generate password")
        print("6. Exit")
        choice = input("Select an option (1-6): ")

        if choice == '1':
            add_entry(data, key)
            save_data(data, key)
        elif choice == '2':
            get_entry(data)
        elif choice == '3':
            delete_entry(data)
            save_data(data, key)
        elif choice == '4':
            list_entries(data)
        elif choice == '5':
            pwd = generate_password()
            print(f"Generated password: {pwd}")
        elif choice == '6':
            print("Exiting Password Manager.")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
