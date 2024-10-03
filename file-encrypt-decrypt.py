# Encrypt and decrypt files using the cryptography library.
from cryptography.fernet import Fernet

def write_key():
    """Write a new key to a file."""
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    """Load the key from the current directory named `key.key`."""
    return open("key.key", "rb").read()

def encrypt_file(filename, key):
    """Encrypt the file."""
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def decrypt_file(filename, key):
    """Decrypt the file."""
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(filename, "wb") as file:
        file.write(decrypted_data)

key = load_key()  # Load the previously generated key
filename = input("Enter the filename: ")
encrypt_file(filename, key)  # Encrypt the file
print("File encrypted.")
decrypt_file(filename, key)  # Decrypt the file
print("File decrypted.")
