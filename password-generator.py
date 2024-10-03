# Generates strong, random passwords using Python.
import secrets
import string

def generate_password(length):
    """Generate a secure random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

length = int(input("Enter the password length: "))
print("Generated Password:", generate_password(length))
