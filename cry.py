from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from cryptography.hazmat.primitives import hashes
import os

def pad_data(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(padded_data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    with open(file_path, 'rb') as file:
        data = file.read()

    salt = os.urandom(16)
    key = generate_key(password, salt)

    data = pad_data(data)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    with open('encrypted_file.txt', 'wb') as file:
        file.write(salt + iv + encrypted_data)

    print("File encrypted and saved as 'encrypted_file.txt'.")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as file:
        salt = file.read(16)
        iv = file.read(16)
        encrypted_data = file.read()

    key = generate_key(password, salt)

    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        decrypted_data = unpad_data(decrypted_data)

        with open('decrypted_file.txt', 'wb') as file:
            file.write(decrypted_data)

        print("File decrypted and saved as 'decrypted_file.txt'.")
    except Exception as e:
        print("Decryption failed. Incorrect password or corrupted file.")


password = input("Enter password for encryption/decryption: ")

choice = input("Enter 'enc' for encryption or 'dec' for decryption: ")

if choice == 'enc':
    file_path = input('Enter filename:')  # Replace this with your text file's path
    encrypt_file(file_path, password)
elif choice == 'dec':
    file_path = 'encrypted_file.txt'  # Replace this with the encrypted file's path
    decrypt_file(file_path, password)
else:
    print("Invalid choice. Please enter 'enc' or 'dec'.")