import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket

def encrypt_file_aes(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename + ".enc", "wb") as file:
        file.write(encrypted_data)

def decrypt_file_aes(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(filename[:-4], "wb") as file:  # Remove ".enc" from filename
        file.write(decrypted_data)

def encrypt_file_3des(filename, key):
    backend = default_backend()
    iv = os.urandom(8)  # Generate 8-byte initialization vector
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    with open(filename, "rb") as file:
        plaintext = file.read()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    with open(filename + ".enc", "wb") as file:
        file.write(iv + ciphertext)

def decrypt_file_3des(filename, key):
    backend = default_backend()
    with open(filename, "rb") as file:
        iv = file.read(8)
        ciphertext = file.read()
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    with open(filename[:-4], "wb") as file:  # Remove ".enc" from filename
        file.write(plaintext)

# Choose mode (sender or receiver)
mode = input("Choose mode (sender or receiver): ")

if mode == "sender":
    # Encryption and sending
    algorithm = input("Choose algorithm (AES or 3DES): ")
    key = Fernet.generate_key() if algorithm == "AES" else os.urandom(24)  # 16 bytes for AES, 24 for 3DES
    filename = input("Enter filename to encrypt: ")
    if algorithm == "AES":
        encrypt_file_aes(filename, key)
    else:
        encrypt_file_3des(filename, key)

    host = "127.0.0.1"
    port = 12345 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    with open(filename + ".enc", "rb") as file:
        data = file.read()
        s.sendall(data)
    s.close()

elif mode == "receiver":
    # Receiving and decryption
    port = 12345  # Use same port as sender
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))  # Bind to all interfaces
    s.listen()
    conn, addr = s.accept()
    with open("received_file.enc", "wb") as file:
        data = conn.recv(1024)
        while data:
            file.write(data)
            data = conn.recv(1024)
    s.close()

    algorithm = input("Enter algorithm used for encryption (AES or 3DES): ")
    key = input("Enter the shared encryption key: ")
    filename = "received_file.enc"

  
