from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import os
import sys

def custom_reverse_shift_rows(state):
    # Define the reverse of the custom shift amounts for each row
    shifts = [0, -2, -1, -3]  # Reverse pattern: 0 for no shift, negative values for right shifts

    # Apply the reverse shifts to each row
    for i in range(len(state)):
        state[i] = state[i][shifts[i]:] + state[i][:shifts[i]]

    return state


def generate_key(password, salt):
    key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    return key


def custom_shift_rows(state):
    # Define custom shift amounts for each row
    shifts = [0, 2, 1, 3]  # Custom pattern: 0 for no shift, 1 for left by 1, 2 for left by 2, 3 for left by 3

    # Apply custom shifts to each row
    for i in range(len(state)):
        state[i] = state[i][shifts[i]:] + state[i][:shifts[i]]

    return state

def pad_data(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(padded_data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encrypt_file(file_path, password):
    with open(file_path, 'rb') as file:
        data = file.read()

    salt = os.urandom(16)
    key = generate_key(password.encode(), salt)

    cipher = AES.new(key, AES.MODE_ECB)

    # Ensure data is padded to match block size
    data = pad(data, AES.block_size)

    # Split data into blocks
    blocks = [data[i:i + AES.block_size] for i in range(0, len(data), AES.block_size)]

    encrypted_blocks = []
    for block in blocks:
        state = [block[i:i + 4] for i in range(0, len(block), 4)]
        
        # Custom ShiftRows step
        state = custom_shift_rows(state)

        # Convert state back to bytes
        modified_block = b''.join(state)

        # Encrypt the modified block
        encrypted_block = cipher.encrypt(modified_block)
        encrypted_blocks.append(encrypted_block)

    # Write encrypted blocks to file
    with open('encrypted_file.txt', 'wb') as file:
        file.write(salt)
        for block in encrypted_blocks:
            file.write(block)

    print("File encrypted and saved as 'encrypted_file.txt'.")

# The rest of the code remains similar for decryption and other functionalities...

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as file:
        salt = file.read(16)
        encrypted_data = file.read()

    key = generate_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_ECB)

    # Split encrypted data into blocks
    block_size = AES.block_size
    encrypted_blocks = [encrypted_data[i:i + block_size] for i in range(0, len(encrypted_data), block_size)]

    decrypted_blocks = []
    try:
        for block in encrypted_blocks:
            decrypted_block = cipher.decrypt(block)

            # Reverse the custom ShiftRows operation
            state = [decrypted_block[i:i + 4] for i in range(0, len(decrypted_block), 4)]
            # Custom reverse ShiftRows step
            state = custom_reverse_shift_rows(state)

            # Convert state back to bytes
            modified_block = b''.join(state)
            decrypted_blocks.append(modified_block)

        # Join decrypted blocks and unpad the data
        decrypted_data = b''.join(decrypted_blocks)
        decrypted_data = unpad(decrypted_data, AES.block_size)

        with open('decrypted_file.txt', 'wb') as file:
            file.write(decrypted_data)

        print("File decrypted and saved as 'decrypted_file.txt'.")

    except Exception as e:
        print("Decryption failed. Incorrect password or corrupted file.")
        # Handle the exception or re-raise to propagate the error
        # raise e


# password = input("Enter password for encryption/decryption: ")

# choice = input("Enter 'enc' for encryption or 'dec' for decryption: ")

# if choice == 'enc':
#     file_path = input('Enter filename:')  # Replace this with your text file's path
#     encrypt_file(file_path, password)
# elif choice == 'dec':
#     file_path = 'encrypted_file.txt'  # Replace this with the encrypted file's path
#     decrypt_file(file_path, password)
# else:
#     print("Invalid choice. Please enter 'enc' or 'dec'.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python cry.py <enc/dec> <filename>")
        sys.exit(1)

    choice = sys.argv[1]
    file_path = sys.argv[2]

    password = input("Enter password for encryption/decryption: ")

    if choice == 'enc':
        encrypt_file(file_path, password)
    elif choice == 'dec':
        decrypt_file(file_path, password)
    else:
        print("Invalid choice. Please enter 'enc' or 'dec'.")