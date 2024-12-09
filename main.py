import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import base64

class SecuredEncryptionSystem:
    def __init__(self):
        self.users = {}  # A dictionary to store user data (username: password)

    def register_user(self, username, password):
        if username in self.users:
            return "User already exists!"
        self.users[username] = self.hash_password(password)
        return "User registered successfully!"

    def authenticate_user(self, username, password):
        hashed = self.hash_password(password)
        if username in self.users and self.users[username] == hashed:
            return "Authentication successful!"
        return "Authentication failed!"

    def hash_password(self, password):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(password.encode())
        return base64.urlsafe_b64encode(digest.finalize()).decode()

    def generate_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, password, input_file, output_file):
        salt = os.urandom(16)
        key = self.generate_key(password, salt)

        with open(input_file, "rb") as f:
            plaintext = f.read()

        padder = PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        with open(output_file, "wb") as f:
            f.write(salt + iv + ciphertext)

        return "File encrypted successfully!"

    def decrypt_file(self, password, input_file, output_file):
        with open(input_file, "rb") as f:
            data = f.read()

        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]

        key = self.generate_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        with open(output_file, "wb") as f:
            f.write(plaintext)

        return "File decrypted successfully!"

# Example usage
if __name__ == "__main__":
    ses = SecuredEncryptionSystem()

    # Register a user
    print(ses.register_user("test_user", "secure_password"))

    # Authenticate a user
    print(ses.authenticate_user("test_user", "secure_password"))

    # Encrypt a file
    print(ses.encrypt_file("secure_password", "input.txt", "encrypted.dat"))

    # Decrypt the file
    print(ses.decrypt_file("secure_password", "encrypted.dat", "decrypted.txt"))
