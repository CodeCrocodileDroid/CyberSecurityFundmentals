from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os


class SecureEncryption:
    def __init__(self):
        self.key = None

    def generate_key(self):
        """Generate a new encryption key"""
        return Fernet.generate_key()

    def derive_key_from_password(self, password, salt=None):
        """Derive encryption key from password"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def encrypt_data(self, data, password=None):
        """Encrypt dataset with password or generated key"""
        if password:
            key, salt = self.derive_key_from_password(password)
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(salt + encrypted_data).decode()
        else:
            if not self.key:
                self.key = self.generate_key()
            fernet = Fernet(self.key)
            return fernet.encrypt(data.encode())

    def decrypt_data(self, encrypted_data, password=None):
        """Decrypt dataset"""
        if password:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            salt = encrypted_bytes[:16]
            encrypted_content = encrypted_bytes[16:]

            key, _ = self.derive_key_from_password(password, salt)
            fernet = Fernet(key)
            return fernet.decrypt(encrypted_content).decode()
        else:
            if not self.key:
                raise ValueError("No key available for decryption")
            fernet = Fernet(self.key)
            return fernet.decrypt(encrypted_data).decode()


# Example usage
encryptor = SecureEncryption()

# Password-based encryption
message = "This is a secret message!"
password = "MySecurePassword123!"

encrypted = encryptor.encrypt_data(message, password)
print(f"Encrypted: {encrypted}")

decrypted = encryptor.decrypt_data(encrypted, password)
print(f"Decrypted: {decrypted}")

# Key-based encryption
key = encryptor.generate_key()
encryptor.key = key
encrypted2 = encryptor.encrypt_data("Another secret message")
print(f"Key-based encrypted: {encrypted2}")
decrypted2 = encryptor.decrypt_data(encrypted2)
print(f"Key-based decrypted: {decrypted2}")