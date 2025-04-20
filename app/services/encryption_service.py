from cryptography.fernet import Fernet
import os

FERNET_KEY = os.getenv("ENCRYPTION_KEY")

if not FERNET_KEY:
    raise ValueError("Missing ENCRYPTION_KEY environment variable!")

fernet = Fernet(FERNET_KEY)

def encrypt_sensitive_value(value: str) -> str:
    return fernet.encrypt(value.encode()).decode()

def decrypt_sensitive_value(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()