from cryptography.fernet import Fernet

# Static encryption key (must be securely generated and stored in .env)
ENCRYPTION_KEY = "BnhMfP3d4n2H2k8OS7p0R9M_d5qhecbnOBuOZ43oMg0="

fernet = Fernet(ENCRYPTION_KEY)

def decrypt_sensitive_value(token: str) -> str:
    """Decrypt a previously encrypted string."""
    return fernet.decrypt(token.encode()).decode()