import re

FORBIDDEN_WORDS = ["admin", "password", "qwerty", "letmein", "123456", "welcome"]

def is_password_complex(password: str, username: str) -> (bool, str):
    if len(password) < 14:
        return False, "Password must be at least 14 characters long."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[^a-zA-Z0-9]', password):
        return False, "Password must contain at least one special symbol."
    if username.lower() in password.lower():
        return False, "Password cannot contain your username."
    for word in FORBIDDEN_WORDS:
        if word in password.lower():
            return False, f"Password cannot contain common word: {word}"
    return True, ""