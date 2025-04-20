import secrets
from models.models import get_db_connection, encrypt_password, get_setting
from services.password_validator import is_password_complex  # we'll move password checks here

async def update_admin_password(username: str, new_password: str, check_complexity: bool = True) -> (bool, str):
    # If needed, check password complexity
    if check_complexity and get_setting('enforce_password_complexity') == '1':
        valid, message = is_password_complex(new_password, username)
        if not valid:
            return False, message

    # Generate new salt and password hash
    salt = secrets.token_hex(8)
    password_hash = encrypt_password(new_password, salt)

    # Update in database
    conn = get_db_connection()
    result = conn.execute('UPDATE admins SET password_md5salted = ?, salt = ?, must_change_password = 0 WHERE admin_username = ?', (password_hash, salt, username))
    conn.commit()
    conn.close()

    # Check if update affected exactly one row
    if result.rowcount == 0:
        return False, "Failed to update password."

    return True, ""