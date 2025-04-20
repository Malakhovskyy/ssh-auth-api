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

async def create_admin_with_password(username: str, password: str, email: str) -> (bool, str):
    conn = get_db_connection()

    # Check if username already exists
    existing_username = conn.execute('SELECT * FROM admins WHERE admin_username = ?', (username,)).fetchone()
    if existing_username:
        conn.close()
        return False, "Username already exists."

    # Check if email already exists
    existing_email = conn.execute('SELECT * FROM admins WHERE email = ?', (email,)).fetchone()
    if existing_email:
        conn.close()
        return False, "Email already exists."

    # Check password complexity if setting enabled
    if get_setting('enforce_password_complexity') == '1':
        valid, message = is_password_complex(password, username)
        if not valid:
            conn.close()
            return False, message

    salt = secrets.token_hex(8)
    password_hash = encrypt_password(password, salt)

    try:
        conn.execute('''
            INSERT INTO admins (admin_username, email, password_md5salted, salt, must_change_password, enabled)
            VALUES (?, ?, ?, ?, 1, 1)
        ''', (username, email, password_hash, salt))
        conn.commit()
        conn.close()
        return True, ""
    except Exception as e:
        conn.close()
        return False, str(e)



async def verify_admin_password(admin_row, plain_password: str) -> bool:
    expected_hash = encrypt_password(plain_password, admin_row['salt'])
    return expected_hash == admin_row['password_md5salted']