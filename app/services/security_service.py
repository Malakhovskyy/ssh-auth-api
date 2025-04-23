import secrets
from models.models import get_db_connection, get_setting, encrypt_password
from services.password_validator import is_password_complex

# New: Salt generator
def generate_salt(length: int = 8) -> str:
    return secrets.token_hex(length)

# Update admin password
async def update_admin_password(username: str, new_password: str, check_complexity: bool = True) -> (bool, str):
    if check_complexity and get_setting('enforce_password_complexity') == '1':
        valid, message = is_password_complex(new_password, username)
        if not valid:
            return False, message

    salt = generate_salt(8)
    password_hash = encrypt_password(new_password, salt)

    conn = get_db_connection()
    result = conn.execute(
        'UPDATE users SET password_md5salted = ?, salt = ?, must_change_password = 0 WHERE username = ?',
        (password_hash, salt, username)
    )
    conn.commit()
    conn.close()

    if result.rowcount == 0:
        return False, "Failed to update password."

    return True, ""


# Generalized user creation function
async def create_user(username: str, password: str, email: str, context: str = 'ssh_user') -> (bool, str):
    conn = get_db_connection()

    # Check duplicates
    existing_username = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if existing_username:
        conn.close()
        return False, "Username already exists."

    existing_email = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if existing_email:
        conn.close()
        return False, "Email already exists."

    # Validate password complexity if needed (for all users)
    if get_setting('enforce_password_complexity') == '1':
        valid, message = is_password_complex(password, username)
        if not valid:
            conn.close()
            return False, message

    salt = generate_salt(8)
    password_hash = encrypt_password(password, salt)

    try:
        conn.execute('''
            INSERT INTO users (username, email, password_md5salted, salt, must_change_password, enabled, context, expiration_date, locked, created_at)
            VALUES (?, ?, ?, ?, 1, 1, ?, '2099-12-31 23:59:59', 0, datetime('now'))
        ''', (username, email, password_hash, salt, context))
        conn.commit()
        conn.close()
        return True, ""
    except Exception as e:
        conn.close()
        return False, str(e)


# Generalized user update function
async def update_user(user_id: int, username: str, email: str, expiration_date: str, locked: int, context: str, password: str = None) -> (bool, str):
    conn = get_db_connection()

    # Check duplicates
    existing_username = conn.execute('SELECT id FROM users WHERE username = ? AND id != ?', (username, user_id)).fetchone()
    if existing_username:
        conn.close()
        return False, "Username already exists."

    existing_email = conn.execute('SELECT id FROM users WHERE email = ? AND id != ?', (email, user_id)).fetchone()
    if existing_email:
        conn.close()
        return False, "Email already exists."

    if password:
        salt = generate_salt(8)
        password_hash = encrypt_password(password, salt)
        conn.execute('''
            UPDATE users
            SET username = ?, email = ?, expiration_date = ?, locked = ?, context = ?, password_md5salted = ?, salt = ?
            WHERE id = ?
        ''', (username, email, expiration_date, locked, context, password_hash, salt, user_id))
    else:
        conn.execute('''
            UPDATE users
            SET username = ?, email = ?, expiration_date = ?, locked = ?, context = ?
            WHERE id = ?
        ''', (username, email, expiration_date, locked, context, user_id))

    conn.commit()
    conn.close()
    return True, ""

# Verify password for admin users
async def verify_admin_password(admin_row, plain_password: str) -> bool:
    expected_hash = encrypt_password(plain_password, admin_row['salt'])
    return expected_hash == admin_row['password_md5salted'] 