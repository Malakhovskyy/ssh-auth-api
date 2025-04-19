import secrets
import sqlite3
from datetime import datetime, timedelta

DB_PATH = "sshkeys.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def generate_reset_token(admin_id):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)

    conn = get_db_connection()
    conn.execute('INSERT INTO reset_tokens (admin_id, token, expires_at) VALUES (?, ?, ?)',
                 (admin_id, token, expires_at.strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    return token

def verify_reset_token(token):
    conn = get_db_connection()
    token_entry = conn.execute('SELECT * FROM reset_tokens WHERE token = ?', (token,)).fetchone()
    conn.close()

    if token_entry:
        expires_at = datetime.strptime(token_entry["expires_at"], '%Y-%m-%d %H:%M:%S')
        if datetime.utcnow() <= expires_at:
            return token_entry["admin_id"]

    return None