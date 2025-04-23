import sqlite3
import os
import hashlib
import random
import string

DB_DIR = os.getenv("DB_DIR", "/app/data")
DB_PATH = os.path.join(DB_DIR, "sshkeys.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_setting(key: str) -> str:
    conn = get_db_connection()
    cursor = conn.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    return row["value"] if row else None

def log_email(to_email: str, subject: str, status: str, error_message: str = None):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO email_logs (to_email, subject, status, error_message)
        VALUES (?, ?, ?, ?)
    ''', (to_email, subject, status, error_message))
    conn.commit()
    conn.close()