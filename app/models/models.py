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

def generate_salt(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def column_exists(conn, table_name, column_name):
    cursor = conn.execute(f"PRAGMA table_info({table_name})")
    columns = [row["name"] for row in cursor.fetchall()]
    return column_name in columns

def log_login_attempt(username, ip_address, success):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO login_attempts (username, ip_address, success)
        VALUES (?, ?, ?)
    ''', (username, ip_address, success))
    conn.commit()
    conn.close()
    
def log_admin_action(username, action, object_modified=None):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO admin_logs (admin_username, action, object_modified)
        VALUES (?, ?, ?)
    ''', (username, action, object_modified))
    conn.commit()
    conn.close()

def encrypt_password(password: str, salt: str) -> str:
    return hashlib.md5((salt + password).encode('utf-8')).hexdigest()

def get_setting(key: str) -> str:
    conn = get_db_connection()
    cursor = conn.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    return row["value"] if row else None

def set_setting(key: str, value: str):
    conn = get_db_connection()
    conn.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()

def log_email(to_email: str, subject: str, status: str, error_message: str = None):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO email_logs (to_email, subject, status, error_message)
        VALUES (?, ?, ?, ?)
    ''', (to_email, subject, status, error_message))
    conn.commit()
    conn.close()

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create tables if they don't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_md5salted TEXT NOT NULL,
            salt TEXT NOT NULL,
            must_change_password BOOLEAN DEFAULT 1
        )
    ''')

    cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            expiration_date DATETIME,
            locked BOOLEAN DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_name TEXT UNIQUE NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ssh_key_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (ssh_key_id) REFERENCES ssh_keys(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssh_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_name TEXT UNIQUE NOT NULL,
            expiration_date DATETIME,
            locked BOOLEAN DEFAULT 0,
            ssh_key_data TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_username TEXT NOT NULL,
            action TEXT NOT NULL,
            object_modified TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            server_name TEXT,
            success BOOLEAN,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

# Allowed API Sources table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS allowed_api_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_or_cidr_or_asn TEXT NOT NULL,
            type TEXT NOT NULL,
            description TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY (admin_id) REFERENCES admins(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            success BOOLEAN,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            to_email TEXT NOT NULL,
            subject TEXT NOT NULL,
            status TEXT NOT NULL, -- "Success" or "Failed"
            error_message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

# Server Assignments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS server_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            ssh_key_id INTEGER NOT NULL,
            FOREIGN KEY (server_id) REFERENCES servers(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (ssh_key_id) REFERENCES ssh_keys(id)
        )
    ''')



    # ====== SMART COLUMN ADDITIONS HERE ======

    # Admins table must have 'enabled' column
    if not column_exists(conn, "admins", "enabled"):
        print("[DB INIT] Adding missing 'enabled' column to admins...")
        conn.execute('ALTER TABLE admins ADD COLUMN enabled BOOLEAN DEFAULT 1')


# Insert default value if not exists
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('enforce_password_complexity', '0')")


    # ====== CREATE DEFAULT ADMIN IF NONE EXIST ======

    cursor.execute('SELECT COUNT(*) as count FROM admins')
    count = cursor.fetchone()["count"]

    if count == 0:
        print("[INIT_DB] No admin found. Creating default super admin...")

        default_username = "admin"
        default_email = "admin@example.com"
        default_password = "admin123"
        salt = generate_salt(8)
        password_hash = encrypt_password(default_password, salt)

        cursor.execute('''
            INSERT INTO admins (admin_username, email, password_md5salted, salt, must_change_password, enabled)
            VALUES (?, ?, ?, ?, 1, 1)
        ''', (default_username, default_email, password_hash, salt))

        print(f"[INIT_DB] Default admin created: username=admin password=admin123 (you must change password on first login!)")

    conn.commit()
    conn.close()