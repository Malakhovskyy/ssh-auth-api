import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "../../sshkeys.db")
DB_PATH = os.path.abspath(DB_PATH)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    # Admins table
    c.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_md5salted TEXT NOT NULL,
            salt TEXT NOT NULL,
            must_change_password BOOLEAN DEFAULT 1
        )
    ''')

    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL
        )
    ''')

    # SSH Keys table
    c.execute('''
        CREATE TABLE IF NOT EXISTS ssh_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ssh_key TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Servers table
    c.execute('''
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_name TEXT UNIQUE NOT NULL
        )
    ''')

    # Assignments table
    c.execute('''
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            server_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(server_id) REFERENCES servers(id)
        )
    ''')

    # Admin logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_username TEXT,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # API access logs
    c.execute('''
        CREATE TABLE IF NOT EXISTS api_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_name TEXT,
            username TEXT,
            status TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Allowed API sources (IP, CIDR, ASN)
    c.execute('''
        CREATE TABLE IF NOT EXISTS allowed_api_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_type TEXT,
            value TEXT,
            description TEXT
        )
    ''')

    # Password reset tokens
    c.execute('''
        CREATE TABLE IF NOT EXISTS reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            token TEXT,
            expires_at DATETIME,
            FOREIGN KEY(admin_id) REFERENCES admins(id)
        )
    ''')

    conn.commit()
    conn.close()