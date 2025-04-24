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
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()

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
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            expiration_date TEXT NOT NULL,
            locked INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            must_change_password INTEGER DEFAULT 0,
            password_md5salted TEXT,
            salt TEXT,
            context TEXT NOT NULL DEFAULT 'ssh_user',
            created_at TEXT DEFAULT (datetime('now'))
        );
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_name TEXT UNIQUE NOT NULL,
            server_ip TEXT,
            server_ssh_port INTEGER DEFAULT 22,
            system_username TEXT,
            system_ssh_key_id INTEGER,
            proxy_id INTEGER,
            auth_token TEXT,
            FOREIGN KEY (system_ssh_key_id) REFERENCES ssh_keys(id),
            FOREIGN KEY (proxy_id) REFERENCES gateway_proxies(id)
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
            key_name TEXT NOT NULL UNIQUE,
            expiration_date TEXT NOT NULL,
            locked INTEGER DEFAULT 0,
            ssh_key_data TEXT NOT NULL,
            owner_id INTEGER,
            FOREIGN KEY (owner_id) REFERENCES users(id)
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
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            reason TEXT
        )
    ''')

# Allowed API Sources table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS allowed_api_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_or_cidr_or_asn TEXT NOT NULL,
            type TEXT NOT NULL CHECK (type IN ('ip', 'cidr', 'asn')),
            description TEXT,
            context TEXT NOT NULL DEFAULT 'api' CHECK (context IN ('api', 'admin', 'both'))
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
            provisioning_task_id INTEGER,
            FOREIGN KEY (server_id) REFERENCES servers(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (ssh_key_id) REFERENCES ssh_keys(id),
            FOREIGN KEY (provisioning_task_id) REFERENCES provisioning_tasks(id)
        )
    ''')


    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT,
            body TEXT,
            to_email TEXT,
            status TEXT DEFAULT 'queued',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            error_message TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gateway_proxies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proxy_name TEXT NOT NULL,
            proxy_ip TEXT NOT NULL,
            proxy_port INTEGER NOT NULL DEFAULT 443,
            proxy_type TEXT NOT NULL DEFAULT 'active',
            proxy_auth_token TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS provisioning_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            server_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            type TEXT NOT NULL DEFAULT 'create',
            generated_password TEXT,
            FOREIGN KEY (server_id) REFERENCES servers(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS provisioning_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            log_text TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (task_id) REFERENCES provisioning_tasks(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_ssh_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_name TEXT NOT NULL,
            key_data TEXT NOT NULL,
            key_password TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            comment TEXT
        )
    ''')



# Insert default value if not exists
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('enforce_password_complexity', '0')")


    # ====== CREATE DEFAULT ADMIN IF NONE EXIST ======

    # Check if any admin users exist
    cursor.execute("SELECT COUNT(*) as count FROM users WHERE context = 'admin'")
    count = cursor.fetchone()["count"]

    if count == 0:
        print("[INIT_DB] No admin found. Creating default super admin...")

        default_username = "admin"
        default_email = "admin@example.com"
        default_password = "admin123"
        salt = generate_salt(8)
        password_hash = encrypt_password(default_password, salt)

        cursor.execute('''
            INSERT INTO users (username, email, password_md5salted, salt, must_change_password, enabled, context, expiration_date, locked, created_at)
            VALUES (?, ?, ?, ?, 1, 1, 'admin', '2099-12-31 23:59:59', 0, datetime('now'))
        ''', (default_username, default_email, password_hash, salt))

        print(f"[INIT_DB] Default admin created: username=admin password=admin123 (you must change password on first login!)")

    conn.commit()
    conn.close()