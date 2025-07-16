import sqlite3
import os
from typing import Optional

DATABASE_FILE = os.path.join(os.path.dirname(__file__), 'auth_data', 'database.db')

def get_db_connection(db_path: Optional[str] = None):
    """Establishes a connection to the SQLite database."""
    db_to_connect = db_path if db_path else DATABASE_FILE
    conn = sqlite3.connect(db_to_connect)
    conn.row_factory = sqlite3.Row # This allows accessing columns by name
    return conn

def init_db(db_path: Optional[str] = None):
    """Initializes the database by creating tables if they don't exist."""
    db_to_init = db_path if db_path else DATABASE_FILE
    os.makedirs(os.path.dirname(db_to_init), exist_ok=True)
    conn = get_db_connection(db_to_init)
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            last_login TEXT,
            access_key_used TEXT,
            hubert_coins INTEGER NOT NULL DEFAULT 0,
            password_reset_token TEXT,
            password_reset_expires TEXT,
            recovery_token TEXT
        )
    ''')

    # Create access_keys table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_keys (
            key TEXT PRIMARY KEY UNIQUE NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            used_count INTEGER NOT NULL DEFAULT 0,
            last_used TEXT
        )
    ''')

    # Create notifications table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (username)
        )
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print(f"Database initialized at {DATABASE_FILE}")
