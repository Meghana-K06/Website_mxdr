import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'bank.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT NOT NULL UNIQUE,
            password  TEXT NOT NULL,
            full_name TEXT,
            email     TEXT,
            balance   REAL DEFAULT 0.00
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user  TEXT,
            to_user    TEXT,
            amount     REAL,
            note       TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS messages (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT,
            message    TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    # Seed users
    users = [
        ('admin',     'admin123',    'Admin User',    'admin@securbank.com',  99999.00),
        ('john_doe',  'password123', 'John Doe',      'john@example.com',     15420.75),
        ('jane_doe',  'jane2024',    'Jane Doe',      'jane@example.com',      8900.50),
        ('alice',     'alice123',    'Alice Johnson', 'alice@example.com',     3200.00),
        ('bob',       'bob123',      'Bob Smith',     'bob@example.com',       6750.25),
    ]
    cursor.executemany('''
        INSERT OR IGNORE INTO users (username, password, full_name, email, balance)
        VALUES (?, ?, ?, ?, ?)
    ''', users)

    # Seed transactions
    transactions = [
        ('john_doe', 'jane_doe', 500.00,  'Rent payment'),
        ('alice',    'bob',      250.00,  'Dinner split'),
        ('admin',    'john_doe', 1000.00, 'Bonus'),
    ]
    cursor.executemany('''
        INSERT OR IGNORE INTO transactions (from_user, to_user, amount, note)
        VALUES (?, ?, ?, ?)
    ''', transactions)

    conn.commit()
    conn.close()
    print('✅ Database initialized with seed data')

if __name__ == '__main__':
    init_db()
