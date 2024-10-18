import sqlite3
import os

def setup_device_db():
    # Create device.db if it doesn't exist
    conn = sqlite3.connect('device.db')
    cursor = conn.cursor()

    # Create router_device table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS router_device (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_type TEXT,
        ip_address TEXT,
        user TEXT,
        password TEXT,
        secret_password TEXT,
        hostname TEXT,
        date_add TEXT,
        device_p TEXT
    )
    ''')

    # Create sl2_device table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sl2_device (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_type TEXT,
        ip_address TEXT,
        user TEXT,
        password TEXT,
        secret_password TEXT,
        hostname TEXT,
        date_add TEXT,
        device_p TEXT
    )
    ''')

    # Create sl3_device table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sl3_device (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_type TEXT,
        ip_address TEXT,
        user TEXT,
        password TEXT,
        secret_password TEXT,
        hostname TEXT,
        date_add TEXT,
        device_p TEXT
    )
    ''')

    conn.commit()
    conn.close()
    print("device.db setup complete.")

def setup_user_db():
    # Create user.db if it doesn't exist
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()

    # Create log table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS log (
        id INTEGER PRIMARY KEY,
        event TEXT,
        username TEXT,
        timestamp TEXT
    )
    ''')

    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT
    )
    ''')

    conn.commit()
    conn.close()
    print("user.db setup complete.")

if __name__ == "__main__":
    setup_device_db()
    setup_user_db()
    print("Database setup complete.")