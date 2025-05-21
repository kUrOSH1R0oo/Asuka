#!/usr/bin/env python3
"""
Asuka Database Initialization Module
This script initializes a SQLite database for the Asuka Phishing Framework. It creates
two tables ('credentials' and 'sessions') to store captured credentials and session data,
along with indexes to optimize queries by timestamp. It includes error handling and logging
for robust database setup.
"""

import sqlite3
import logging
import sys

def init_db():
    """
    Initializes the SQLite database 'asuka_data.db' with two tables:
    - credentials: Stores captured login details (username, password, IP, etc.).
    - sessions: Stores session information (IP, user agent, geolocation, etc.).
    Creates indexes on the timestamp columns for efficient querying.
    Exits the program on database errors after logging.
    """
    try:
        conn = sqlite3.connect('asuka_data.db', timeout=10)  # Connect to SQLite database with 10-second timeout
        c = conn.cursor()
        # Create credentials table with fields for storing captured login data
        c.execute('''CREATE TABLE IF NOT EXISTS credentials
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      timestamp TEXT,
                      username TEXT,
                      password TEXT,
                      ip TEXT,
                      user_agent TEXT,
                      cookies TEXT,
                      headers TEXT,
                      raw_data TEXT,
                      csrf_token TEXT)''')
        # Create sessions table with fields for storing session data
        c.execute('''CREATE TABLE IF NOT EXISTS sessions
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      timestamp TEXT,
                      ip TEXT,
                      user_agent TEXT,
                      path TEXT,
                      geolocation TEXT)''')
        # Create index on credentials timestamp for faster queries
        c.execute('''CREATE INDEX IF NOT EXISTS idx_credentials_timestamp ON credentials (timestamp)''')
        # Create index on sessions timestamp for faster queries
        c.execute('''CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON sessions (timestamp)''')
        conn.commit()  # Commit changes to the database
        logging.info("Database initialized successfully")
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
        print(f"{Fore.RED}Database error: {e}{Style.RESET_ALL}")  # Print error in red (assumes colorama or similar)
        sys.exit(1)  # Exit program on database error
    finally:
        conn.close()  # Ensure database connection is closed