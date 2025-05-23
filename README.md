# Asuka Phishing Framework

## Overview

The Asuka Phishing Framework is a Python-based tool designed for educational and authorized security testing purposes. It allows users to clone a target website, host it on a local phishing server, and capture credentials, session data, and user interactions. The framework leverages modern web scraping, dynamic rendering, and server technologies to create convincing website replicas while storing captured data securely in a SQLite database. It includes features like form modification, JavaScript injection for obfuscation, and concurrent request handling.

**Important**: This tool is intended solely for ethical use in authorized security assessments, such as penetration testing with explicit permission. Unauthorized use for malicious phishing is illegal, unethical, and can cause significant harm. Always obtain proper authorization before using this tool.

## Features

- **Website Cloning**: Uses Playwright for dynamic page rendering and BeautifulSoup for HTML parsing to clone target websites accurately.
- **Asset Downloading**: Optionally downloads static assets (e.g., images, CSS, JavaScript) to ensure the cloned site closely resembles the original.
- **Multi-Page Cloning**: Recursively clones linked pages up to a configurable depth for comprehensive site replication.
- **Credential Capture**: Modifies HTML forms to capture usernames, passwords, CSRF tokens, and other form data, with fallback parsing for non-standard fields.
- **Data Encryption**: Employs Fernet symmetric encryption to secure captured data during transmission.
- **Session Tracking**: Logs session details, user agent, and requested paths.
- **Local Phishing Server**: Runs a concurrent HTTP server using Python’s `ThreadingHTTPServer` to serve cloned pages and handle POST requests.
- **Database Storage**: Stores captured credentials and session data in a SQLite database (`asuka_data.db`) with indexed tables for efficient querying.
- **Custom JavaScript Injection**: Supports injecting custom JavaScript for additional functionality or obfuscation (Only 1 for now).
- **Obfuscation Techniques**: Injects JavaScript to spoof browser properties (e.g., `navigator.webdriver`) and simulate human-like behavior (e.g., mouse movements, clicks).
- **Dynamic Content Handling**: Uses Playwright to capture dynamically loaded images and monitor DOM changes via MutationObserver.
- **Logging**: Detailed logging to files (`error.log`, `clone.log`, `server.log`, etc.) with optional console output and a custom filter to reduce noise from non-critical errors.
- **Duplicate Prevention**: Prevents duplicate credential submissions within a 5-second window to avoid redundant data.

## Technical Architecture

The framework is modular, with each file handling specific functionality:

1. **asuka.py**: The main entry point, orchestrating the framework. It parses command-line arguments, sets up logging, initializes the database, clones the target website, and starts the phishing server.
2. **database.py**: Initializes a SQLite database with two tables (`credentials` and `sessions`) and creates indexes on timestamp fields for efficient querying.
3. **utils.py**: Provides utility functions for downloading web assets (e.g., images, CSS) and retrieving geolocation data using `socket.gethostbyaddr`.
4. **clone.py**: Handles website cloning, including dynamic rendering with Playwright, HTML parsing with BeautifulSoup, form modification, and JavaScript injection for credential capture and obfuscation.
5. **server.py**: Implements a concurrent HTTP server to serve cloned pages, capture POST data (credentials, AJAX, keylogs, etc.), and log interactions to files and the database.

## Requirements

- **Python**: Version 3.6 or higher.
- **Dependencies**:
  - `requests`: For HTTP requests to download assets.
  - `beautifulsoup4`: For HTML parsing and modification.
  - `playwright`: For dynamic page rendering and JavaScript execution.
  - `cryptography`: For Fernet encryption of captured data.
  - `netifaces`: For auto-detecting local IP addresses.
- **System Dependencies**: Playwright requires browser binaries (Chromium) for rendering.

## Installation

1. **Clone the Repository** (or download the source files):

   ```bash
   git clone <repository-url>
   cd asuka-phishing-framework
   ```

2. **Create a Virtual Environment** (recommended):

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Python Dependencies**:

   Create a `requirements.txt` file with the following content:

   ```
   requests
   beautifulsoup4
   playwright
   cryptography
   netifaces
   pyshorteners
   ```

   Then run:

   ```bash
   pip install -r requirements.txt
   ```

4. **Install Playwright Browser Binaries**:

   ```bash
   playwright install
   ```

5. **Verify Permissions**:

   Ensure the user has write permissions for the directory to store:
   - Cloned templates (`templates/fake/`).
   - SQLite database (`asuka_data.db`).
   - Log files (`error.log`, `clone.log`, `server.log`, `credentials.log`, etc.).
   - Fernet key (`fernet_key.bin`).

   On Linux/macOS, set permissions if needed:

   ```bash
   chmod -R u+rw .
   ```

## Usage

Run the main script (`asuka.py`) with the required `--url` argument and optional parameters to customize the cloning and server behavior:

```bash
python asuka.py --url <target-url> [options]
```

### Command-Line Arguments

| Argument         | Description                                                                 | Required | Default Value                |
|------------------|-----------------------------------------------------------------------------|----------|------------------------------|
| `--url`          | Target website URL to clone (e.g., `https://example.com`).                   | Yes      | N/A                          |
| `--port`         | Port for the HTTP server.                                                   | No       | 4443                         |
| `--host`         | Host IP address for the server (auto-detected if not specified).             | No       | Auto-detected local IP       |
| `--assets`       | Download assets like images, CSS, and JS (`yes` or `no`).                    | No       | `yes`                        |
| `--multi-page`   | Clone linked pages recursively (`yes` or `no`).                              | No       | `no`                         |
| `--custom-js`    | Path to a custom JavaScript file to inject into the cloned site.             | No       | Empty string (`''`)          |
| `--redirect-url` | URL to redirect users to after credential capture.                           | No       | `https://www.example.com`    |
| `--show-logs`    | Display logs in the console (flag, no value needed).                         | No       | Disabled                     |

### Example Commands

1. **Basic Usage** (clone a website and host it locally):

   ```bash
   python asuka.py --url https://example.com --port 8080
   ```

   - Clones `https://example.com`.
   - Downloads assets.
   - Hosts the phishing server on port 8080.
   - Redirects to `https://www.example.com` after capturing credentials.

2. **Clone with Linked Pages and Custom JavaScript**:

   ```bash
   python3 asuka.py --url https://example.com --multi-page yes --custom-js custom.js --show-logs
   ```

   - Clones `https://example.com` and linked pages (up to 3 levels deep).
   - Injects `custom.js` into the cloned site.
   - Shows logs in the console.

3. **Minimal Setup without Assets**:

   ```bash
   python3 asuka.py --url https://example.com --assets no --port 8000
   ```

   - Clones only the main page without downloading assets.
   - Hosts the server on port 8000.

4. **Tunnel the Phishing URL to make it accessible to the Internet (Serveo)**:

   ```bash
   ./serveo_tunnel.sh <ip> <port>
   ```

5. **How to use the Asuka URL Masker**:
   - First you will need to tunnel it using Serveo (See the command above).
   - Then use URL Masker to mask the Serveo URL:
     
   ```bash
   python3 asuka_url_masker.py -u <serveo_url> -d <domain> -k <keyword(e.g login, login-account)>
   ``` 

### Output Files

- **Cloned Website**: Stored in `templates/fake/<user-agent>/<sanitized-url>/`, with `index.html` as the main page and additional pages/assets in subdirectories.
- **Database**: `asuka_data.db` contains:
  - `credentials` table: Stores username, password, IP, user agent, cookies, CSRF token, and raw form data.
  - `sessions` table: Stores session details (timestamp, IP, user agent, path, geolocation).
- **Log Files**:
  - `error.log`: General errors from `asuka.py`.
  - `clone.log`: Cloning-related logs (e.g., asset download failures).
  - `server.log`: Server-related logs (e.g., requests, errors).
  - `credentials.log`: Captured credentials in plain text.
  - `ajax.log`: Captured AJAX request data.
  - `images.log`: URLs of dynamically loaded images.
  - `interactions.log`: User interactions (e.g., mouse clicks, scrolls).
- **Fernet Key**: `fernet_key.bin` stores the encryption key for securing captured data.

## Module Details

### asuka.py
- **Purpose**: Main script to coordinate the framework.
- **Key Functions**:
  - `get_local_ip()`: Detects the local IP address using `netifaces`, prioritizing private IP ranges (192.168.*, 10.*, 172.*).
  - `setup_database()`: Initializes the SQLite database by calling `database.py`.
  - `main()`: Parses CLI arguments, configures logging, clones the website, and starts the server.
- **Key Features**:
  - Displays a startup banner with the tool’s name and author (Kur0Sh1r0).
  - Supports graceful shutdown via KeyboardInterrupt (Ctrl+C).
  - Auto-detects host IP if not specified.

### database.py
- **Purpose**: Initializes the SQLite database for storing captured data.
- **Key Functions**:
  - `init_db()`: Creates `credentials` and `sessions` tables with fields for timestamps, usernames, passwords, IPs, user agents, cookies, and more. Adds indexes on timestamp fields for performance.
- **Key Features**:
  - Uses a 10-second timeout for SQLite connections to handle concurrent access.
  - Logs errors and exits on database failures.
  - Assumes `colorama` or similar for colored console output (though not explicitly imported).

### utils.py
- **Purpose**: Provides utility functions for asset downloading and geolocation.
- **Key Functions**:
  - `download_asset()`: Downloads web assets (e.g., images, CSS) with retries and fallback logic if `urllib.parse` is unavailable.
  - `get_geolocation()`: Resolves IP addresses to hostnames using `socket.gethostbyaddr` with a 5-second timeout.
- **Key Features**:
  - Handles up to 3 retries for asset downloads with a 10-second timeout per request.
  - Uses `ThreadPoolExecutor` for non-blocking geolocation queries.
  - Logs warnings for missing dependencies (e.g., `urllib.parse`).

### clone.py
- **Purpose**: Clones the target website, modifies forms, and injects JavaScript for data capture.
- **Key Functions**:
  - `configure_logging()`: Sets up logging for cloning operations.
  - `initialize_browser()`: Launches a Playwright Chromium browser in headless mode.
  - `get_page_content()`: Fetches rendered HTML using Playwright with a 60-second timeout.
  - `get_dynamic_images()`: Extracts dynamically loaded image URLs via JavaScript execution.
  - `clone_linked_pages()`: Recursively clones linked pages up to a specified depth.
  - `download_assets()`: Downloads and updates asset paths in the HTML.
  - `clone()`: Main cloning function, orchestrating rendering, form modification, and JavaScript injection.
- **Key Features**:
  - Uses Fernet encryption for secure data transmission (key stored in `fernet_key.bin`).
  - Injects JavaScript to:
    - Spoof browser properties (e.g., `navigator.webdriver`) to evade detection.
    - Simulate human behavior (mouse movements, clicks, scrolls).
    - Capture form data, CSRF tokens, AJAX requests, and keystrokes.
    - Monitor DOM changes for dynamically added forms and images.
  - Supports custom JavaScript injection for extended functionality.
  - Removes script tags if `disable_scripts` is enabled.

### server.py
- **Purpose**: Runs an HTTP server to serve cloned pages and capture data.
- **Key Functions**:
  - `configure_logging()`: Sets up server logging with a custom filter (`No404Errors`) to suppress non-critical errors.
  - `is_port_in_use()`: Checks if the specified host and port are available.
  - `start_server()`: Starts a `ThreadingHTTPServer` for concurrent request handling.
  - `AsukaHandler`: Custom HTTP handler for GET and POST requests.
- **Key Features**:
  - Handles GET requests to serve cloned pages and assets (HTML, CSS, JS, images).
  - Handles POST requests for:
    - `/login`: Captures credentials with Fernet decryption and fallback parsing.
    - `/ajax`: Logs AJAX request data.
    - `/image`: Logs dynamic image URLs.
    - `/keylog`: Logs keystrokes.
    - `/csrf`: Logs CSRF tokens.
    - `/track`: Logs user interactions (e.g., mouse clicks).
  - Prevents duplicate credential submissions within 5 seconds.
  - Logs captured data to both files and the SQLite database.
  - Supports colored console output for credentials (green text).

## Security and Ethical Considerations

- **Encryption**: Captured form data is encrypted using Fernet (key stored in `fernet_key.bin`). Ensure this file is secured and not exposed.
- **Data Storage**: Credentials and session data are stored in plain text in `credentials.log` and `asuka_data.db`. Secure these files and delete them after testing.
- **Ethical Use**: Use this tool only with explicit permission from the system owner or during authorized penetration tests. Unauthorized phishing is illegal in most jurisdictions and can lead to severe legal consequences.
- **Network Security**: The server runs over HTTP (not HTTPS), making it vulnerable to interception. For production use, consider adding SSL/TLS support.
- **Data Privacy**: Handle captured data responsibly, as it may contain sensitive information (e.g., usernames, passwords).

## Troubleshooting

- **Port in Use**: If the server fails to start due to a port conflict, check if the port is in use:
  ```bash
  netstat -tuln | grep <port>
  ```
  Use a different port with the `--port` argument.

- **Database Errors**: If `asuka_data.db` is locked or inaccessible, ensure no other processes are accessing it, or increase the timeout in `database.py` (currently 10 seconds).

- **Asset Download Failures**: Slow or unstable internet connections may cause asset downloads to fail. Retry with `--assets no` to skip asset downloading.

- **Playwright Issues**: Ensure browser binaries are installed (`playwright install`). If rendering fails, check the target URL’s accessibility or increase the timeout in `clone.py` (`page.goto`).

- **Missing Dependencies**: Verify all dependencies are installed. If `urllib.parse` is unavailable, asset downloading may be limited (see `utils.py`).

- **Log Noise**: Enable `--show-logs` for debugging, but note that `server.py` filters out 404 errors to reduce clutter.

## Limitations

- **No HTTPS Support**: The server runs over HTTP, which is less secure and may be flagged by browsers. Adding SSL/TLS (e.g., via `ssl.wrap_socket`) is recommended for realism.
- **Dynamic Content**: Complex JavaScript-heavy sites may not clone perfectly due to AJAX or client-side rendering limitations.
- **Geolocation**: Limited to hostname resolution via `socket.gethostbyaddr`, which may not provide detailed location data.
- **Resource Usage**: Cloning multiple pages or downloading many assets can be resource-intensive (CPU, disk space).
- **Error Handling**: While robust, some edge cases (e.g., malformed HTML, network timeouts) may cause cloning or server errors.

## Extending the Framework

- **Add HTTPS**: Modify `server.py` to use SSL/TLS with a self-signed certificate for secure connections.
- **Enhance Geolocation**: Integrate a third-party geolocation API (e.g., ip-api.com) in `utils.py` for more accurate data.
- **Improve Obfuscation**: Add more sophisticated JavaScript obfuscation techniques in `clone.py` to evade detection.
- **Database Enhancements**: Add queries to analyze captured data or export to other formats (e.g., CSV) in `database.py`.
- **Custom JavaScript**: Use the `--custom-js` option to inject advanced tracking or manipulation scripts.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The author and contributors are not responsible for any misuse or illegal activities conducted with this framework. Always comply with applicable laws and obtain permission before testing.

## Author

- **Kur0Sh1r0**

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
