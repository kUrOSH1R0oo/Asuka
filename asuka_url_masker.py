import re
import sys
import json
import logging
import asyncio
import aiohttp
from urllib.parse import urlparse
from datetime import datetime
import argparse
try:
    import pyshorteners
except ImportError:
    # Exit if pyshorteners module is not installed
    print("Error: pyshorteners module required. Install with: pip install pyshorteners")
    sys.exit(1)

# Banner
banner = r"""
                     _           _    _ _____  _        __  __           _
     /\             | |         | |  | |  __ \| |      |  \/  |         | |
    /  \   ___ _   _| | ____ _  | |  | | |__) | |      | \  / | __ _ ___| | _____ _ __
   / /\ \ / __| | | | |/ / _` | | |  | |  _  /| |      | |\/| |/ _` / __| |/ / _ \ '__|
  / ____ \\__ \ |_| |   < (_| | | |__| | | \ \| |____  | |  | | (_| \__ \   <  __/ |
 /_/    \_\___/\__,_|_|\_\__,_|  \____/|_|  \_\______| |_|  |_|\__,_|___/_|\_\___|_|
                                                                - Kur0Sh1r0
"""

# ANSI color codes for console output formatting
G = '\033[32m'  # Green text for URLs
W = '\033[0m'   # Reset text color

# Configure logging to track program execution and errors
logging.basicConfig(
    filename=f'url_masker_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Default configuration settings for the URL masker
CONFIG = {
    'max_keyword_length': 12,  # Maximum length for the keyword
    'max_retries': 2,          # Number of retry attempts for URL shortening
    'timeout': 5,              # Timeout for HTTP requests in seconds
    'output_file': 'masked_urls.json'  # Output file for saving results
}

def load_config(config_file='config.json'):
    """Load configuration from a JSON file or use defaults if file is unavailable.

    Args:
        config_file (str): Path to the configuration JSON file.

    Returns:
        dict: Configuration settings, either from file or defaults.
    """
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning(f"Config file {config_file} not found, using default settings")
        return CONFIG
    except json.JSONDecodeError:
        logging.error("Invalid config file format")
        return CONFIG

def validate_url(url):
    """Validate the format and constraints of a URL.

    Args:
        url (str): The URL to validate.

    Returns:
        tuple: (bool, str) - True if valid, False with error message if invalid.
    """
    pattern = r'^https?://[\w.-]+\.[a-zA-Z]{2,}(?::\d{1,5})?(?:/.*)?$'
    if not url:
        return False, "[-] URL cannot be empty"
    if len(url) > 2048:
        return False, "[-] URL exceeds maximum length (2048 characters)"
    if not re.match(pattern, url):
        return False, "[-] Invalid URL format. Use https://example.com"
    return True, ""

def validate_domain(domain):
    """Validate the format of a domain name.

    Args:
        domain (str): The domain to validate.

    Returns:
        tuple: (bool, str) - True if valid, False with error message if invalid.
    """
    pattern = r'^[\w.-]+\.[a-zA-Z]{2,}$'
    if not domain:
        return False, "[-] Domain cannot be empty"
    if not re.match(pattern, domain):
        return False, "[-] Invalid domain format. Use example.com"
    return True, ""

def validate_keyword(keyword, max_length):
    """Validate the keyword for length and character constraints.

    Args:
        keyword (str): The keyword to validate.
        max_length (int): Maximum allowed length for the keyword.

    Returns:
        tuple: (bool, str) - True if valid, False with error message if invalid.
    """
    if not keyword:
        return False, "[-] Keyword cannot be empty"
    if len(keyword) > max_length:
        return False, f"[-] Keyword exceeds {max_length} characters"
    if ' ' in keyword or keyword.isspace():
        return False, "[-] Keyword cannot contain spaces"
    if not re.match(r'^[\w-]+$', keyword):
        return False, "[-] Keyword can only contain letters, numbers, or hyphens"
    return True, ""

def mask_url(domain, keyword, url):
    """Generate a masked URL by combining domain, keyword, and original URL.

    Args:
        domain (str): Custom domain for masking.
        keyword (str): Keyword for masking.
        url (str): Original URL to mask.

    Returns:
        str or None: Masked URL if successful, None if an error occurs.
    """
    try:
        parsed = urlparse(url)
        masked = f"{parsed.scheme}://{domain}-{keyword}@{parsed.netloc}{parsed.path}"
        logging.info(f"Masked URL generated: {masked}")
        return masked
    except ValueError as e:
        logging.error(f"Failed to mask URL {url}: {str(e)}")
        return None

async def shorten_url_async(service_name, shortener, url, max_retries, timeout):
    """Asynchronously shorten a URL with retry logic for robustness.

    Args:
        service_name (str): Name of the shortening service.
        shortener: Shortener object from pyshorteners.
        url (str): URL to shorten.
        max_retries (int): Maximum number of retry attempts.
        timeout (int): Timeout for HTTP requests in seconds.

    Returns:
        tuple: (service_name, shortened_url) or (service_name, error_message).
    """
    for attempt in range(max_retries + 1):
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                return service_name, shortener.short(url)
        except Exception as e:
            error_msg = f"[-] Attempt {attempt + 1} failed: {str(e)}"
            if attempt == max_retries:
                logging.error(f"Shortener {service_name} failed: {error_msg}")
                return service_name, f"[-] Error: {error_msg}"
            await asyncio.sleep(0.5)

async def shorten_urls(url, max_retries, timeout):
    """Shorten a URL using multiple services concurrently.

    Args:
        url (str): URL to shorten.
        max_retries (int): Maximum number of retry attempts.
        timeout (int): Timeout for HTTP requests in seconds.

    Returns:
        list: List of tuples containing service name and shortened URL or error.
    """
    s = pyshorteners.Shortener()
    services = [
        ('Clckru', s.clckru),
        ('Dagd', s.dagd),
        ('Osdb', s.osdb)
    ]
    tasks = [shorten_url_async(name, shortener, url, max_retries, timeout) for name, shortener in services]
    return await asyncio.gather(*tasks)

def save_results(url, results, domain, keyword, output_file):
    """Save the original and masked URLs to a JSON file.

    Args:
        url (str): Original URL.
        results (list): List of (service_name, shortened_url) tuples.
        domain (str): Custom domain used for masking.
        keyword (str): Keyword used for masking.
        output_file (str): Path to the output JSON file.

    Saves results to the specified file or logs an error if saving fails.
    """
    data = {
        'original_url': url,
        'domain': domain,
        'keyword': keyword,
        'timestamp': datetime.now().isoformat(),
        'results': [
            {'service': name, 'url': result, 'masked': mask_url(domain, keyword, result) if not result.startswith("Error") else None}
            for name, result in results
        ]
    }
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        logging.info(f"Results saved to {output_file}")
        print(f"[+] Results saved to {output_file}")
    except Exception as e:
        logging.error(f"Failed to save results: {str(e)}")
        print(f"[-] Error saving results: {str(e)}")

async def main(args):
    """Main function to orchestrate URL masking and shortening.

    Args:
        args: Command-line arguments containing url, domain, and keyword.

    Validates inputs, processes URLs, and saves results.
    """
    config = load_config()

    # Validate command-line arguments
    valid, error = validate_url(args.url)
    if not valid:
        print(f"[-] Error: {error}")
        sys.exit(1)
    url = args.url

    valid, error = validate_domain(args.domain)
    if not valid:
        print(f"[-] Error: {error}")
        sys.exit(1)
    domain = args.domain

    valid, error = validate_keyword(args.keyword, config['max_keyword_length'])
    if not valid:
        print(f"[-] Error: {error}")
        sys.exit(1)
    keyword = args.keyword

    # Log input parameters and process URLs
    logging.info(f"Processing URL: {url}, Domain: {domain}, Keyword: {keyword}")
    print("[*] Processing URL......")
    results = await shorten_urls(url, config['max_retries'], config['timeout'])

    # Display results in the console
    print(f"[+] Original URL: {G}{url}{W}")
    print("[+] Masked URLs:")
    for name, result in results:
        if not result.startswith("Error"):
            masked = mask_url(domain, keyword, result)
            if masked:
                print(f"- {name}: {G}{masked}{W}")
            else:
                print(f"- {name}: Failed to mask URL")
        else:
            print(f"- {name}: {result}")

    # Save results to output file
    save_results(url, results, domain, keyword, config['output_file'])

if __name__ == "__main__":
    print(banner)
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Asuka Framework URL Masker")
    parser.add_argument("-u", "--url", required=True, help="URL to mask (e.g., https://example.com)")
    parser.add_argument("-d", "--domain", required=True, help="Custom domain (e.g., github.com)")
    parser.add_argument("-k", "--keyword", required=True, help=f"Keyword (max {CONFIG['max_keyword_length']} chars, no spaces)")
    args = parser.parse_args()

    try:
        # Run the main asynchronous function
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n[-] Exiting...")
        logging.info("Program terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        logging.error(f"Unexpected error: {str(e)}")
        sys.exit(1)
