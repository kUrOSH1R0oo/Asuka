#!/usr/bin/env python3
"""
Utility functions for the Asuka Phishing Framework.
Includes functions for downloading assets and retrieving geolocation data.
"""

import os
import requests
import logging
from urllib.parse import urljoin, urlparse
import json
import hashlib

def download_asset(asset_url, base_url, base_path, session):
    """
    Downloads an asset from a URL and saves it to the specified path.
    
    Args:
        asset_url (str): URL of the asset to download.
        base_url (str): Base URL of the page for resolving relative URLs.
        base_path (str): Directory to save the asset.
        session (requests.Session): HTTP session for making requests.
    
    Returns:
        str: Relative path to the saved asset, or None if download fails.
    """
    try:
        full_url = urljoin(base_url, asset_url)
        parsed_url = urlparse(full_url)
        path = parsed_url.path.lstrip('/')
        if not path:
            path = 'asset_' + hashlib.md5(full_url.encode()).hexdigest()
        ext = os.path.splitext(path)[1].lower()
        if not ext:
            content_types = {
                'image/png': '.png',
                'image/jpeg': '.jpg',
                'image/gif': '.gif',
                'text/css': '.css',
                'application/javascript': '.js',
                'font/woff': '.woff',
                'font/woff2': '.woff2',
                'font/ttf': '.ttf',
                'font/otf': '.otf',
                'image/x-icon': '.ico',
                'image/svg+xml': '.svg',
                'application/json': '.json'
            }
            try:
                response = session.head(full_url, timeout=5, allow_redirects=True)
                content_type = response.headers.get('Content-Type', '').split(';')[0]
                ext = content_types.get(content_type, '.bin')
            except:
                ext = '.bin'
            path += ext
        local_path = os.path.join(base_path, path)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        
        response = session.get(full_url, timeout=15, allow_redirects=True)
        if response.status_code == 200:
            with open(local_path, 'wb') as f:
                f.write(response.content)
            logging.debug(f"Downloaded asset: {full_url} to {local_path}")
            return path
        else:
            logging.warning(f"Failed to download asset: {full_url}, status: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error downloading asset {asset_url}: {e}")
        return None

def get_geolocation(ip):
    """
    Retrieves geolocation data for an IP address using a free API.
    """
    try:
        if ip in ('127.0.0.1', 'localhost'):
            return json.dumps({'city': 'Local', 'country': 'Local'})
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return json.dumps({
                'city': data.get('city', ''),
                'country': data.get('country', ''),
                'region': data.get('regionName', ''),
                'isp': data.get('isp', '')
            })
        else:
            logging.warning(f"Geolocation failed for IP {ip}: Status {response.status_code}")
            return ""
    except Exception as e:
        logging.error(f"Error getting geolocation for IP {ip}: {e}")
        return ""
