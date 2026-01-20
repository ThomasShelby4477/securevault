"""Geolocation utilities for IP address lookup."""

import requests
from functools import lru_cache


@lru_cache(maxsize=100)
def get_ip_location(ip_address):
    """
    Get approximate location for an IP address.
    Uses ip-api.com free service (no API key required).
    
    Args:
        ip_address: IP address to lookup
        
    Returns:
        dict with city, country, or None if failed
    """
    # Skip localhost/private IPs
    if ip_address in ('127.0.0.1', 'localhost', '::1') or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
        return {'city': 'Local', 'country': 'Network', 'display': '🏠 Local Network'}
    
    try:
        response = requests.get(
            f'http://ip-api.com/json/{ip_address}',
            timeout=2,
            params={'fields': 'status,city,country,countryCode'}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                city = data.get('city', 'Unknown')
                country = data.get('country', 'Unknown')
                country_code = data.get('countryCode', '??')
                
                # Map country codes to flag emojis
                flag = get_country_flag(country_code)
                
                return {
                    'city': city,
                    'country': country,
                    'display': f'{flag} {city}, {country}'
                }
        
        return {'city': 'Unknown', 'country': 'Unknown', 'display': '🌍 Unknown'}
        
    except Exception:
        return {'city': 'Unknown', 'country': 'Unknown', 'display': '🌍 Unknown'}


def get_country_flag(country_code):
    """
    Convert country code to flag emoji.
    
    Args:
        country_code: 2-letter country code (e.g., 'US', 'IN')
        
    Returns:
        Flag emoji string
    """
    if not country_code or len(country_code) != 2:
        return '🌍'
    
    # Convert country code to regional indicator symbols
    try:
        flag = ''.join(chr(ord(c) + 127397) for c in country_code.upper())
        return flag
    except Exception:
        return '🌍'


def format_ip_with_location(ip_address):
    """
    Format IP address with location for display.
    
    Args:
        ip_address: IP address to format
        
    Returns:
        Formatted string with IP and location
    """
    if not ip_address:
        return 'Unknown'
    
    location = get_ip_location(ip_address)
    return location.get('display', '🌍 Unknown')
