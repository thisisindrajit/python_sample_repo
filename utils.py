"""
Utility functions module for the sample Python application.
Contains helper functions for string manipulation, file operations, and common utilities.
"""

import os
import sys
import re
import json
import hashlib
import datetime
from typing import List, Dict, Any, Optional, Union
from pathlib import Path

# Import configuration constants
from config import UPLOAD_CONFIG, APP_VERSION


def validate_email(email: str) -> bool:
    """
    Validate email address format.
    
    Args:
        email (str): Email address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def sanitize_string(text: str, max_length: int = 255) -> str:
    """
    Sanitize input string by removing special characters and limiting length.
    
    Args:
        text (str): Input text to sanitize
        max_length (int): Maximum allowed length
        
    Returns:
        str: Sanitized string
    """
    if not isinstance(text, str):
        text = str(text)
    
    # Remove special characters except alphanumeric, spaces, and basic punctuation
    sanitized = re.sub(r'[^\w\s\-_.,!?]', '', text)
    
    # Limit length
    return sanitized[:max_length].strip()


def generate_hash(data: str, algorithm: str = 'sha256') -> str:
    """
    Generate hash for given data.
    
    Args:
        data (str): Data to hash
        algorithm (str): Hash algorithm to use
        
    Returns:
        str: Hexadecimal hash string
    """
    if algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha1':
        hasher = hashlib.sha1()
    elif algorithm == 'sha256':
        hasher = hashlib.sha256()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    hasher.update(data.encode('utf-8'))
    return hasher.hexdigest()


def format_currency(amount: float, currency: str = 'USD') -> str:
    """
    Format currency amount with proper symbols.
    
    Args:
        amount (float): Amount to format
        currency (str): Currency code
        
    Returns:
        str: Formatted currency string
    """
    symbols = {
        'USD': '$',
        'EUR': '€',
        'GBP': '£',
        'JPY': '¥'
    }
    
    symbol = symbols.get(currency, currency)
    return f"{symbol}{amount:.2f}"


def parse_json_file(file_path: str) -> Dict[str, Any]:
    """
    Parse JSON file and return dictionary.
    
    Args:
        file_path (str): Path to JSON file
        
    Returns:
        Dict[str, Any]: Parsed JSON data
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If JSON is invalid
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)


def write_json_file(data: Dict[str, Any], file_path: str) -> bool:
    """
    Write dictionary to JSON file.
    
    Args:
        data (Dict[str, Any]): Data to write
        file_path (str): Output file path
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def get_file_extension(filename: str) -> str:
    """
    Get file extension from filename.
    
    Args:
        filename (str): Filename to extract extension from
        
    Returns:
        str: File extension (including dot)
    """
    return Path(filename).suffix.lower()


def is_allowed_file(filename: str) -> bool:
    """
    Check if file extension is allowed based on configuration.
    
    Args:
        filename (str): Filename to check
        
    Returns:
        bool: True if allowed, False otherwise
    """
    extension = get_file_extension(filename)
    return extension in UPLOAD_CONFIG['allowed_extensions']


def get_file_size(file_path: str) -> int:
    """
    Get file size in bytes.
    
    Args:
        file_path (str): Path to file
        
    Returns:
        int: File size in bytes
        
    Raises:
        FileNotFoundError: If file doesn't exist
    """
    return os.path.getsize(file_path)


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes (int): Size in bytes
        
    Returns:
        str: Formatted size string
    """
    size = float(size_bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def generate_unique_filename(original_filename: str, directory: str = '') -> str:
    """
    Generate unique filename by appending timestamp.
    
    Args:
        original_filename (str): Original filename
        directory (str): Target directory
        
    Returns:
        str: Unique filename
    """
    name, ext = os.path.splitext(original_filename)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_name = f"{name}_{timestamp}{ext}"
    
    if directory:
        return os.path.join(directory, unique_name)
    return unique_name


def chunk_list(data: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split list into chunks of specified size.
    
    Args:
        data (List[Any]): List to chunk
        chunk_size (int): Size of each chunk
        
    Returns:
        List[List[Any]]: List of chunks
    """
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """
    Flatten nested dictionary.
    
    Args:
        d (Dict[str, Any]): Dictionary to flatten
        parent_key (str): Parent key prefix
        sep (str): Separator for nested keys
        
    Returns:
        Dict[str, Any]: Flattened dictionary
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def get_app_info() -> Dict[str, str]:
    """
    Get application information.
    
    Returns:
        Dict[str, str]: Application information
    """
    return {
        'version': APP_VERSION,
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'platform': os.name,
        'timestamp': datetime.datetime.now().isoformat()
    }


# Export all utility functions
__all__ = [
    'validate_email', 'sanitize_string', 'generate_hash', 'format_currency',
    'parse_json_file', 'write_json_file', 'get_file_extension', 'is_allowed_file',
    'get_file_size', 'format_file_size', 'generate_unique_filename',
    'chunk_list', 'flatten_dict', 'get_app_info'
]