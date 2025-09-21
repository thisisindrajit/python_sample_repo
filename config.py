"""
Configuration module for the sample Python application.
Contains application constants, database settings, and shared configuration variables.
"""

import os
from typing import Dict, Any

# Application Constants
APP_NAME = "Python Sample Repository"
APP_VERSION = "1.0.0"
DEBUG_MODE = True

# Database Configuration
DATABASE_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "name": os.getenv("DB_NAME", "sample_db"),
    "user": os.getenv("DB_USER", "admin"),
    "password": os.getenv("DB_PASSWORD", "password123"),
    "pool_size": 10,
    "timeout": 30
}

# API Configuration
API_CONFIG = {
    "host": "0.0.0.0",
    "port": 8000,
    "workers": 4,
    "timeout": 120,
    "max_request_size": 1024 * 1024 * 10,  # 10MB
}

# Authentication Configuration
AUTH_CONFIG = {
    "secret_key": os.getenv("SECRET_KEY", "your-secret-key-here"),
    "token_expiry_hours": 24,
    "max_login_attempts": 5,
    "password_min_length": 8,
}

# Logging Configuration
LOG_CONFIG = {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file_path": "logs/app.log",
    "max_file_size": 1024 * 1024 * 5,  # 5MB
    "backup_count": 3,
}

# Business Logic Constants
BUSINESS_CONSTANTS = {
    "max_order_items": 100,
    "default_currency": "USD",
    "tax_rate": 0.08,
    "shipping_cost": 9.99,
    "free_shipping_threshold": 50.00,
}

# File Upload Configuration
UPLOAD_CONFIG = {
    "allowed_extensions": [".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"],
    "max_file_size": 1024 * 1024 * 5,  # 5MB
    "upload_directory": "uploads/",
}


def get_config(section: str) -> Dict[str, Any]:
    """
    Get configuration for a specific section.
    
    Args:
        section (str): Configuration section name
        
    Returns:
        Dict[str, Any]: Configuration dictionary for the section
        
    Raises:
        KeyError: If section does not exist
    """
    config_sections = {
        "database": DATABASE_CONFIG,
        "api": API_CONFIG,
        "auth": AUTH_CONFIG,
        "logging": LOG_CONFIG,
        "business": BUSINESS_CONSTANTS,
        "upload": UPLOAD_CONFIG,
    }
    
    if section not in config_sections:
        raise KeyError(f"Configuration section '{section}' not found")
    
    return config_sections[section].copy()


def is_production() -> bool:
    """Check if the application is running in production mode."""
    return os.getenv("ENVIRONMENT", "development").lower() == "production"


def get_database_url() -> str:
    """Generate database connection URL from configuration."""
    db_config = DATABASE_CONFIG
    return (f"postgresql://{db_config['user']}:{db_config['password']}"
            f"@{db_config['host']}:{db_config['port']}/{db_config['name']}")


# Export commonly used configurations
__all__ = [
    "APP_NAME", "APP_VERSION", "DEBUG_MODE",
    "DATABASE_CONFIG", "API_CONFIG", "AUTH_CONFIG", 
    "LOG_CONFIG", "BUSINESS_CONSTANTS", "UPLOAD_CONFIG",
    "get_config", "is_production", "get_database_url"
]