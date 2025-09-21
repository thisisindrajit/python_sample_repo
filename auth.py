"""
Authentication module for the sample Python application.
Contains user authentication functions importing from models and utils.
"""

import datetime
import secrets
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass

# Import models, utilities, and configuration
from models import User, UserRole
from utils import generate_hash, validate_email
from config import AUTH_CONFIG, get_config
from database import DatabaseManager


@dataclass
class AuthToken:
    """Authentication token data class."""
    token: str
    user_id: int
    expires_at: datetime.datetime
    created_at: datetime.datetime = datetime.datetime.now()

    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.datetime.now() > self.expires_at

    def time_remaining(self) -> datetime.timedelta:
        """Get remaining time until expiration."""
        return self.expires_at - datetime.datetime.now()


class AuthenticationError(Exception):
    """Custom exception for authentication failures."""
    pass


class PasswordValidator:
    """Password validation utilities."""
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
        """
        Validate password strength according to security requirements.
        
        Args:
            password (str): Password to validate
            
        Returns:
            Tuple[bool, List[str]]: (is_valid, list_of_errors)
        """
        errors = []
        min_length = AUTH_CONFIG['password_min_length']
        
        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters long")
        
        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash password with salt.
        
        Args:
            password (str): Plain text password
            
        Returns:
            str: Hashed password
        """
        # Add salt to password before hashing
        salt = secrets.token_hex(16)
        salted_password = f"{salt}{password}{AUTH_CONFIG['secret_key']}"
        return f"{salt}:{generate_hash(salted_password)}"

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password (str): Plain text password
            hashed_password (str): Stored hash with salt
            
        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            salt, hash_part = hashed_password.split(':', 1)
            salted_password = f"{salt}{password}{AUTH_CONFIG['secret_key']}"
            return generate_hash(salted_password) == hash_part
        except ValueError:
            # Fallback for simple hashes (for backward compatibility)
            return generate_hash(password) == hashed_password


class SessionManager:
    """Manages user sessions and tokens."""
    
    def __init__(self):
        """Initialize session manager."""
        self.active_sessions: Dict[str, AuthToken] = {}
        self.login_attempts: Dict[str, List[datetime.datetime]] = {}

    def generate_token(self, user: User) -> str:
        """
        Generate authentication token for user.
        
        Args:
            user (User): User to generate token for
            
        Returns:
            str: Authentication token
        """
        token = secrets.token_urlsafe(32)
        expires_at = datetime.datetime.now() + datetime.timedelta(
            hours=AUTH_CONFIG['token_expiry_hours']
        )
        
        auth_token = AuthToken(
            token=token,
            user_id=user.user_id,
            expires_at=expires_at
        )
        
        self.active_sessions[token] = auth_token
        return token

    def validate_token(self, token: str) -> Optional[AuthToken]:
        """
        Validate authentication token.
        
        Args:
            token (str): Token to validate
            
        Returns:
            Optional[AuthToken]: AuthToken if valid, None otherwise
        """
        if token not in self.active_sessions:
            return None
        
        auth_token = self.active_sessions[token]
        if auth_token.is_expired():
            del self.active_sessions[token]
            return None
        
        return auth_token

    def revoke_token(self, token: str) -> bool:
        """
        Revoke authentication token.
        
        Args:
            token (str): Token to revoke
            
        Returns:
            bool: True if token was revoked, False if not found
        """
        if token in self.active_sessions:
            del self.active_sessions[token]
            return True
        return False

    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions.
        
        Returns:
            int: Number of sessions cleaned up
        """
        expired_tokens = [
            token for token, auth_token in self.active_sessions.items()
            if auth_token.is_expired()
        ]
        
        for token in expired_tokens:
            del self.active_sessions[token]
        
        return len(expired_tokens)

    def record_login_attempt(self, identifier: str) -> None:
        """
        Record a login attempt for rate limiting.
        
        Args:
            identifier (str): Email or IP address
        """
        now = datetime.datetime.now()
        if identifier not in self.login_attempts:
            self.login_attempts[identifier] = []
        
        self.login_attempts[identifier].append(now)
        
        # Keep only attempts from the last hour
        cutoff = now - datetime.timedelta(hours=1)
        self.login_attempts[identifier] = [
            attempt for attempt in self.login_attempts[identifier]
            if attempt > cutoff
        ]

    def is_rate_limited(self, identifier: str) -> bool:
        """
        Check if identifier is rate limited.
        
        Args:
            identifier (str): Email or IP address
            
        Returns:
            bool: True if rate limited, False otherwise
        """
        if identifier not in self.login_attempts:
            return False
        
        max_attempts = AUTH_CONFIG['max_login_attempts']
        return len(self.login_attempts[identifier]) >= max_attempts


class AuthenticationService:
    """
    Main authentication service coordinating all auth operations.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize authentication service.
        
        Args:
            db_manager (DatabaseManager): Database manager instance
        """
        self.db_manager = db_manager
        self.session_manager = SessionManager()
        self.password_validator = PasswordValidator()

    def register_user(self, username: str, email: str, password: str, 
                     role: UserRole = UserRole.CUSTOMER) -> User:
        """
        Register a new user.
        
        Args:
            username (str): Username
            email (str): Email address
            password (str): Plain text password
            role (UserRole): User role
            
        Returns:
            User: Created user instance
            
        Raises:
            AuthenticationError: If registration fails
        """
        # Validate email
        if not validate_email(email):
            raise AuthenticationError("Invalid email address")
        
        # Validate password strength
        is_valid, errors = self.password_validator.validate_password_strength(password)
        if not is_valid:
            raise AuthenticationError(f"Password validation failed: {', '.join(errors)}")
        
        # Check if user already exists
        existing_user = self.db_manager.users.get_user_by_email(email)
        if existing_user:
            raise AuthenticationError("User with this email already exists")
        
        # Hash password and create user
        hashed_password = self.password_validator.hash_password(password)
        
        try:
            user = self.db_manager.users.create_user(username, email, hashed_password, role)
            return user
        except Exception as e:
            raise AuthenticationError(f"Failed to create user: {str(e)}")

    def authenticate_user(self, email: str, password: str) -> Tuple[User, str]:
        """
        Authenticate user and return user object with token.
        
        Args:
            email (str): Email address
            password (str): Plain text password
            
        Returns:
            Tuple[User, str]: User object and authentication token
            
        Raises:
            AuthenticationError: If authentication fails
        """
        # Check rate limiting
        if self.session_manager.is_rate_limited(email):
            raise AuthenticationError("Too many login attempts. Please try again later.")
        
        # Record login attempt
        self.session_manager.record_login_attempt(email)
        
        # Get user from database
        user = self.db_manager.users.get_user_by_email(email)
        if not user:
            raise AuthenticationError("Invalid email or password")
        
        # Check if user is active
        if not user.is_active:
            raise AuthenticationError("Account is deactivated")
        
        # Verify password
        if not user._password_hash or not self.password_validator.verify_password(password, user._password_hash):
            raise AuthenticationError("Invalid email or password")
        
        # Update last login
        self.db_manager.users.update_user_login(user.user_id)
        user.update_last_login()
        
        # Generate and return token
        token = self.session_manager.generate_token(user)
        return user, token

    def get_current_user(self, token: str) -> Optional[User]:
        """
        Get current user from authentication token.
        
        Args:
            token (str): Authentication token
            
        Returns:
            Optional[User]: User object if token is valid, None otherwise
        """
        auth_token = self.session_manager.validate_token(token)
        if not auth_token:
            return None
        
        return self.db_manager.users.get_user_by_id(auth_token.user_id)

    def logout_user(self, token: str) -> bool:
        """
        Logout user by revoking token.
        
        Args:
            token (str): Authentication token
            
        Returns:
            bool: True if successful, False if token not found
        """
        return self.session_manager.revoke_token(token)

    def change_password(self, user_id: int, old_password: str, new_password: str) -> bool:
        """
        Change user password.
        
        Args:
            user_id (int): User ID
            old_password (str): Current password
            new_password (str): New password
            
        Returns:
            bool: True if successful, False otherwise
            
        Raises:
            AuthenticationError: If password change fails
        """
        # Get user
        user = self.db_manager.users.get_user_by_id(user_id)
        if not user:
            raise AuthenticationError("User not found")
        
        # Verify old password
        if not user._password_hash or not self.password_validator.verify_password(old_password, user._password_hash):
            raise AuthenticationError("Current password is incorrect")
        
        # Validate new password
        is_valid, errors = self.password_validator.validate_password_strength(new_password)
        if not is_valid:
            raise AuthenticationError(f"New password validation failed: {', '.join(errors)}")
        
        # Hash and update password (this would require extending the UserRepository)
        new_hash = self.password_validator.hash_password(new_password)
        # TODO: Implement password update in UserRepository
        
        return True

    def require_role(self, token: str, required_role: UserRole) -> bool:
        """
        Check if current user has required role.
        
        Args:
            token (str): Authentication token
            required_role (UserRole): Required role
            
        Returns:
            bool: True if user has required role, False otherwise
        """
        user = self.get_current_user(token)
        if not user:
            return False
        
        return user.role == required_role or user.role == UserRole.ADMIN

    def get_session_info(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get session information for a token.
        
        Args:
            token (str): Authentication token
            
        Returns:
            Optional[Dict[str, Any]]: Session information
        """
        auth_token = self.session_manager.validate_token(token)
        if not auth_token:
            return None
        
        return {
            'token': auth_token.token,
            'user_id': auth_token.user_id,
            'created_at': auth_token.created_at.isoformat(),
            'expires_at': auth_token.expires_at.isoformat(),
            'time_remaining': str(auth_token.time_remaining())
        }


# Export main classes
__all__ = [
    'AuthToken', 'AuthenticationError', 'PasswordValidator', 
    'SessionManager', 'AuthenticationService'
]