"""
Business logic services module for the sample Python application.
Contains business logic classes and functions.
"""

from typing import List, Dict, Any, Optional
import datetime

# Import from our models module
from models import User, Product, Order, UserRole, OrderStatus, BUSINESS_CONSTANTS, validate_email, sanitize_string


def format_currency(amount: float, currency: str = "USD") -> str:
    """Format currency amount."""
    return f"{currency} {amount:.2f}"


def calculate_order_total(items: List[Dict[str, Any]]) -> float:
    """Calculate total for order items."""
    return sum(item.get('price', 0) * item.get('quantity', 1) for item in items)


def validate_user_data(username: str, email: str) -> bool:
    """Validate user registration data."""
    if len(username) < 3 or len(username) > BUSINESS_CONSTANTS['MAX_USERNAME_LENGTH']:
        return False
    return validate_email(email)


def process_payment(amount: float, payment_method: str) -> Dict[str, Any]:
    """Simulate payment processing."""
    return {
        'success': True,
        'transaction_id': f"txn_{hash(amount + len(payment_method))}",
        'amount': amount,
        'currency': BUSINESS_CONSTANTS['DEFAULT_CURRENCY'],
        'timestamp': datetime.datetime.now()
    }


class ServiceError(Exception):
    """Custom exception for business logic service errors."""
    pass


class UserService:
    """
    Business logic service for user operations.
    """
    
    def __init__(self):
        """Initialize user service."""
        self.users: Dict[int, User] = {}
        self.next_user_id = 1

    def create_user_account(self, username: str, email: str, 
                          role: UserRole = UserRole.CUSTOMER) -> User:
        """
        Create a user account with validation.
        
        Args:
            username (str): Username
            email (str): Email address
            role (UserRole): User role
            
        Returns:
            User: Created user object
            
        Raises:
            ServiceError: If validation fails
        """
        if not validate_user_data(username, email):
            raise ServiceError("Invalid user data provided")
        
        user = User(
            user_id=self.next_user_id,
            username=sanitize_string(username),
            email=email.lower().strip(),
            role=role
        )
        
        self.users[user.user_id] = user
        self.next_user_id += 1
        
        return user
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        return self.users.get(user_id)
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        for user in self.users.values():
            if user.email == email.lower().strip():
                return user
        return None


class ProductService:
    """
    Business logic service for product operations.
    """
    
    def __init__(self):
        """Initialize product service."""
        self.products: Dict[int, Product] = {}
        self.next_product_id = 1
    
    def create_product(self, name: str, price: float, category: str = "general") -> Product:
        """
        Create a new product.
        
        Args:
            name (str): Product name
            price (float): Product price
            category (str): Product category
            
        Returns:
            Product: Created product object
        """
        product = Product(
            product_id=self.next_product_id,
            name=sanitize_string(name, BUSINESS_CONSTANTS['MAX_PRODUCT_NAME_LENGTH']),
            description=f"Product description for {name}",
            price=max(0.0, float(price)),
            category=category,
            created_at=datetime.datetime.now()
        )
        
        self.products[product.product_id] = product
        self.next_product_id += 1
        
        return product
    
    def get_product_by_id(self, product_id: int) -> Optional[Product]:
        """Get product by ID."""
        return self.products.get(product_id)
    
    def search_products(self, query: str) -> List[Product]:
        """Search products by name or category."""
        query = query.lower()
        results = []
        
        for product in self.products.values():
            if (query in product.name.lower() or 
                query in product.category.lower()):
                results.append(product)
        
        return results
    
    def get_formatted_price(self, product_id: int) -> str:
        """Get formatted price for a product."""
        product = self.get_product_by_id(product_id)
        if not product:
            return "Price not available"
        
        return format_currency(product.price, BUSINESS_CONSTANTS['DEFAULT_CURRENCY'])


class ApplicationService:
    """
    Main application service that coordinates all business logic.
    """
    
    def __init__(self):
        """Initialize application service."""
        self.user_service = UserService()
        self.product_service = ProductService()
    
    def register_user_with_products(self, username: str, email: str, 
                                  product_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Complete workflow: register user and create products.
        
        Args:
            username (str): Username
            email (str): Email
            product_data (List[Dict]): Product information
            
        Returns:
            Dict: Complete workflow result
        """
        try:
            # Create user
            user = self.user_service.create_user_account(username, email)
            
            # Create products
            created_products = []
            for product_info in product_data:
                product = self.product_service.create_product(
                    name=product_info['name'],
                    price=product_info['price'],
                    category=product_info.get('category', 'general')
                )
                created_products.append({
                    'product_id': product.product_id,
                    'name': product.name,
                    'price': product.price,
                    'formatted_price': self.product_service.get_formatted_price(product.product_id)
                })
            
            return {
                'success': True,
                'user': {
                    'user_id': user.user_id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role.value
                },
                'products': created_products,
                'message': f"User {username} registered with {len(created_products)} products"
            }
            
        except ServiceError as e:
            return {
                'success': False,
                'error': str(e),
                'message': "Failed to complete user registration and product creation"
            }
    
    def get_application_stats(self) -> Dict[str, Any]:
        """Get application statistics."""
        return {
            'total_users': len(self.user_service.users),
            'total_products': len(self.product_service.products),
            'business_constants': BUSINESS_CONSTANTS
        }