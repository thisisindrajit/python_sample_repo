"""
Data models module for the sample Python application.
Contains User, Product, and Order classes with methods and properties.
"""

import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

# Import utilities and configuration
from utils import validate_email, generate_hash, sanitize_string
from config import BUSINESS_CONSTANTS


class UserRole(Enum):
    """User role enumeration."""
    ADMIN = "admin"
    CUSTOMER = "customer"
    MODERATOR = "moderator"


class OrderStatus(Enum):
    """Order status enumeration."""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"


@dataclass
class User:
    """
    User model class representing a system user.
    """
    user_id: int
    username: str
    email: str
    role: UserRole = UserRole.CUSTOMER
    created_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    last_login: Optional[datetime.datetime] = None
    is_active: bool = True
    profile_data: Dict[str, Any] = field(default_factory=dict)
    _password_hash: Optional[str] = field(default=None, repr=False)

    def __post_init__(self):
        """Post-initialization validation."""
        self.username = sanitize_string(self.username, 50)
        if not validate_email(self.email):
            raise ValueError(f"Invalid email address: {self.email}")
        if isinstance(self.role, str):
            self.role = UserRole(self.role)

    def set_password(self, password: str) -> None:
        """
        Set user password with hashing.
        
        Args:
            password (str): Plain text password
        """
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        self._password_hash = generate_hash(password)

    def check_password(self, password: str) -> bool:
        """
        Check if provided password matches stored hash.
        
        Args:
            password (str): Plain text password to check
            
        Returns:
            bool: True if password matches, False otherwise
        """
        if not self._password_hash:
            return False
        return self._password_hash == generate_hash(password)

    def update_last_login(self) -> None:
        """Update last login timestamp."""
        self.last_login = datetime.datetime.now()

    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == UserRole.ADMIN

    def get_full_profile(self) -> Dict[str, Any]:
        """
        Get complete user profile information.
        
        Returns:
            Dict[str, Any]: User profile data
        """
        return {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'role': self.role.value,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active,
            'profile_data': self.profile_data
        }

    def __str__(self) -> str:
        return f"User({self.username}, {self.email}, {self.role.value})"


@dataclass
class Product:
    """
    Product model class representing a store product.
    """
    product_id: int
    name: str
    description: str
    price: float
    category: str
    stock_quantity: int = 0
    is_active: bool = True
    created_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    updated_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Post-initialization validation."""
        self.name = sanitize_string(self.name, 200)
        self.description = sanitize_string(self.description, 1000)
        self.category = sanitize_string(self.category, 100)
        
        if self.price < 0:
            raise ValueError("Price cannot be negative")
        if self.stock_quantity < 0:
            raise ValueError("Stock quantity cannot be negative")

    def update_stock(self, quantity: int) -> None:
        """
        Update product stock quantity.
        
        Args:
            quantity (int): New stock quantity
        """
        if quantity < 0:
            raise ValueError("Stock quantity cannot be negative")
        self.stock_quantity = quantity
        self.updated_at = datetime.datetime.now()

    def is_in_stock(self) -> bool:
        """Check if product is in stock."""
        return self.stock_quantity > 0

    def calculate_discounted_price(self, discount_percent: float = 0.0) -> float:
        """
        Calculate price with discount applied.
        
        Args:
            discount_percent (float): Discount percentage (0-100)
            
        Returns:
            float: Discounted price
        """
        if not 0 <= discount_percent <= 100:
            raise ValueError("Discount percent must be between 0 and 100")
        
        discount_amount = (self.price * discount_percent) / 100
        return self.price - discount_amount

    def get_product_info(self) -> Dict[str, Any]:
        """
        Get complete product information.
        
        Returns:
            Dict[str, Any]: Product information dictionary
        """
        return {
            'product_id': self.product_id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'category': self.category,
            'stock_quantity': self.stock_quantity,
            'is_active': self.is_active,
            'in_stock': self.is_in_stock(),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'metadata': self.metadata
        }

    def __str__(self) -> str:
        return f"Product({self.name}, ${self.price}, Stock: {self.stock_quantity})"


@dataclass
class OrderItem:
    """Order item representing a product in an order."""
    product: Product
    quantity: int
    unit_price: float = field(init=False)

    def __post_init__(self):
        """Set unit price from product."""
        self.unit_price = self.product.price
        if self.quantity <= 0:
            raise ValueError("Quantity must be positive")

    def get_total_price(self) -> float:
        """Calculate total price for this order item."""
        return self.unit_price * self.quantity

    def to_dict(self) -> Dict[str, Any]:
        """Convert order item to dictionary."""
        return {
            'product_id': self.product.product_id,
            'product_name': self.product.name,
            'quantity': self.quantity,
            'unit_price': self.unit_price,
            'total_price': self.get_total_price()
        }


@dataclass
class Order:
    """
    Order model class representing a customer order.
    """
    order_id: int
    customer: User
    status: OrderStatus = OrderStatus.PENDING
    created_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    updated_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    items: List[OrderItem] = field(default_factory=list)
    shipping_address: Dict[str, str] = field(default_factory=dict)
    notes: str = ""

    def __post_init__(self):
        """Post-initialization validation."""
        if isinstance(self.status, str):
            self.status = OrderStatus(self.status)
        self.notes = sanitize_string(self.notes, 500)

    def add_item(self, product: Product, quantity: int) -> None:
        """
        Add item to order.
        
        Args:
            product (Product): Product to add
            quantity (int): Quantity to add
        """
        if len(self.items) >= BUSINESS_CONSTANTS['max_order_items']:
            raise ValueError(f"Cannot add more than {BUSINESS_CONSTANTS['max_order_items']} items to an order")
        
        # Check if product already exists in order
        for item in self.items:
            if item.product.product_id == product.product_id:
                item.quantity += quantity
                self.updated_at = datetime.datetime.now()
                return
        
        # Add new item
        self.items.append(OrderItem(product, quantity))
        self.updated_at = datetime.datetime.now()

    def remove_item(self, product_id: int) -> bool:
        """
        Remove item from order.
        
        Args:
            product_id (int): Product ID to remove
            
        Returns:
            bool: True if item was removed, False if not found
        """
        for i, item in enumerate(self.items):
            if item.product.product_id == product_id:
                del self.items[i]
                self.updated_at = datetime.datetime.now()
                return True
        return False

    def get_subtotal(self) -> float:
        """Calculate order subtotal (before tax and shipping)."""
        return sum(item.get_total_price() for item in self.items)

    def get_tax_amount(self) -> float:
        """Calculate tax amount."""
        return self.get_subtotal() * BUSINESS_CONSTANTS['tax_rate']

    def get_shipping_cost(self) -> float:
        """Calculate shipping cost."""
        subtotal = self.get_subtotal()
        if subtotal >= BUSINESS_CONSTANTS['free_shipping_threshold']:
            return 0.0
        return BUSINESS_CONSTANTS['shipping_cost']

    def get_total(self) -> float:
        """Calculate order total."""
        return self.get_subtotal() + self.get_tax_amount() + self.get_shipping_cost()

    def update_status(self, new_status: OrderStatus) -> None:
        """
        Update order status.
        
        Args:
            new_status (OrderStatus): New status
        """
        self.status = new_status
        self.updated_at = datetime.datetime.now()

    def get_order_summary(self) -> Dict[str, Any]:
        """
        Get complete order summary.
        
        Returns:
            Dict[str, Any]: Order summary data
        """
        return {
            'order_id': self.order_id,
            'customer': self.customer.get_full_profile(),
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'items': [item.to_dict() for item in self.items],
            'subtotal': self.get_subtotal(),
            'tax_amount': self.get_tax_amount(),
            'shipping_cost': self.get_shipping_cost(),
            'total': self.get_total(),
            'shipping_address': self.shipping_address,
            'notes': self.notes
        }

    def __str__(self) -> str:
        return f"Order({self.order_id}, {self.customer.username}, {self.status.value}, ${self.get_total():.2f})"


# Export all model classes and enums
__all__ = [
    'UserRole', 'OrderStatus', 'User', 'Product', 'OrderItem', 'Order'
]