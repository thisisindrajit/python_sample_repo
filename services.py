"""
Business logic services module for the sample Python application.
Contains business logic classes that orchestrate database and auth operations.
"""

from typing import List, Dict, Any, Optional, Tuple
import datetime

# Import all required modules
from models import User, Product, Order, OrderItem, UserRole, OrderStatus
from database import DatabaseManager, DatabaseError
from auth import AuthenticationService, AuthenticationError
from utils import format_currency, sanitize_string
from config import BUSINESS_CONSTANTS, get_config


class ServiceError(Exception):
    """Custom exception for business logic service errors."""
    pass


class UserService:
    """
    Business logic service for user operations.
    Orchestrates authentication and user data management.
    """
    
    def __init__(self, db_manager: DatabaseManager, auth_service: AuthenticationService):
        """
        Initialize user service.
        
        Args:
            db_manager (DatabaseManager): Database manager
            auth_service (AuthenticationService): Authentication service
        """
        self.db_manager = db_manager
        self.auth_service = auth_service

    def create_user_account(self, username: str, email: str, password: str, 
                          role: UserRole = UserRole.CUSTOMER) -> Dict[str, Any]:
        """
        Create a complete user account with validation and authentication.
        
        Args:
            username (str): Username
            email (str): Email address
            password (str): Password
            role (UserRole): User role
            
        Returns:
            Dict[str, Any]: User account information with token
            
        Raises:
            ServiceError: If account creation fails
        """
        try:
            # Register user through auth service (includes validation)
            user = self.auth_service.register_user(username, email, password, role)
            
            # Generate initial authentication token
            _, token = self.auth_service.authenticate_user(email, password)
            
            return {
                'user': user.get_full_profile(),
                'token': token,
                'message': 'User account created successfully',
                'account_status': 'active'
            }
        
        except AuthenticationError as e:
            raise ServiceError(f"Account creation failed: {str(e)}")
        except Exception as e:
            raise ServiceError(f"Unexpected error during account creation: {str(e)}")

    def get_user_dashboard(self, user_id: int) -> Dict[str, Any]:
        """
        Get comprehensive user dashboard information.
        
        Args:
            user_id (int): User ID
            
        Returns:
            Dict[str, Any]: Dashboard data
        """
        try:
            user = self.db_manager.users.get_user_by_id(user_id)
            if not user:
                raise ServiceError("User not found")
            
            # Get user's recent orders (this would require extending OrderRepository)
            # orders = self.db_manager.orders.get_orders_by_user(user_id, limit=5)
            orders = []  # Placeholder
            
            # Calculate user statistics
            total_orders = len(orders)
            total_spent = sum(order.get_total() for order in orders)
            
            return {
                'user_profile': user.get_full_profile(),
                'statistics': {
                    'total_orders': total_orders,
                    'total_spent': format_currency(total_spent),
                    'member_since': user.created_at.strftime('%B %Y'),
                    'last_login': user.last_login.isoformat() if user.last_login else None
                },
                'recent_orders': [order.get_order_summary() for order in orders[:3]],
                'account_status': 'active' if user.is_active else 'inactive'
            }
        
        except Exception as e:
            raise ServiceError(f"Failed to load user dashboard: {str(e)}")

    def update_user_preferences(self, user_id: int, preferences: Dict[str, Any]) -> bool:
        """
        Update user preferences and profile data.
        
        Args:
            user_id (int): User ID
            preferences (Dict[str, Any]): User preferences
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            user = self.db_manager.users.get_user_by_id(user_id)
            if not user:
                raise ServiceError("User not found")
            
            # Sanitize and validate preferences
            sanitized_preferences = {}
            for key, value in preferences.items():
                if isinstance(value, str):
                    sanitized_preferences[key] = sanitize_string(value, 500)
                else:
                    sanitized_preferences[key] = value
            
            # Update user profile data (this would require extending UserRepository)
            user.profile_data.update(sanitized_preferences)
            
            return True
        
        except Exception as e:
            raise ServiceError(f"Failed to update user preferences: {str(e)}")


class ProductService:
    """
    Business logic service for product operations.
    Handles product management and inventory.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize product service.
        
        Args:
            db_manager (DatabaseManager): Database manager
        """
        self.db_manager = db_manager

    def get_product_catalog(self, category: Optional[str] = None, 
                          price_range: Optional[Tuple[float, float]] = None) -> Dict[str, Any]:
        """
        Get filtered product catalog.
        
        Args:
            category (Optional[str]): Product category filter
            price_range (Optional[Tuple[float, float]]): Price range filter (min, max)
            
        Returns:
            Dict[str, Any]: Product catalog data
        """
        try:
            if category:
                products = self.db_manager.products.get_products_by_category(category)
            else:
                # This would require implementing get_all_products method
                products = []  # Placeholder
            
            # Apply price filtering if specified
            if price_range:
                min_price, max_price = price_range
                products = [p for p in products if min_price <= p.price <= max_price]
            
            # Only include active products
            active_products = [p for p in products if p.is_active]
            
            # Group products by category
            categories = {}
            for product in active_products:
                if product.category not in categories:
                    categories[product.category] = []
                categories[product.category].append(product.get_product_info())
            
            return {
                'products': [p.get_product_info() for p in active_products],
                'categories': categories,
                'total_count': len(active_products),
                'filters_applied': {
                    'category': category,
                    'price_range': price_range
                }
            }
        
        except Exception as e:
            raise ServiceError(f"Failed to load product catalog: {str(e)}")

    def check_product_availability(self, product_id: int, quantity: int) -> Dict[str, Any]:
        """
        Check if product is available in requested quantity.
        
        Args:
            product_id (int): Product ID
            quantity (int): Requested quantity
            
        Returns:
            Dict[str, Any]: Availability information
        """
        try:
            product = self.db_manager.products.get_product_by_id(product_id)
            if not product:
                return {
                    'available': False,
                    'reason': 'Product not found',
                    'suggested_quantity': 0
                }
            
            if not product.is_active:
                return {
                    'available': False,
                    'reason': 'Product is not active',
                    'suggested_quantity': 0
                }
            
            if product.stock_quantity >= quantity:
                return {
                    'available': True,
                    'product': product.get_product_info(),
                    'requested_quantity': quantity,
                    'total_price': format_currency(product.price * quantity)
                }
            else:
                return {
                    'available': False,
                    'reason': 'Insufficient stock',
                    'requested_quantity': quantity,
                    'available_quantity': product.stock_quantity,
                    'suggested_quantity': product.stock_quantity
                }
        
        except Exception as e:
            raise ServiceError(f"Failed to check product availability: {str(e)}")

    def update_product_inventory(self, product_id: int, quantity_change: int, 
                               reason: str = "Manual adjustment") -> Dict[str, Any]:
        """
        Update product inventory with tracking.
        
        Args:
            product_id (int): Product ID
            quantity_change (int): Change in quantity (positive or negative)
            reason (str): Reason for the change
            
        Returns:
            Dict[str, Any]: Update result
        """
        try:
            product = self.db_manager.products.get_product_by_id(product_id)
            if not product:
                raise ServiceError("Product not found")
            
            old_quantity = product.stock_quantity
            new_quantity = max(0, old_quantity + quantity_change)
            
            success = self.db_manager.products.update_product_stock(product_id, new_quantity)
            
            if success:
                return {
                    'success': True,
                    'product_id': product_id,
                    'old_quantity': old_quantity,
                    'new_quantity': new_quantity,
                    'change': quantity_change,
                    'reason': reason,
                    'timestamp': datetime.datetime.now().isoformat()
                }
            else:
                raise ServiceError("Failed to update inventory")
        
        except Exception as e:
            raise ServiceError(f"Failed to update product inventory: {str(e)}")


class OrderService:
    """
    Business logic service for order operations.
    Orchestrates order processing, inventory management, and business rules.
    """
    
    def __init__(self, db_manager: DatabaseManager, product_service: ProductService):
        """
        Initialize order service.
        
        Args:
            db_manager (DatabaseManager): Database manager
            product_service (ProductService): Product service
        """
        self.db_manager = db_manager
        self.product_service = product_service

    def create_shopping_cart(self, user: User) -> Order:
        """
        Create a new shopping cart (order) for user.
        
        Args:
            user (User): User creating the cart
            
        Returns:
            Order: Created order instance
        """
        try:
            order = self.db_manager.orders.create_order(user)
            return order
        
        except Exception as e:
            raise ServiceError(f"Failed to create shopping cart: {str(e)}")

    def add_item_to_cart(self, order_id: int, product_id: int, quantity: int) -> Dict[str, Any]:
        """
        Add item to shopping cart with business logic validation.
        
        Args:
            order_id (int): Order ID
            product_id (int): Product ID
            quantity (int): Quantity to add
            
        Returns:
            Dict[str, Any]: Add item result
        """
        try:
            # Get order
            order = self.db_manager.orders.get_order_by_id(order_id)
            if not order:
                raise ServiceError("Order not found")
            
            if order.status != OrderStatus.PENDING:
                raise ServiceError("Cannot modify confirmed order")
            
            # Check product availability
            availability = self.product_service.check_product_availability(product_id, quantity)
            if not availability['available']:
                return {
                    'success': False,
                    'message': f"Cannot add item: {availability['reason']}",
                    'availability': availability
                }
            
            # Get product
            product = self.db_manager.products.get_product_by_id(product_id)
            if not product:
                raise ServiceError("Product not found")
            
            # Check order item limit
            if len(order.items) >= BUSINESS_CONSTANTS['max_order_items']:
                return {
                    'success': False,
                    'message': f"Cannot add more than {BUSINESS_CONSTANTS['max_order_items']} items to an order"
                }
            
            # Add item to order
            order.add_item(product, quantity)
            
            return {
                'success': True,
                'message': 'Item added to cart successfully',
                'order_summary': order.get_order_summary(),
                'item_added': {
                    'product': product.get_product_info(),
                    'quantity': quantity,
                    'total_price': format_currency(product.price * quantity)
                }
            }
        
        except Exception as e:
            raise ServiceError(f"Failed to add item to cart: {str(e)}")

    def calculate_order_pricing(self, order: Order) -> Dict[str, Any]:
        """
        Calculate comprehensive order pricing with all fees and taxes.
        
        Args:
            order (Order): Order to calculate pricing for
            
        Returns:
            Dict[str, Any]: Detailed pricing breakdown
        """
        try:
            subtotal = order.get_subtotal()
            tax_amount = order.get_tax_amount()
            shipping_cost = order.get_shipping_cost()
            total = order.get_total()
            
            # Calculate potential savings
            savings = {
                'free_shipping_threshold': BUSINESS_CONSTANTS['free_shipping_threshold'],
                'amount_for_free_shipping': max(0, BUSINESS_CONSTANTS['free_shipping_threshold'] - subtotal),
                'would_save': BUSINESS_CONSTANTS['shipping_cost'] if subtotal < BUSINESS_CONSTANTS['free_shipping_threshold'] else 0
            }
            
            return {
                'subtotal': format_currency(subtotal),
                'subtotal_raw': subtotal,
                'tax_rate': BUSINESS_CONSTANTS['tax_rate'],
                'tax_amount': format_currency(tax_amount),
                'tax_amount_raw': tax_amount,
                'shipping_cost': format_currency(shipping_cost),
                'shipping_cost_raw': shipping_cost,
                'total': format_currency(total),
                'total_raw': total,
                'currency': BUSINESS_CONSTANTS['default_currency'],
                'savings_info': savings,
                'item_count': len(order.items)
            }
        
        except Exception as e:
            raise ServiceError(f"Failed to calculate order pricing: {str(e)}")

    def process_order_checkout(self, order_id: int, shipping_address: Dict[str, str], 
                             payment_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process order checkout with validation and inventory updates.
        
        Args:
            order_id (int): Order ID
            shipping_address (Dict[str, str]): Shipping address
            payment_info (Dict[str, Any]): Payment information
            
        Returns:
            Dict[str, Any]: Checkout result
        """
        try:
            # Get order
            order = self.db_manager.orders.get_order_by_id(order_id)
            if not order:
                raise ServiceError("Order not found")
            
            if order.status != OrderStatus.PENDING:
                raise ServiceError("Order has already been processed")
            
            if not order.items:
                raise ServiceError("Cannot checkout empty order")
            
            # Validate inventory for all items
            inventory_check = []
            for item in order.items:
                availability = self.product_service.check_product_availability(
                    item.product.product_id, item.quantity
                )
                inventory_check.append({
                    'product_id': item.product.product_id,
                    'product_name': item.product.name,
                    'requested': item.quantity,
                    'available': availability['available']
                })
                
                if not availability['available']:
                    return {
                        'success': False,
                        'message': 'Some items are no longer available',
                        'inventory_issues': inventory_check
                    }
            
            # Validate shipping address
            required_fields = ['street', 'city', 'state', 'zip_code', 'country']
            missing_fields = [field for field in required_fields if not shipping_address.get(field)]
            if missing_fields:
                return {
                    'success': False,
                    'message': f"Missing required shipping address fields: {', '.join(missing_fields)}"
                }
            
            # Update shipping address
            order.shipping_address = {
                key: sanitize_string(str(value), 200) for key, value in shipping_address.items()
            }
            
            # Process payment (simulated)
            payment_result = self._process_payment(order, payment_info)
            if not payment_result['success']:
                return {
                    'success': False,
                    'message': 'Payment processing failed',
                    'payment_error': payment_result['error']
                }
            
            # Update inventory for all items
            for item in order.items:
                self.product_service.update_product_inventory(
                    item.product.product_id, 
                    -item.quantity, 
                    f"Order #{order.order_id} checkout"
                )
            
            # Update order status
            order.update_status(OrderStatus.CONFIRMED)
            
            # Calculate final pricing
            pricing = self.calculate_order_pricing(order)
            
            return {
                'success': True,
                'message': 'Order processed successfully',
                'order_id': order.order_id,
                'order_summary': order.get_order_summary(),
                'pricing': pricing,
                'payment_confirmation': payment_result['confirmation_id'],
                'estimated_delivery': self._calculate_delivery_date()
            }
        
        except Exception as e:
            raise ServiceError(f"Failed to process checkout: {str(e)}")

    def _process_payment(self, order: Order, payment_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate payment processing.
        
        Args:
            order (Order): Order to process payment for
            payment_info (Dict[str, Any]): Payment information
            
        Returns:
            Dict[str, Any]: Payment result
        """
        # This is a simplified simulation
        required_fields = ['card_number', 'expiry_date', 'cvv', 'cardholder_name']
        missing_fields = [field for field in required_fields if not payment_info.get(field)]
        
        if missing_fields:
            return {
                'success': False,
                'error': f"Missing payment fields: {', '.join(missing_fields)}"
            }
        
        # Simulate successful payment
        return {
            'success': True,
            'confirmation_id': f"PAY_{order.order_id}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
            'amount_charged': order.get_total()
        }

    def _calculate_delivery_date(self) -> str:
        """Calculate estimated delivery date."""
        delivery_date = datetime.datetime.now() + datetime.timedelta(days=5)
        return delivery_date.strftime('%Y-%m-%d')


class ApplicationService:
    """
    Main application service that coordinates all business logic services.
    Provides a unified interface for the application layer.
    """
    
    def __init__(self, db_manager: DatabaseManager, auth_service: AuthenticationService):
        """
        Initialize application service.
        
        Args:
            db_manager (DatabaseManager): Database manager
            auth_service (AuthenticationService): Authentication service
        """
        self.db_manager = db_manager
        self.auth_service = auth_service
        
        # Initialize business logic services
        self.product_service = ProductService(db_manager)
        self.user_service = UserService(db_manager, auth_service)
        self.order_service = OrderService(db_manager, self.product_service)

    def get_application_status(self) -> Dict[str, Any]:
        """
        Get comprehensive application status.
        
        Returns:
            Dict[str, Any]: Application status information
        """
        try:
            db_healthy = self.db_manager.health_check()
            
            # Clean up expired sessions
            expired_sessions = self.auth_service.session_manager.cleanup_expired_sessions()
            
            return {
                'status': 'healthy' if db_healthy else 'unhealthy',
                'database': {
                    'connected': db_healthy,
                    'info': self.db_manager.get_connection_info()
                },
                'services': {
                    'user_service': 'active',
                    'product_service': 'active',
                    'order_service': 'active',
                    'auth_service': 'active'
                },
                'session_cleanup': {
                    'expired_sessions_removed': expired_sessions
                },
                'business_config': BUSINESS_CONSTANTS,
                'timestamp': datetime.datetime.now().isoformat()
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.datetime.now().isoformat()
            }

    def get_service_statistics(self) -> Dict[str, Any]:
        """
        Get service usage statistics.
        
        Returns:
            Dict[str, Any]: Service statistics
        """
        try:
            # Get active sessions count
            active_sessions = len(self.auth_service.session_manager.active_sessions)
            
            return {
                'authentication': {
                    'active_sessions': active_sessions,
                    'login_attempts_tracked': len(self.auth_service.session_manager.login_attempts)
                },
                'business_constants': BUSINESS_CONSTANTS,
                'system_info': {
                    'uptime': 'N/A',  # Would be calculated in real application
                    'memory_usage': 'N/A',  # Would be calculated in real application
                }
            }
        
        except Exception as e:
            raise ServiceError(f"Failed to get service statistics: {str(e)}")


# Export main classes
__all__ = [
    'ServiceError', 'UserService', 'ProductService', 'OrderService', 'ApplicationService'
]