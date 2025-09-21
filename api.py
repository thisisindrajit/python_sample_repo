"""
API handlers module for the sample Python application.
Contains REST API endpoint handlers importing from multiple modules.
"""

import json
from typing import Dict, Any, List, Optional, Callable, Tuple
from dataclasses import dataclass
from functools import wraps
from http import HTTPStatus

# Import all required modules
from models import User, Product, Order, UserRole, OrderStatus
from database import DatabaseManager
from auth import AuthenticationService, AuthenticationError
from utils import sanitize_string, validate_email, format_currency
from config import API_CONFIG, BUSINESS_CONSTANTS


@dataclass
class APIRequest:
    """API request data structure."""
    method: str
    path: str
    headers: Dict[str, str]
    body: Dict[str, Any]
    query_params: Dict[str, str]
    current_user: Optional['User'] = None


@dataclass
class APIResponse:
    """API response data structure."""
    status_code: int
    headers: Dict[str, str]
    body: Dict[str, Any]
    
    def to_json(self) -> str:
        """Convert response to JSON string."""
        return json.dumps(self.body, indent=2, default=str)


class APIError(Exception):
    """Custom exception for API errors."""
    
    def __init__(self, message: str, status_code: int = 500):
        """
        Initialize API error.
        
        Args:
            message (str): Error message
            status_code (int): HTTP status code
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def require_auth(f: Callable) -> Callable:
    """
    Decorator to require authentication for API endpoints.
    
    Args:
        f (Callable): Function to wrap
        
    Returns:
        Callable: Wrapped function
    """
    @wraps(f)
    def wrapper(self, request: APIRequest, *args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            raise APIError("Authentication required", 401)
        
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        user = self.auth_service.get_current_user(token)
        if not user:
            raise APIError("Invalid or expired token", 401)
        
        # Add user to request context
        request.current_user = user
        return f(self, request, *args, **kwargs)
    
    return wrapper


def require_role(role: UserRole) -> Callable:
    """
    Decorator to require specific role for API endpoints.
    
    Args:
        role (UserRole): Required role
        
    Returns:
        Callable: Decorator function
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(self, request: APIRequest, *args, **kwargs):
            if not hasattr(request, 'current_user') or request.current_user is None:
                raise APIError("Authentication required", 401)
            
            user = request.current_user
            if user.role != role and user.role != UserRole.ADMIN:
                raise APIError("Insufficient permissions", 403)
            
            return f(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


class UserAPIHandler:
    """API handlers for user-related endpoints."""
    
    def __init__(self, auth_service: AuthenticationService, db_manager: DatabaseManager):
        """
        Initialize user API handler.
        
        Args:
            auth_service (AuthenticationService): Authentication service
            db_manager (DatabaseManager): Database manager
        """
        self.auth_service = auth_service
        self.db_manager = db_manager

    def register(self, request: APIRequest) -> APIResponse:
        """
        Register a new user.
        
        Args:
            request (APIRequest): API request
            
        Returns:
            APIResponse: API response
        """
        try:
            data = request.body
            username = sanitize_string(data.get('username', ''))
            email = data.get('email', '')
            password = data.get('password', '')
            role_str = data.get('role', 'customer')
            
            if not username or not email or not password:
                raise APIError("Username, email, and password are required", 400)
            
            try:
                role = UserRole(role_str)
            except ValueError:
                role = UserRole.CUSTOMER
            
            user = self.auth_service.register_user(username, email, password, role)
            
            return APIResponse(
                status_code=201,
                headers={'Content-Type': 'application/json'},
                body={
                    'success': True,
                    'message': 'User registered successfully',
                    'user': user.get_full_profile()
                }
            )
        
        except AuthenticationError as e:
            raise APIError(str(e), 400)
        except Exception as e:
            raise APIError(f"Registration failed: {str(e)}", 500)

    def login(self, request: APIRequest) -> APIResponse:
        """
        Authenticate user and return token.
        
        Args:
            request (APIRequest): API request
            
        Returns:
            APIResponse: API response
        """
        try:
            data = request.body
            email = data.get('email', '')
            password = data.get('password', '')
            
            if not email or not password:
                raise APIError("Email and password are required", 400)
            
            user, token = self.auth_service.authenticate_user(email, password)
            
            return APIResponse(
                status_code=200,
                headers={'Content-Type': 'application/json'},
                body={
                    'success': True,
                    'message': 'Login successful',
                    'token': token,
                    'user': user.get_full_profile()
                }
            )
        
        except AuthenticationError as e:
            raise APIError(str(e), 401)
        except Exception as e:
            raise APIError(f"Login failed: {str(e)}", 500)

    @require_auth
    def get_profile(self, request: APIRequest) -> APIResponse:
        """
        Get current user profile.
        
        Args:
            request (APIRequest): API request
            
        Returns:
            APIResponse: API response
        """
        user = request.current_user
        if user is None:
            raise APIError("User not found", 404)
        
        return APIResponse(
            status_code=200,
            headers={'Content-Type': 'application/json'},
            body={
                'success': True,
                'user': user.get_full_profile()
            }
        )

    @require_auth
    def logout(self, request: APIRequest) -> APIResponse:
        """
        Logout current user.
        
        Args:
            request (APIRequest): API request
            
        Returns:
            APIResponse: API response
        """
        auth_header = request.headers.get('Authorization', '')
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        success = self.auth_service.logout_user(token)
        
        return APIResponse(
            status_code=200,
            headers={'Content-Type': 'application/json'},
            body={
                'success': success,
                'message': 'Logged out successfully'
            }
        )


class ProductAPIHandler:
    """API handlers for product-related endpoints."""
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize product API handler.
        
        Args:
            db_manager (DatabaseManager): Database manager
        """
        self.db_manager = db_manager

    def get_products(self, request: APIRequest) -> APIResponse:
        """
        Get all products or products by category.
        
        Args:
            request (APIRequest): API request
            
        Returns:
            APIResponse: API response
        """
        try:
            category = request.query_params.get('category')
            
            if category:
                products = self.db_manager.products.get_products_by_category(category)
            else:
                # This would require implementing get_all_products method
                products = []  # Placeholder
            
            return APIResponse(
                status_code=200,
                headers={'Content-Type': 'application/json'},
                body={
                    'success': True,
                    'products': [product.get_product_info() for product in products],
                    'count': len(products)
                }
            )
        
        except Exception as e:
            raise APIError(f"Failed to retrieve products: {str(e)}", 500)

    def get_product(self, request: APIRequest, product_id: int) -> APIResponse:
        """
        Get product by ID.
        
        Args:
            request (APIRequest): API request
            product_id (int): Product ID
            
        Returns:
            APIResponse: API response
        """
        try:
            product = self.db_manager.products.get_product_by_id(product_id)
            
            if not product:
                raise APIError("Product not found", 404)
            
            return APIResponse(
                status_code=200,
                headers={'Content-Type': 'application/json'},
                body={
                    'success': True,
                    'product': product.get_product_info()
                }
            )
        
        except APIError:
            raise
        except Exception as e:
            raise APIError(f"Failed to retrieve product: {str(e)}", 500)

    @require_auth
    @require_role(UserRole.ADMIN)
    def create_product(self, request: APIRequest) -> APIResponse:
        """
        Create a new product (admin only).
        
        Args:
            request (APIRequest): API request
            
        Returns:
            APIResponse: API response
        """
        try:
            data = request.body
            name = sanitize_string(data.get('name', ''))
            description = sanitize_string(data.get('description', ''))
            price = float(data.get('price', 0))
            category = sanitize_string(data.get('category', ''))
            stock_quantity = int(data.get('stock_quantity', 0))
            
            if not name or not category or price <= 0:
                raise APIError("Name, category, and valid price are required", 400)
            
            product = self.db_manager.products.create_product(
                name, description, price, category, stock_quantity
            )
            
            return APIResponse(
                status_code=201,
                headers={'Content-Type': 'application/json'},
                body={
                    'success': True,
                    'message': 'Product created successfully',
                    'product': product.get_product_info()
                }
            )
        
        except APIError:
            raise
        except Exception as e:
            raise APIError(f"Failed to create product: {str(e)}", 500)


class OrderAPIHandler:
    """API handlers for order-related endpoints."""
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize order API handler.
        
        Args:
            db_manager (DatabaseManager): Database manager
        """
        self.db_manager = db_manager

    @require_auth
    def create_order(self, request: APIRequest) -> APIResponse:
        """
        Create a new order.
        
        Args:
            request (APIRequest): API request
            
        Returns:
            APIResponse: API response
        """
        try:
            user = request.current_user
            if user is None:
                raise APIError("User not found", 404)
                
            order = self.db_manager.orders.create_order(user)
            
            return APIResponse(
                status_code=201,
                headers={'Content-Type': 'application/json'},
                body={
                    'success': True,
                    'message': 'Order created successfully',
                    'order': order.get_order_summary()
                }
            )
        
        except Exception as e:
            raise APIError(f"Failed to create order: {str(e)}", 500)

    @require_auth
    def get_order(self, request: APIRequest, order_id: int) -> APIResponse:
        """
        Get order by ID.
        
        Args:
            request (APIRequest): API request
            order_id (int): Order ID
            
        Returns:
            APIResponse: API response
        """
        try:
            order = self.db_manager.orders.get_order_by_id(order_id)
            
            if not order:
                raise APIError("Order not found", 404)
            
            # Check if user owns the order or is admin
            user = request.current_user
            if user is None:
                raise APIError("User not found", 404)
                
            if order.customer.user_id != user.user_id and user.role != UserRole.ADMIN:
                raise APIError("Access denied", 403)
            
            return APIResponse(
                status_code=200,
                headers={'Content-Type': 'application/json'},
                body={
                    'success': True,
                    'order': order.get_order_summary()
                }
            )
        
        except APIError:
            raise
        except Exception as e:
            raise APIError(f"Failed to retrieve order: {str(e)}", 500)


class APIRouter:
    """
    Main API router that coordinates all endpoint handlers.
    """
    
    def __init__(self, db_manager: DatabaseManager, auth_service: AuthenticationService):
        """
        Initialize API router.
        
        Args:
            db_manager (DatabaseManager): Database manager
            auth_service (AuthenticationService): Authentication service
        """
        self.db_manager = db_manager
        self.auth_service = auth_service
        
        # Initialize handlers
        self.user_handler = UserAPIHandler(auth_service, db_manager)
        self.product_handler = ProductAPIHandler(db_manager)
        self.order_handler = OrderAPIHandler(db_manager)
        
        # Define routes
        self.routes = {
            ('POST', '/api/users/register'): self.user_handler.register,
            ('POST', '/api/users/login'): self.user_handler.login,
            ('GET', '/api/users/profile'): self.user_handler.get_profile,
            ('POST', '/api/users/logout'): self.user_handler.logout,
            ('GET', '/api/products'): self.product_handler.get_products,
            ('GET', '/api/products/{id}'): self.product_handler.get_product,
            ('POST', '/api/products'): self.product_handler.create_product,
            ('POST', '/api/orders'): self.order_handler.create_order,
            ('GET', '/api/orders/{id}'): self.order_handler.get_order,
        }

    def handle_request(self, request: APIRequest) -> APIResponse:
        """
        Route and handle API request.
        
        Args:
            request (APIRequest): API request
            
        Returns:
            APIResponse: API response
        """
        try:
            # Find matching route
            route_key = (request.method, request.path)
            
            # Handle parameterized routes (simple implementation)
            handler = None
            path_params = {}
            
            for (method, pattern), route_handler in self.routes.items():
                if method == request.method:
                    if pattern == request.path:
                        handler = route_handler
                        break
                    elif '{id}' in pattern:
                        # Simple parameter extraction
                        pattern_parts = pattern.split('/')
                        path_parts = request.path.split('/')
                        
                        if len(pattern_parts) == len(path_parts):
                            match = True
                            for i, part in enumerate(pattern_parts):
                                if part == '{id}':
                                    try:
                                        path_params['id'] = int(path_parts[i])
                                    except ValueError:
                                        match = False
                                        break
                                elif part != path_parts[i]:
                                    match = False
                                    break
                            
                            if match:
                                handler = route_handler
                                break
            
            if not handler:
                raise APIError("Endpoint not found", 404)
            
            # Call handler with path parameters
            if path_params:
                return handler(request, **path_params)
            else:
                return handler(request)
        
        except APIError:
            raise
        except Exception as e:
            raise APIError(f"Internal server error: {str(e)}", 500)

    def get_api_info(self) -> Dict[str, Any]:
        """
        Get API information and available endpoints.
        
        Returns:
            Dict[str, Any]: API information
        """
        return {
            'name': 'Sample Python Repository API',
            'version': '1.0.0',
            'endpoints': list(self.routes.keys()),
            'config': API_CONFIG
        }


# Export main classes
__all__ = [
    'APIRequest', 'APIResponse', 'APIError', 'UserAPIHandler', 
    'ProductAPIHandler', 'OrderAPIHandler', 'APIRouter',
    'require_auth', 'require_role'
]