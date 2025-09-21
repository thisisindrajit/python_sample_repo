"""
Main application module for the sample Python repository.
Entry point that imports and uses all other modules to demonstrate cross-linking.
"""

import sys
import json
import argparse
from typing import Dict, Any, List, Optional

# Import all modules to demonstrate cross-linking
from config import (
    APP_NAME, APP_VERSION, DEBUG_MODE, API_CONFIG, DATABASE_CONFIG,
    get_config, is_production, get_database_url
)
from utils import (
    validate_email, sanitize_string, generate_hash, format_currency,
    parse_json_file, write_json_file, get_app_info
)
from models import User, Product, Order, OrderItem, UserRole, OrderStatus
from database import DatabaseManager, DatabaseError
from auth import AuthenticationService, AuthenticationError, PasswordValidator
from api import APIRouter, APIRequest, APIResponse, APIError
from services import ApplicationService, UserService, ProductService, OrderService, ServiceError
from logger import Logger, SystemMonitor, performance_monitor, app_logger


class SampleApplication:
    """
    Main application class that orchestrates all components.
    Demonstrates integration between all modules.
    """
    
    def __init__(self):
        """Initialize the sample application."""
        # Initialize logging first
        self.logger = Logger(f"{APP_NAME}.main")
        self.system_monitor = SystemMonitor(self.logger)
        
        # Initialize core components
        self.db_manager = None
        self.auth_service = None
        self.app_service = None
        self.api_router = None
        
        self.logger.info("Initializing Sample Application", version=APP_VERSION)

    @performance_monitor("application_startup")
    def initialize(self) -> bool:
        """
        Initialize all application components.
        
        Returns:
            bool: True if initialization successful, False otherwise
        """
        try:
            self.logger.info("Starting application initialization")
            
            # Initialize database
            self.logger.info("Initializing database connection")
            self.db_manager = DatabaseManager()
            
            if not self.db_manager.health_check():
                raise RuntimeError("Database health check failed")
            
            # Initialize authentication service
            self.logger.info("Initializing authentication service")
            self.auth_service = AuthenticationService(self.db_manager)
            
            # Initialize application services
            self.logger.info("Initializing application services")
            self.app_service = ApplicationService(self.db_manager, self.auth_service)
            
            # Initialize API router
            self.logger.info("Initializing API router")
            self.api_router = APIRouter(self.db_manager, self.auth_service)
            
            self.logger.info("Application initialization completed successfully")
            return True
            
        except Exception as e:
            self.logger.error("Failed to initialize application", exception=e)
            return False

    def create_sample_data(self) -> Dict[str, Any]:
        """
        Create sample data to demonstrate all functionality.
        
        Returns:
            Dict[str, Any]: Sample data creation results
        """
        try:
            self.logger.info("Creating sample data")
            results = {
                'users': [],
                'products': [],
                'orders': [],
                'errors': []
            }
            
            # Create sample users
            sample_users = [
                ('admin_user', 'admin@example.com', 'SecurePass123!', UserRole.ADMIN),
                ('john_doe', 'john@example.com', 'Password123!', UserRole.CUSTOMER),
                ('jane_smith', 'jane@example.com', 'MyPass456!', UserRole.CUSTOMER),
            ]
            
            for username, email, password, role in sample_users:
                try:
                    user_data = self.app_service.user_service.create_user_account(
                        username, email, password, role
                    )
                    results['users'].append(user_data)
                    self.logger.info(f"Created user: {username}", user_id=user_data['user']['user_id'])
                except ServiceError as e:
                    error_msg = f"Failed to create user {username}: {str(e)}"
                    results['errors'].append(error_msg)
                    self.logger.warning(error_msg)
            
            # Create sample products
            sample_products = [
                ('Laptop Pro', 'High-performance laptop for professionals', 1299.99, 'Electronics', 10),
                ('Wireless Headphones', 'Premium noise-canceling headphones', 299.99, 'Electronics', 25),
                ('Ergonomic Desk Chair', 'Comfortable office chair with lumbar support', 399.99, 'Furniture', 15),
                ('Coffee Maker', 'Programmable coffee maker with thermal carafe', 89.99, 'Appliances', 30),
                ('Python Programming Book', 'Complete guide to Python development', 49.99, 'Books', 50),
            ]
            
            for name, description, price, category, stock in sample_products:
                try:
                    product = self.db_manager.products.create_product(
                        name, description, price, category, stock
                    )
                    results['products'].append(product.get_product_info())
                    self.logger.info(f"Created product: {name}", product_id=product.product_id)
                except DatabaseError as e:
                    error_msg = f"Failed to create product {name}: {str(e)}"
                    results['errors'].append(error_msg)
                    self.logger.warning(error_msg)
            
            # Create sample orders
            if results['users'] and results['products']:
                try:
                    # Get a customer user
                    customer_data = next(
                        (u for u in results['users'] if u['user']['role'] == 'customer'), 
                        None
                    )
                    
                    if customer_data:
                        # Recreate user object
                        user = User(
                            user_id=customer_data['user']['user_id'],
                            username=customer_data['user']['username'],
                            email=customer_data['user']['email'],
                            role=UserRole(customer_data['user']['role'])
                        )
                        
                        # Create order
                        order = self.app_service.order_service.create_shopping_cart(user)
                        
                        # Add some products to the order
                        for product_info in results['products'][:2]:  # Add first 2 products
                            add_result = self.app_service.order_service.add_item_to_cart(
                                order.order_id, product_info['product_id'], 2
                            )
                            if not add_result['success']:
                                results['errors'].append(add_result['message'])
                        
                        # Get updated order
                        order = self.db_manager.orders.get_order_by_id(order.order_id)
                        if order:
                            results['orders'].append(order.get_order_summary())
                            self.logger.info(f"Created order: {order.order_id}", 
                                           customer_id=user.user_id, 
                                           total=order.get_total())
                
                except Exception as e:
                    error_msg = f"Failed to create sample order: {str(e)}"
                    results['errors'].append(error_msg)
                    self.logger.warning(error_msg)
            
            self.logger.info("Sample data creation completed", 
                           users_created=len(results['users']),
                           products_created=len(results['products']),
                           orders_created=len(results['orders']),
                           errors=len(results['errors']))
            
            return results
            
        except Exception as e:
            self.logger.error("Failed to create sample data", exception=e)
            return {'error': str(e)}

    def demonstrate_api_endpoints(self) -> Dict[str, Any]:
        """
        Demonstrate API functionality.
        
        Returns:
            Dict[str, Any]: API demonstration results
        """
        try:
            self.logger.info("Demonstrating API endpoints")
            
            results = {
                'api_info': self.api_router.get_api_info(),
                'endpoint_tests': []
            }
            
            # Test user registration
            register_request = APIRequest(
                method='POST',
                path='/api/users/register',
                headers={'Content-Type': 'application/json'},
                body={
                    'username': 'api_test_user',
                    'email': 'apitest@example.com',
                    'password': 'TestPass123!',
                    'role': 'customer'
                },
                query_params={}
            )
            
            try:
                response = self.api_router.handle_request(register_request)
                results['endpoint_tests'].append({
                    'endpoint': 'POST /api/users/register',
                    'status': 'success',
                    'status_code': response.status_code,
                    'response_preview': str(response.body)[:200] + '...' if len(str(response.body)) > 200 else str(response.body)
                })
            except APIError as e:
                results['endpoint_tests'].append({
                    'endpoint': 'POST /api/users/register',
                    'status': 'error',
                    'error': str(e),
                    'status_code': e.status_code
                })
            
            # Test user login
            login_request = APIRequest(
                method='POST',
                path='/api/users/login',
                headers={'Content-Type': 'application/json'},
                body={
                    'email': 'apitest@example.com',
                    'password': 'TestPass123!'
                },
                query_params={}
            )
            
            try:
                response = self.api_router.handle_request(login_request)
                results['endpoint_tests'].append({
                    'endpoint': 'POST /api/users/login',
                    'status': 'success',
                    'status_code': response.status_code,
                    'has_token': 'token' in response.body
                })
                
                # Store token for subsequent requests
                if 'token' in response.body:
                    token = response.body['token']
                    
                    # Test protected endpoint
                    profile_request = APIRequest(
                        method='GET',
                        path='/api/users/profile',
                        headers={
                            'Content-Type': 'application/json',
                            'Authorization': f'Bearer {token}'
                        },
                        body={},
                        query_params={}
                    )
                    
                    try:
                        profile_response = self.api_router.handle_request(profile_request)
                        results['endpoint_tests'].append({
                            'endpoint': 'GET /api/users/profile',
                            'status': 'success',
                            'status_code': profile_response.status_code,
                            'authenticated': True
                        })
                    except APIError as e:
                        results['endpoint_tests'].append({
                            'endpoint': 'GET /api/users/profile',
                            'status': 'error',
                            'error': str(e),
                            'status_code': e.status_code
                        })
                
            except APIError as e:
                results['endpoint_tests'].append({
                    'endpoint': 'POST /api/users/login',
                    'status': 'error',
                    'error': str(e),
                    'status_code': e.status_code
                })
            
            self.logger.info("API endpoint demonstration completed", 
                           tests_run=len(results['endpoint_tests']))
            
            return results
            
        except Exception as e:
            self.logger.error("Failed to demonstrate API endpoints", exception=e)
            return {'error': str(e)}

    def run_system_diagnostics(self) -> Dict[str, Any]:
        """
        Run comprehensive system diagnostics.
        
        Returns:
            Dict[str, Any]: Diagnostic results
        """
        try:
            self.logger.info("Running system diagnostics")
            
            # Get system health
            health_info = self.system_monitor.get_system_health()
            
            # Get application status
            app_status = self.app_service.get_application_status()
            
            # Get service statistics
            service_stats = self.app_service.get_service_statistics()
            
            # Test database connectivity
            db_health = self.db_manager.health_check()
            
            # Test configuration access
            config_test = {
                'database_config': get_config('database'),
                'api_config': get_config('api'),
                'auth_config': get_config('auth'),
                'database_url': get_database_url(),
                'is_production': is_production()
            }
            
            # Test utility functions
            utils_test = {
                'email_validation': validate_email('test@example.com'),
                'currency_formatting': format_currency(123.45),
                'hash_generation': len(generate_hash('test_data')) > 0,
                'app_info': get_app_info()
            }
            
            return {
                'system_health': health_info,
                'application_status': app_status,
                'service_statistics': service_stats,
                'database_health': db_health,
                'configuration_test': config_test,
                'utilities_test': utils_test,
                'diagnostics_completed': True
            }
            
        except Exception as e:
            self.logger.error("Failed to run system diagnostics", exception=e)
            return {
                'diagnostics_completed': False,
                'error': str(e)
            }

    def save_results_to_file(self, results: Dict[str, Any], filename: str = 'application_results.json') -> bool:
        """
        Save results to a JSON file.
        
        Args:
            results (Dict[str, Any]): Results to save
            filename (str): Output filename
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            success = write_json_file(results, filename)
            if success:
                self.logger.info(f"Results saved to {filename}")
            else:
                self.logger.error(f"Failed to save results to {filename}")
            return success
        except Exception as e:
            self.logger.error(f"Error saving results to file", exception=e)
            return False

    def run_full_demonstration(self) -> Dict[str, Any]:
        """
        Run a complete demonstration of all functionality.
        
        Returns:
            Dict[str, Any]: Complete demonstration results
        """
        self.logger.info("Starting full application demonstration")
        
        # Initialize application
        if not self.initialize():
            return {'error': 'Failed to initialize application'}
        
        # Run demonstrations
        demo_results = {
            'application_info': {
                'name': APP_NAME,
                'version': APP_VERSION,
                'debug_mode': DEBUG_MODE,
                'app_info': get_app_info()
            },
            'sample_data': self.create_sample_data(),
            'api_demonstration': self.demonstrate_api_endpoints(),
            'system_diagnostics': self.run_system_diagnostics(),
            'demonstration_completed': True
        }
        
        self.logger.info("Full application demonstration completed")
        return demo_results


def create_cli_parser() -> argparse.ArgumentParser:
    """
    Create command-line interface parser.
    
    Returns:
        argparse.ArgumentParser: CLI parser
    """
    parser = argparse.ArgumentParser(
        description=f'{APP_NAME} - Sample Python Repository Demonstration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo                    # Run full demonstration
  python main.py --create-data            # Create sample data only
  python main.py --api-test               # Test API endpoints
  python main.py --diagnostics            # Run system diagnostics
  python main.py --save-results demo.json # Save results to custom file
        """
    )
    
    parser.add_argument('--demo', action='store_true',
                       help='Run full demonstration')
    parser.add_argument('--create-data', action='store_true',
                       help='Create sample data only')
    parser.add_argument('--api-test', action='store_true',
                       help='Test API endpoints')
    parser.add_argument('--diagnostics', action='store_true',
                       help='Run system diagnostics')
    parser.add_argument('--save-results', metavar='FILENAME',
                       help='Save results to specified JSON file')
    parser.add_argument('--version', action='version',
                       version=f'{APP_NAME} {APP_VERSION}')
    
    return parser


def main():
    """Main entry point for the application."""
    try:
        # Parse command-line arguments
        parser = create_cli_parser()
        args = parser.parse_args()
        
        # Initialize application
        app = SampleApplication()
        
        # Determine what to run
        if args.demo:
            print(f"Running full demonstration of {APP_NAME}...")
            results = app.run_full_demonstration()
        elif args.create_data:
            print("Creating sample data...")
            app.initialize()
            results = {'sample_data': app.create_sample_data()}
        elif args.api_test:
            print("Testing API endpoints...")
            app.initialize()
            results = {'api_test': app.demonstrate_api_endpoints()}
        elif args.diagnostics:
            print("Running system diagnostics...")
            app.initialize()
            results = {'diagnostics': app.run_system_diagnostics()}
        else:
            # Default: run full demonstration
            print(f"Running full demonstration of {APP_NAME}...")
            results = app.run_full_demonstration()
        
        # Display results summary
        print(f"\n{'-' * 60}")
        print(f"DEMONSTRATION RESULTS SUMMARY")
        print(f"{'-' * 60}")
        
        if 'error' in results:
            print(f"❌ Error: {results['error']}")
        else:
            if 'sample_data' in results:
                data = results['sample_data']
                if isinstance(data, dict) and 'users' in data:
                    print(f"✅ Sample Data: {len(data.get('users', []))} users, "
                          f"{len(data.get('products', []))} products, "
                          f"{len(data.get('orders', []))} orders created")
                    if data.get('errors'):
                        print(f"⚠️  Errors: {len(data['errors'])} issues encountered")
            
            if 'api_demonstration' in results:
                api_data = results['api_demonstration']
                if isinstance(api_data, dict) and 'endpoint_tests' in api_data:
                    tests = api_data['endpoint_tests']
                    successful = len([t for t in tests if t.get('status') == 'success'])
                    print(f"✅ API Tests: {successful}/{len(tests)} endpoints tested successfully")
            
            if 'system_diagnostics' in results:
                diag = results['system_diagnostics']
                if isinstance(diag, dict) and diag.get('diagnostics_completed'):
                    db_status = "✅" if diag.get('database_health') else "❌"
                    print(f"{db_status} System Diagnostics: Database health check completed")
        
        # Save results if requested
        if args.save_results:
            if app.save_results_to_file(results, args.save_results):
                print(f"📁 Results saved to: {args.save_results}")
        
        print(f"\n🎉 Demonstration completed! Check the logs directory for detailed logging.")
        print(f"📊 Application: {APP_NAME} v{APP_VERSION}")
        
    except KeyboardInterrupt:
        print("\n⏹️  Demonstration interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        app_logger.error("Unexpected error in main", exception=e)
        sys.exit(1)


if __name__ == '__main__':
    main()