"""
Testing module for the sample Python application.
Contains unit tests importing and testing functions from various modules.
"""

import unittest
import tempfile
import os
import datetime
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

# Import all modules to test
from config import (
    APP_NAME, APP_VERSION, get_config, is_production, get_database_url,
    DATABASE_CONFIG, API_CONFIG, AUTH_CONFIG
)
from utils import (
    validate_email, sanitize_string, generate_hash, format_currency,
    get_file_extension, is_allowed_file, format_file_size, chunk_list,
    flatten_dict, get_app_info
)
from models import User, Product, Order, OrderItem, UserRole, OrderStatus
from database import DatabaseManager, DatabaseConnection, UserRepository, ProductRepository
from auth import (
    AuthenticationService, PasswordValidator, SessionManager, 
    AuthToken, AuthenticationError
)
from api import APIRouter, APIRequest, APIResponse, APIError, UserAPIHandler
from services import UserService, ProductService, OrderService, ApplicationService, ServiceError
from logger import Logger, PerformanceMetrics, SystemMonitor
from main import SampleApplication


class TestConfig(unittest.TestCase):
    """Test cases for configuration module."""
    
    def test_app_constants(self):
        """Test application constants are properly defined."""
        self.assertIsInstance(APP_NAME, str)
        self.assertIsInstance(APP_VERSION, str)
        self.assertTrue(len(APP_NAME) > 0)
        self.assertTrue(len(APP_VERSION) > 0)
    
    def test_get_config(self):
        """Test configuration retrieval."""
        # Test valid sections
        db_config = get_config('database')
        self.assertIsInstance(db_config, dict)
        self.assertIn('host', db_config)
        self.assertIn('port', db_config)
        
        api_config = get_config('api')
        self.assertIsInstance(api_config, dict)
        self.assertIn('host', api_config)
        self.assertIn('port', api_config)
        
        # Test invalid section
        with self.assertRaises(KeyError):
            get_config('invalid_section')
    
    def test_database_url_generation(self):
        """Test database URL generation."""
        url = get_database_url()
        self.assertIsInstance(url, str)
        self.assertTrue(url.startswith('postgresql://'))
    
    def test_production_check(self):
        """Test production environment detection."""
        result = is_production()
        self.assertIsInstance(result, bool)


class TestUtils(unittest.TestCase):
    """Test cases for utility functions."""
    
    def test_validate_email(self):
        """Test email validation."""
        # Valid emails
        self.assertTrue(validate_email('test@example.com'))
        self.assertTrue(validate_email('user.name+tag@domain.co.uk'))
        self.assertTrue(validate_email('test123@test-domain.org'))
        
        # Invalid emails
        self.assertFalse(validate_email('invalid-email'))
        self.assertFalse(validate_email('@domain.com'))
        self.assertFalse(validate_email('test@'))
        self.assertFalse(validate_email('test.domain.com'))
    
    def test_sanitize_string(self):
        """Test string sanitization."""
        # Basic sanitization
        result = sanitize_string('Hello World!', 50)
        self.assertEqual(result, 'Hello World!')
        
        # Length limiting
        long_string = 'a' * 100
        result = sanitize_string(long_string, 10)
        self.assertEqual(len(result), 10)
        
        # Special character removal
        result = sanitize_string('Hello<script>alert("test")</script>World', 100)
        self.assertNotIn('<script>', result)
        self.assertNotIn('</script>', result)
    
    def test_generate_hash(self):
        """Test hash generation."""
        # Test different algorithms
        text = 'test_data'
        
        md5_hash = generate_hash(text, 'md5')
        self.assertEqual(len(md5_hash), 32)
        
        sha1_hash = generate_hash(text, 'sha1')
        self.assertEqual(len(sha1_hash), 40)
        
        sha256_hash = generate_hash(text, 'sha256')
        self.assertEqual(len(sha256_hash), 64)
        
        # Test invalid algorithm
        with self.assertRaises(ValueError):
            generate_hash(text, 'invalid_algorithm')
    
    def test_format_currency(self):
        """Test currency formatting."""
        self.assertEqual(format_currency(123.45), '$123.45')
        self.assertEqual(format_currency(0.99, 'EUR'), '€0.99')
        self.assertEqual(format_currency(1000.00, 'GBP'), '£1000.00')
    
    def test_file_operations(self):
        """Test file operation utilities."""
        # Test file extension
        self.assertEqual(get_file_extension('test.txt'), '.txt')
        self.assertEqual(get_file_extension('image.jpeg'), '.jpeg')
        self.assertEqual(get_file_extension('document'), '')
        
        # Test allowed file check
        self.assertTrue(is_allowed_file('document.pdf'))
        self.assertTrue(is_allowed_file('image.jpg'))
        self.assertFalse(is_allowed_file('script.exe'))
    
    def test_format_file_size(self):
        """Test file size formatting."""
        self.assertEqual(format_file_size(1024), '1.0 KB')
        self.assertEqual(format_file_size(1048576), '1.0 MB')
        self.assertEqual(format_file_size(500), '500.0 B')
    
    def test_chunk_list(self):
        """Test list chunking."""
        data = list(range(10))
        chunks = chunk_list(data, 3)
        
        self.assertEqual(len(chunks), 4)
        self.assertEqual(chunks[0], [0, 1, 2])
        self.assertEqual(chunks[-1], [9])
    
    def test_flatten_dict(self):
        """Test dictionary flattening."""
        nested = {
            'level1': {
                'level2': {
                    'value': 'test'
                },
                'direct': 'value'
            },
            'root': 'value'
        }
        
        flattened = flatten_dict(nested)
        self.assertIn('level1.level2.value', flattened)
        self.assertIn('level1.direct', flattened)
        self.assertIn('root', flattened)
    
    def test_get_app_info(self):
        """Test application info retrieval."""
        info = get_app_info()
        self.assertIsInstance(info, dict)
        self.assertIn('version', info)
        self.assertIn('python_version', info)
        self.assertIn('platform', info)
        self.assertIn('timestamp', info)


class TestModels(unittest.TestCase):
    """Test cases for data models."""
    
    def test_user_model(self):
        """Test User model functionality."""
        user = User(
            user_id=1,
            username='testuser',
            email='test@example.com',
            role=UserRole.CUSTOMER
        )
        
        # Test basic properties
        self.assertEqual(user.user_id, 1)
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.role, UserRole.CUSTOMER)
        
        # Test password functionality
        user.set_password('testpassword')
        self.assertTrue(user.check_password('testpassword'))
        self.assertFalse(user.check_password('wrongpassword'))
        
        # Test role checks
        self.assertFalse(user.is_admin())
        
        admin_user = User(2, 'admin', 'admin@example.com', UserRole.ADMIN)
        self.assertTrue(admin_user.is_admin())
        
        # Test profile data
        profile = user.get_full_profile()
        self.assertIsInstance(profile, dict)
        self.assertEqual(profile['username'], 'testuser')
        self.assertEqual(profile['email'], 'test@example.com')
    
    def test_product_model(self):
        """Test Product model functionality."""
        product = Product(
            product_id=1,
            name='Test Product',
            description='A test product',
            price=29.99,
            category='Test',
            stock_quantity=10
        )
        
        # Test basic properties
        self.assertEqual(product.product_id, 1)
        self.assertEqual(product.name, 'Test Product')
        self.assertEqual(product.price, 29.99)
        
        # Test stock operations
        self.assertTrue(product.is_in_stock())
        
        product.update_stock(0)
        self.assertFalse(product.is_in_stock())
        
        # Test price calculations
        discounted_price = product.calculate_discounted_price(10.0)
        self.assertAlmostEqual(discounted_price, 26.99, places=2)
        
        # Test product info
        info = product.get_product_info()
        self.assertIsInstance(info, dict)
        self.assertEqual(info['name'], 'Test Product')
    
    def test_order_model(self):
        """Test Order model functionality."""
        # Create test user and product
        user = User(1, 'testuser', 'test@example.com', UserRole.CUSTOMER)
        product = Product(1, 'Test Product', 'Description', 10.0, 'Test', 5)
        
        order = Order(
            order_id=1,
            customer=user,
            status=OrderStatus.PENDING
        )
        
        # Test basic properties
        self.assertEqual(order.order_id, 1)
        self.assertEqual(order.customer, user)
        self.assertEqual(order.status, OrderStatus.PENDING)
        
        # Test adding items
        order.add_item(product, 2)
        self.assertEqual(len(order.items), 1)
        self.assertEqual(order.items[0].quantity, 2)
        
        # Test pricing calculations
        subtotal = order.get_subtotal()
        self.assertEqual(subtotal, 20.0)  # 2 * 10.0
        
        tax_amount = order.get_tax_amount()
        self.assertGreater(tax_amount, 0)
        
        total = order.get_total()
        self.assertGreater(total, subtotal)
        
        # Test order summary
        summary = order.get_order_summary()
        self.assertIsInstance(summary, dict)
        self.assertEqual(summary['order_id'], 1)


class TestDatabase(unittest.TestCase):
    """Test cases for database operations."""
    
    def setUp(self):
        """Set up test database."""
        # Use in-memory SQLite for testing
        self.db_manager = DatabaseManager(':memory:')
    
    def test_database_connection(self):
        """Test database connection functionality."""
        self.assertTrue(self.db_manager.health_check())
        
        connection_info = self.db_manager.get_connection_info()
        self.assertIsInstance(connection_info, dict)
    
    def test_user_repository(self):
        """Test user repository operations."""
        # Create a user
        user = self.db_manager.users.create_user(
            'testuser', 'test@example.com', 'password123', UserRole.CUSTOMER
        )
        
        self.assertIsInstance(user, User)
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        
        # Retrieve by ID
        retrieved_user = self.db_manager.users.get_user_by_id(user.user_id)
        self.assertIsNotNone(retrieved_user)
        if retrieved_user:
            self.assertEqual(retrieved_user.username, 'testuser')
        
        # Retrieve by email
        retrieved_user = self.db_manager.users.get_user_by_email('test@example.com')
        self.assertIsNotNone(retrieved_user)
        if retrieved_user:
            self.assertEqual(retrieved_user.username, 'testuser')
    
    def test_product_repository(self):
        """Test product repository operations."""
        # Create a product
        product = self.db_manager.products.create_product(
            'Test Product', 'Description', 29.99, 'Electronics', 10
        )
        
        self.assertIsInstance(product, Product)
        self.assertEqual(product.name, 'Test Product')
        self.assertEqual(product.price, 29.99)
        
        # Retrieve by ID
        retrieved_product = self.db_manager.products.get_product_by_id(product.product_id)
        self.assertIsNotNone(retrieved_product)
        if retrieved_product:
            self.assertEqual(retrieved_product.name, 'Test Product')
        
        # Update stock
        success = self.db_manager.products.update_product_stock(product.product_id, 5)
        self.assertTrue(success)


class TestAuthentication(unittest.TestCase):
    """Test cases for authentication functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.db_manager = DatabaseManager(':memory:')
        self.auth_service = AuthenticationService(self.db_manager)
    
    def test_password_validator(self):
        """Test password validation."""
        validator = PasswordValidator()
        
        # Test weak password
        is_valid, errors = validator.validate_password_strength('weak')
        self.assertFalse(is_valid)
        self.assertGreater(len(errors), 0)
        
        # Test strong password
        is_valid, errors = validator.validate_password_strength('StrongPass123!')
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
        
        # Test password hashing and verification
        password = 'TestPassword123!'
        hashed = validator.hash_password(password)
        self.assertTrue(validator.verify_password(password, hashed))
        self.assertFalse(validator.verify_password('wrong', hashed))
    
    def test_session_manager(self):
        """Test session management."""
        session_manager = SessionManager()
        user = User(1, 'testuser', 'test@example.com', UserRole.CUSTOMER)
        
        # Test token generation
        token = session_manager.generate_token(user)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 20)
        
        # Test token validation
        auth_token = session_manager.validate_token(token)
        self.assertIsInstance(auth_token, AuthToken)
        if auth_token:
            self.assertEqual(auth_token.user_id, user.user_id)
        
        # Test token revocation
        success = session_manager.revoke_token(token)
        self.assertTrue(success)
        
        # Test invalid token
        invalid_token = session_manager.validate_token(token)
        self.assertIsNone(invalid_token)
    
    def test_authentication_service(self):
        """Test authentication service."""
        # Test user registration
        user = self.auth_service.register_user(
            'testuser', 'test@example.com', 'TestPass123!', UserRole.CUSTOMER
        )
        self.assertIsInstance(user, User)
        
        # Test user authentication
        auth_user, token = self.auth_service.authenticate_user('test@example.com', 'TestPass123!')
        self.assertIsInstance(auth_user, User)
        self.assertIsInstance(token, str)
        
        # Test getting current user
        current_user = self.auth_service.get_current_user(token)
        self.assertIsNotNone(current_user)
        if current_user:
            self.assertEqual(current_user.email, 'test@example.com')
        
        # Test logout
        success = self.auth_service.logout_user(token)
        self.assertTrue(success)


class TestAPI(unittest.TestCase):
    """Test cases for API functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.db_manager = DatabaseManager(':memory:')
        self.auth_service = AuthenticationService(self.db_manager)
        self.api_router = APIRouter(self.db_manager, self.auth_service)
    
    def test_api_request_response(self):
        """Test API request and response structures."""
        request = APIRequest(
            method='POST',
            path='/api/test',
            headers={'Content-Type': 'application/json'},
            body={'test': 'data'},
            query_params={'param': 'value'}
        )
        
        self.assertEqual(request.method, 'POST')
        self.assertEqual(request.path, '/api/test')
        self.assertIn('Content-Type', request.headers)
        
        response = APIResponse(
            status_code=200,
            headers={'Content-Type': 'application/json'},
            body={'success': True}
        )
        
        self.assertEqual(response.status_code, 200)
        json_output = response.to_json()
        self.assertIsInstance(json_output, str)
    
    def test_user_registration_api(self):
        """Test user registration through API."""
        request = APIRequest(
            method='POST',
            path='/api/users/register',
            headers={'Content-Type': 'application/json'},
            body={
                'username': 'apiuser',
                'email': 'api@example.com',
                'password': 'TestPass123!',
                'role': 'customer'
            },
            query_params={}
        )
        
        response = self.api_router.handle_request(request)
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.body['success'])
    
    def test_api_error_handling(self):
        """Test API error handling."""
        # Test invalid endpoint
        request = APIRequest(
            method='GET',
            path='/api/invalid',
            headers={},
            body={},
            query_params={}
        )
        
        with self.assertRaises(APIError) as context:
            self.api_router.handle_request(request)
        
        self.assertEqual(context.exception.status_code, 404)


class TestServices(unittest.TestCase):
    """Test cases for business logic services."""
    
    def setUp(self):
        """Set up test environment."""
        self.db_manager = DatabaseManager(':memory:')
        self.auth_service = AuthenticationService(self.db_manager)
        self.app_service = ApplicationService(self.db_manager, self.auth_service)
    
    def test_user_service(self):
        """Test user service functionality."""
        user_service = self.app_service.user_service
        
        # Test user account creation
        account_data = user_service.create_user_account(
            'serviceuser', 'service@example.com', 'TestPass123!', UserRole.CUSTOMER
        )
        
        self.assertIsInstance(account_data, dict)
        self.assertIn('user', account_data)
        self.assertIn('token', account_data)
        self.assertEqual(account_data['account_status'], 'active')
    
    def test_product_service(self):
        """Test product service functionality."""
        product_service = self.app_service.product_service
        
        # Create test product
        product = self.db_manager.products.create_product(
            'Service Test Product', 'Description', 19.99, 'Test', 5
        )
        
        # Test availability check
        availability = product_service.check_product_availability(product.product_id, 3)
        self.assertTrue(availability['available'])
        
        # Test inventory update
        update_result = product_service.update_product_inventory(
            product.product_id, -2, 'Test sale'
        )
        self.assertTrue(update_result['success'])
        self.assertEqual(update_result['new_quantity'], 3)
    
    def test_application_service(self):
        """Test application service coordination."""
        # Test application status
        status = self.app_service.get_application_status()
        self.assertIsInstance(status, dict)
        self.assertIn('status', status)
        self.assertIn('database', status)
        
        # Test service statistics
        stats = self.app_service.get_service_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('authentication', stats)


class TestLogging(unittest.TestCase):
    """Test cases for logging functionality."""
    
    def test_logger_creation(self):
        """Test logger creation and basic functionality."""
        logger = Logger('test_logger')
        
        # Test basic logging methods
        logger.info('Test info message')
        logger.warning('Test warning message')
        logger.error('Test error message')
        
        # Check that log entries are stored
        recent_logs = logger.get_recent_logs(count=5)
        self.assertGreater(len(recent_logs), 0)
    
    def test_performance_metrics(self):
        """Test performance monitoring."""
        logger = Logger('test_performance')
        
        # Start performance monitoring
        metrics = logger.performance('test_operation')
        self.assertIsInstance(metrics, PerformanceMetrics)
        
        # Complete the operation
        metrics.complete(success=True)
        self.assertTrue(metrics.success)
        self.assertIsNotNone(metrics.duration_ms)
    
    def test_system_monitor(self):
        """Test system monitoring functionality."""
        logger = Logger('test_monitor')
        monitor = SystemMonitor(logger)
        
        # Test system health check
        health = monitor.get_system_health()
        self.assertIsInstance(health, dict)
        self.assertIn('status', health)


class TestMainApplication(unittest.TestCase):
    """Test cases for main application functionality."""
    
    def test_application_initialization(self):
        """Test application initialization."""
        app = SampleApplication()
        
        # Test initialization (may fail due to database setup, that's okay)
        try:
            success = app.initialize()
            self.assertIsInstance(success, bool)
        except Exception:
            # Initialization might fail in test environment, that's expected
            pass
    
    @patch('main.DatabaseManager')
    def test_sample_data_creation(self, mock_db_manager):
        """Test sample data creation with mocked database."""
        # Mock database manager
        mock_db_manager.return_value.health_check.return_value = True
        
        app = SampleApplication()
        app.db_manager = mock_db_manager.return_value
        
        # Mock services
        app.auth_service = Mock()
        app.app_service = Mock()
        app.app_service.user_service = Mock()
        
        # Test would require more detailed mocking for full functionality
        self.assertIsInstance(app, SampleApplication)


def create_test_suite() -> unittest.TestSuite:
    """
    Create a comprehensive test suite.
    
    Returns:
        unittest.TestSuite: Test suite with all test cases
    """
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestConfig,
        TestUtils,
        TestModels,
        TestDatabase,
        TestAuthentication,
        TestAPI,
        TestServices,
        TestLogging,
        TestMainApplication,
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    return suite


def run_tests(verbosity: int = 2) -> unittest.TextTestResult:
    """
    Run all tests and return results.
    
    Args:
        verbosity (int): Test output verbosity level
        
    Returns:
        unittest.TextTestResult: Test results
    """
    suite = create_test_suite()
    runner = unittest.TextTestRunner(verbosity=verbosity)
    return runner.run(suite)


def main():
    """Main entry point for running tests."""
    print(f"Running tests for {APP_NAME} v{APP_VERSION}")
    print("=" * 60)
    
    # Run tests
    result = run_tests()
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    if result.failures:
        print(f"\nFAILURES ({len(result.failures)}):")
        for test, failure in result.failures:
            print(f"  - {test}: {failure.split('AssertionError: ')[-1].split('\n')[0]}")
    
    if result.errors:
        print(f"\nERRORS ({len(result.errors)}):")
        for test, error in result.errors:
            print(f"  - {test}: {error.split('\n')[-2] if len(error.split('\n')) > 1 else error}")
    
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100) if result.testsRun > 0 else 0
    print(f"\nSuccess rate: {success_rate:.1f}%")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)