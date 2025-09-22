"""
Main application file demonstrating imports and usage of functions from other modules.
This file contains the main application logic and imports functions from models.py and services.py.
"""

import sys
from typing import Dict, Any, List

# Import classes and functions from our modules
from models import (
    User, Product, Order, UserRole, OrderStatus, 
    validate_email, generate_hash, sanitize_string, BUSINESS_CONSTANTS
)
from services import (
    UserService, ProductService, ApplicationService,
    format_currency, calculate_order_total, validate_user_data, 
    process_payment, ServiceError
)


def main_application_demo():
    """
    Main application demonstration function that uses imported classes and functions.
    """
    print("🚀 Python Sample Repository - Main Application Demo")
    print("=" * 60)
    
    # Use imported validation functions
    print("\n📧 Testing Email Validation (imported from models.py):")
    test_emails = ["user@example.com", "invalid-email", "test@domain.co.uk"]
    for email in test_emails:
        is_valid = validate_email(email)
        print(f"   {email}: {'✅ Valid' if is_valid else '❌ Invalid'}")
    
    # Use imported string sanitization
    print("\n🧹 Testing String Sanitization (imported from models.py):")
    test_strings = ["  Hello World!  ", "A very long string that needs truncation", "Normal text"]
    for text in test_strings:
        sanitized = sanitize_string(text, 20)
        print(f"   Original: '{text}' → Sanitized: '{sanitized}'")
    
    # Use imported hash generation
    print("\n🔐 Testing Hash Generation (imported from models.py):")
    passwords = ["password123", "mysecret", "strongpassword"]
    for pwd in passwords:
        hashed = generate_hash(pwd)
        print(f"   Password: '{pwd}' → Hash: '{hashed}'")


def demonstrate_user_workflow():
    """
    Demonstrate user workflow using imported service classes and functions.
    """
    print("\n👤 User Workflow Demonstration")
    print("-" * 40)
    
    # Use imported ApplicationService class
    app_service = ApplicationService()
    
    # Test user data validation (imported function)
    print("\n🔍 Testing User Data Validation (imported from services.py):")
    test_users = [
        ("john_doe", "john@example.com"),
        ("ab", "invalid-email"),  # Invalid: username too short, bad email
        ("valid_user", "user@domain.com")
    ]
    
    for username, email in test_users:
        is_valid = validate_user_data(username, email)
        print(f"   User: {username}, Email: {email} → {'✅ Valid' if is_valid else '❌ Invalid'}")
    
    # Create users using imported UserService
    print("\n👥 Creating Users (using imported UserService class):")
    try:
        user1 = app_service.user_service.create_user_account("alice_smith", "alice@example.com", UserRole.CUSTOMER)
        user2 = app_service.user_service.create_user_account("bob_jones", "bob@example.com", UserRole.ADMIN)
        
        print(f"   Created User 1: {user1.username} (ID: {user1.user_id}, Role: {user1.role.value})")
        print(f"   Created User 2: {user2.username} (ID: {user2.user_id}, Role: {user2.role.value})")
        
    except ServiceError as e:
        print(f"   ❌ Error creating users: {e}")


def demonstrate_product_workflow():
    """
    Demonstrate product workflow using imported classes and functions.
    """
    print("\n🛍️ Product Workflow Demonstration")
    print("-" * 40)
    
    # Use imported ProductService
    product_service = ProductService()
    
    # Create products
    print("\n📦 Creating Products (using imported ProductService class):")
    products_data = [
        {"name": "Laptop Computer", "price": 999.99, "category": "electronics"},
        {"name": "Coffee Mug", "price": 15.50, "category": "kitchen"},
        {"name": "Programming Book", "price": 45.00, "category": "books"}
    ]
    
    created_products = []
    for product_info in products_data:
        product = product_service.create_product(
            name=product_info["name"],
            price=product_info["price"],
            category=product_info["category"]
        )
        created_products.append(product)
        
        # Use imported format_currency function
        formatted_price = format_currency(product.price, BUSINESS_CONSTANTS['DEFAULT_CURRENCY'])
        print(f"   Created: {product.name} - {formatted_price} (ID: {product.product_id})")
    
    # Search products
    print("\n🔍 Searching Products:")
    search_queries = ["laptop", "coffee", "programming"]
    for query in search_queries:
        results = product_service.search_products(query)
        print(f"   Search '{query}': Found {len(results)} products")
        for product in results:
            print(f"      - {product.name} ({product.category})")


def demonstrate_payment_processing():
    """
    Demonstrate payment processing using imported functions.
    """
    print("\n💳 Payment Processing Demonstration")
    print("-" * 40)
    
    # Use imported process_payment function
    print("\n💰 Processing Payments (using imported process_payment function):")
    payments = [
        {"amount": 99.99, "method": "credit_card"},
        {"amount": 250.00, "method": "paypal"},
        {"amount": 15.50, "method": "debit_card"}
    ]
    
    for payment in payments:
        result = process_payment(payment["amount"], payment["method"])
        formatted_amount = format_currency(result["amount"], result["currency"])
        
        print(f"   Payment: {formatted_amount} via {payment['method']}")
        print(f"      Status: {'✅ Success' if result['success'] else '❌ Failed'}")
        print(f"      Transaction ID: {result['transaction_id']}")
        print(f"      Timestamp: {result['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")


def demonstrate_complete_workflow():
    """
    Demonstrate complete workflow using imported ApplicationService.
    """
    print("\n🔄 Complete Workflow Demonstration")
    print("-" * 40)
    
    # Use imported ApplicationService for complete workflow
    app_service = ApplicationService()
    
    print("\n🚀 Running Complete User Registration with Products:")
    
    # Test data
    username = "demo_user"
    email = "demo@example.com"
    product_data = [
        {"name": "Wireless Headphones", "price": 89.99, "category": "electronics"},
        {"name": "Notebook", "price": 12.99, "category": "office"}
    ]
    
    # Use imported method from ApplicationService
    result = app_service.register_user_with_products(username, email, product_data)
    
    if result['success']:
        print(f"   ✅ {result['message']}")
        print(f"   User Details:")
        user_info = result['user']
        print(f"      - ID: {user_info['user_id']}")
        print(f"      - Username: {user_info['username']}")
        print(f"      - Email: {user_info['email']}")
        print(f"      - Role: {user_info['role']}")
        
        print(f"   Created Products:")
        for product in result['products']:
            print(f"      - {product['name']}: {product['formatted_price']} (ID: {product['product_id']})")
    else:
        print(f"   ❌ {result['message']}: {result['error']}")
    
    # Get application statistics using imported method
    print("\n📊 Application Statistics (using imported get_application_stats):")
    stats = app_service.get_application_stats()
    print(f"   Total Users: {stats['total_users']}")
    print(f"   Total Products: {stats['total_products']}")
    print(f"   Business Constants: {stats['business_constants']}")


def display_configuration():
    """
    Display configuration information using imported constants.
    """
    print("\n⚙️ Configuration Information")
    print("-" * 40)
    
    # Use imported BUSINESS_CONSTANTS
    print("\n📋 Business Constants (imported from models.py):")
    for key, value in BUSINESS_CONSTANTS.items():
        print(f"   {key}: {value}")
    
    # Use imported enums
    print(f"\n👤 Available User Roles (imported from models.py):")
    for role in UserRole:
        print(f"   - {role.value}")
    
    print(f"\n📦 Available Order Statuses (imported from models.py):")
    for status in OrderStatus:
        print(f"   - {status.value}")


def interactive_menu():
    """
    Interactive menu system using imported functions and classes.
    """
    print("\n🎯 Interactive Menu System")
    print("-" * 40)
    
    while True:
        print("\nChoose a demo to run:")
        print("1. Email Validation & String Functions")
        print("2. User Workflow")
        print("3. Product Workflow")
        print("4. Payment Processing")
        print("5. Complete Workflow")
        print("6. View Configuration")
        print("7. Exit")
        
        try:
            choice = input("\nEnter your choice (1-7): ").strip()
            
            if choice == "1":
                main_application_demo()
            elif choice == "2":
                demonstrate_user_workflow()
            elif choice == "3":
                demonstrate_product_workflow()
            elif choice == "4":
                demonstrate_payment_processing()
            elif choice == "5":
                demonstrate_complete_workflow()
            elif choice == "6":
                display_configuration()
            elif choice == "7":
                print("\n👋 Goodbye! Thanks for trying the demo.")
                break
            else:
                print("\n❌ Invalid choice. Please enter a number between 1-7.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Demo interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ An error occurred: {e}")


if __name__ == "__main__":
    print("🐍 Python Sample Repository")
    print("This application demonstrates importing classes and functions from other modules.")
    print(f"Current Python version: {sys.version}")
    print()
    
    # Check if we want to run interactive mode
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_menu()
    else:
        # Run all demonstrations
        main_application_demo()
        demonstrate_user_workflow()
        demonstrate_product_workflow()
        demonstrate_payment_processing()
        demonstrate_complete_workflow()
        display_configuration()
        
        print("\n" + "=" * 60)
        print("✅ All demonstrations completed successfully!")
        print("Run with --interactive flag for menu-driven experience.")
        print("Example: python main.py --interactive")