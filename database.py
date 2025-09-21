"""
Database operations module for the sample Python application.
Contains connection handling and CRUD operations using models.
"""

import sqlite3
import datetime
from typing import List, Dict, Any, Optional, Union
from contextlib import contextmanager

# Import models and configuration
from models import User, Product, Order, OrderItem, UserRole, OrderStatus
from config import get_database_url, DATABASE_CONFIG
from utils import generate_hash


class DatabaseError(Exception):
    """Custom exception for database operations."""
    pass


class DatabaseConnection:
    """
    Database connection manager.
    Handles SQLite connections for this sample (in production, would use PostgreSQL).
    """
    
    def __init__(self, db_path: str = "sample_app.db"):
        """
        Initialize database connection.
        
        Args:
            db_path (str): Path to SQLite database file
        """
        self.db_path = db_path
        self.connection = None
        self._initialize_database()

    def _initialize_database(self):
        """Create database tables if they don't exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT,
                    role TEXT DEFAULT 'customer',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    profile_data TEXT
                )
            """)
            
            # Create products table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    product_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    price REAL NOT NULL,
                    category TEXT NOT NULL,
                    stock_quantity INTEGER DEFAULT 0,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            """)
            
            # Create orders table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    order_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    customer_id INTEGER NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    shipping_address TEXT,
                    notes TEXT,
                    FOREIGN KEY (customer_id) REFERENCES users (user_id)
                )
            """)
            
            # Create order_items table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS order_items (
                    item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    order_id INTEGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    quantity INTEGER NOT NULL,
                    unit_price REAL NOT NULL,
                    FOREIGN KEY (order_id) REFERENCES orders (order_id),
                    FOREIGN KEY (product_id) REFERENCES products (product_id)
                )
            """)
            
            conn.commit()

    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        
        Yields:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Database operation failed: {str(e)}")
        finally:
            conn.close()


class UserRepository:
    """Repository class for User CRUD operations."""
    
    def __init__(self, db_connection: DatabaseConnection):
        """
        Initialize user repository.
        
        Args:
            db_connection (DatabaseConnection): Database connection instance
        """
        self.db = db_connection

    def create_user(self, username: str, email: str, password: str, 
                   role: UserRole = UserRole.CUSTOMER) -> User:
        """
        Create a new user.
        
        Args:
            username (str): Username
            email (str): Email address
            password (str): Plain text password
            role (UserRole): User role
            
        Returns:
            User: Created user instance
            
        Raises:
            DatabaseError: If user creation fails
        """
        password_hash = generate_hash(password)
        
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (?, ?, ?, ?)
            """, (username, email, password_hash, role.value))
            
            user_id = cursor.lastrowid
            if user_id is None:
                raise DatabaseError("Failed to create user")
            conn.commit()
            
            # Create and return User object
            user = User(
                user_id=user_id,
                username=username,
                email=email,
                role=role
            )
            user._password_hash = password_hash
            return user

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Get user by ID.
        
        Args:
            user_id (int): User ID
            
        Returns:
            Optional[User]: User instance or None if not found
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            
            if row:
                return self._row_to_user(row)
            return None

    def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email.
        
        Args:
            email (str): Email address
            
        Returns:
            Optional[User]: User instance or None if not found
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            row = cursor.fetchone()
            
            if row:
                return self._row_to_user(row)
            return None

    def update_user_login(self, user_id: int) -> bool:
        """
        Update user's last login timestamp.
        
        Args:
            user_id (int): User ID
            
        Returns:
            bool: True if successful, False otherwise
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users SET last_login = CURRENT_TIMESTAMP 
                WHERE user_id = ?
            """, (user_id,))
            conn.commit()
            return cursor.rowcount > 0

    def _row_to_user(self, row: sqlite3.Row) -> User:
        """Convert database row to User object."""
        user = User(
            user_id=row['user_id'],
            username=row['username'],
            email=row['email'],
            role=UserRole(row['role']),
            created_at=datetime.datetime.fromisoformat(row['created_at']),
            last_login=datetime.datetime.fromisoformat(row['last_login']) if row['last_login'] else None,
            is_active=bool(row['is_active'])
        )
        user._password_hash = row['password_hash']
        return user


class ProductRepository:
    """Repository class for Product CRUD operations."""
    
    def __init__(self, db_connection: DatabaseConnection):
        """
        Initialize product repository.
        
        Args:
            db_connection (DatabaseConnection): Database connection instance
        """
        self.db = db_connection

    def create_product(self, name: str, description: str, price: float, 
                      category: str, stock_quantity: int = 0) -> Product:
        """
        Create a new product.
        
        Args:
            name (str): Product name
            description (str): Product description
            price (float): Product price
            category (str): Product category
            stock_quantity (int): Initial stock quantity
            
        Returns:
            Product: Created product instance
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO products (name, description, price, category, stock_quantity)
                VALUES (?, ?, ?, ?, ?)
            """, (name, description, price, category, stock_quantity))
            
            product_id = cursor.lastrowid
            if product_id is None:
                raise DatabaseError("Failed to create product")
            conn.commit()
            
            return Product(
                product_id=product_id,
                name=name,
                description=description,
                price=price,
                category=category,
                stock_quantity=stock_quantity
            )

    def get_product_by_id(self, product_id: int) -> Optional[Product]:
        """
        Get product by ID.
        
        Args:
            product_id (int): Product ID
            
        Returns:
            Optional[Product]: Product instance or None if not found
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
            row = cursor.fetchone()
            
            if row:
                return self._row_to_product(row)
            return None

    def get_products_by_category(self, category: str) -> List[Product]:
        """
        Get all products in a category.
        
        Args:
            category (str): Product category
            
        Returns:
            List[Product]: List of products in the category
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM products WHERE category = ? AND is_active = 1", (category,))
            rows = cursor.fetchall()
            
            return [self._row_to_product(row) for row in rows]

    def update_product_stock(self, product_id: int, new_quantity: int) -> bool:
        """
        Update product stock quantity.
        
        Args:
            product_id (int): Product ID
            new_quantity (int): New stock quantity
            
        Returns:
            bool: True if successful, False otherwise
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE products SET stock_quantity = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE product_id = ?
            """, (new_quantity, product_id))
            conn.commit()
            return cursor.rowcount > 0

    def _row_to_product(self, row: sqlite3.Row) -> Product:
        """Convert database row to Product object."""
        return Product(
            product_id=row['product_id'],
            name=row['name'],
            description=row['description'],
            price=row['price'],
            category=row['category'],
            stock_quantity=row['stock_quantity'],
            is_active=bool(row['is_active']),
            created_at=datetime.datetime.fromisoformat(row['created_at']),
            updated_at=datetime.datetime.fromisoformat(row['updated_at'])
        )


class OrderRepository:
    """Repository class for Order CRUD operations."""
    
    def __init__(self, db_connection: DatabaseConnection):
        """
        Initialize order repository.
        
        Args:
            db_connection (DatabaseConnection): Database connection instance
        """
        self.db = db_connection

    def create_order(self, customer: User) -> Order:
        """
        Create a new order.
        
        Args:
            customer (User): Customer placing the order
            
        Returns:
            Order: Created order instance
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO orders (customer_id)
                VALUES (?)
            """, (customer.user_id,))
            
            order_id = cursor.lastrowid
            if order_id is None:
                raise DatabaseError("Failed to create order")
            conn.commit()
            
            return Order(
                order_id=order_id,
                customer=customer
            )

    def get_order_by_id(self, order_id: int) -> Optional[Order]:
        """
        Get order by ID with all items loaded.
        
        Args:
            order_id (int): Order ID
            
        Returns:
            Optional[Order]: Order instance or None if not found
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT o.*, u.username, u.email, u.role 
                FROM orders o 
                JOIN users u ON o.customer_id = u.user_id 
                WHERE o.order_id = ?
            """, (order_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            # Create customer object
            customer = User(
                user_id=row['customer_id'],
                username=row['username'],
                email=row['email'],
                role=UserRole(row['role'])
            )
            
            # Create order object
            order = Order(
                order_id=row['order_id'],
                customer=customer,
                status=OrderStatus(row['status']),
                created_at=datetime.datetime.fromisoformat(row['created_at']),
                updated_at=datetime.datetime.fromisoformat(row['updated_at']),
                notes=row['notes'] or ""
            )
            
            # Load order items
            self._load_order_items(order)
            
            return order

    def _load_order_items(self, order: Order) -> None:
        """Load order items for an order."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT oi.*, p.name, p.description, p.price, p.category, p.stock_quantity
                FROM order_items oi
                JOIN products p ON oi.product_id = p.product_id
                WHERE oi.order_id = ?
            """, (order.order_id,))
            rows = cursor.fetchall()
            
            for row in rows:
                product = Product(
                    product_id=row['product_id'],
                    name=row['name'],
                    description=row['description'],
                    price=row['price'],
                    category=row['category'],
                    stock_quantity=row['stock_quantity']
                )
                
                order_item = OrderItem(
                    product=product,
                    quantity=row['quantity']
                )
                order_item.unit_price = row['unit_price']
                order.items.append(order_item)


# Database manager that coordinates all repositories
class DatabaseManager:
    """
    Central database manager coordinating all repository operations.
    """
    
    def __init__(self, db_path: str = "sample_app.db"):
        """
        Initialize database manager.
        
        Args:
            db_path (str): Path to SQLite database file
        """
        self.connection = DatabaseConnection(db_path)
        self.users = UserRepository(self.connection)
        self.products = ProductRepository(self.connection)
        self.orders = OrderRepository(self.connection)

    def get_connection_info(self) -> Dict[str, Any]:
        """
        Get database connection information.
        
        Returns:
            Dict[str, Any]: Connection information
        """
        return {
            'database_path': self.connection.db_path,
            'database_config': DATABASE_CONFIG,
            'connection_url': get_database_url()
        }

    def health_check(self) -> bool:
        """
        Perform database health check.
        
        Returns:
            bool: True if database is healthy, False otherwise
        """
        try:
            with self.connection.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                return True
        except Exception:
            return False


# Export main classes
__all__ = [
    'DatabaseError', 'DatabaseConnection', 'UserRepository', 
    'ProductRepository', 'OrderRepository', 'DatabaseManager'
]