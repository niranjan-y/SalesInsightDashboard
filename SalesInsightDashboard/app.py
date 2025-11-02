import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
from datetime import datetime, date, timedelta
import io
import os
import shutil
import zipfile
import json
from typing import cast
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures
from sklearn.pipeline import Pipeline
from sklearn.metrics import mean_absolute_error, r2_score
import scipy.stats as stats
import hashlib
import secrets
import uuid
from functools import wraps

# Configure page
st.set_page_config(
    page_title="Retail Sales Management & Analytics",
    page_icon="🛍️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Database initialization
def init_db():
    """Initialize SQLite database with tables and demo data"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            address TEXT,
            gender TEXT CHECK(gender IN ('Male', 'Female', 'Other')),
            age INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            total_amount REAL NOT NULL,
            sale_date DATE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products (id),
            FOREIGN KEY (customer_id) REFERENCES customers (id)
        )
    ''')
    
    # User management tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role_id INTEGER NOT NULL,
            full_name TEXT,
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (role_id) REFERENCES roles (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS role_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (role_id) REFERENCES roles (id),
            FOREIGN KEY (permission_id) REFERENCES permissions (id),
            UNIQUE(role_id, permission_id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Initialize default roles and permissions
    cursor.execute('SELECT COUNT(*) FROM roles')
    if cursor.fetchone()[0] == 0:
        # Default roles
        roles = [
            ('Super Admin', 'Full system access with all permissions'),
            ('Manager', 'Management access with most features enabled'),
            ('Sales Associate', 'Sales and customer management access'),
            ('Viewer', 'Read-only access to reports and analytics')
        ]
        cursor.executemany('INSERT INTO roles (name, description) VALUES (?, ?)', roles)
        
        # Default permissions
        permissions = [
            ('view_dashboard', 'View main dashboard and analytics'),
            ('manage_products', 'Create, edit, and delete products'),
            ('manage_customers', 'Create, edit, and delete customers'),
            ('manage_sales', 'Create, edit, and delete sales records'),
            ('view_reports', 'Access to all reports and analytics'),
            ('manage_users', 'Create, edit, and delete user accounts'),
            ('manage_roles', 'Create and modify user roles and permissions'),
            ('export_data', 'Export data in various formats'),
            ('backup_restore', 'Backup and restore database'),
            ('system_settings', 'Modify system-wide settings')
        ]
        cursor.executemany('INSERT INTO permissions (name, description) VALUES (?, ?)', permissions)
        
        # Role-Permission assignments
        role_perms = [
            # Super Admin - all permissions
            (1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 7), (1, 8), (1, 9), (1, 10),
            # Manager - most permissions except user/role management
            (2, 1), (2, 2), (2, 3), (2, 4), (2, 5), (2, 8), (2, 9),
            # Sales Associate - sales and customer focused
            (3, 1), (3, 2), (3, 3), (3, 4), (3, 5), (3, 8),
            # Viewer - read-only access
            (4, 1), (4, 5)
        ]
        cursor.executemany('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', role_perms)
        
        # Create default admin user (password: admin123) using secure hashing
        admin_password_hash = hash_password('admin123')
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role_id, full_name)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 'admin@retail.com', admin_password_hash, 1, 'System Administrator'))
    
    # Check if demo data already exists
    cursor.execute('SELECT COUNT(*) FROM products')
    if cursor.fetchone()[0] == 0:
        # Insert demo products
        demo_products = [
            ('Laptop Pro 15"', 'Electronics', 1299.99, 25, 'High-performance laptop for professionals'),
            ('Wireless Headphones', 'Electronics', 199.99, 50, 'Premium noise-cancelling headphones'),
            ('Coffee Maker Deluxe', 'Appliances', 89.99, 30, 'Programmable coffee maker with thermal carafe'),
            ('Running Shoes Elite', 'Sports', 129.99, 40, 'Professional running shoes with advanced cushioning'),
            ('Desk Organizer Set', 'Office', 34.99, 75, 'Complete desk organization solution')
        ]
        cursor.executemany('INSERT INTO products (name, category, price, stock, description) VALUES (?, ?, ?, ?, ?)', demo_products)
        
        # Insert demo customers
        demo_customers = [
            ('John Smith', 'john.smith@email.com', '+1-555-0101', '123 Main St, City, State', 'Male', 32),
            ('Sarah Johnson', 'sarah.j@email.com', '+1-555-0102', '456 Oak Ave, City, State', 'Female', 28),
            ('Mike Davis', 'mike.davis@email.com', '+1-555-0103', '789 Pine Rd, City, State', 'Male', 45),
            ('Emily Brown', 'emily.brown@email.com', '+1-555-0104', '321 Elm St, City, State', 'Female', 35),
            ('Alex Chen', 'alex.chen@email.com', '+1-555-0105', '654 Maple Dr, City, State', 'Other', 29),
            ('Lisa Wilson', 'lisa.wilson@email.com', '+1-555-0106', '987 Cedar Ln, City, State', 'Female', 41),
            ('Tom Anderson', 'tom.anderson@email.com', '+1-555-0107', '147 Birch Way, City, State', 'Male', 38),
            ('Kate Martinez', 'kate.martinez@email.com', '+1-555-0108', '258 Spruce Ave, City, State', 'Female', 33)
        ]
        cursor.executemany('INSERT INTO customers (name, email, phone, address, gender, age) VALUES (?, ?, ?, ?, ?, ?)', demo_customers)
        
        # Insert demo sales
        demo_sales = [
            (1, 1, 1, 1299.99, 1299.99, '2024-01-15'),
            (2, 2, 2, 199.99, 399.98, '2024-01-16'),
            (3, 3, 1, 89.99, 89.99, '2024-01-17'),
            (4, 4, 1, 129.99, 129.99, '2024-01-18'),
            (5, 5, 3, 34.99, 104.97, '2024-01-19'),
            (1, 6, 1, 1299.99, 1299.99, '2024-01-20'),
            (2, 7, 1, 199.99, 199.99, '2024-01-21'),
            (3, 8, 2, 89.99, 179.98, '2024-01-22'),
            (4, 1, 1, 129.99, 129.99, '2024-02-01'),
            (5, 2, 2, 34.99, 69.98, '2024-02-02'),
            (1, 3, 1, 1299.99, 1299.99, '2024-02-03'),
            (2, 4, 3, 199.99, 599.97, '2024-02-04'),
            (3, 5, 1, 89.99, 89.99, '2024-02-05'),
            (4, 6, 2, 129.99, 259.98, '2024-02-06'),
            (5, 7, 1, 34.99, 34.99, '2024-02-07'),
            (1, 8, 1, 1299.99, 1299.99, '2024-02-08'),
            (2, 1, 2, 199.99, 399.98, '2024-02-09'),
            (3, 2, 1, 89.99, 89.99, '2024-02-10'),
            (4, 3, 1, 129.99, 129.99, '2024-02-11'),
            (5, 4, 4, 34.99, 139.96, '2024-02-12')
        ]
        cursor.executemany('INSERT INTO sales (product_id, customer_id, quantity, unit_price, total_amount, sale_date) VALUES (?, ?, ?, ?, ?, ?)', demo_sales)
    
    conn.commit()
    conn.close()

# Database helper functions
def get_connection():
    """Get database connection"""
    return sqlite3.connect('database.db')

def get_products() -> pd.DataFrame:
    """Get all products from database"""
    conn = get_connection()
    df = pd.read_sql_query('SELECT * FROM products ORDER BY name', conn)
    conn.close()
    return df

def get_customers() -> pd.DataFrame:
    """Get all customers from database"""
    conn = get_connection()
    df = pd.read_sql_query('SELECT * FROM customers ORDER BY name', conn)
    conn.close()
    return df

def get_sales() -> pd.DataFrame:
    """Get all sales with product and customer details"""
    conn = get_connection()
    query = '''
        SELECT s.id, s.product_id, s.customer_id, s.quantity, s.unit_price, s.total_amount, s.sale_date,
               p.name as product_name, p.category, c.name as customer_name
        FROM sales s
        JOIN products p ON s.product_id = p.id
        JOIN customers c ON s.customer_id = c.id
        ORDER BY s.sale_date DESC
    '''
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def add_product(name, category, price, stock, description):
    """Add new product to database"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO products (name, category, price, stock, description) VALUES (?, ?, ?, ?, ?)',
        (name, category, price, stock, description)
    )
    conn.commit()
    conn.close()

def update_product(product_id, name, category, price, stock, description):
    """Update existing product"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE products SET name=?, category=?, price=?, stock=?, description=? WHERE id=?',
        (name, category, price, stock, description, product_id)
    )
    conn.commit()
    conn.close()

def delete_product(product_id):
    """Delete product from database"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM products WHERE id=?', (product_id,))
    conn.commit()
    conn.close()

def add_customer(name, email, phone, address, gender, age):
    """Add new customer to database"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO customers (name, email, phone, address, gender, age) VALUES (?, ?, ?, ?, ?, ?)',
        (name, email, phone, address, gender, age)
    )
    conn.commit()
    conn.close()

def update_customer(customer_id, name, email, phone, address, gender, age):
    """Update existing customer"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE customers SET name=?, email=?, phone=?, address=?, gender=?, age=? WHERE id=?',
        (name, email, phone, address, gender, age, customer_id)
    )
    conn.commit()
    conn.close()

def delete_customer(customer_id):
    """Delete customer from database"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM customers WHERE id=?', (customer_id,))
    conn.commit()
    conn.close()

def add_sale(product_id, customer_id, quantity, sale_date):
    """Add new sale to database"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get product price
    cursor.execute('SELECT price, stock FROM products WHERE id=?', (product_id,))
    result = cursor.fetchone()
    if not result:
        conn.close()
        return False, "Product not found"
    
    price, current_stock = result
    if current_stock < quantity:
        conn.close()
        return False, f"Insufficient stock. Available: {current_stock}"
    
    total_amount = price * quantity
    
    # Insert sale
    cursor.execute(
        'INSERT INTO sales (product_id, customer_id, quantity, unit_price, total_amount, sale_date) VALUES (?, ?, ?, ?, ?, ?)',
        (product_id, customer_id, quantity, price, total_amount, sale_date)
    )
    
    # Update product stock
    cursor.execute('UPDATE products SET stock = stock - ? WHERE id=?', (quantity, product_id))
    
    conn.commit()
    conn.close()
    return True, "Sale added successfully"

def delete_sale(sale_id):
    """Delete sale and restore product stock"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get sale details first
    cursor.execute('SELECT product_id, quantity FROM sales WHERE id=?', (sale_id,))
    result = cursor.fetchone()
    if result:
        product_id, quantity = result
        # Restore stock
        cursor.execute('UPDATE products SET stock = stock + ? WHERE id=?', (quantity, product_id))
        # Delete sale
        cursor.execute('DELETE FROM sales WHERE id=?', (sale_id,))
    
    conn.commit()
    conn.close()

def get_kpis():
    """Calculate KPIs from database"""
    conn = get_connection()
    
    # Total sales
    cursor = conn.cursor()
    cursor.execute('SELECT SUM(total_amount) FROM sales')
    total_sales = cursor.fetchone()[0] or 0
    
    # Monthly revenue (current month)
    current_month = datetime.now().strftime('%Y-%m')
    cursor.execute('SELECT SUM(total_amount) FROM sales WHERE sale_date LIKE ?', (f'{current_month}%',))
    monthly_revenue = cursor.fetchone()[0] or 0
    
    # Total customers
    cursor.execute('SELECT COUNT(*) FROM customers')
    total_customers = cursor.fetchone()[0] or 0
    
    # Best-selling product
    cursor.execute('''
        SELECT p.name, SUM(s.quantity) as total_qty
        FROM sales s
        JOIN products p ON s.product_id = p.id
        GROUP BY s.product_id, p.name
        ORDER BY total_qty DESC
        LIMIT 1
    ''')
    result = cursor.fetchone()
    best_product = result[0] if result else "No sales yet"
    
    conn.close()
    
    return {
        'total_sales': total_sales,
        'monthly_revenue': monthly_revenue,
        'total_customers': total_customers,
        'best_product': best_product
    }

# === AUTHENTICATION AND SESSION MANAGEMENT ===

def hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 for enterprise-grade security"""
    # Generate a cryptographically secure salt
    salt = secrets.token_bytes(32)  # 32 bytes = 256 bits
    
    # Use PBKDF2-HMAC-SHA256 with 100,000 iterations (recommended minimum)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # 100,000 iterations for computational resistance
    )
    
    # Return base64-encoded salt + hash for storage
    import base64
    salt_b64 = base64.b64encode(salt).decode('ascii')
    hash_b64 = base64.b64encode(password_hash).decode('ascii')
    return f"pbkdf2${salt_b64}${hash_b64}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password with constant-time comparison and legacy support"""
    import base64
    import hmac
    
    # Check format to determine hash type
    if stored_hash.startswith('pbkdf2$'):
        # New PBKDF2 format: pbkdf2$salt_b64$hash_b64
        try:
            parts = stored_hash.split('$')
            if len(parts) != 3:
                return False
            
            salt = base64.b64decode(parts[1])
            expected_hash = base64.b64decode(parts[2])
            
            # Hash the provided password with stored salt
            computed_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000
            )
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(expected_hash, computed_hash)
        except Exception:
            return False
    
    elif len(stored_hash) == 64:
        # Legacy unsalted SHA-256 verification
        legacy_hash = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(legacy_hash, stored_hash)
    
    elif len(stored_hash) == 96:
        # Legacy salted SHA-256 verification
        try:
            salt = stored_hash[:32]
            expected_hash = stored_hash[32:]
            
            salted_password = salt + password
            password_hash = hashlib.sha256(salted_password.encode()).hexdigest()
            
            return hmac.compare_digest(password_hash, expected_hash)
        except Exception:
            return False
    
    return False

def migrate_legacy_password(user_id: int, password: str):
    """Migrate legacy password to new PBKDF2 format"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Create new PBKDF2 hash
    new_hash = hash_password(password)
    
    # Update the user's password hash
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user_id))
    conn.commit()
    conn.close()

def create_session_token() -> str:
    """Generate a secure session token"""
    return secrets.token_urlsafe(32)

def create_user_session(user_id: int) -> str:
    """Create a new session for user"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Clean up expired sessions
    cursor.execute('DELETE FROM user_sessions WHERE expires_at < ?', (datetime.now(),))
    
    # Create new session
    session_token = create_session_token()
    expires_at = datetime.now() + timedelta(hours=24)  # 24 hour sessions
    
    cursor.execute('''
        INSERT INTO user_sessions (user_id, session_token, expires_at)
        VALUES (?, ?, ?)
    ''', (user_id, session_token, expires_at))
    
    conn.commit()
    conn.close()
    return session_token

def get_user_from_session(session_token: str):
    """Get user from session token"""
    if not session_token:
        return None
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get user from valid session
    cursor.execute('''
        SELECT u.id, u.username, u.email, u.full_name, u.role_id, r.name as role_name
        FROM users u
        JOIN user_sessions s ON u.id = s.user_id
        JOIN roles r ON u.role_id = r.id
        WHERE s.session_token = ? AND s.expires_at > ? AND u.is_active = 1
    ''', (session_token, datetime.now()))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            'id': result[0],
            'username': result[1],
            'email': result[2],
            'full_name': result[3],
            'role_id': result[4],
            'role_name': result[5]
        }
    return None

def authenticate_user(username: str, password: str):
    """Authenticate user with username and password and migrate legacy passwords"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, username, email, password_hash, full_name, role_id, is_active
        FROM users
        WHERE username = ? OR email = ?
    ''', (username, username))
    
    result = cursor.fetchone()
    
    if result and result[6] and verify_password(password, result[3]):
        user_id = result[0]
        password_hash = result[3]
        
        # Check if this is any legacy password format and migrate to PBKDF2
        if not password_hash.startswith('pbkdf2$'):
            # Migrate any legacy format (unsalted SHA-256 or salted SHA-256) to PBKDF2
            migrate_legacy_password(user_id, password)
        
        # Update last login
        cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user_id))
        conn.commit()
        conn.close()
        
        return {
            'id': user_id,
            'username': result[1],
            'email': result[2],
            'full_name': result[4],
            'role_id': result[5]
        }
    
    conn.close()
    return None

def logout_user(session_token: str):
    """Logout user by removing session"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM user_sessions WHERE session_token = ?', (session_token,))
    conn.commit()
    conn.close()

def get_user_permissions(user_id: int) -> list:
    """Get user permissions based on role"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT p.name
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        JOIN users u ON rp.role_id = u.role_id
        WHERE u.id = ?
    ''', (user_id,))
    
    permissions = [row[0] for row in cursor.fetchall()]
    conn.close()
    return permissions

def has_permission(user_id: int, permission: str) -> bool:
    """Check if user has specific permission"""
    permissions = get_user_permissions(user_id)
    return permission in permissions

def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'current_user' not in st.session_state or not st.session_state.current_user:
                st.error("Authentication required")
                return None
            
            user_id = st.session_state.current_user['id']
            if not has_permission(user_id, permission):
                st.error("You don't have permission to access this feature")
                return None
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def get_all_users():
    """Get all users with role information"""
    conn = get_connection()
    query = '''
        SELECT u.id, u.username, u.email, u.full_name, u.is_active, u.last_login, r.name as role_name
        FROM users u
        JOIN roles r ON u.role_id = r.id
        ORDER BY u.username
    '''
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def get_all_roles():
    """Get all roles"""
    conn = get_connection()
    df = pd.read_sql_query('SELECT * FROM roles ORDER BY name', conn)
    conn.close()
    return df

def create_user(username: str, email: str, password: str, role_id: int, full_name: str = None, current_user_id: int = None):
    """Create new user with permission validation"""
    # Server-side permission check
    if current_user_id:
        if not has_permission(current_user_id, 'manage_users'):
            return False, "Insufficient permissions to create users"
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        password_hash = hash_password(password)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role_id, full_name)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, email, password_hash, role_id, full_name))
        conn.commit()
        conn.close()
        return True, "User created successfully"
    except sqlite3.IntegrityError as e:
        conn.close()
        if 'username' in str(e):
            return False, "Username already exists"
        elif 'email' in str(e):
            return False, "Email already exists"
        else:
            return False, "Error creating user"

def update_user(user_id: int, username: str, email: str, role_id: int, full_name: str, is_active: bool, current_user_id: int = None):
    """Update existing user with security checks"""
    # Server-side permission check
    if current_user_id:
        if not has_permission(current_user_id, 'manage_users'):
            return False, "Insufficient permissions to update users"
        
        # Prevent updating your own role or deactivating yourself
        if user_id == current_user_id:
            return False, "You cannot modify your own account through this interface"
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # Check if target user is Super Admin and prevent role changes
    cursor.execute('''
        SELECT r.name FROM users u 
        JOIN roles r ON u.role_id = r.id 
        WHERE u.id = ?
    ''', (user_id,))
    result = cursor.fetchone()
    
    if result and result[0] == 'Super Admin':
        # Don't allow changing Super Admin role or status
        cursor.execute('SELECT role_id FROM roles WHERE name = ?', ('Super Admin',))
        super_admin_role_id = cursor.fetchone()[0]
        if role_id != super_admin_role_id or not is_active:
            conn.close()
            return False, "Cannot modify Super Admin accounts"
    
    try:
        cursor.execute('''
            UPDATE users SET username=?, email=?, role_id=?, full_name=?, is_active=?
            WHERE id=?
        ''', (username, email, role_id, full_name, is_active, user_id))
        conn.commit()
        conn.close()
        return True, "User updated successfully"
    except sqlite3.IntegrityError as e:
        conn.close()
        if 'username' in str(e):
            return False, "Username already exists"
        elif 'email' in str(e):
            return False, "Email already exists"
        else:
            return False, "Error updating user"

def delete_user(user_id: int, current_user_id: int):
    """Delete user with proper security checks"""
    # Security checks
    if user_id == current_user_id:
        return False, "You cannot delete your own account"
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # Check if target user is a Super Admin
    cursor.execute('''
        SELECT r.name FROM users u 
        JOIN roles r ON u.role_id = r.id 
        WHERE u.id = ?
    ''', (user_id,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return False, "User not found"
    
    if result[0] == 'Super Admin':
        conn.close()
        return False, "Cannot delete Super Admin accounts"
    
    # Check if this is the last Super Admin (prevent system lockout)
    cursor.execute('''
        SELECT COUNT(*) FROM users u 
        JOIN roles r ON u.role_id = r.id 
        WHERE r.name = 'Super Admin' AND u.is_active = 1
    ''')
    admin_count = cursor.fetchone()[0]
    
    if admin_count <= 1:
        conn.close()
        return False, "Cannot delete the last Super Admin account"
    
    try:
        # Delete user sessions first
        cursor.execute('DELETE FROM user_sessions WHERE user_id=?', (user_id,))
        # Delete user
        cursor.execute('DELETE FROM users WHERE id=?', (user_id,))
        
        conn.commit()
        conn.close()
        return True, "User deleted successfully"
    except Exception as e:
        conn.close()
        return False, f"Error deleting user: {str(e)}"

# Session management for Streamlit
def check_authentication():
    """Check if user is authenticated via session state"""
    if 'session_token' in st.session_state:
        user = get_user_from_session(st.session_state.session_token)
        if user:
            st.session_state.current_user = user
            return True
    
    # Clear invalid session
    if 'session_token' in st.session_state:
        del st.session_state.session_token
    if 'current_user' in st.session_state:
        del st.session_state.current_user
    
    return False

def login_form():
    """Display login form"""
    st.markdown("### 🔐 Login to Retail Dashboard")
    
    with st.form("login_form"):
        username = st.text_input("Username or Email")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            if username and password:
                user = authenticate_user(username, password)
                if user:
                    session_token = create_user_session(user['id'])
                    st.session_state.session_token = session_token
                    st.session_state.current_user = user
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid username/email or password")
            else:
                st.error("Please enter both username and password")
    
    st.info("Default login: **admin** / **admin123**")

# === DATABASE BACKUP AND RESTORE FUNCTIONS ===

def create_backup_directory():
    """Create backup directory if it doesn't exist"""
    backup_dir = "backups"
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    return backup_dir

def create_database_backup(backup_name: str = None, user_id: int = None) -> tuple[bool, str]:
    """Create a complete database backup with metadata"""
    # Permission check
    if user_id and not has_permission(user_id, 'backup_restore'):
        return False, "Insufficient permissions to create backups"
    
    try:
        backup_dir = create_backup_directory()
        
        # Generate backup name if not provided
        if not backup_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_{timestamp}"
        
        # Create backup subdirectory
        backup_path = os.path.join(backup_dir, backup_name)
        os.makedirs(backup_path, exist_ok=True)
        
        # Create SQL dump
        conn = get_connection()
        
        # Get all table data
        tables = ['products', 'customers', 'sales', 'roles', 'permissions', 'role_permissions', 'users', 'user_sessions']
        sql_dump = []
        
        # Add metadata
        metadata = {
            'backup_name': backup_name,
            'created_at': datetime.now().isoformat(),
            'created_by': user_id,
            'application_version': '2.0.0',
            'database_version': 'SQLite',
            'tables_backed_up': tables
        }
        
        # Save metadata
        with open(os.path.join(backup_path, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Create SQL schema dump
        cursor = conn.cursor()
        
        # Get schema for each table
        schema_dump = []
        for table in tables:
            cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table}'")
            result = cursor.fetchone()
            if result:
                schema_dump.append(f"-- Table: {table}")
                schema_dump.append(result[0] + ";")
                schema_dump.append("")
        
        # Save schema
        with open(os.path.join(backup_path, 'schema.sql'), 'w') as f:
            f.write('\n'.join(schema_dump))
        
        # Export data for each table
        for table in tables:
            try:
                df = pd.read_sql_query(f'SELECT * FROM {table}', conn)
                if len(df) > 0:
                    # Save as CSV for easy import/export
                    df.to_csv(os.path.join(backup_path, f'{table}.csv'), index=False)
                    
                    # Save as JSON for structured data
                    json_data = df.to_json(orient='records')
                    with open(os.path.join(backup_path, f'{table}.json'), 'w') as f:
                        # Parse and re-write with proper indentation
                        import json as json_module
                        parsed_data = json_module.loads(json_data)
                        json_module.dump(parsed_data, f, indent=2)
            except Exception as e:
                # Table might be empty or have issues, continue with others
                continue
        
        conn.close()
        
        # Create ZIP archive
        zip_path = os.path.join(backup_dir, f"{backup_name}.zip")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(backup_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, backup_path)
                    zipf.write(file_path, arcname)
        
        # Clean up temporary directory
        shutil.rmtree(backup_path)
        
        return True, f"Backup created successfully: {backup_name}.zip"
        
    except Exception as e:
        return False, f"Error creating backup: {str(e)}"

def restore_database_from_backup(backup_file_path: str, user_id: int = None) -> tuple[bool, str]:
    """Restore database from backup file"""
    # Permission check
    if user_id and not has_permission(user_id, 'backup_restore'):
        return False, "Insufficient permissions to restore backups"
    
    try:
        backup_dir = create_backup_directory()
        
        # Extract backup file
        extract_path = os.path.join(backup_dir, "temp_restore")
        if os.path.exists(extract_path):
            shutil.rmtree(extract_path)
        os.makedirs(extract_path)
        
        with zipfile.ZipFile(backup_file_path, 'r') as zipf:
            zipf.extractall(extract_path)
        
        # Verify backup integrity
        metadata_path = os.path.join(extract_path, 'metadata.json')
        if not os.path.exists(metadata_path):
            return False, "Invalid backup file: missing metadata"
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Create backup of current database before restore
        current_backup_name = f"pre_restore_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        create_database_backup(current_backup_name, user_id)
        
        # Close existing connections and backup current database
        if os.path.exists('database.db'):
            shutil.copy('database.db', 'database_backup_before_restore.db')
        
        # Create new database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Drop all existing tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        for table in tables:
            cursor.execute(f"DROP TABLE IF EXISTS {table[0]}")
        
        # Restore schema
        schema_path = os.path.join(extract_path, 'schema.sql')
        if os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                schema_sql = f.read()
            cursor.executescript(schema_sql)
        
        # Restore data from CSV files
        for table_name in metadata.get('tables_backed_up', []):
            csv_path = os.path.join(extract_path, f'{table_name}.csv')
            if os.path.exists(csv_path):
                try:
                    df = pd.read_csv(csv_path)
                    df.to_sql(table_name, conn, if_exists='append', index=False)
                except Exception as e:
                    # Skip problematic tables but continue with others
                    continue
        
        conn.commit()
        conn.close()
        
        # Clean up
        shutil.rmtree(extract_path)
        
        return True, f"Database restored successfully from backup: {metadata['backup_name']}"
        
    except Exception as e:
        # Restore original database if restoration failed
        if os.path.exists('database_backup_before_restore.db'):
            shutil.copy('database_backup_before_restore.db', 'database.db')
        return False, f"Error restoring backup: {str(e)}"

def get_available_backups() -> list:
    """Get list of available backup files"""
    backup_dir = create_backup_directory()
    backups = []
    
    for file in os.listdir(backup_dir):
        if file.endswith('.zip'):
            file_path = os.path.join(backup_dir, file)
            file_stats = os.stat(file_path)
            
            backup_info = {
                'name': file,
                'path': file_path,
                'size': file_stats.st_size,
                'created': datetime.fromtimestamp(file_stats.st_mtime),
                'size_mb': round(file_stats.st_size / (1024 * 1024), 2)
            }
            backups.append(backup_info)
    
    # Sort by creation date (newest first)
    backups.sort(key=lambda x: x['created'], reverse=True)
    return backups

def delete_backup(backup_name: str, user_id: int = None) -> tuple[bool, str]:
    """Delete a backup file"""
    # Permission check
    if user_id and not has_permission(user_id, 'backup_restore'):
        return False, "Insufficient permissions to delete backups"
    
    try:
        backup_dir = create_backup_directory()
        backup_path = os.path.join(backup_dir, backup_name)
        
        if os.path.exists(backup_path):
            os.remove(backup_path)
            return True, f"Backup {backup_name} deleted successfully"
        else:
            return False, "Backup file not found"
    except Exception as e:
        return False, f"Error deleting backup: {str(e)}"

def export_data_csv() -> dict:
    """Export all data as CSV files in memory"""
    exported_data = {}
    
    try:
        conn = get_connection()
        
        # Export each table
        tables = ['products', 'customers', 'sales']
        for table in tables:
            df = pd.read_sql_query(f'SELECT * FROM {table}', conn)
            csv_buffer = io.StringIO()
            df.to_csv(csv_buffer, index=False)
            exported_data[table] = csv_buffer.getvalue()
        
        conn.close()
        
        # Create metadata
        exported_data['metadata'] = {
            'export_date': datetime.now().isoformat(),
            'export_type': 'CSV',
            'tables': list(tables),
            'application_version': '2.0.0'
        }
        
        return exported_data
        
    except Exception as e:
        return {'error': str(e)}

def cleanup_old_backups(days_to_keep: int = 30) -> tuple[bool, str]:
    """Clean up backup files older than specified days"""
    try:
        backup_dir = create_backup_directory()
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        deleted_count = 0
        
        for file in os.listdir(backup_dir):
            if file.endswith('.zip'):
                file_path = os.path.join(backup_dir, file)
                file_date = datetime.fromtimestamp(os.path.getmtime(file_path))
                
                if file_date < cutoff_date:
                    os.remove(file_path)
                    deleted_count += 1
        
        return True, f"Cleaned up {deleted_count} old backup files"
        
    except Exception as e:
        return False, f"Error cleaning up backups: {str(e)}"

# === FORECASTING FUNCTIONS ===

def prepare_sales_data_for_forecasting():
    """Prepare historical sales data for forecasting"""
    sales_df = get_sales()
    if len(sales_df) == 0:
        return None
    
    # Convert to datetime and aggregate by date
    sales_df['sale_date'] = pd.to_datetime(sales_df['sale_date'])
    daily_sales = sales_df.groupby('sale_date')['total_amount'].sum().reset_index()
    daily_sales = daily_sales.sort_values('sale_date')
    
    # Create numerical features for modeling
    daily_sales['days_since_start'] = (daily_sales['sale_date'] - daily_sales['sale_date'].min()).dt.days
    
    return daily_sales

def generate_sales_forecast(days_ahead=30, model_type='linear', confidence_level=90):
    """Generate sales forecast using machine learning models with confidence intervals"""
    daily_sales = prepare_sales_data_for_forecasting()
    
    if daily_sales is None or len(daily_sales) < 7:
        return None, None, None
    
    X = daily_sales[['days_since_start']].values
    y = daily_sales['total_amount'].values
    
    # Choose model based on type
    if model_type == 'polynomial':
        model = Pipeline([
            ('poly', PolynomialFeatures(degree=2)),
            ('linear', LinearRegression())
        ])
    else:
        model = LinearRegression()
    
    # Fit the model
    model.fit(X, y)
    
    # Calculate model performance and residuals
    y_pred = model.predict(X)
    mae = mean_absolute_error(y, y_pred)
    r2 = r2_score(y, y_pred)
    residuals = y - y_pred
    residual_std = np.std(residuals)
    
    # Generate future predictions with confidence intervals
    last_day = daily_sales['days_since_start'].max()
    future_days = np.arange(last_day + 1, last_day + days_ahead + 1).reshape(-1, 1)
    future_predictions = model.predict(future_days)
    
    # Calculate confidence intervals
    alpha = (100 - confidence_level) / 100
    t_critical = stats.t.ppf(1 - alpha/2, len(y) - 2)  # degrees of freedom = n - 2
    margin_error = t_critical * residual_std
    
    # Create forecast dataframe with confidence intervals
    start_date = daily_sales['sale_date'].max() + timedelta(days=1)
    future_dates = [start_date + timedelta(days=i) for i in range(days_ahead)]
    
    forecast_df = pd.DataFrame({
        'date': future_dates,
        'predicted_sales': np.maximum(future_predictions, 0),  # Ensure non-negative predictions
        'lower_bound': np.maximum(future_predictions - margin_error, 0),
        'upper_bound': future_predictions + margin_error
    })
    
    return daily_sales, forecast_df, {'mae': mae, 'r2': r2, 'model_type': model_type, 'confidence_level': confidence_level}

def get_product_sales_velocity(analysis_days=60):
    """Calculate sales velocity for inventory management"""
    sales_df = get_sales()
    if len(sales_df) == 0:
        return pd.DataFrame(), []
    
    # Convert to datetime and get date range
    sales_df['sale_date'] = pd.to_datetime(sales_df['sale_date'])
    
    # Use configurable analysis window, fallback to available data if needed
    max_date = sales_df['sale_date'].max()
    min_date = sales_df['sale_date'].min()
    analysis_start = max_date - timedelta(days=analysis_days)
    
    # If analysis period extends before available data, use all available data
    if analysis_start < min_date:
        analysis_start = min_date
        actual_days = (max_date - min_date).days + 1
    else:
        actual_days = analysis_days
    
    recent_sales = sales_df[sales_df['sale_date'] >= analysis_start]
    
    # Group by product and calculate metrics
    product_velocity = recent_sales.groupby(['product_id', 'product_name']).agg({
        'quantity': 'sum',
        'total_amount': 'sum',
        'sale_date': 'count'
    }).reset_index()
    
    product_velocity['avg_daily_quantity'] = product_velocity['quantity'] / actual_days
    product_velocity['avg_daily_revenue'] = product_velocity['total_amount'] / actual_days
    product_velocity.rename(columns={'sale_date': 'transaction_count'}, inplace=True)
    
    # Get current stock levels
    products_df = get_products()
    product_velocity = product_velocity.merge(
        products_df[['id', 'stock']], 
        left_on='product_id', 
        right_on='id', 
        how='left'
    )
    
    # Calculate days until stockout
    product_velocity['days_until_stockout'] = np.where(
        product_velocity['avg_daily_quantity'] > 0,
        product_velocity['stock'] / product_velocity['avg_daily_quantity'],
        float('inf')
    )
    
    # Generate concrete reorder recommendations
    recommendations = []
    
    # Urgent reorders (< 7 days)
    urgent = product_velocity[product_velocity['days_until_stockout'] < 7]
    for _, product in urgent.iterrows():
        if product['days_until_stockout'] != float('inf'):
            recommendations.append({
                'type': 'urgent',
                'product_name': product['product_name'],
                'current_stock': int(product['stock']),
                'days_until_stockout': product['days_until_stockout'],
                'avg_daily_sales': product['avg_daily_quantity'],
                'recommended_order': max(int(product['avg_daily_quantity'] * 30), 10),  # 30-day supply minimum
                'message': f"URGENT: {product['product_name']} will run out in {product['days_until_stockout']:.1f} days"
            })
    
    # Warning reorders (7-14 days)
    warning = product_velocity[
        (product_velocity['days_until_stockout'] >= 7) & 
        (product_velocity['days_until_stockout'] < 14)
    ]
    for _, product in warning.iterrows():
        recommendations.append({
            'type': 'warning',
            'product_name': product['product_name'],
            'current_stock': int(product['stock']),
            'days_until_stockout': product['days_until_stockout'],
            'avg_daily_sales': product['avg_daily_quantity'],
            'recommended_order': max(int(product['avg_daily_quantity'] * 21), 5),  # 21-day supply
            'message': f"WARNING: {product['product_name']} needs reordering soon ({product['days_until_stockout']:.1f} days left)"
        })
    
    # Low performers (no recent sales but have stock)
    no_sales = product_velocity[product_velocity['avg_daily_quantity'] == 0]
    for _, product in no_sales.iterrows():
        if product['stock'] > 0:
            recommendations.append({
                'type': 'slow_mover',
                'product_name': product['product_name'],
                'current_stock': int(product['stock']),
                'days_until_stockout': float('inf'),
                'avg_daily_sales': 0,
                'recommended_order': 0,
                'message': f"SLOW MOVER: {product['product_name']} has no sales in last {actual_days} days"
            })
    
    return product_velocity.sort_values('days_until_stockout'), recommendations

# === CUSTOMER SEGMENTATION FUNCTIONS ===

def calculate_rfm_metrics():
    """Calculate RFM (Recency, Frequency, Monetary) metrics for customer segmentation"""
    sales_df = get_sales()
    customers_df = get_customers()
    
    if len(sales_df) == 0 or len(customers_df) == 0:
        return pd.DataFrame()
    
    # Convert sale_date to datetime
    sales_df['sale_date'] = pd.to_datetime(sales_df['sale_date'])
    
    # Calculate the analysis date (most recent sale date + 1 day)
    analysis_date = sales_df['sale_date'].max() + timedelta(days=1)
    
    # Calculate RFM metrics for each customer
    rfm_metrics = sales_df.groupby('customer_id').agg({
        'sale_date': lambda x: (analysis_date - x.max()).days,  # Recency (days since last purchase)
        'id': 'count',  # Frequency (number of transactions)
        'total_amount': 'sum'  # Monetary (total spending)
    }).reset_index()
    
    rfm_metrics.columns = ['customer_id', 'recency', 'frequency', 'monetary']
    
    # Merge with customer details
    rfm_data = rfm_metrics.merge(
        customers_df[['id', 'name', 'email', 'age', 'gender']], 
        left_on='customer_id', 
        right_on='id', 
        how='left'
    )
    
    # Calculate RFM scores (1-5 scale, 5 being the best)
    # Handle small datasets gracefully
    num_customers = len(rfm_data)
    
    if num_customers < 5:
        # For small datasets, use simple scoring based on relative position
        # Recency: Lower days is better (recent purchases get higher scores)
        rfm_data['r_score'] = rfm_data['recency'].rank(method='min', ascending=True).apply(
            lambda x: min(5, max(1, int(6 - ((x - 1) / max(1, num_customers - 1)) * 4)))
        )
        
        # Frequency: Higher is better (more purchases)
        rfm_data['f_score'] = rfm_data['frequency'].rank(method='min', ascending=True).apply(
            lambda x: min(5, max(1, int(1 + ((x - 1) / max(1, num_customers - 1)) * 4)))
        )
        
        # Monetary: Higher is better (more spending)
        rfm_data['m_score'] = rfm_data['monetary'].rank(method='min', ascending=True).apply(
            lambda x: min(5, max(1, int(1 + ((x - 1) / max(1, num_customers - 1)) * 4)))
        )
    else:
        # For larger datasets, use quintile binning with duplicate handling
        try:
            # Recency: Lower is better (recent purchases)
            rfm_data['r_score'] = pd.qcut(rfm_data['recency'].rank(method='first'), 5, labels=[5,4,3,2,1], duplicates='drop')
            
            # Frequency: Higher is better (more purchases)
            rfm_data['f_score'] = pd.qcut(rfm_data['frequency'].rank(method='first'), 5, labels=[1,2,3,4,5], duplicates='drop')
            
            # Monetary: Higher is better (more spending)
            rfm_data['m_score'] = pd.qcut(rfm_data['monetary'].rank(method='first'), 5, labels=[1,2,3,4,5], duplicates='drop')
        except ValueError:
            # Fallback to rank-based scoring if qcut still fails
            rfm_data['r_score'] = rfm_data['recency'].rank(method='min', ascending=True, pct=True).apply(
                lambda x: min(5, max(1, int(6 - x * 5)))
            )
            rfm_data['f_score'] = rfm_data['frequency'].rank(method='min', ascending=True, pct=True).apply(
                lambda x: min(5, max(1, int(1 + x * 4)))
            )
            rfm_data['m_score'] = rfm_data['monetary'].rank(method='min', ascending=True, pct=True).apply(
                lambda x: min(5, max(1, int(1 + x * 4)))
            )
    
    # Ensure scores are integers
    rfm_data['r_score'] = rfm_data['r_score'].astype(int)
    rfm_data['f_score'] = rfm_data['f_score'].astype(int)
    rfm_data['m_score'] = rfm_data['m_score'].astype(int)
    
    # Create combined RFM score
    rfm_data['rfm_score'] = rfm_data['r_score'].astype(str) + rfm_data['f_score'].astype(str) + rfm_data['m_score'].astype(str)
    
    return rfm_data

def segment_customers(rfm_data):
    """Segment customers based on RFM scores"""
    if len(rfm_data) == 0:
        return pd.DataFrame(), pd.DataFrame(), {}
    
    # Define customer segments based on RFM scores
    def get_segment(row):
        r, f, m = int(row['r_score']), int(row['f_score']), int(row['m_score'])
        
        # Champions: Best customers (high on all metrics)
        if r >= 4 and f >= 4 and m >= 4:
            return 'Champions'
        
        # Loyal Customers: High frequency and monetary, decent recency
        elif r >= 3 and f >= 4 and m >= 3:
            return 'Loyal Customers'
        
        # Potential Loyalists: Recent customers with good potential
        elif r >= 4 and f >= 2 and m >= 2:
            return 'Potential Loyalists'
        
        # New Customers: Very recent but low frequency/monetary
        elif r >= 4 and f <= 2 and m <= 2:
            return 'New Customers'
        
        # Promising: Recent with decent frequency or monetary
        elif r >= 3 and f >= 2 and m >= 2:
            return 'Promising'
        
        # Need Attention: Above average on frequency and monetary but not recent
        elif r <= 3 and f >= 3 and m >= 3:
            return 'Need Attention'
        
        # About to Sleep: Below average recency and frequency
        elif r <= 3 and f <= 3 and m >= 2:
            return 'About to Sleep'
        
        # At Risk: Low recency but previously good customers
        elif r <= 2 and f >= 3 and m >= 3:
            return 'At Risk'
        
        # Cannot Lose Them: Very low recency but high monetary
        elif r <= 2 and f <= 3 and m >= 4:
            return 'Cannot Lose Them'
        
        # Hibernating: Low on all metrics but some past value
        elif r <= 2 and f <= 2 and m >= 2:
            return 'Hibernating'
        
        # Lost: Very low on recency and frequency
        else:
            return 'Lost'
    
    # Apply segmentation
    rfm_data['segment'] = rfm_data.apply(get_segment, axis=1)
    
    # Calculate segment statistics
    segment_stats = rfm_data.groupby('segment').agg({
        'customer_id': 'count',
        'recency': 'mean',
        'frequency': 'mean',
        'monetary': ['mean', 'sum'],
        'age': 'mean'
    }).round(2)
    
    segment_stats.columns = ['count', 'avg_recency', 'avg_frequency', 'avg_monetary', 'total_revenue', 'avg_age']
    segment_stats = segment_stats.reset_index()
    
    # Calculate percentage of total customers
    total_customers = len(rfm_data)
    segment_stats['percentage'] = (segment_stats['count'] / total_customers * 100).round(1)
    
    # Define marketing recommendations for each segment
    marketing_recommendations = {
        'Champions': {
            'strategy': 'Reward and Retain',
            'actions': ['VIP treatment', 'Early access to new products', 'Loyalty rewards'],
            'message': 'Your best customers! Focus on retention and advocacy.'
        },
        'Loyal Customers': {
            'strategy': 'Upsell and Cross-sell',
            'actions': ['Product recommendations', 'Premium offerings', 'Exclusive deals'],
            'message': 'Reliable customers who respond well to upselling.'
        },
        'Potential Loyalists': {
            'strategy': 'Develop Loyalty',
            'actions': ['Membership programs', 'Product education', 'Engagement campaigns'],
            'message': 'Recent customers with potential for loyalty development.'
        },
        'New Customers': {
            'strategy': 'Onboard and Educate',
            'actions': ['Welcome campaigns', 'Product tutorials', 'Support offers'],
            'message': 'New customers who need guidance and support.'
        },
        'Promising': {
            'strategy': 'Nurture and Grow',
            'actions': ['Targeted offers', 'Product bundles', 'Engagement content'],
            'message': 'Good potential customers who need nurturing.'
        },
        'Need Attention': {
            'strategy': 'Re-engage',
            'actions': ['Personalized offers', 'Satisfaction surveys', 'Win-back campaigns'],
            'message': 'Previously good customers who are becoming less active.'
        },
        'About to Sleep': {
            'strategy': 'Reactivate',
            'actions': ['Limited-time offers', 'Reactivation emails', 'Incentives'],
            'message': 'Customers at risk of becoming inactive.'
        },
        'At Risk': {
            'strategy': 'Win Back',
            'actions': ['Aggressive discounts', 'Personal outreach', 'Feedback requests'],
            'message': 'Important customers who are at risk of churning.'
        },
        'Cannot Lose Them': {
            'strategy': 'Urgent Recovery',
            'actions': ['Personal calls', 'Exclusive offers', 'Account management'],
            'message': 'High-value customers who must be retained immediately.'
        },
        'Hibernating': {
            'strategy': 'Revive Interest',
            'actions': ['Brand awareness campaigns', 'Product updates', 'Special promotions'],
            'message': 'Inactive customers who might be re-engaged.'
        },
        'Lost': {
            'strategy': 'Investigate and Learn',
            'actions': ['Exit surveys', 'Competitive analysis', 'Process improvement'],
            'message': 'Lost customers - focus on learning to prevent future churn.'
        }
    }
    
    return rfm_data, segment_stats, marketing_recommendations

# UI rendering functions
def render_dashboard():
    """Render main dashboard with KPIs and charts"""
    st.title("📊 Retail Sales Dashboard")
    
    # Get KPIs
    kpis = get_kpis()
    
    # KPI Cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("💰 Total Sales", f"${kpis['total_sales']:,.2f}")
    
    with col2:
        st.metric("📈 Monthly Revenue", f"${kpis['monthly_revenue']:,.2f}")
    
    with col3:
        st.metric("👥 Total Customers", f"{kpis['total_customers']:,}")
    
    with col4:
        st.metric("🏆 Best Product", kpis['best_product'])
    
    st.divider()
    
    # Filters
    st.subheader("📊 Analytics & Visualizations")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # Date range filter
        start_date = st.date_input("Start Date", value=date(2024, 1, 1))
        
    with col2:
        end_date = st.date_input("End Date", value=date.today())
    
    with col3:
        # Category filter
        products_df = get_products()
        categories = ['All'] + list(products_df['category'].unique())
        selected_category = st.selectbox("Category", categories)
    
    # Get filtered sales data
    sales_df: pd.DataFrame = get_sales()
    sales_df['sale_date'] = pd.to_datetime(sales_df['sale_date'])
    
    # Apply filters
    date_mask = (sales_df['sale_date'] >= pd.to_datetime(start_date)) & (sales_df['sale_date'] <= pd.to_datetime(end_date))
    filtered_sales = cast(pd.DataFrame, sales_df[date_mask].copy())
    
    if selected_category != 'All':
        category_mask = filtered_sales['category'] == selected_category
        filtered_sales = cast(pd.DataFrame, filtered_sales[category_mask].copy())
    
    if len(filtered_sales) > 0:
        # Charts
        chart_col1, chart_col2 = st.columns(2)
        
        with chart_col1:
            # Sales trend
            daily_sales = filtered_sales.groupby('sale_date')['total_amount'].sum().reset_index()
            fig_trend = px.line(daily_sales, x='sale_date', y='total_amount', 
                              title='📈 Sales Trend Over Time',
                              labels={'total_amount': 'Sales Amount ($)', 'sale_date': 'Date'})
            st.plotly_chart(fig_trend, use_container_width=True)
        
        with chart_col2:
            # Top products
            top_products = filtered_sales.groupby('product_name')['total_amount'].sum().reset_index()
            top_products = top_products.sort_values('total_amount', ascending=False).head(10)
            fig_products = px.bar(top_products, x='total_amount', y='product_name', 
                                orientation='h', title='🏆 Top Products by Revenue',
                                labels={'total_amount': 'Revenue ($)', 'product_name': 'Product'})
            st.plotly_chart(fig_products, use_container_width=True)
        
        chart_col3, chart_col4 = st.columns(2)
        
        with chart_col3:
            # Sales by category
            category_sales = filtered_sales.groupby('category')['total_amount'].sum().reset_index()
            fig_category = px.pie(category_sales, values='total_amount', names='category',
                                title='🍩 Sales by Category')
            st.plotly_chart(fig_category, use_container_width=True)
        
        with chart_col4:
            # Customer demographics
            customers_df = get_customers()
            if len(customers_df) > 0:
                fig_demo = px.histogram(customers_df, x='age', nbins=10, 
                                      title='👥 Customer Age Distribution',
                                      labels={'age': 'Age', 'count': 'Number of Customers'})
                st.plotly_chart(fig_demo, use_container_width=True)
    else:
        st.info("No sales data available for the selected filters.")

def render_manage_data(user_permissions):
    """Render data management interface with role-based access"""
    st.title("📝 Manage Data")
    
    # Filter tabs based on permissions
    available_tabs = []
    if 'manage_products' in user_permissions:
        available_tabs.append("Products")
    if 'manage_customers' in user_permissions:
        available_tabs.append("Customers")
    if 'manage_sales' in user_permissions:
        available_tabs.append("Sales")
    
    if not available_tabs:
        st.error("You don't have permission to manage any data")
        return
    
    # Create tabs based on available permissions
    if len(available_tabs) == 1:
        if available_tabs[0] == "Products":
            render_products_management()
        elif available_tabs[0] == "Customers":
            render_customers_management()
        elif available_tabs[0] == "Sales":
            render_sales_management()
    else:
        tabs = st.tabs(available_tabs)
        
        for i, tab_name in enumerate(available_tabs):
            with tabs[i]:
                if tab_name == "Products":
                    render_products_management()
                elif tab_name == "Customers":
                    render_customers_management()
                elif tab_name == "Sales":
                    render_sales_management()

def render_products_management():
    """Render products management interface"""
    st.subheader("🛍️ Products Management")
    
    # Add new product form
    with st.expander("➕ Add New Product"):
        with st.form("add_product_form"):
            col1, col2 = st.columns(2)
            with col1:
                name = st.text_input("Product Name*")
                category = st.text_input("Category*")
                price = st.number_input("Price*", min_value=0.01, step=0.01)
            with col2:
                stock = st.number_input("Stock Quantity*", min_value=0, step=1)
                description = st.text_area("Description")
            
            if st.form_submit_button("Add Product"):
                if name and category and price > 0:
                    add_product(name, category, price, stock, description)
                    st.success("Product added successfully!")
                    st.rerun()
                else:
                    st.error("Please fill in all required fields.")
    
    # Products table
    st.subheader("📋 Products List")
    products_df = get_products()
    
    if len(products_df) > 0:
        # Low stock threshold
        low_stock_threshold = st.number_input("Low Stock Alert Threshold", min_value=1, value=10, step=1)
        
        # Display products with low stock alerts
        for index, product in products_df.iterrows():
            # Highlight low stock
            if product['stock'] <= low_stock_threshold:
                st.error(f"⚠️ LOW STOCK ALERT: {product['name']} (Stock: {product['stock']})")
            
            with st.expander(f"{product['name']} - ${product['price']:.2f} (Stock: {product['stock']})"):
                col1, col2, col3 = st.columns([2, 1, 1])
                
                with col1:
                    st.write(f"**Category:** {product['category']}")
                    st.write(f"**Description:** {product['description']}")
                    st.write(f"**Created:** {product['created_at']}")
                
                with col2:
                    if st.button(f"✏️ Edit", key=f"edit_product_{product['id']}"):
                        st.session_state[f'edit_product_{product["id"]}'] = True
                
                with col3:
                    if st.button(f"🗑️ Delete", key=f"delete_product_{product['id']}"):
                        delete_product(product['id'])
                        st.success("Product deleted!")
                        st.rerun()
                
                # Edit form
                if st.session_state.get(f'edit_product_{product["id"]}', False):
                    with st.form(f"edit_product_form_{product['id']}"):
                        edit_col1, edit_col2 = st.columns(2)
                        with edit_col1:
                            edit_name = st.text_input("Name", value=product['name'])
                            edit_category = st.text_input("Category", value=product['category'])
                            edit_price = st.number_input("Price", value=float(product['price']), min_value=0.01, step=0.01)
                        with edit_col2:
                            edit_stock = st.number_input("Stock", value=int(product['stock']), min_value=0, step=1)
                            edit_description = st.text_area("Description", value=str(product['description']) if product['description'] is not None else "")
                        
                        col_save, col_cancel = st.columns(2)
                        with col_save:
                            if st.form_submit_button("💾 Save"):
                                update_product(product['id'], edit_name, edit_category, edit_price, edit_stock, edit_description)
                                st.session_state[f'edit_product_{product["id"]}'] = False
                                st.success("Product updated!")
                                st.rerun()
                        with col_cancel:
                            if st.form_submit_button("❌ Cancel"):
                                st.session_state[f'edit_product_{product["id"]}'] = False
                                st.rerun()
    else:
        st.info("No products found. Add your first product above.")

def render_customers_management():
    """Render customers management interface"""
    st.subheader("👥 Customers Management")
    
    # Add new customer form
    with st.expander("➕ Add New Customer"):
        with st.form("add_customer_form"):
            col1, col2 = st.columns(2)
            with col1:
                name = st.text_input("Customer Name*")
                email = st.text_input("Email*")
                phone = st.text_input("Phone")
            with col2:
                address = st.text_area("Address")
                gender = st.selectbox("Gender", ["Male", "Female", "Other"])
                age = st.number_input("Age", min_value=1, max_value=120, value=30)
            
            if st.form_submit_button("Add Customer"):
                if name and email:
                    try:
                        add_customer(name, email, phone, address, gender, age)
                        st.success("Customer added successfully!")
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("Email already exists. Please use a different email.")
                else:
                    st.error("Please fill in all required fields.")
    
    # Customers table
    st.subheader("📋 Customers List")
    customers_df = get_customers()
    
    if len(customers_df) > 0:
        for index, customer in customers_df.iterrows():
            with st.expander(f"{customer['name']} - {customer['email']}"):
                col1, col2, col3 = st.columns([2, 1, 1])
                
                with col1:
                    st.write(f"**Phone:** {customer['phone']}")
                    st.write(f"**Address:** {customer['address']}")
                    st.write(f"**Gender:** {customer['gender']} | **Age:** {customer['age']}")
                    st.write(f"**Created:** {customer['created_at']}")
                
                with col2:
                    if st.button(f"✏️ Edit", key=f"edit_customer_{customer['id']}"):
                        st.session_state[f'edit_customer_{customer["id"]}'] = True
                
                with col3:
                    if st.button(f"🗑️ Delete", key=f"delete_customer_{customer['id']}"):
                        delete_customer(customer['id'])
                        st.success("Customer deleted!")
                        st.rerun()
                
                # Edit form
                if st.session_state.get(f'edit_customer_{customer["id"]}', False):
                    with st.form(f"edit_customer_form_{customer['id']}"):
                        edit_col1, edit_col2 = st.columns(2)
                        with edit_col1:
                            edit_name = st.text_input("Name", value=customer['name'])
                            edit_email = st.text_input("Email", value=customer['email'])
                            edit_phone = st.text_input("Phone", value=str(customer['phone']) if customer['phone'] is not None else "")
                        with edit_col2:
                            edit_address = st.text_area("Address", value=str(customer['address']) if customer['address'] is not None else "")
                            gender_options = ["Male", "Female", "Other"]
                            current_gender = str(customer['gender'])
                            gender_index = gender_options.index(current_gender) if current_gender in gender_options else 0
                            edit_gender = st.selectbox("Gender", gender_options, index=gender_index)
                            edit_age = st.number_input("Age", value=int(customer['age']), min_value=1, max_value=120)
                        
                        col_save, col_cancel = st.columns(2)
                        with col_save:
                            if st.form_submit_button("💾 Save"):
                                try:
                                    update_customer(customer['id'], edit_name, edit_email, edit_phone, edit_address, edit_gender, edit_age)
                                    st.session_state[f'edit_customer_{customer["id"]}'] = False
                                    st.success("Customer updated!")
                                    st.rerun()
                                except sqlite3.IntegrityError:
                                    st.error("Email already exists. Please use a different email.")
                        with col_cancel:
                            if st.form_submit_button("❌ Cancel"):
                                st.session_state[f'edit_customer_{customer["id"]}'] = False
                                st.rerun()
    else:
        st.info("No customers found. Add your first customer above.")

def render_sales_management():
    """Render sales management interface"""
    st.subheader("💰 Sales Management")
    
    # Add new sale form
    with st.expander("➕ Add New Sale"):
        with st.form("add_sale_form"):
            col1, col2 = st.columns(2)
            
            products_df = get_products()
            customers_df = get_customers()
            
            if len(products_df) > 0 and len(customers_df) > 0:
                with col1:
                    product_options = {f"{row['name']} (${row['price']:.2f})": row['id'] for _, row in products_df.iterrows()}
                    selected_product_display = st.selectbox("Select Product*", list(product_options.keys()))
                    selected_product_id = product_options[selected_product_display]
                    
                    quantity = st.number_input("Quantity*", min_value=1, step=1)
                
                with col2:
                    customer_options = {row['name']: row['id'] for _, row in customers_df.iterrows()}
                    selected_customer_display = st.selectbox("Select Customer*", list(customer_options.keys()))
                    selected_customer_id = customer_options[selected_customer_display]
                    
                    sale_date = st.date_input("Sale Date*", value=date.today())
                
                if st.form_submit_button("Add Sale"):
                    success, message = add_sale(selected_product_id, selected_customer_id, quantity, sale_date)
                    if success:
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)
            else:
                st.warning("Please add products and customers before creating sales.")
    
    # Sales table
    st.subheader("📋 Sales List")
    sales_df = get_sales()
    
    if len(sales_df) > 0:
        for index, sale in sales_df.iterrows():
            with st.expander(f"Sale #{sale['id']} - {sale['product_name']} - ${sale['total_amount']:.2f}"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**Product:** {sale['product_name']} ({sale['category']})")
                    st.write(f"**Customer:** {sale['customer_name']}")
                    st.write(f"**Quantity:** {sale['quantity']} | **Unit Price:** ${sale['unit_price']:.2f}")
                    st.write(f"**Total Amount:** ${sale['total_amount']:.2f}")
                    st.write(f"**Sale Date:** {sale['sale_date']}")
                
                with col2:
                    if st.button(f"🗑️ Delete", key=f"delete_sale_{sale['id']}"):
                        delete_sale(sale['id'])
                        st.success("Sale deleted and stock restored!")
                        st.rerun()
    else:
        st.info("No sales found. Add your first sale above.")

def render_reports():
    """Render reports and export functionality"""
    st.title("📊 Reports & Export")
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        start_date = st.date_input("Start Date", value=date(2024, 1, 1))
    
    with col2:
        end_date = st.date_input("End Date", value=date.today())
    
    with col3:
        report_type = st.selectbox("Report Type", ["Sales Report", "Products Report", "Customers Report"])
    
    # Generate and display report
    if report_type == "Sales Report":
        sales_df = get_sales()
        sales_df['sale_date'] = pd.to_datetime(sales_df['sale_date'])
        
        filtered_sales = sales_df[
            (sales_df['sale_date'] >= pd.to_datetime(start_date)) &
            (sales_df['sale_date'] <= pd.to_datetime(end_date))
        ]
        
        if len(filtered_sales) > 0:
            st.subheader("💰 Sales Report Summary")
            
            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Sales", f"${filtered_sales['total_amount'].sum():,.2f}")
            with col2:
                st.metric("Total Transactions", len(filtered_sales))
            with col3:
                st.metric("Average Sale", f"${filtered_sales['total_amount'].mean():.2f}")
            with col4:
                st.metric("Total Items Sold", filtered_sales['quantity'].sum())
            
            st.subheader("📋 Detailed Sales Data")
            st.dataframe(filtered_sales, use_container_width=True)
            
            # Export button
            csv_data = filtered_sales.to_csv(index=False)
            st.download_button(
                label="📥 Download Sales Report (CSV)",
                data=csv_data,
                file_name=f"sales_report_{start_date}_to_{end_date}.csv",
                mime="text/csv"
            )
        else:
            st.info("No sales data found for the selected date range.")
    
    elif report_type == "Products Report":
        products_df = get_products()
        
        if len(products_df) > 0:
            st.subheader("🛍️ Products Report")
            st.dataframe(products_df, use_container_width=True)
            
            # Export button
            csv_data = products_df.to_csv(index=False)
            st.download_button(
                label="📥 Download Products Report (CSV)",
                data=csv_data,
                file_name="products_report.csv",
                mime="text/csv"
            )
        else:
            st.info("No products found.")
    
    elif report_type == "Customers Report":
        customers_df = get_customers()
        
        if len(customers_df) > 0:
            st.subheader("👥 Customers Report")
            st.dataframe(customers_df, use_container_width=True)
            
            # Export button
            csv_data = customers_df.to_csv(index=False)
            st.download_button(
                label="📥 Download Customers Report (CSV)",
                data=csv_data,
                file_name="customers_report.csv",
                mime="text/csv"
            )
        else:
            st.info("No customers found.")

def render_settings(user_permissions):
    """Render settings page with role-based features"""
    st.title("⚙️ Settings")
    
    current_user = st.session_state.current_user
    
    # User profile section
    st.subheader("👤 User Profile")
    with st.expander("🔧 Account Information", expanded=True):
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**Username:** {current_user['username']}")
            st.write(f"**Email:** {current_user['email']}")
        with col2:
            st.write(f"**Full Name:** {current_user['full_name'] or 'Not set'}")
            st.write(f"**Role:** {current_user['role_name']}")
        
        # Change password form
        with st.form("change_password_form"):
            st.markdown("**Change Password**")
            old_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            
            if st.form_submit_button("🔐 Change Password"):
                if old_password and new_password and confirm_password:
                    if new_password == confirm_password:
                        # Verify current password
                        user = authenticate_user(current_user['username'], old_password)
                        if user:
                            # Update password
                            conn = get_connection()
                            cursor = conn.cursor()
                            new_hash = hash_password(new_password)
                            cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', 
                                         (new_hash, current_user['id']))
                            conn.commit()
                            conn.close()
                            st.success("Password changed successfully!")
                        else:
                            st.error("Current password is incorrect")
                    else:
                        st.error("New passwords don't match")
                else:
                    st.error("Please fill in all password fields")
    
    st.subheader("📊 System Information")
    
    # Database information - available to all users
    with st.expander("🗄️ Database Statistics"):
        conn = get_connection()
        cursor = conn.cursor()
        
        # Get table sizes
        cursor.execute('SELECT COUNT(*) FROM products')
        products_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM customers')
        customers_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM sales')
        sales_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM users')
        users_count = cursor.fetchone()[0]
        
        conn.close()
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Products", products_count)
        with col2:
            st.metric("Customers", customers_count)
        with col3:
            st.metric("Sales", sales_count)
        with col4:
            st.metric("Users", users_count)
    
    # System actions based on permissions
    st.subheader("🔧 System Actions")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Refresh Application"):
            st.rerun()
    
    with col2:
        if 'backup_restore' in user_permissions:
            if st.button("💾 Create Backup"):
                with st.spinner("Creating database backup..."):
                    success, message = create_database_backup(user_id=current_user['id'])
                    if success:
                        st.success(message)
                    else:
                        st.error(message)
    
    # Backup and Restore section for authorized users
    if 'backup_restore' in user_permissions:
        st.subheader("💾 Backup & Restore")
        
        backup_tab1, backup_tab2, backup_tab3, backup_tab4 = st.tabs(["📋 Manage Backups", "⬆️ Create Backup", "⬇️ Restore", "📤 Data Export"])
        
        with backup_tab1:
            st.markdown("**Available Backups**")
            
            backups = get_available_backups()
            if backups:
                for backup in backups:
                    with st.container():
                        col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
                        
                        with col1:
                            st.write(f"📦 **{backup['name']}**")
                            st.caption(f"Created: {backup['created'].strftime('%Y-%m-%d %H:%M:%S')}")
                        
                        with col2:
                            st.write(f"💾 {backup['size_mb']} MB")
                        
                        with col3:
                            # Download button
                            with open(backup['path'], 'rb') as f:
                                backup_data = f.read()
                                st.download_button(
                                    label="💾 Download",
                                    data=backup_data,
                                    file_name=backup['name'],
                                    mime="application/zip",
                                    key=f"download_{backup['name']}"
                                )
                        
                        with col4:
                            if st.button("🗑️", key=f"delete_{backup['name']}", help="Delete backup"):
                                success, message = delete_backup(backup['name'], current_user['id'])
                                if success:
                                    st.success(message)
                                    st.rerun()
                                else:
                                    st.error(message)
                        
                        st.markdown("---")
                
                # Cleanup section
                st.markdown("**Cleanup Tools**")
                col1, col2 = st.columns(2)
                with col1:
                    days_to_keep = st.number_input("Keep backups newer than (days):", value=30, min_value=1, max_value=365)
                with col2:
                    if st.button("🧹 Cleanup Old Backups"):
                        success, message = cleanup_old_backups(days_to_keep)
                        if success:
                            st.success(message)
                            st.rerun()
                        else:
                            st.error(message)
            else:
                st.info("No backups available. Create your first backup to get started.")
        
        with backup_tab2:
            st.markdown("**Create New Backup**")
            st.info("💡 Backups include all data: products, customers, sales, users, and system settings.")
            
            with st.form("create_backup_form"):
                backup_name = st.text_input("Backup Name (optional)", placeholder="Leave empty for auto-generated name")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.form_submit_button("💾 Create Full Backup", use_container_width=True):
                        with st.spinner("Creating comprehensive backup..."):
                            name = backup_name if backup_name else None
                            success, message = create_database_backup(name, current_user['id'])
                            if success:
                                st.success(message)
                                st.balloons()
                            else:
                                st.error(message)
        
        with backup_tab3:
            st.markdown("**Restore Database**")
            st.warning("⚠️ **Warning**: Restoring will replace all current data. A backup of current data will be created automatically before restore.")
            
            backups = get_available_backups()
            if backups:
                backup_options = {f"{backup['name']} ({backup['created'].strftime('%Y-%m-%d %H:%M')} - {backup['size_mb']}MB)": backup['path'] 
                                for backup in backups}
                
                with st.form("restore_backup_form"):
                    selected_backup = st.selectbox("Select Backup to Restore:", options=list(backup_options.keys()))
                    
                    confirm_restore = st.checkbox("I understand this will replace all current data")
                    
                    if st.form_submit_button("🔄 Restore Database", type="secondary"):
                        if confirm_restore:
                            backup_path = backup_options[selected_backup]
                            with st.spinner("Restoring database... This may take a few minutes."):
                                success, message = restore_database_from_backup(backup_path, current_user['id'])
                                if success:
                                    st.success(message)
                                    st.info("🔄 Please refresh the page to see restored data.")
                                    st.balloons()
                                else:
                                    st.error(message)
                        else:
                            st.error("Please confirm that you understand the restore will replace current data")
            else:
                st.info("No backups available for restore. Create a backup first.")
        
        with backup_tab4:
            st.markdown("**Data Export**")
            st.info("💡 Export business data (products, customers, sales) as CSV files for external use.")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("📊 Export All Data (CSV)", use_container_width=True):
                    with st.spinner("Preparing data export..."):
                        exported_data = export_data_csv()
                        
                        if 'error' not in exported_data:
                            # Create a zip file with all CSV exports
                            zip_buffer = io.BytesIO()
                            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
                                for table_name, csv_data in exported_data.items():
                                    if table_name != 'metadata':
                                        zipf.writestr(f"{table_name}.csv", csv_data)
                                # Add metadata
                                zipf.writestr("export_info.json", json.dumps(exported_data['metadata'], indent=2))
                            
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            st.download_button(
                                label="💾 Download Export Package",
                                data=zip_buffer.getvalue(),
                                file_name=f"data_export_{timestamp}.zip",
                                mime="application/zip"
                            )
                            st.success("Data export prepared! Click the download button above.")
                        else:
                            st.error(f"Export failed: {exported_data['error']}")
            
            with col2:
                st.markdown("**Export Includes:**")
                st.write("• Products catalog")
                st.write("• Customer database") 
                st.write("• Sales transactions")
                st.write("• Export metadata")
    
    # Admin-only sections
    if 'system_settings' in user_permissions:
        st.subheader("🛠️ Administrator Tools")
        
        with st.expander("⚠️ Advanced System Operations"):
            st.warning("These operations are for system administrators only and may affect all users.")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔄 Reset Demo Data", type="secondary"):
                    st.info("Demo data reset functionality coming soon")
            
            with col2:
                if st.button("📊 System Maintenance", type="secondary"):
                    st.info("System maintenance tools coming soon")
    
    # User permissions display
    with st.expander("🔑 Your Permissions"):
        st.write("**Your current permissions:**")
        for permission in user_permissions:
            permission_descriptions = {
                'view_dashboard': '📊 View Dashboard',
                'manage_products': '🛍️ Manage Products',
                'manage_customers': '👥 Manage Customers',
                'manage_sales': '💰 Manage Sales',
                'view_reports': '📈 View Reports',
                'manage_users': '👤 Manage Users',
                'manage_roles': '🏷️ Manage Roles',
                'export_data': '📤 Export Data',
                'backup_restore': '💾 Backup & Restore',
                'system_settings': '⚙️ System Settings'
            }
            desc = permission_descriptions.get(permission, permission)
            st.write(f"• {desc}")
    
    st.subheader("ℹ️ About")
    st.info("""
    **Retail Sales Management & Analytics Dashboard**
    
    Version: 2.0.0 - with User Role Management
    
    This application provides comprehensive retail sales management capabilities including:
    - Product inventory management
    - Customer relationship management  
    - Sales tracking and analytics
    - Advanced sales forecasting with ML
    - Customer segmentation analysis
    - Interactive dashboards and reports
    - Role-based access control
    - User management system
    - Data export functionality
    
    Built with Streamlit, SQLite, Pandas, Plotly, and scikit-learn.
    """)

def render_forecasting():
    """Render sales forecasting interface"""
    st.title("🔮 Sales Forecasting & Analytics")
    
    # Forecasting controls
    col1, col2, col3 = st.columns(3)
    
    with col1:
        forecast_days = st.selectbox("Forecast Period", [7, 14, 30, 60, 90], index=2)
    
    with col2:
        model_type = st.selectbox("Model Type", ['linear', 'polynomial'])
    
    with col3:
        confidence_level = st.selectbox("Confidence Level", [80, 90, 95], index=1)
    
    st.divider()
    
    # Generate forecast
    with st.spinner("Generating forecast..."):
        historical_data, forecast_data, model_stats = generate_sales_forecast(forecast_days, model_type, confidence_level)
    
    if historical_data is not None and forecast_data is not None and model_stats is not None:
        # Display model performance
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Model Accuracy (R²)", f"{model_stats['r2']:.3f}")
        
        with col2:
            st.metric("Mean Error", f"${model_stats['mae']:.2f}")
        
        with col3:
            total_forecast = forecast_data['predicted_sales'].sum()
            st.metric("Total Forecast Revenue", f"${total_forecast:,.2f}")
        
        # Forecast chart
        st.subheader("📈 Sales Forecast Visualization")
        
        # Combine historical and forecast data for plotting
        fig = go.Figure()
        
        # Historical data
        fig.add_trace(go.Scatter(
            x=historical_data['sale_date'],
            y=historical_data['total_amount'],
            mode='lines+markers',
            name='Historical Sales',
            line=dict(color='#1f77b4'),
            marker=dict(size=4)
        ))
        
        # Confidence interval upper bound
        fig.add_trace(go.Scatter(
            x=forecast_data['date'],
            y=forecast_data['upper_bound'],
            mode='lines',
            name=f'{confidence_level}% Confidence Upper',
            line=dict(color='rgba(255,127,14,0.3)', dash='dot'),
            showlegend=False
        ))
        
        # Confidence interval lower bound
        fig.add_trace(go.Scatter(
            x=forecast_data['date'],
            y=forecast_data['lower_bound'],
            mode='lines',
            name=f'{confidence_level}% Confidence Lower',
            line=dict(color='rgba(255,127,14,0.3)', dash='dot'),
            fill='tonexty',
            fillcolor='rgba(255,127,14,0.2)',
            showlegend=False
        ))
        
        # Forecast data (main prediction)
        fig.add_trace(go.Scatter(
            x=forecast_data['date'],
            y=forecast_data['predicted_sales'],
            mode='lines+markers',
            name=f'Forecast ({confidence_level}% Confidence)',
            line=dict(color='#ff7f0e', dash='dash'),
            marker=dict(size=4)
        ))
        
        fig.update_layout(
            title=f"{forecast_days}-Day Sales Forecast ({model_type.title()} Model)",
            xaxis_title="Date",
            yaxis_title="Sales Amount ($)",
            hovermode='x unified',
            showlegend=True
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Forecast summary table
        st.subheader("📊 Detailed Forecast Data")
        
        # Show first 10 days of forecast
        display_forecast = forecast_data.head(10).copy()
        display_forecast['date'] = display_forecast['date'].dt.strftime('%Y-%m-%d')
        display_forecast['predicted_sales'] = display_forecast['predicted_sales'].round(2)
        
        st.dataframe(display_forecast, use_container_width=True)
        
        # Weekly/Monthly summaries
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📅 Weekly Forecast Summary")
            forecast_data['week'] = forecast_data['date'].dt.isocalendar().week
            weekly_forecast = forecast_data.groupby('week')['predicted_sales'].sum().reset_index()
            weekly_forecast['predicted_sales'] = weekly_forecast['predicted_sales'].round(2)
            st.dataframe(weekly_forecast, use_container_width=True)
        
        with col2:
            st.subheader("📅 Monthly Forecast Summary")
            forecast_data['month'] = forecast_data['date'].dt.strftime('%Y-%m')
            monthly_forecast = forecast_data.groupby('month')['predicted_sales'].sum().reset_index()
            monthly_forecast['predicted_sales'] = monthly_forecast['predicted_sales'].round(2)
            st.dataframe(monthly_forecast, use_container_width=True)
        
        # Export forecast data
        st.subheader("📥 Export Forecast")
        if st.button("📊 Download Forecast Data (CSV)"):
            csv_data = forecast_data.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv_data,
                file_name=f"sales_forecast_{forecast_days}days_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
    else:
        st.warning("⚠️ Insufficient historical data for forecasting. Please ensure you have at least 7 days of sales data.")
        st.info("💡 Add more sales records in the 'Manage Data' section to enable forecasting.")
    
    st.divider()
    
    # Product velocity analysis
    st.subheader("🚀 Product Sales Velocity Analysis")
    st.markdown("*Analyze product performance and predict inventory needs*")
    
    velocity_data, recommendations = get_product_sales_velocity()
    
    if len(velocity_data) > 0:
        # Display velocity metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            velocity_df = cast(pd.DataFrame, velocity_data)
            avg_velocity = velocity_df['avg_daily_quantity'].mean()
            st.metric("Avg Daily Sales Velocity", f"{avg_velocity:.1f} units/day")
        
        with col2:
            fast_movers = len(velocity_df[velocity_df['avg_daily_quantity'] > avg_velocity])
            st.metric("Fast-Moving Products", f"{fast_movers}")
        
        with col3:
            low_stock_products = len(velocity_df[velocity_df['days_until_stockout'] < 14])
            st.metric("Low Stock Alert", f"{low_stock_products} products")
        
        # Velocity chart
        fig_velocity = px.scatter(
            velocity_df, 
            x='avg_daily_quantity', 
            y='avg_daily_revenue',
            size='stock',
            color='days_until_stockout',
            hover_data=['product_name', 'transaction_count'],
            title='Product Sales Velocity Matrix',
            labels={
                'avg_daily_quantity': 'Daily Quantity Sold',
                'avg_daily_revenue': 'Daily Revenue ($)',
                'days_until_stockout': 'Days Until Stockout',
                'stock': 'Current Stock'
            },
            color_continuous_scale='RdYlGn_r'
        )
        
        st.plotly_chart(fig_velocity, use_container_width=True)
        
        # Velocity table
        st.subheader("📋 Product Velocity Details")
        
        # Format the data for display
        display_velocity = velocity_df[[
            'product_name', 'avg_daily_quantity', 'avg_daily_revenue', 
            'stock', 'days_until_stockout', 'transaction_count'
        ]].copy()
        
        display_velocity['avg_daily_quantity'] = display_velocity['avg_daily_quantity'].round(2)
        display_velocity['avg_daily_revenue'] = display_velocity['avg_daily_revenue'].round(2)
        # Convert infinite values to 'No Sales' string  
        for idx in display_velocity.index:
            if display_velocity.loc[idx, 'days_until_stockout'] == float('inf'):
                display_velocity.loc[idx, 'days_until_stockout'] = 'No Sales'
        
        # Color code based on urgency
        def color_stockout_days(val):
            if val == 'No Sales':
                return 'background-color: #f0f0f0'
            elif isinstance(val, (int, float)) and val < 7:
                return 'background-color: #ffcccb'
            elif isinstance(val, (int, float)) and val < 14:
                return 'background-color: #fff3cd'
            else:
                return 'background-color: #d4edda'
        
        styled_velocity = display_velocity.style.applymap(
            color_stockout_days, subset=['days_until_stockout']
        )
        
        st.dataframe(styled_velocity, use_container_width=True)
        
        # Recommendations
        st.subheader("💡 Automated Reorder Recommendations")
        
        if recommendations:
            urgent_recs = [r for r in recommendations if r['type'] == 'urgent']
            warning_recs = [r for r in recommendations if r['type'] == 'warning']
            slow_recs = [r for r in recommendations if r['type'] == 'slow_mover']
            
            if urgent_recs:
                st.error(f"🚨 **URGENT REORDERS** ({len(urgent_recs)} products)")
                for rec in urgent_recs:
                    with st.expander(f"🔴 {rec['product_name']} - {rec['days_until_stockout']:.1f} days left"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"**Current Stock:** {rec['current_stock']} units")
                            st.write(f"**Daily Sales:** {rec['avg_daily_sales']:.2f} units/day")
                        with col2:
                            st.write(f"**Recommended Order:** {rec['recommended_order']} units")
                            st.write(f"**Priority:** HIGH")
            
            if warning_recs:
                st.warning(f"⚠️ **WARNING REORDERS** ({len(warning_recs)} products)")
                for rec in warning_recs:
                    with st.expander(f"🟡 {rec['product_name']} - {rec['days_until_stockout']:.1f} days left"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"**Current Stock:** {rec['current_stock']} units")
                            st.write(f"**Daily Sales:** {rec['avg_daily_sales']:.2f} units/day")
                        with col2:
                            st.write(f"**Recommended Order:** {rec['recommended_order']} units")
                            st.write(f"**Priority:** MEDIUM")
            
            if slow_recs:
                with st.expander(f"📊 **SLOW MOVERS** ({len(slow_recs)} products)"):
                    for rec in slow_recs:
                        st.info(f"• {rec['product_name']}: {rec['current_stock']} units in stock, no recent sales")
            
            if not urgent_recs and not warning_recs:
                st.success("✅ All products have adequate stock levels based on current sales velocity.")
        else:
            st.info("📊 No specific recommendations available. All products appear to have adequate stock levels.")
    
    else:
        st.info("📊 No recent sales data available for velocity analysis. Add sales records to see insights.")

def render_customer_segmentation():
    """Render customer segmentation analysis interface"""
    st.title("👥 Customer Segmentation & Marketing Analytics")
    st.markdown("*Analyze customer behavior patterns using RFM analysis and generate targeted marketing strategies*")
    
    # Calculate RFM metrics
    with st.spinner("Calculating RFM metrics..."):
        rfm_data = calculate_rfm_metrics()
    
    if len(rfm_data) == 0:
        st.warning("⚠️ Insufficient data for customer segmentation analysis.")
        st.info("💡 Add customers and sales records in the 'Manage Data' section to enable segmentation analysis.")
        return
    
    # Perform customer segmentation
    rfm_data, segment_stats, marketing_recommendations = segment_customers(rfm_data)
    
    # Show information about dataset size for small datasets
    num_customers = len(rfm_data)
    if num_customers < 5:
        st.info(f"ℹ️ **Small Dataset Notice**: You have {num_customers} customers. RFM analysis is optimized for larger datasets (5+ customers) but still provides meaningful insights for your current customer base.")
    elif num_customers < 10:
        st.info(f"ℹ️ **Growing Dataset**: You have {num_customers} customers. Consider adding more customer data to unlock more detailed segmentation insights.")
    
    # Overview metrics
    st.subheader("📊 Customer Portfolio Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_customers = len(rfm_data)
        st.metric("Total Customers", f"{total_customers:,}")
    
    with col2:
        avg_monetary = rfm_data['monetary'].mean()
        st.metric("Avg Customer Value", f"${avg_monetary:,.2f}")
    
    with col3:
        top_segment = segment_stats.loc[segment_stats['total_revenue'].idxmax(), 'segment']
        st.metric("Top Revenue Segment", top_segment)
    
    with col4:
        total_revenue = rfm_data['monetary'].sum()
        st.metric("Total Revenue", f"${total_revenue:,.2f}")
    
    st.divider()
    
    # RFM Distribution Analysis
    st.subheader("🎯 RFM Score Distribution")
    
    tab1, tab2 = st.tabs(["📈 RFM Metrics", "🎯 Segment Analysis"])
    
    with tab1:
        # RFM distribution charts
        col1, col2, col3 = st.columns(3)
        
        with col1:
            fig_recency = px.histogram(
                rfm_data, 
                x='recency', 
                title='📅 Recency Distribution (Days Since Last Purchase)',
                labels={'recency': 'Days Since Last Purchase', 'count': 'Number of Customers'},
                nbins=20
            )
            st.plotly_chart(fig_recency, use_container_width=True)
        
        with col2:
            fig_frequency = px.histogram(
                rfm_data, 
                x='frequency', 
                title='🔄 Frequency Distribution (Number of Purchases)',
                labels={'frequency': 'Number of Purchases', 'count': 'Number of Customers'},
                nbins=10
            )
            st.plotly_chart(fig_frequency, use_container_width=True)
        
        with col3:
            fig_monetary = px.histogram(
                rfm_data, 
                x='monetary', 
                title='💰 Monetary Distribution (Total Spending)',
                labels={'monetary': 'Total Spending ($)', 'count': 'Number of Customers'},
                nbins=20
            )
            st.plotly_chart(fig_monetary, use_container_width=True)
        
        # 3D RFM scatter plot
        st.subheader("📊 3D RFM Analysis")
        fig_3d = px.scatter_3d(
            rfm_data,
            x='recency',
            y='frequency', 
            z='monetary',
            color='segment',
            hover_data=['name', 'rfm_score'],
            title='Customer RFM 3D Analysis',
            labels={
                'recency': 'Recency (Days)',
                'frequency': 'Frequency (Purchases)',
                'monetary': 'Monetary ($)'
            }
        )
        st.plotly_chart(fig_3d, use_container_width=True)
    
    with tab2:
        # Customer segment analysis
        st.subheader("📋 Customer Segment Breakdown")
        
        # Segment overview chart
        fig_segments = px.pie(
            segment_stats,
            values='count',
            names='segment',
            title='Customer Distribution by Segment',
            hover_data=['percentage']
        )
        st.plotly_chart(fig_segments, use_container_width=True)
        
        # Segment statistics table
        st.subheader("📊 Segment Statistics")
        
        # Format the segment stats for display
        display_stats = segment_stats.copy()
        display_stats['avg_monetary'] = display_stats['avg_monetary'].apply(lambda x: f"${x:,.2f}")
        display_stats['total_revenue'] = display_stats['total_revenue'].apply(lambda x: f"${x:,.2f}")
        display_stats['avg_recency'] = display_stats['avg_recency'].apply(lambda x: f"{x:.1f} days")
        display_stats['avg_frequency'] = display_stats['avg_frequency'].apply(lambda x: f"{x:.1f} purchases")
        display_stats['percentage'] = display_stats['percentage'].apply(lambda x: f"{x}%")
        
        st.dataframe(display_stats, use_container_width=True)
    
    st.divider()
    
    # Marketing Recommendations
    st.subheader("🎯 Marketing Strategy Recommendations")
    st.markdown("*Actionable strategies for each customer segment*")
    
    # Create tabs for each segment with customers
    active_segments = segment_stats['segment'].tolist()
    
    if active_segments:
        # Group segments by priority
        high_priority = ['Champions', 'Loyal Customers', 'Cannot Lose Them', 'At Risk']
        medium_priority = ['Potential Loyalists', 'Need Attention', 'Promising']
        low_priority = ['New Customers', 'About to Sleep', 'Hibernating', 'Lost']
        
        priority_tabs = st.tabs(["🔴 High Priority", "🟡 Medium Priority", "🟢 Low Priority"])
        
        with priority_tabs[0]:
            render_segment_recommendations(active_segments, high_priority, marketing_recommendations, rfm_data)
        
        with priority_tabs[1]:
            render_segment_recommendations(active_segments, medium_priority, marketing_recommendations, rfm_data)
        
        with priority_tabs[2]:
            render_segment_recommendations(active_segments, low_priority, marketing_recommendations, rfm_data)
    
    st.divider()
    
    # Customer Details
    st.subheader("👤 Individual Customer Analysis")
    
    # Customer selection
    customer_options = rfm_data['name'].tolist()
    selected_customer = st.selectbox("Select Customer for Detailed Analysis", customer_options)
    
    if selected_customer:
        customer_data = rfm_data[rfm_data['name'] == selected_customer].iloc[0]
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write(f"**Customer:** {customer_data['name']}")
            st.write(f"**Email:** {customer_data['email']}")
            st.write(f"**Segment:** {customer_data['segment']}")
            st.write(f"**RFM Score:** {customer_data['rfm_score']}")
        
        with col2:
            st.write(f"**Recency:** {customer_data['recency']} days")
            st.write(f"**Frequency:** {customer_data['frequency']} purchases")
            st.write(f"**Monetary:** ${customer_data['monetary']:,.2f}")
            st.write(f"**Age:** {customer_data['age']} years")
        
        # Display segment-specific recommendations
        segment = customer_data['segment']
        if segment in marketing_recommendations:
            rec = marketing_recommendations[segment]
            st.info(f"**Strategy:** {rec['strategy']}")
            st.write(f"**Message:** {rec['message']}")
            st.write(f"**Recommended Actions:** {', '.join(rec['actions'])}")
    
    st.divider()
    
    # Export functionality
    st.subheader("📥 Export Customer Segmentation Data")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📊 Download Customer Segments (CSV)"):
            csv_data = rfm_data.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv_data,
                file_name=f"customer_segments_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
    
    with col2:
        if st.button("📈 Download Segment Statistics (CSV)"):
            csv_data = segment_stats.to_csv(index=False)
            st.download_button(
                label="Download Statistics CSV",
                data=csv_data,
                file_name=f"segment_statistics_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )

def render_segment_recommendations(active_segments, priority_segments, marketing_recommendations, rfm_data):
    """Render marketing recommendations for segments by priority"""
    priority_active = [seg for seg in priority_segments if seg in active_segments]
    
    if not priority_active:
        st.info("No customers in this priority category.")
        return
    
    for segment in priority_active:
        if segment in marketing_recommendations:
            rec = marketing_recommendations[segment]
            customer_count = len(rfm_data[rfm_data['segment'] == segment])
            
            with st.expander(f"📋 {segment} ({customer_count} customers)"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Strategy:** {rec['strategy']}")
                    st.write(f"**Message:** {rec['message']}")
                
                with col2:
                    st.write("**Recommended Actions:**")
                    for action in rec['actions']:
                        st.write(f"• {action}")
                
                # Show top customers in this segment
                segment_customers = rfm_data[rfm_data['segment'] == segment].nlargest(3, 'monetary')
                if len(segment_customers) > 0:
                    st.write("**Top Customers in Segment:**")
                    for _, customer in segment_customers.iterrows():
                        st.write(f"• {customer['name']} - ${customer['monetary']:,.2f} (RFM: {customer['rfm_score']})")

def render_user_management():
    """Render user management interface"""
    st.title("👤 User Management")
    st.markdown("Manage user accounts, roles, and permissions")
    
    tab1, tab2, tab3 = st.tabs(["👥 Users", "🏷️ Roles", "➕ Add User"])
    
    with tab1:
        st.subheader("👥 User Accounts")
        
        users_df = get_all_users()
        if len(users_df) > 0:
            # Display users in a more user-friendly format
            for _, user in users_df.iterrows():
                with st.container():
                    col1, col2, col3, col4 = st.columns([3, 2, 2, 2])
                    
                    with col1:
                        status_icon = "🟢" if user['is_active'] else "🔴"
                        st.write(f"{status_icon} **{user['full_name'] or user['username']}**")
                        st.caption(f"@{user['username']} • {user['email']}")
                    
                    with col2:
                        st.write(f"🏷️ {user['role_name']}")
                    
                    with col3:
                        last_login = user['last_login']
                        if last_login:
                            login_date = pd.to_datetime(last_login).strftime('%Y-%m-%d')
                            st.write(f"🕒 {login_date}")
                        else:
                            st.write("🕒 Never")
                    
                    with col4:
                        # Don't allow editing yourself or other super admins
                        current_user = st.session_state.current_user
                        can_edit = (user['id'] != current_user['id'] and 
                                  user['role_name'] != 'Super Admin')
                        
                        if can_edit:
                            if st.button(f"✏️ Edit", key=f"edit_user_{user['id']}"):
                                st.session_state[f"editing_user_{user['id']}"] = True
                        else:
                            st.write("🔒 Protected")
                    
                    # Edit form
                    if st.session_state.get(f"editing_user_{user['id']}", False):
                        with st.form(f"edit_user_form_{user['id']}"):
                            st.markdown(f"**Editing: {user['username']}**")
                            
                            roles_df = get_all_roles()
                            role_options = {row['name']: row['id'] for _, row in roles_df.iterrows()}
                            
                            new_username = st.text_input("Username", value=user['username'])
                            new_email = st.text_input("Email", value=user['email'])
                            new_full_name = st.text_input("Full Name", value=user['full_name'] or "")
                            new_role = st.selectbox("Role", options=list(role_options.keys()), 
                                                  index=list(role_options.values()).index(user['role_name'] if user['role_name'] in role_options.values() else 1))
                            new_is_active = st.checkbox("Active", value=user['is_active'])
                            
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                if st.form_submit_button("💾 Save"):
                                    success, message = update_user(
                                        user['id'], new_username, new_email, 
                                        role_options[new_role], new_full_name, new_is_active,
                                        current_user['id']
                                    )
                                    if success:
                                        st.success(message)
                                        st.session_state[f"editing_user_{user['id']}"] = False
                                        st.rerun()
                                    else:
                                        st.error(message)
                            
                            with col2:
                                if st.form_submit_button("❌ Cancel"):
                                    st.session_state[f"editing_user_{user['id']}"] = False
                                    st.rerun()
                            
                            with col3:
                                if st.form_submit_button("🗑️ Delete", type="secondary"):
                                    success, message = delete_user(user['id'], current_user['id'])
                                    if success:
                                        st.success(message)
                                        st.session_state[f"editing_user_{user['id']}"] = False
                                        st.rerun()
                                    else:
                                        st.error(message)
                    
                    st.markdown("---")
        else:
            st.info("No users found")
    
    with tab2:
        st.subheader("🏷️ User Roles")
        
        roles_df = get_all_roles()
        
        for _, role in roles_df.iterrows():
            with st.expander(f"🏷️ {role['name']}"):
                st.write(f"**Description:** {role['description']}")
                
                # Get permissions for this role
                conn = get_connection()
                permissions_query = '''
                    SELECT p.name, p.description
                    FROM permissions p
                    JOIN role_permissions rp ON p.id = rp.permission_id
                    WHERE rp.role_id = ?
                    ORDER BY p.name
                '''
                role_permissions = pd.read_sql_query(permissions_query, conn, params=(role['id'],))
                conn.close()
                
                if len(role_permissions) > 0:
                    st.write("**Permissions:**")
                    for _, perm in role_permissions.iterrows():
                        st.write(f"• **{perm['name']}**: {perm['description']}")
                else:
                    st.write("No permissions assigned")
    
    with tab3:
        st.subheader("➕ Add New User")
        
        with st.form("add_user_form"):
            roles_df = get_all_roles()
            role_options = {row['name']: row['id'] for _, row in roles_df.iterrows()}
            
            username = st.text_input("Username *")
            email = st.text_input("Email *")
            password = st.text_input("Password *", type="password")
            full_name = st.text_input("Full Name")
            role = st.selectbox("Role *", options=list(role_options.keys()))
            
            if st.form_submit_button("👤 Create User"):
                if username and email and password and role:
                    current_user = st.session_state.current_user
                    success, message = create_user(username, email, password, role_options[role], full_name, current_user['id'])
                    if success:
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)
                else:
                    st.error("Please fill in all required fields")

# Main application
def main():
    """Main application function"""
    
    # Initialize database
    init_db()
    
    # Check authentication
    is_authenticated = check_authentication()
    
    if not is_authenticated:
        # Show login form if not authenticated
        st.title("🛍️ Retail Sales Management & Analytics")
        st.markdown("---")
        login_form()
        return
    
    # User is authenticated, show main application
    user = st.session_state.current_user
    
    # Initialize session state
    if 'current_page' not in st.session_state:
        st.session_state.current_page = 'Dashboard'
    
    # Sidebar navigation
    st.sidebar.title("🛍️ Retail Sales Manager")
    st.sidebar.markdown(f"👤 Welcome, **{user['full_name'] or user['username']}**")
    st.sidebar.markdown(f"🏷️ Role: **{user['role_name']}**")
    st.sidebar.markdown("---")
    
    # Build navigation based on user permissions
    user_permissions = get_user_permissions(user['id'])
    
    pages = {}
    
    # Dashboard - available to all authenticated users
    if 'view_dashboard' in user_permissions:
        pages["📊 Dashboard"] = "Dashboard"
    
    # Forecasting - available to users with view_reports permission
    if 'view_reports' in user_permissions:
        pages["🔮 Forecasting"] = "Forecasting"
        pages["👥 Customer Segments"] = "Segmentation"
        pages["📊 Reports & Export"] = "Reports"
    
    # Data management - requires specific permissions
    if any(perm in user_permissions for perm in ['manage_products', 'manage_customers', 'manage_sales']):
        pages["📝 Manage Data"] = "Manage Data"
    
    # User management - Super Admin and Manager only
    if 'manage_users' in user_permissions:
        pages["👤 User Management"] = "User Management"
    
    # Settings - available to all
    pages["⚙️ Settings"] = "Settings"
    
    # Navigation buttons
    for page_display, page_key in pages.items():
        if st.sidebar.button(page_display, use_container_width=True):
            st.session_state.current_page = page_key
    
    st.sidebar.markdown("---")
    
    # Logout button
    if st.sidebar.button("🚪 Logout", use_container_width=True):
        if 'session_token' in st.session_state:
            logout_user(st.session_state.session_token)
        if 'session_token' in st.session_state:
            del st.session_state.session_token
        if 'current_user' in st.session_state:
            del st.session_state.current_user
        st.rerun()
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("💡 **Quick Stats**")
    
    # Quick stats in sidebar
    try:
        kpis = get_kpis()
        st.sidebar.metric("💰 Total Sales", f"${kpis['total_sales']:,.0f}")
        st.sidebar.metric("👥 Customers", f"{kpis['total_customers']:,}")
    except:
        st.sidebar.info("Loading stats...")
    
    # Render selected page with permission checks
    current_page = st.session_state.current_page
    
    if current_page == "Dashboard":
        if 'view_dashboard' in user_permissions:
            render_dashboard()
        else:
            st.error("You don't have permission to access the Dashboard")
    elif current_page == "Forecasting":
        if 'view_reports' in user_permissions:
            render_forecasting()
        else:
            st.error("You don't have permission to access Forecasting")
    elif current_page == "Segmentation":
        if 'view_reports' in user_permissions:
            render_customer_segmentation()
        else:
            st.error("You don't have permission to access Customer Segmentation")
    elif current_page == "Manage Data":
        if any(perm in user_permissions for perm in ['manage_products', 'manage_customers', 'manage_sales']):
            render_manage_data(user_permissions)
        else:
            st.error("You don't have permission to manage data")
    elif current_page == "Reports":
        if 'view_reports' in user_permissions:
            render_reports()
        else:
            st.error("You don't have permission to access Reports")
    elif current_page == "User Management":
        if 'manage_users' in user_permissions:
            render_user_management()
        else:
            st.error("You don't have permission to manage users")
    elif current_page == "Settings":
        render_settings(user_permissions)

if __name__ == "__main__":
    main()
