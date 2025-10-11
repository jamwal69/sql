"""
Secure Authentication System with Role-Based Access Control
Ensures users can only access their own data
"""

import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, Dict
import sqlite3
import secrets


class AuthSystem:
    """
    Authentication and Authorization System
    - User registration and login
    - JWT token generation
    - Role-based access control
    - Data filtering by user
    """
    
    def __init__(self, db_path: str = "customer_memory.db"):
        self.db_path = db_path
        self.secret_key = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
        self.token_expiry_hours = 24
        self._init_auth_tables()
    
    def _init_auth_tables(self):
        """Initialize authentication tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table with authentication
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT,
                role TEXT NOT NULL,
                customer_id TEXT,
                phone TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT,
                is_active INTEGER DEFAULT 1,
                failed_login_attempts INTEGER DEFAULT 0
            )
        """)
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        
        # Audit log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                success INTEGER,
                details TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def register_user(self, email: str, password: str, name: str, 
                     role: str = "customer", customer_id: str = None,
                     phone: str = None) -> Dict:
        """
        Register a new user
        """
        # Validate input
        if len(password) < 8:
            return {"success": False, "error": "Password must be at least 8 characters"}
        
        if role not in ["customer", "support_agent", "admin", "owner"]:
            return {"success": False, "error": "Invalid role"}
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Generate user ID
        user_id = f"USER-{secrets.token_hex(8)}"
        
        # If customer_id not provided and role is customer, generate one
        if role == "customer" and not customer_id:
            customer_id = f"CUST-{secrets.token_hex(6)}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO users 
                (user_id, email, password_hash, name, role, customer_id, phone, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                email.lower(),
                password_hash.decode('utf-8'),
                name,
                role,
                customer_id,
                phone,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            
            # Log registration
            self._log_action(user_id, "user_registered", "user", user_id, True)
            
            return {
                "success": True,
                "user_id": user_id,
                "customer_id": customer_id,
                "message": "User registered successfully"
            }
            
        except sqlite3.IntegrityError:
            return {"success": False, "error": "Email already registered"}
        finally:
            conn.close()
    
    def login(self, email: str, password: str, ip_address: str = None,
              user_agent: str = None) -> Dict:
        """
        Authenticate user and return JWT token
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_id, password_hash, name, role, customer_id, is_active, failed_login_attempts
            FROM users
            WHERE email = ?
        """, (email.lower(),))
        
        result = cursor.fetchone()
        
        if not result:
            self._log_action(None, "login_failed", "auth", email, False, 
                           "User not found")
            return {"success": False, "error": "Invalid credentials"}
        
        user_id, password_hash, name, role, customer_id, is_active, failed_attempts = result
        
        # Check if account is locked
        if failed_attempts >= 5:
            return {"success": False, "error": "Account locked. Contact support."}
        
        # Check if account is active
        if not is_active:
            return {"success": False, "error": "Account deactivated"}
        
        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            # Increment failed attempts
            cursor.execute("""
                UPDATE users 
                SET failed_login_attempts = failed_login_attempts + 1
                WHERE user_id = ?
            """, (user_id,))
            conn.commit()
            conn.close()
            
            self._log_action(user_id, "login_failed", "auth", email, False,
                           "Invalid password")
            return {"success": False, "error": "Invalid credentials"}
        
        # Reset failed attempts
        cursor.execute("""
            UPDATE users 
            SET failed_login_attempts = 0, last_login = ?
            WHERE user_id = ?
        """, (datetime.now().isoformat(), user_id))
        
        # Generate JWT token
        token = self._generate_token(user_id, role, customer_id)
        
        # Create session
        session_id = f"SESSION-{secrets.token_hex(16)}"
        expires_at = datetime.now() + timedelta(hours=self.token_expiry_hours)
        
        cursor.execute("""
            INSERT INTO sessions 
            (session_id, user_id, token, created_at, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            user_id,
            token,
            datetime.now().isoformat(),
            expires_at.isoformat(),
            ip_address,
            user_agent
        ))
        
        conn.commit()
        conn.close()
        
        # Log successful login
        self._log_action(user_id, "login_success", "auth", user_id, True)
        
        return {
            "success": True,
            "token": token,
            "user": {
                "user_id": user_id,
                "name": name,
                "role": role,
                "customer_id": customer_id
            },
            "expires_in": self.token_expiry_hours * 3600
        }
    
    def _generate_token(self, user_id: str, role: str, customer_id: str = None) -> str:
        """Generate JWT token"""
        payload = {
            "user_id": user_id,
            "role": role,
            "customer_id": customer_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=self.token_expiry_hours)
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        return token
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """
        Verify JWT token and return user info
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            
            # Check if session is still active
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT is_active FROM sessions
                WHERE token = ? AND is_active = 1
            """, (token,))
            
            if not cursor.fetchone():
                conn.close()
                return None
            
            conn.close()
            
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def logout(self, token: str) -> bool:
        """Logout user by invalidating session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE sessions
            SET is_active = 0
            WHERE token = ?
        """, (token,))
        
        conn.commit()
        conn.close()
        
        return True
    
    def check_permission(self, user_role: str, action: str, resource_type: str) -> bool:
        """
        Check if user role has permission for action on resource
        """
        permissions = {
            "customer": {
                "view": ["own_orders", "own_profile", "policies", "products"],
                "create": ["support_tickets"],
                "update": ["own_profile"],
                "delete": []
            },
            "support_agent": {
                "view": ["orders", "profiles", "policies", "products", "tickets"],
                "create": ["tickets", "returns", "refunds", "adjustments"],
                "update": ["tickets", "order_status"],
                "delete": []
            },
            "admin": {
                "view": ["*"],
                "create": ["*"],
                "update": ["*"],
                "delete": ["tickets", "adjustments"]
            },
            "owner": {
                "view": ["*"],
                "create": ["*"],
                "update": ["*"],
                "delete": ["*"]
            }
        }
        
        role_perms = permissions.get(user_role, {})
        action_perms = role_perms.get(action, [])
        
        return "*" in action_perms or resource_type in action_perms
    
    def filter_data_by_user(self, data: list, user_info: Dict, data_type: str) -> list:
        """
        Filter data based on user role and ownership
        Customers can only see their own data
        """
        role = user_info.get("role")
        customer_id = user_info.get("customer_id")
        
        # Admin and owner see everything
        if role in ["admin", "owner"]:
            return data
        
        # Support agents see everything
        if role == "support_agent":
            return data
        
        # Customers only see their own data
        if role == "customer":
            if data_type == "orders":
                return [item for item in data if item.get("customer_id") == customer_id]
            elif data_type == "profiles":
                return [item for item in data if item.get("customer_id") == customer_id]
            elif data_type in ["policies", "products"]:
                return data  # Public data
            else:
                return []  # Deny by default
        
        return []  # Deny by default
    
    def can_access_resource(self, user_info: Dict, resource_owner_id: str) -> bool:
        """
        Check if user can access a specific resource
        """
        role = user_info.get("role")
        customer_id = user_info.get("customer_id")
        
        # Admin and owner can access everything
        if role in ["admin", "owner"]:
            return True
        
        # Support agents can access everything
        if role == "support_agent":
            return True
        
        # Customers can only access their own resources
        if role == "customer":
            return customer_id == resource_owner_id
        
        return False
    
    def _log_action(self, user_id: str, action: str, resource_type: str,
                   resource_id: str, success: bool, details: str = None,
                   ip_address: str = None):
        """Log action to audit trail"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO audit_log
            (user_id, action, resource_type, resource_id, timestamp, ip_address, success, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            action,
            resource_type,
            resource_id,
            datetime.now().isoformat(),
            ip_address,
            1 if success else 0,
            details
        ))
        
        conn.commit()
        conn.close()
    
    def get_audit_log(self, user_id: str = None, limit: int = 100) -> list:
        """Get audit log (admin/owner only)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute("""
                SELECT * FROM audit_log
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (user_id, limit))
        else:
            cursor.execute("""
                SELECT * FROM audit_log
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        
        columns = [desc[0] for desc in cursor.description]
        results = []
        
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        
        conn.close()
        return results


# Example usage
if __name__ == "__main__":
    auth = AuthSystem()
    
    print("=== Authentication System Demo ===\n")
    
    # Register users
    print("1. Registering users...")
    
    # Customer
    result = auth.register_user(
        email="rohan@email.com",
        password="secure123",
        name="Rohan",
        role="customer",
        phone="+1234567890"
    )
    print(f"Customer registered: {result}")
    
    # Support Agent
    result = auth.register_user(
        email="emma@support.com",
        password="agent123",
        name="Emma",
        role="support_agent"
    )
    print(f"Agent registered: {result}")
    
    # Owner
    result = auth.register_user(
        email="owner@company.com",
        password="owner123",
        name="Owner",
        role="owner"
    )
    print(f"Owner registered: {result}")
    
    # Login
    print("\n2. Testing login...")
    result = auth.login("rohan@email.com", "secure123")
    if result["success"]:
        token = result["token"]
        print(f"✓ Login successful! Token: {token[:20]}...")
        
        # Verify token
        user_info = auth.verify_token(token)
        print(f"✓ Token verified: {user_info}")
        
        # Check permissions
        can_view_orders = auth.check_permission("customer", "view", "own_orders")
        print(f"✓ Customer can view own orders: {can_view_orders}")
        
        can_delete = auth.check_permission("customer", "delete", "orders")
        print(f"✓ Customer can delete orders: {can_delete}")
