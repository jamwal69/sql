"""
Website Integration Module
Connects agent to your website to fetch real customer data

Supports multiple integration methods:
1. Direct Database Connection (MySQL, PostgreSQL, etc.)
2. REST API Integration
3. WooCommerce Integration
4. Shopify Integration
5. Custom E-commerce Integration
"""

import os
import json
import requests
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta
import mysql.connector
import psycopg2
from psycopg2.extras import RealDictCursor


class WebsiteDataFetcher:
    """
    Fetches real customer data from your website
    Replace test_data.py with this for production
    """
    
    def __init__(self, integration_type: str = "api"):
        """
        Initialize website integration
        
        Args:
            integration_type: 'database', 'api', 'woocommerce', 'shopify', 'custom'
        """
        self.integration_type = integration_type
        self.config = self._load_config()
        
        if integration_type == "database":
            self.db_connection = self._init_database()
        elif integration_type in ["api", "woocommerce", "shopify", "custom"]:
            self.api_config = self._init_api()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment or config file"""
        return {
            # Database config
            "db_type": os.getenv("WEBSITE_DB_TYPE", "mysql"),  # mysql, postgresql, sqlite
            "db_host": os.getenv("WEBSITE_DB_HOST", "localhost"),
            "db_port": os.getenv("WEBSITE_DB_PORT", "3306"),
            "db_name": os.getenv("WEBSITE_DB_NAME", "ecommerce"),
            "db_user": os.getenv("WEBSITE_DB_USER", "root"),
            "db_password": os.getenv("WEBSITE_DB_PASSWORD", ""),
            
            # API config
            "api_base_url": os.getenv("WEBSITE_API_URL", "https://yourwebsite.com/api"),
            "api_key": os.getenv("WEBSITE_API_KEY", ""),
            "api_secret": os.getenv("WEBSITE_API_SECRET", ""),
            
            # WooCommerce config
            "woo_url": os.getenv("WOO_URL", "https://yoursite.com"),
            "woo_consumer_key": os.getenv("WOO_CONSUMER_KEY", ""),
            "woo_consumer_secret": os.getenv("WOO_CONSUMER_SECRET", ""),
            
            # Shopify config
            "shopify_shop_url": os.getenv("SHOPIFY_SHOP_URL", ""),
            "shopify_access_token": os.getenv("SHOPIFY_ACCESS_TOKEN", ""),
        }
    
    def _init_database(self):
        """Initialize database connection"""
        db_type = self.config["db_type"]
        
        try:
            if db_type == "mysql":
                return mysql.connector.connect(
                    host=self.config["db_host"],
                    port=int(self.config["db_port"]),
                    database=self.config["db_name"],
                    user=self.config["db_user"],
                    password=self.config["db_password"]
                )
            elif db_type == "postgresql":
                return psycopg2.connect(
                    host=self.config["db_host"],
                    port=int(self.config["db_port"]),
                    database=self.config["db_name"],
                    user=self.config["db_user"],
                    password=self.config["db_password"],
                    cursor_factory=RealDictCursor
                )
            else:
                print(f"⚠️ Unsupported database type: {db_type}")
                return None
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return None
    
    def _init_api(self) -> Dict[str, Any]:
        """Initialize API configuration"""
        return {
            "base_url": self.config["api_base_url"],
            "headers": {
                "Authorization": f"Bearer {self.config['api_key']}",
                "Content-Type": "application/json"
            },
            "timeout": 10
        }
    
    # ============================================================================
    # CUSTOMER DATA METHODS
    # ============================================================================
    
    def get_customer_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Fetch customer profile by email"""
        if self.integration_type == "database":
            return self._get_customer_from_db(email=email)
        elif self.integration_type == "api":
            return self._get_customer_from_api(email=email)
        elif self.integration_type == "woocommerce":
            return self._get_customer_from_woocommerce(email=email)
        elif self.integration_type == "shopify":
            return self._get_customer_from_shopify(email=email)
        return None
    
    def get_customer_by_phone(self, phone: str) -> Optional[Dict[str, Any]]:
        """Fetch customer profile by phone number (for WhatsApp)"""
        if self.integration_type == "database":
            return self._get_customer_from_db(phone=phone)
        elif self.integration_type == "api":
            return self._get_customer_from_api(phone=phone)
        elif self.integration_type == "woocommerce":
            return self._get_customer_from_woocommerce(phone=phone)
        elif self.integration_type == "shopify":
            return self._get_customer_from_shopify(phone=phone)
        return None
    
    def get_customer_by_id(self, customer_id: str) -> Optional[Dict[str, Any]]:
        """Fetch customer profile by customer ID"""
        if self.integration_type == "database":
            return self._get_customer_from_db(customer_id=customer_id)
        elif self.integration_type == "api":
            return self._get_customer_from_api(customer_id=customer_id)
        elif self.integration_type == "woocommerce":
            return self._get_customer_from_woocommerce(customer_id=customer_id)
        elif self.integration_type == "shopify":
            return self._get_customer_from_shopify(customer_id=customer_id)
        return None
    
    # ============================================================================
    # ORDER DATA METHODS
    # ============================================================================
    
    def get_customer_orders(self, customer_id: str) -> List[Dict[str, Any]]:
        """Fetch all orders for a customer"""
        if self.integration_type == "database":
            return self._get_orders_from_db(customer_id)
        elif self.integration_type == "api":
            return self._get_orders_from_api(customer_id)
        elif self.integration_type == "woocommerce":
            return self._get_orders_from_woocommerce(customer_id)
        elif self.integration_type == "shopify":
            return self._get_orders_from_shopify(customer_id)
        return []
    
    def get_order_by_id(self, order_id: str) -> Optional[Dict[str, Any]]:
        """Fetch specific order details"""
        if self.integration_type == "database":
            return self._get_order_details_from_db(order_id)
        elif self.integration_type == "api":
            return self._get_order_details_from_api(order_id)
        elif self.integration_type == "woocommerce":
            return self._get_order_details_from_woocommerce(order_id)
        elif self.integration_type == "shopify":
            return self._get_order_details_from_shopify(order_id)
        return None
    
    # ============================================================================
    # DATABASE INTEGRATION (Direct SQL)
    # ============================================================================
    
    def _get_customer_from_db(self, email: str = None, phone: str = None, 
                              customer_id: str = None) -> Optional[Dict[str, Any]]:
        """Fetch customer from database"""
        if not self.db_connection:
            return None
        
        try:
            cursor = self.db_connection.cursor(dictionary=True)
            
            # Build query based on available identifier
            if customer_id:
                query = "SELECT * FROM customers WHERE id = %s OR customer_id = %s"
                cursor.execute(query, (customer_id, customer_id))
            elif email:
                query = "SELECT * FROM customers WHERE email = %s"
                cursor.execute(query, (email,))
            elif phone:
                query = "SELECT * FROM customers WHERE phone = %s OR phone_number = %s"
                cursor.execute(query, (phone, phone))
            else:
                return None
            
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                # Transform database format to agent format
                return self._transform_customer_data(result)
            
            return None
            
        except Exception as e:
            print(f"❌ Database query error: {e}")
            return None
    
    def _get_orders_from_db(self, customer_id: str) -> List[Dict[str, Any]]:
        """Fetch customer orders from database"""
        if not self.db_connection:
            return []
        
        try:
            cursor = self.db_connection.cursor(dictionary=True)
            
            # Fetch orders
            query = """
                SELECT o.*, 
                       GROUP_CONCAT(CONCAT(oi.product_name, '|', oi.quantity, '|', oi.price) 
                                    SEPARATOR ';;') as items
                FROM orders o
                LEFT JOIN order_items oi ON o.id = oi.order_id
                WHERE o.customer_id = %s
                GROUP BY o.id
                ORDER BY o.created_at DESC
            """
            cursor.execute(query, (customer_id,))
            results = cursor.fetchall()
            cursor.close()
            
            # Transform to agent format
            orders = []
            for row in results:
                orders.append(self._transform_order_data(row))
            
            return orders
            
        except Exception as e:
            print(f"❌ Database query error: {e}")
            return []
    
    def _get_order_details_from_db(self, order_id: str) -> Optional[Dict[str, Any]]:
        """Fetch specific order from database"""
        if not self.db_connection:
            return None
        
        try:
            cursor = self.db_connection.cursor(dictionary=True)
            
            query = """
                SELECT o.*, 
                       GROUP_CONCAT(CONCAT(oi.product_name, '|', oi.quantity, '|', oi.price, '|', oi.sku) 
                                    SEPARATOR ';;') as items
                FROM orders o
                LEFT JOIN order_items oi ON o.id = oi.order_id
                WHERE o.id = %s OR o.order_number = %s
                GROUP BY o.id
            """
            cursor.execute(query, (order_id, order_id))
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                return self._transform_order_data(result)
            
            return None
            
        except Exception as e:
            print(f"❌ Database query error: {e}")
            return None
    
    # ============================================================================
    # REST API INTEGRATION
    # ============================================================================
    
    def _get_customer_from_api(self, email: str = None, phone: str = None, 
                               customer_id: str = None) -> Optional[Dict[str, Any]]:
        """Fetch customer from REST API"""
        try:
            base_url = self.api_config["base_url"]
            headers = self.api_config["headers"]
            
            # Build endpoint
            if customer_id:
                url = f"{base_url}/customers/{customer_id}"
            elif email:
                url = f"{base_url}/customers?email={email}"
            elif phone:
                url = f"{base_url}/customers?phone={phone}"
            else:
                return None
            
            response = requests.get(url, headers=headers, timeout=self.api_config["timeout"])
            
            if response.status_code == 200:
                data = response.json()
                # Handle different API response formats
                customer = data if isinstance(data, dict) else data.get("customer") or data.get("data") or data[0]
                return self._transform_customer_data(customer)
            
            return None
            
        except Exception as e:
            print(f"❌ API request error: {e}")
            return None
    
    def _get_orders_from_api(self, customer_id: str) -> List[Dict[str, Any]]:
        """Fetch orders from REST API"""
        try:
            base_url = self.api_config["base_url"]
            headers = self.api_config["headers"]
            
            url = f"{base_url}/customers/{customer_id}/orders"
            response = requests.get(url, headers=headers, timeout=self.api_config["timeout"])
            
            if response.status_code == 200:
                data = response.json()
                orders = data if isinstance(data, list) else data.get("orders") or data.get("data") or []
                return [self._transform_order_data(order) for order in orders]
            
            return []
            
        except Exception as e:
            print(f"❌ API request error: {e}")
            return []
    
    def _get_order_details_from_api(self, order_id: str) -> Optional[Dict[str, Any]]:
        """Fetch order details from REST API"""
        try:
            base_url = self.api_config["base_url"]
            headers = self.api_config["headers"]
            
            url = f"{base_url}/orders/{order_id}"
            response = requests.get(url, headers=headers, timeout=self.api_config["timeout"])
            
            if response.status_code == 200:
                data = response.json()
                order = data if "order_id" in data else data.get("order") or data.get("data")
                return self._transform_order_data(order)
            
            return None
            
        except Exception as e:
            print(f"❌ API request error: {e}")
            return None
    
    # ============================================================================
    # WOOCOMMERCE INTEGRATION
    # ============================================================================
    
    def _get_customer_from_woocommerce(self, email: str = None, phone: str = None,
                                       customer_id: str = None) -> Optional[Dict[str, Any]]:
        """Fetch customer from WooCommerce API"""
        try:
            from woocommerce import API
            
            wcapi = API(
                url=self.config["woo_url"],
                consumer_key=self.config["woo_consumer_key"],
                consumer_secret=self.config["woo_consumer_secret"],
                version="wc/v3"
            )
            
            if customer_id:
                response = wcapi.get(f"customers/{customer_id}")
            elif email:
                response = wcapi.get(f"customers?email={email}")
            else:
                return None
            
            if response.status_code == 200:
                data = response.json()
                customer = data if isinstance(data, dict) else data[0]
                return self._transform_woocommerce_customer(customer)
            
            return None
            
        except Exception as e:
            print(f"❌ WooCommerce API error: {e}")
            return None
    
    def _get_orders_from_woocommerce(self, customer_id: str) -> List[Dict[str, Any]]:
        """Fetch orders from WooCommerce"""
        try:
            from woocommerce import API
            
            wcapi = API(
                url=self.config["woo_url"],
                consumer_key=self.config["woo_consumer_key"],
                consumer_secret=self.config["woo_consumer_secret"],
                version="wc/v3"
            )
            
            response = wcapi.get(f"orders?customer={customer_id}")
            
            if response.status_code == 200:
                orders = response.json()
                return [self._transform_woocommerce_order(order) for order in orders]
            
            return []
            
        except Exception as e:
            print(f"❌ WooCommerce API error: {e}")
            return []
    
    def _get_order_details_from_woocommerce(self, order_id: str) -> Optional[Dict[str, Any]]:
        """Fetch order from WooCommerce"""
        try:
            from woocommerce import API
            
            wcapi = API(
                url=self.config["woo_url"],
                consumer_key=self.config["woo_consumer_key"],
                consumer_secret=self.config["woo_consumer_secret"],
                version="wc/v3"
            )
            
            response = wcapi.get(f"orders/{order_id}")
            
            if response.status_code == 200:
                order = response.json()
                return self._transform_woocommerce_order(order)
            
            return None
            
        except Exception as e:
            print(f"❌ WooCommerce API error: {e}")
            return None
    
    # ============================================================================
    # SHOPIFY INTEGRATION
    # ============================================================================
    
    def _get_customer_from_shopify(self, email: str = None, phone: str = None,
                                   customer_id: str = None) -> Optional[Dict[str, Any]]:
        """Fetch customer from Shopify API"""
        try:
            headers = {
                "X-Shopify-Access-Token": self.config["shopify_access_token"],
                "Content-Type": "application/json"
            }
            
            if customer_id:
                url = f"{self.config['shopify_shop_url']}/admin/api/2024-01/customers/{customer_id}.json"
            elif email:
                url = f"{self.config['shopify_shop_url']}/admin/api/2024-01/customers/search.json?query=email:{email}"
            else:
                return None
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                customer = data.get("customer") or data.get("customers", [{}])[0]
                return self._transform_shopify_customer(customer)
            
            return None
            
        except Exception as e:
            print(f"❌ Shopify API error: {e}")
            return None
    
    def _get_orders_from_shopify(self, customer_id: str) -> List[Dict[str, Any]]:
        """Fetch orders from Shopify"""
        try:
            headers = {
                "X-Shopify-Access-Token": self.config["shopify_access_token"],
                "Content-Type": "application/json"
            }
            
            url = f"{self.config['shopify_shop_url']}/admin/api/2024-01/customers/{customer_id}/orders.json"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                orders = data.get("orders", [])
                return [self._transform_shopify_order(order) for order in orders]
            
            return []
            
        except Exception as e:
            print(f"❌ Shopify API error: {e}")
            return []
    
    def _get_order_details_from_shopify(self, order_id: str) -> Optional[Dict[str, Any]]:
        """Fetch order from Shopify"""
        try:
            headers = {
                "X-Shopify-Access-Token": self.config["shopify_access_token"],
                "Content-Type": "application/json"
            }
            
            url = f"{self.config['shopify_shop_url']}/admin/api/2024-01/orders/{order_id}.json"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                order = data.get("order")
                return self._transform_shopify_order(order)
            
            return None
            
        except Exception as e:
            print(f"❌ Shopify API error: {e}")
            return None
    
    # ============================================================================
    # DATA TRANSFORMATION (Convert website format to agent format)
    # ============================================================================
    
    def _transform_customer_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform raw customer data to agent format"""
        return {
            "customer_id": raw_data.get("id") or raw_data.get("customer_id"),
            "name": raw_data.get("name") or f"{raw_data.get('first_name', '')} {raw_data.get('last_name', '')}".strip(),
            "email": raw_data.get("email"),
            "phone": raw_data.get("phone") or raw_data.get("phone_number") or raw_data.get("billing", {}).get("phone"),
            "member_since": raw_data.get("created_at") or raw_data.get("date_created") or raw_data.get("member_since"),
            "loyalty_tier": raw_data.get("loyalty_tier") or "Standard",
            "total_orders": raw_data.get("orders_count") or raw_data.get("total_orders") or 0,
            "lifetime_value": raw_data.get("total_spent") or raw_data.get("lifetime_value") or 0.0,
            "preferences": raw_data.get("preferences") or {},
            "notes": raw_data.get("notes") or ""
        }
    
    def _transform_order_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform raw order data to agent format"""
        # Parse items if they're in concatenated string format (from database)
        items = []
        if isinstance(raw_data.get("items"), str):
            item_strings = raw_data["items"].split(";;")
            for item_str in item_strings:
                parts = item_str.split("|")
                if len(parts) >= 3:
                    items.append({
                        "name": parts[0],
                        "qty": int(parts[1]),
                        "price": float(parts[2]),
                        "sku": parts[3] if len(parts) > 3 else ""
                    })
        else:
            items = raw_data.get("items") or raw_data.get("line_items") or []
        
        return {
            "order_id": raw_data.get("id") or raw_data.get("order_id") or raw_data.get("order_number"),
            "customer_id": raw_data.get("customer_id"),
            "date": raw_data.get("date_created") or raw_data.get("created_at") or raw_data.get("date"),
            "status": raw_data.get("status"),
            "items": items,
            "total": float(raw_data.get("total") or 0),
            "shipping": {
                "method": raw_data.get("shipping_method") or raw_data.get("shipping", {}).get("method"),
                "tracking": raw_data.get("tracking_number") or raw_data.get("tracking"),
                "carrier": raw_data.get("shipping_carrier") or raw_data.get("carrier")
            },
            "delivery_date": raw_data.get("delivery_date") or raw_data.get("estimated_delivery")
        }
    
    def _transform_woocommerce_customer(self, woo_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform WooCommerce customer to agent format"""
        return {
            "customer_id": str(woo_data.get("id")),
            "name": f"{woo_data.get('first_name', '')} {woo_data.get('last_name', '')}".strip(),
            "email": woo_data.get("email"),
            "phone": woo_data.get("billing", {}).get("phone"),
            "member_since": woo_data.get("date_created"),
            "loyalty_tier": "Standard",
            "total_orders": woo_data.get("orders_count", 0),
            "lifetime_value": float(woo_data.get("total_spent", 0)),
            "preferences": {},
            "notes": woo_data.get("meta_data", {})
        }
    
    def _transform_woocommerce_order(self, woo_order: Dict[str, Any]) -> Dict[str, Any]:
        """Transform WooCommerce order to agent format"""
        items = []
        for item in woo_order.get("line_items", []):
            items.append({
                "name": item.get("name"),
                "qty": item.get("quantity"),
                "price": float(item.get("price", 0)),
                "sku": item.get("sku")
            })
        
        return {
            "order_id": str(woo_order.get("id")),
            "customer_id": str(woo_order.get("customer_id")),
            "date": woo_order.get("date_created"),
            "status": woo_order.get("status"),
            "items": items,
            "total": float(woo_order.get("total", 0)),
            "shipping": {
                "method": woo_order.get("shipping_lines", [{}])[0].get("method_title") if woo_order.get("shipping_lines") else "",
                "tracking": "",
                "carrier": ""
            },
            "delivery_date": None
        }
    
    def _transform_shopify_customer(self, shopify_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Shopify customer to agent format"""
        return {
            "customer_id": str(shopify_data.get("id")),
            "name": f"{shopify_data.get('first_name', '')} {shopify_data.get('last_name', '')}".strip(),
            "email": shopify_data.get("email"),
            "phone": shopify_data.get("phone") or shopify_data.get("default_address", {}).get("phone"),
            "member_since": shopify_data.get("created_at"),
            "loyalty_tier": "Standard",
            "total_orders": shopify_data.get("orders_count", 0),
            "lifetime_value": float(shopify_data.get("total_spent", 0)),
            "preferences": {},
            "notes": shopify_data.get("note", "")
        }
    
    def _transform_shopify_order(self, shopify_order: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Shopify order to agent format"""
        items = []
        for item in shopify_order.get("line_items", []):
            items.append({
                "name": item.get("name"),
                "qty": item.get("quantity"),
                "price": float(item.get("price", 0)),
                "sku": item.get("sku")
            })
        
        return {
            "order_id": str(shopify_order.get("id")),
            "customer_id": str(shopify_order.get("customer", {}).get("id")),
            "date": shopify_order.get("created_at"),
            "status": shopify_order.get("financial_status"),
            "items": items,
            "total": float(shopify_order.get("total_price", 0)),
            "shipping": {
                "method": shopify_order.get("shipping_lines", [{}])[0].get("title") if shopify_order.get("shipping_lines") else "",
                "tracking": shopify_order.get("fulfillments", [{}])[0].get("tracking_number") if shopify_order.get("fulfillments") else "",
                "carrier": shopify_order.get("fulfillments", [{}])[0].get("tracking_company") if shopify_order.get("fulfillments") else ""
            },
            "delivery_date": None
        }


# ============================================================================
# CONVENIENCE FUNCTIONS (drop-in replacement for test_data.py)
# ============================================================================

# Initialize fetcher (configure this based on your setup)
_fetcher = None

def init_website_integration(integration_type: str = "api"):
    """Initialize website integration"""
    global _fetcher
    _fetcher = WebsiteDataFetcher(integration_type)
    return _fetcher

def get_customer_profile(identifier: str, identifier_type: str = "email") -> Optional[Dict[str, Any]]:
    """Get customer profile - drop-in replacement for test_data function"""
    if not _fetcher:
        init_website_integration()
    
    if identifier_type == "email":
        return _fetcher.get_customer_by_email(identifier)
    elif identifier_type == "phone":
        return _fetcher.get_customer_by_phone(identifier)
    elif identifier_type == "id":
        return _fetcher.get_customer_by_id(identifier)
    return None

def get_customer_orders(customer_id: str) -> List[Dict[str, Any]]:
    """Get customer orders - drop-in replacement for test_data function"""
    if not _fetcher:
        init_website_integration()
    return _fetcher.get_customer_orders(customer_id)

def get_order_by_id(order_id: str) -> Optional[Dict[str, Any]]:
    """Get order by ID - drop-in replacement for test_data function"""
    if not _fetcher:
        init_website_integration()
    return _fetcher.get_order_by_id(order_id)


if __name__ == "__main__":
    # Test the integration
    print("🔧 Testing Website Integration...\n")
    
    # Example 1: API Integration
    print("1️⃣ Testing API Integration:")
    fetcher = WebsiteDataFetcher(integration_type="api")
    customer = fetcher.get_customer_by_email("customer@example.com")
    print(f"   Customer: {customer}\n")
    
    # Example 2: Database Integration
    print("2️⃣ Testing Database Integration:")
    fetcher = WebsiteDataFetcher(integration_type="database")
    customer = fetcher.get_customer_by_email("customer@example.com")
    print(f"   Customer: {customer}\n")
    
    print("✅ Integration module ready!")
