"""
RAG (Retrieval-Augmented Generation) System for Customer Support
Stores and retrieves dealer policies, company policies, and product knowledge
"""

import os
import json
import sqlite3
from typing import List, Dict, Optional
from datetime import datetime


class RAGKnowledgeBase:
    """RAG system for storing and retrieving policy and product knowledge"""
    
    def __init__(self, db_path: str = "customer_memory.db"):
        self.db_path = db_path
        self._init_knowledge_base()
        self._populate_default_knowledge()
    
    def _init_knowledge_base(self):
        """Initialize knowledge base tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Policies table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                keywords TEXT,
                last_updated TEXT,
                priority INTEGER DEFAULT 1
            )
        """)
        
        # Product knowledge table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product_knowledge (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_name TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                specifications TEXT,
                common_issues TEXT,
                troubleshooting TEXT,
                warranty_info TEXT
            )
        """)
        
        # Known bugs/issues table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS known_issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_title TEXT NOT NULL,
                description TEXT NOT NULL,
                affected_products TEXT,
                status TEXT DEFAULT 'active',
                workaround TEXT,
                reported_date TEXT,
                resolution_eta TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _populate_default_knowledge(self):
        """Populate with default dealer and company policies"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if already populated
        cursor.execute("SELECT COUNT(*) FROM policies")
        if cursor.fetchone()[0] > 0:
            conn.close()
            return
        
        # Dealer & Company Policies
        policies = [
            {
                "category": "return_policy",
                "title": "30-Day Return Policy",
                "content": """Our return policy allows customers to return items within 30 days of purchase. 
                Items must be unused, in original packaging with all tags attached. 
                Original receipt or proof of purchase required. 
                Refunds processed within 5-7 business days.
                Restocking fee: 10% for opened electronics, no fee for unopened items.
                Sale items: Final sale unless defective.""",
                "keywords": "return, refund, exchange, 30 days, policy",
                "priority": 10
            },
            {
                "category": "warranty_policy",
                "title": "Product Warranty Coverage",
                "content": """All products come with manufacturer warranty:
                - Electronics: 1 year manufacturer warranty
                - Appliances: 2 years parts and labor
                - Extended warranty available for purchase
                - Warranty covers manufacturing defects only
                - Does not cover accidental damage, misuse, or wear and tear
                - Customer must register product within 30 days for extended benefits""",
                "keywords": "warranty, coverage, protection, guarantee",
                "priority": 10
            },
            {
                "category": "shipping_policy",
                "title": "Shipping and Delivery",
                "content": """Shipping options and timeframes:
                - Standard Shipping: 5-7 business days ($9.99, FREE over $50)
                - Express Shipping: 2-3 business days ($19.99)
                - Overnight Shipping: Next business day ($39.99)
                - International: 10-15 business days (varies by location)
                - Tracking provided for all orders
                - Signature required for orders over $500""",
                "keywords": "shipping, delivery, tracking, express, overnight",
                "priority": 9
            },
            {
                "category": "price_match",
                "title": "Price Match Guarantee",
                "content": """We match competitors' prices:
                - Must be identical product (model, color, specifications)
                - Competitor must be authorized dealer
                - Price match within 7 days of purchase
                - Provide proof: ad, website screenshot, or written quote
                - Excludes clearance, closeout, and marketplace sellers
                - Will match and give additional 10% of difference""",
                "keywords": "price match, competitor, guarantee, lower price",
                "priority": 8
            },
            {
                "category": "payment_policy",
                "title": "Payment Methods and Terms",
                "content": """Accepted payment methods:
                - Credit/Debit Cards: Visa, MasterCard, Amex, Discover
                - PayPal and PayPal Credit
                - Bank Transfer/ACH
                - Buy Now Pay Later: Affirm, Klarna (0% APR for 12 months on $500+)
                - Gift Cards and Store Credit
                - No checks accepted for online orders""",
                "keywords": "payment, credit card, paypal, financing, pay",
                "priority": 7
            },
            {
                "category": "damaged_items",
                "title": "Damaged or Defective Items Policy",
                "content": """Procedure for damaged or defective items:
                - Report damage within 48 hours of delivery
                - Provide photos of damage and packaging
                - We'll arrange free return shipping
                - Choice of replacement or full refund
                - Expedited replacement shipping at no cost
                - For defective items: troubleshooting first, then replacement/repair""",
                "keywords": "damaged, defective, broken, faulty, not working",
                "priority": 10
            },
            {
                "category": "customer_service",
                "title": "Customer Service Hours and Contact",
                "content": """Our customer service team is here to help:
                - Phone: 1-800-SUPPORT (Mon-Fri 8AM-8PM, Sat-Sun 9AM-6PM EST)
                - Email: support@dealershop.com (24-48 hour response)
                - Live Chat: Available during business hours
                - Social Media: @DealerShop on Twitter/Facebook
                - Emergency Support: For critical issues, call Priority line
                - Average response time: 2 hours during business hours""",
                "keywords": "contact, support, hours, phone, email, help",
                "priority": 6
            },
            {
                "category": "loyalty_program",
                "title": "Rewards and Loyalty Program",
                "content": """Join our Rewards Program:
                - Earn 1 point per $1 spent
                - 100 points = $5 reward certificate
                - Birthday bonus: 200 points
                - Exclusive member-only sales
                - Early access to new products
                - Free standard shipping for Gold members (spend $500+/year)
                - Platinum members (spend $2000+/year): 2x points, free returns""",
                "keywords": "rewards, loyalty, points, discount, member",
                "priority": 5
            },
            {
                "category": "installation_service",
                "title": "Installation and Assembly Services",
                "content": """Professional installation available:
                - TV mounting: $149
                - Appliance installation: $199-$399
                - Furniture assembly: Starting at $79
                - Smart home setup: $99 per device
                - Book within 7 days of purchase for 20% off
                - 90-day service guarantee
                - Licensed and insured technicians""",
                "keywords": "installation, assembly, setup, mounting, service",
                "priority": 4
            },
            {
                "category": "privacy_policy",
                "title": "Privacy and Data Protection",
                "content": """We protect your privacy:
                - Data encrypted with SSL
                - Never sell personal information to third parties
                - Email opt-out available anytime
                - GDPR and CCPA compliant
                - Customer data retained for 7 years per regulations
                - Can request data deletion at any time
                - Security breach notification within 72 hours""",
                "keywords": "privacy, data, security, personal information",
                "priority": 6
            }
        ]
        
        for policy in policies:
            cursor.execute("""
                INSERT INTO policies (category, title, content, keywords, last_updated, priority)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                policy["category"],
                policy["title"],
                policy["content"],
                policy["keywords"],
                datetime.now().isoformat(),
                policy["priority"]
            ))
        
        # Product Knowledge
        products = [
            {
                "product_name": "SmartHome Hub Pro",
                "category": "Smart Home",
                "description": "Central control hub for all smart home devices with AI voice assistant",
                "specifications": "WiFi 6, Zigbee, Z-Wave, Bluetooth 5.0, 8GB RAM, Quad-core processor",
                "common_issues": "Connection drops, voice recognition issues, device pairing problems",
                "troubleshooting": "1. Restart hub 2. Check WiFi connection 3. Re-pair devices 4. Update firmware",
                "warranty_info": "2-year manufacturer warranty, covers hardware defects"
            },
            {
                "product_name": "UltraView 4K TV 65\"",
                "category": "Electronics",
                "description": "65-inch 4K Smart TV with HDR, Dolby Vision, and built-in streaming apps",
                "specifications": "3840x2160 resolution, 120Hz refresh rate, HDMI 2.1, WiFi, Bluetooth",
                "common_issues": "Picture quality settings, sound sync issues, app crashes",
                "troubleshooting": "1. Check HDMI cables 2. Update TV software 3. Reset picture settings 4. Clear app cache",
                "warranty_info": "1-year parts and labor, 3-year panel warranty"
            },
            {
                "product_name": "EcoClean Robot Vacuum",
                "category": "Home Appliances",
                "description": "Smart robot vacuum with mapping, auto-empty base, and multi-floor cleaning",
                "specifications": "2100Pa suction, 180min runtime, WiFi connected, LIDAR navigation",
                "common_issues": "Navigation errors, charging problems, brush tangles, app connectivity",
                "troubleshooting": "1. Clean sensors 2. Clear brushes 3. Reset WiFi 4. Remap floor plan",
                "warranty_info": "1-year limited warranty, 6-month battery warranty"
            }
        ]
        
        for product in products:
            cursor.execute("""
                INSERT INTO product_knowledge 
                (product_name, category, description, specifications, common_issues, troubleshooting, warranty_info)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                product["product_name"],
                product["category"],
                product["description"],
                product["specifications"],
                product["common_issues"],
                product["troubleshooting"],
                product["warranty_info"]
            ))
        
        # Known Issues
        issues = [
            {
                "issue_title": "SmartHome Hub - Intermittent WiFi Disconnection",
                "description": "Some units experiencing WiFi dropout every 2-3 hours, requiring restart",
                "affected_products": "SmartHome Hub Pro (firmware v2.1.3)",
                "status": "active",
                "workaround": "Manually reconnect or use ethernet cable. Firmware update coming in 2 weeks.",
                "reported_date": "2025-09-15",
                "resolution_eta": "2025-10-15"
            },
            {
                "issue_title": "UltraView TV - HDMI 2.1 Handshake Issue",
                "description": "Xbox Series X/PS5 users experiencing black screen on startup",
                "affected_products": "UltraView 4K TV 65\" (manufactured before Aug 2025)",
                "status": "resolved",
                "workaround": "Power cycle TV and console. Update TV to firmware v4.2.1 (released Sept 2025)",
                "reported_date": "2025-08-01",
                "resolution_eta": "2025-09-10"
            }
        ]
        
        for issue in issues:
            cursor.execute("""
                INSERT INTO known_issues 
                (issue_title, description, affected_products, status, workaround, reported_date, resolution_eta)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                issue["issue_title"],
                issue["description"],
                issue["affected_products"],
                issue["status"],
                issue["workaround"],
                issue["reported_date"],
                issue["resolution_eta"]
            ))
        
        conn.commit()
        conn.close()
    
    def search_policies(self, query: str, category: Optional[str] = None) -> List[Dict]:
        """Search policies using keyword matching"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query_lower = query.lower()
        
        if category:
            cursor.execute("""
                SELECT title, content, category, priority
                FROM policies
                WHERE category = ? AND (
                    LOWER(title) LIKE ? OR 
                    LOWER(content) LIKE ? OR 
                    LOWER(keywords) LIKE ?
                )
                ORDER BY priority DESC
            """, (category, f"%{query_lower}%", f"%{query_lower}%", f"%{query_lower}%"))
        else:
            cursor.execute("""
                SELECT title, content, category, priority
                FROM policies
                WHERE LOWER(title) LIKE ? OR 
                      LOWER(content) LIKE ? OR 
                      LOWER(keywords) LIKE ?
                ORDER BY priority DESC
                LIMIT 3
            """, (f"%{query_lower}%", f"%{query_lower}%", f"%{query_lower}%"))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                "title": row[0],
                "content": row[1],
                "category": row[2],
                "priority": row[3]
            })
        
        conn.close()
        return results
    
    def search_product_knowledge(self, query: str) -> List[Dict]:
        """Search product knowledge base"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query_lower = query.lower()
        
        cursor.execute("""
            SELECT product_name, category, description, specifications, 
                   common_issues, troubleshooting, warranty_info
            FROM product_knowledge
            WHERE LOWER(product_name) LIKE ? OR 
                  LOWER(description) LIKE ? OR
                  LOWER(common_issues) LIKE ?
            LIMIT 3
        """, (f"%{query_lower}%", f"%{query_lower}%", f"%{query_lower}%"))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                "product_name": row[0],
                "category": row[1],
                "description": row[2],
                "specifications": row[3],
                "common_issues": row[4],
                "troubleshooting": row[5],
                "warranty_info": row[6]
            })
        
        conn.close()
        return results
    
    def get_known_issues(self, product: Optional[str] = None, status: str = "active") -> List[Dict]:
        """Get known issues, optionally filtered by product"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if product:
            cursor.execute("""
                SELECT issue_title, description, affected_products, 
                       status, workaround, resolution_eta
                FROM known_issues
                WHERE LOWER(affected_products) LIKE ? AND status = ?
            """, (f"%{product.lower()}%", status))
        else:
            cursor.execute("""
                SELECT issue_title, description, affected_products, 
                       status, workaround, resolution_eta
                FROM known_issues
                WHERE status = ?
            """, (status,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                "issue_title": row[0],
                "description": row[1],
                "affected_products": row[2],
                "status": row[3],
                "workaround": row[4],
                "resolution_eta": row[5]
            })
        
        conn.close()
        return results
    
    def add_policy(self, category: str, title: str, content: str, 
                   keywords: str = "", priority: int = 5):
        """Add a new policy to the knowledge base"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO policies (category, title, content, keywords, last_updated, priority)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (category, title, content, keywords, datetime.now().isoformat(), priority))
        
        conn.commit()
        conn.close()
        
        return {"success": True, "message": "Policy added successfully"}
