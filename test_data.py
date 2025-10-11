"""
Realistic test data for customer support scenarios
Includes customer profiles, orders, and conversation scenarios
"""

from datetime import datetime, timedelta
import random

# Realistic Customer Profiles
CUSTOMER_PROFILES = [
    {
        "customer_id": "CUST-1001",
        "name": "Sarah Johnson",
        "email": "sarah.j@email.com",
        "phone": "(555) 123-4567",
        "member_since": "2023-03-15",
        "loyalty_tier": "Gold",
        "total_orders": 12,
        "lifetime_value": 2450.00,
        "preferences": {"communication": "email", "language": "English"},
        "sentiment_history": ["positive", "positive", "neutral"],
        "notes": "Prefers quick responses. Tech-savvy customer."
    },
    {
        "customer_id": "CUST-1002",
        "name": "Michael Chen",
        "email": "mchen@techcorp.com",
        "phone": "(555) 234-5678",
        "member_since": "2024-01-20",
        "loyalty_tier": "Platinum",
        "total_orders": 28,
        "lifetime_value": 8900.00,
        "preferences": {"communication": "phone", "language": "English"},
        "sentiment_history": ["positive", "positive", "positive"],
        "notes": "Business customer. Very important account."
    },
    {
        "customer_id": "CUST-1003",
        "name": "Emily Rodriguez",
        "email": "emily.r.2024@gmail.com",
        "phone": "(555) 345-6789",
        "member_since": "2024-09-01",
        "loyalty_tier": "Silver",
        "total_orders": 3,
        "lifetime_value": 580.00,
        "preferences": {"communication": "chat", "language": "English"},
        "sentiment_history": ["neutral", "frustrated", "positive"],
        "notes": "New customer. Had delivery issue that was resolved."
    },
    {
        "customer_id": "CUST-1004",
        "name": "James Wilson",
        "email": "jwilson_home@outlook.com",
        "phone": "(555) 456-7890",
        "member_since": "2022-11-10",
        "loyalty_tier": "Gold",
        "total_orders": 15,
        "lifetime_value": 3200.00,
        "preferences": {"communication": "email", "language": "English"},
        "sentiment_history": ["positive", "neutral", "positive"],
        "notes": "Asks detailed questions. Appreciates thorough explanations."
    },
    {
        "customer_id": "CUST-1005",
        "name": "Amanda Lee",
        "email": "amanda.lee.designs@gmail.com",
        "phone": "(555) 567-8901",
        "member_since": "2023-07-22",
        "loyalty_tier": "Silver",
        "total_orders": 7,
        "lifetime_value": 1350.00,
        "preferences": {"communication": "chat", "language": "English"},
        "sentiment_history": ["positive", "positive", "frustrated"],
        "notes": "Interior designer. Recently had issue with damaged item."
    }
]

# Realistic Orders
ORDERS = [
    {
        "order_id": "ORD-20251001-001",
        "customer_id": "CUST-1001",
        "date": "2025-09-28",
        "status": "delivered",
        "items": [
            {"name": "SmartHome Hub Pro", "sku": "SH-HUB-001", "qty": 1, "price": 299.99},
            {"name": "Smart Light Bulbs (4-pack)", "sku": "SL-BULB-004", "qty": 2, "price": 49.99}
        ],
        "total": 399.97,
        "shipping": {"method": "Standard", "tracking": "TRK-9876543210", "carrier": "UPS"},
        "delivery_date": "2025-10-01"
    },
    {
        "order_id": "ORD-20250925-002",
        "customer_id": "CUST-1002",
        "date": "2025-09-25",
        "status": "shipped",
        "items": [
            {"name": "UltraView 4K TV 65\"", "sku": "TV-ULTRA-65", "qty": 3, "price": 1299.99},
            {"name": "Premium HDMI Cable 2.1", "sku": "HDMI-PREM-21", "qty": 6, "price": 29.99}
        ],
        "total": 4079.91,
        "shipping": {"method": "Express", "tracking": "TRK-1234567890", "carrier": "FedEx"},
        "estimated_delivery": "2025-10-04"
    },
    {
        "order_id": "ORD-20250920-003",
        "customer_id": "CUST-1003",
        "date": "2025-09-20",
        "status": "return_initiated",
        "items": [
            {"name": "EcoClean Robot Vacuum", "sku": "VAC-ECO-001", "qty": 1, "price": 449.99}
        ],
        "total": 449.99,
        "shipping": {"method": "Standard", "tracking": "TRK-5555555555", "carrier": "USPS"},
        "return_reason": "Not as described - expected stronger suction",
        "return_status": "Label sent, awaiting return shipment"
    },
    {
        "order_id": "ORD-20250930-004",
        "customer_id": "CUST-1004",
        "date": "2025-09-30",
        "status": "processing",
        "items": [
            {"name": "Smart Thermostat", "sku": "THERM-SMART-01", "qty": 2, "price": 179.99},
            {"name": "Installation Service", "sku": "INST-THERM", "qty": 2, "price": 99.00}
        ],
        "total": 557.98,
        "shipping": {"method": "Standard", "tracking": None, "carrier": "UPS"},
        "estimated_ship_date": "2025-10-03"
    },
    {
        "order_id": "ORD-20250928-005",
        "customer_id": "CUST-1005",
        "date": "2025-09-28",
        "status": "issue",
        "items": [
            {"name": "Designer Table Lamp", "sku": "LAMP-DES-001", "qty": 1, "price": 189.99}
        ],
        "total": 189.99,
        "shipping": {"method": "Express", "tracking": "TRK-7777777777", "carrier": "FedEx"},
        "delivery_date": "2025-09-30",
        "issue": "Item arrived damaged - glass shade cracked",
        "issue_status": "Replacement being sent, arrives Oct 5"
    }
]

# Realistic Test Conversations
TEST_SCENARIOS = [
    {
        "scenario_name": "Order Tracking - Happy Path",
        "customer_id": "CUST-1001",
        "customer_name": "Sarah Johnson",
        "conversation": [
            {
                "customer": "Hi! I placed an order a few days ago and wanted to check on its status. My order number is ORD-20251001-001.",
                "expected_actions": ["check_order_status"],
                "expected_topics": ["order tracking", "delivery status"]
            },
            {
                "customer": "Great! Will it arrive tomorrow?",
                "expected_actions": ["retrieve_order_details"],
                "expected_topics": ["delivery date confirmation"]
            },
            {
                "customer": "Perfect, thank you!",
                "expected_actions": None,
                "expected_topics": ["closing", "satisfaction"]
            }
        ]
    },
    {
        "scenario_name": "Product Question with Policy Lookup",
        "customer_id": "CUST-1004",
        "customer_name": "James Wilson",
        "conversation": [
            {
                "customer": "I'm interested in buying the SmartHome Hub Pro. Does it work with my existing Zigbee devices?",
                "expected_actions": ["get_product_info", "search_knowledge_base"],
                "expected_topics": ["product compatibility", "specifications"]
            },
            {
                "customer": "That sounds good. What's your return policy if it doesn't work with my setup?",
                "expected_actions": ["search_knowledge_base"],
                "expected_topics": ["return policy", "30-day return"]
            },
            {
                "customer": "Is there a restocking fee?",
                "expected_actions": ["search_knowledge_base"],
                "expected_topics": ["restocking fee", "return conditions"]
            }
        ]
    },
    {
        "scenario_name": "Frustrated Customer - Damaged Item",
        "customer_id": "CUST-1005",
        "customer_name": "Amanda Lee",
        "conversation": [
            {
                "customer": "This is the second time I've received a damaged item! The lamp I ordered arrived with a cracked shade. Order ORD-20250928-005.",
                "expected_actions": ["check_order_status", "search_knowledge_base"],
                "expected_topics": ["damaged item", "replacement", "empathy"],
                "sentiment": "frustrated"
            },
            {
                "customer": "I need this for a client presentation next week. Can you expedite the replacement?",
                "expected_actions": ["create_support_ticket", "check_replacement_options"],
                "expected_topics": ["expedited shipping", "urgency"],
                "sentiment": "stressed"
            },
            {
                "customer": "Can you also waive the shipping fee since this is your mistake?",
                "expected_actions": ["apply_courtesy_adjustment"],
                "expected_topics": ["compensation", "courtesy"],
                "sentiment": "assertive"
            }
        ]
    },
    {
        "scenario_name": "Technical Support - Known Issue",
        "customer_id": "CUST-1001",
        "customer_name": "Sarah Johnson",
        "conversation": [
            {
                "customer": "My SmartHome Hub keeps disconnecting from WiFi every few hours. I have to restart it constantly. It's really annoying!",
                "expected_actions": ["search_product_knowledge", "check_known_issues", "get_troubleshooting"],
                "expected_topics": ["technical issue", "known bug", "troubleshooting"],
                "sentiment": "frustrated"
            },
            {
                "customer": "Is there a fix coming? I just bought this last week.",
                "expected_actions": ["check_known_issues", "check_firmware_updates"],
                "expected_topics": ["firmware update", "resolution timeline"],
                "sentiment": "concerned"
            },
            {
                "customer": "Two weeks? Can I return it and get a different model?",
                "expected_actions": ["search_knowledge_base", "check_return_eligibility"],
                "expected_topics": ["return option", "alternative products"],
                "sentiment": "considering_return"
            }
        ]
    },
    {
        "scenario_name": "Return Request - Within Policy",
        "customer_id": "CUST-1003",
        "customer_name": "Emily Rodriguez",
        "conversation": [
            {
                "customer": "I'd like to return the robot vacuum I ordered. It's not picking up as well as I expected.",
                "expected_actions": ["check_order_status", "search_knowledge_base"],
                "expected_topics": ["return request", "return policy"]
            },
            {
                "customer": "I still have the box and everything. It's only been used twice.",
                "expected_actions": ["validate_return_eligibility", "initiate_return_process"],
                "expected_topics": ["return conditions", "refund process"]
            },
            {
                "customer": "How long will the refund take?",
                "expected_actions": ["search_knowledge_base"],
                "expected_topics": ["refund timeline", "5-7 business days"]
            }
        ]
    },
    {
        "scenario_name": "Price Match Request",
        "customer_id": "CUST-1002",
        "customer_name": "Michael Chen",
        "conversation": [
            {
                "customer": "I bought 3 UltraView TVs from you last week for $1299 each. I just saw them on sale at Best Buy for $1199. Can you price match?",
                "expected_actions": ["search_knowledge_base", "check_order_status"],
                "expected_topics": ["price match", "policy verification"]
            },
            {
                "customer": "It's been 6 days since I placed the order. Here's a screenshot of Best Buy's price.",
                "expected_actions": ["validate_price_match", "calculate_refund"],
                "expected_topics": ["price match eligibility", "refund calculation"]
            },
            {
                "customer": "Great! So I'll get $300 back plus 10%?",
                "expected_actions": ["confirm_price_match_adjustment"],
                "expected_topics": ["confirmation", "additional discount"]
            }
        ]
    },
    {
        "scenario_name": "Complex Multi-Issue Request",
        "customer_id": "CUST-1004",
        "customer_name": "James Wilson",
        "conversation": [
            {
                "customer": "Hi, I have a few questions. First, what's the status of my order ORD-20250930-004?",
                "expected_actions": ["check_order_status"],
                "expected_topics": ["order status"]
            },
            {
                "customer": "Okay. Second, I also need to know about your warranty on the Smart Thermostats. And third, do you have installation slots available next week?",
                "expected_actions": ["search_product_knowledge", "check_installation_availability"],
                "expected_topics": ["warranty info", "installation scheduling", "multi-part question"]
            },
            {
                "customer": "Perfect. One more thing - I'm a Gold member, do I get any discount on the installation?",
                "expected_actions": ["check_customer_profile", "search_knowledge_base"],
                "expected_topics": ["loyalty benefits", "member discounts"]
            }
        ]
    },
    {
        "scenario_name": "Proactive Known Issue Notification",
        "customer_id": "CUST-1001",
        "customer_name": "Sarah Johnson",
        "conversation": [
            {
                "customer": "Hey, I just got my SmartHome Hub today and I'm setting it up. Anything I should know?",
                "expected_actions": ["get_product_info", "check_known_issues", "provide_setup_tips"],
                "expected_topics": ["setup guidance", "proactive issue warning"]
            },
            {
                "customer": "Oh, there's a WiFi issue? Should I be worried?",
                "expected_actions": ["explain_known_issue", "provide_workaround"],
                "expected_topics": ["issue explanation", "workaround", "firmware update ETA"]
            },
            {
                "customer": "Thanks for letting me know upfront. I'll use an ethernet cable for now.",
                "expected_actions": None,
                "expected_topics": ["customer satisfaction", "proactive support appreciation"]
            }
        ]
    }
]

# Support History Examples
SUPPORT_HISTORY = {
    "CUST-1003": [
        {
            "date": "2025-09-22",
            "issue": "Delivery delay - package stuck in transit",
            "resolution": "Contacted carrier, package delivered next day with apology discount",
            "sentiment": "frustrated -> satisfied",
            "agent_notes": "Customer was understanding after explanation. Applied 10% courtesy discount."
        }
    ],
    "CUST-1005": [
        {
            "date": "2025-08-15",
            "issue": "First damaged item - picture frame glass broken",
            "resolution": "Replacement sent with expedited shipping",
            "sentiment": "disappointed -> satisfied",
            "agent_notes": "Professional designer, needs items in perfect condition"
        }
    ]
}

def get_customer_profile(customer_id: str):
    """Get customer profile by ID"""
    for profile in CUSTOMER_PROFILES:
        if profile["customer_id"] == customer_id:
            return profile
    return None

def get_customer_orders(customer_id: str):
    """Get all orders for a customer"""
    return [order for order in ORDERS if order["customer_id"] == customer_id]

def get_order_by_id(order_id: str):
    """Get specific order by order ID"""
    for order in ORDERS:
        if order["order_id"] == order_id:
            return order
    return None

def get_support_history(customer_id: str):
    """Get support history for a customer"""
    return SUPPORT_HISTORY.get(customer_id, [])

def get_test_scenario(scenario_name: str):
    """Get a specific test scenario"""
    for scenario in TEST_SCENARIOS:
        if scenario["scenario_name"] == scenario_name:
            return scenario
    return None

def list_all_scenarios():
    """List all available test scenarios"""
    return [s["scenario_name"] for s in TEST_SCENARIOS]
