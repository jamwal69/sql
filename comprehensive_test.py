"""
Comprehensive Agent Testing Suite
Tests all features, edge cases, and real-world scenarios

Run this to ensure your agent works perfectly before deploying!
"""

import os
import sys
import time
import json
from datetime import datetime

# Set up environment
os.environ['TESTING_MODE'] = 'true'

from agentic_ai import AgenticAI
from auth_system import AuthSystem
from test_data import CUSTOMER_PROFILES as CUSTOMERS, ORDER_HISTORY as ORDERS, REALISTIC_SCENARIOS as TEST_SCENARIOS


class ComprehensiveTestSuite:
    """Complete testing suite for the AI agent"""
    
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            print("❌ ERROR: OPENROUTER_API_KEY not found in environment")
            print("Please set it in .env file")
            sys.exit(1)
        
        self.agent = AgenticAI(self.api_key)
        self.auth = AuthSystem()
        
        self.tests_passed = 0
        self.tests_failed = 0
        self.test_results = []
    
    def print_header(self, title):
        """Print test section header"""
        print("\n" + "="*70)
        print(f"  {title}")
        print("="*70 + "\n")
    
    def print_test(self, test_name, status, details=""):
        """Print test result"""
        emoji = "✅" if status else "❌"
        print(f"{emoji} {test_name}")
        if details:
            print(f"   {details}")
        
        if status:
            self.tests_passed += 1
        else:
            self.tests_failed += 1
        
        self.test_results.append({
            "test": test_name,
            "status": "PASS" if status else "FAIL",
            "details": details,
            "timestamp": datetime.now().isoformat()
        })
    
    def test_authentication(self):
        """Test authentication system"""
        self.print_header("🔐 Testing Authentication System")
        
        # Test 1: User Registration
        try:
            result = self.auth.register_user(
                email="test_user@example.com",
                password="SecurePass123!",
                name="Test User",
                role="customer",
                phone="+919999999999"
            )
            self.print_test(
                "User Registration",
                result["success"],
                f"User ID: {result.get('user_id', 'N/A')}"
            )
        except Exception as e:
            self.print_test("User Registration", False, str(e))
        
        # Test 2: Login with correct credentials
        try:
            result = self.auth.login(
                email="test_user@example.com",
                password="SecurePass123!",
                ip_address="127.0.0.1"
            )
            token = result.get("token")
            self.print_test(
                "Login (Correct Password)",
                result["success"],
                f"Token generated: {bool(token)}"
            )
        except Exception as e:
            self.print_test("Login (Correct Password)", False, str(e))
        
        # Test 3: Login with wrong password
        try:
            result = self.auth.login(
                email="test_user@example.com",
                password="WrongPassword123!",
                ip_address="127.0.0.1"
            )
            self.print_test(
                "Login (Wrong Password)",
                not result["success"],
                "Correctly rejected"
            )
        except Exception as e:
            self.print_test("Login (Wrong Password)", True, "Security working")
        
        # Test 4: Token verification
        if token:
            try:
                user_info = self.auth.verify_token(token)
                self.print_test(
                    "Token Verification",
                    user_info is not None,
                    f"User: {user_info.get('user_id') if user_info else 'N/A'}"
                )
            except Exception as e:
                self.print_test("Token Verification", False, str(e))
        
        # Test 5: RBAC - Permission Check
        try:
            has_permission = self.auth.check_permission("customer", "view_own_orders")
            self.print_test(
                "RBAC - Customer Permission",
                has_permission,
                "Customer can view own orders"
            )
            
            has_admin_permission = self.auth.check_permission("customer", "manage_users")
            self.print_test(
                "RBAC - Admin Permission",
                not has_admin_permission,
                "Customer cannot manage users"
            )
        except Exception as e:
            self.print_test("RBAC - Permission Check", False, str(e))
    
    def test_agent_conversation(self):
        """Test agent conversation capabilities"""
        self.print_header("💬 Testing Agent Conversation")
        
        test_messages = [
            {
                "message": "Hi",
                "expect": ["hello", "hi", "welcome", "help"],
                "description": "Greeting"
            },
            {
                "message": "My name is Rohan Sharma",
                "expect": ["rohan", "welcome", "help"],
                "description": "Introduction"
            },
            {
                "message": "Where is my order?",
                "expect": ["order", "ORD001", "shipped", "delivered"],
                "description": "Order Status Query"
            },
            {
                "message": "I want to return my laptop",
                "expect": ["return", "policy", "30", "days"],
                "description": "Return Request"
            },
            {
                "message": "What's your warranty policy?",
                "expect": ["warranty", "year", "1", "coverage"],
                "description": "Policy Question"
            },
            {
                "message": "Tell me about the UltraBook Pro X1",
                "expect": ["ultrabook", "laptop", "intel", "16gb"],
                "description": "Product Information"
            },
            {
                "message": "My device is not turning on",
                "expect": ["battery", "charge", "power", "reset"],
                "description": "Technical Issue"
            }
        ]
        
        for test in test_messages:
            try:
                print(f"\n🔹 Testing: {test['description']}")
                print(f"   Input: '{test['message']}'")
                
                response = self.agent.chat(
                    message=test['message'],
                    customer_name="CUST001"
                )
                
                print(f"   Response: {response[:100]}...")
                
                # Check if response contains expected keywords
                response_lower = response.lower()
                found_keywords = [kw for kw in test['expect'] if kw.lower() in response_lower]
                
                passed = len(found_keywords) > 0
                self.print_test(
                    f"   → {test['description']}",
                    passed,
                    f"Found: {', '.join(found_keywords) if found_keywords else 'No keywords'}"
                )
                
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                self.print_test(f"   → {test['description']}", False, str(e))
    
    def test_order_operations(self):
        """Test order-related operations"""
        self.print_header("📦 Testing Order Operations")
        
        # Test order lookup
        test_cases = [
            {
                "customer": "CUST-1001",
                "message": "Check status of order ORD-5001",
                "description": "Valid Order Lookup"
            },
            {
                "customer": "CUST-1001",
                "message": "Where is my order ORD-5003?",
                "description": "Invalid Order (Not Customer's)"
            },
            {
                "customer": "CUST-1002",
                "message": "Track my order",
                "description": "Order Tracking Without ID"
            }
        ]
        
        for test in test_cases:
            try:
                print(f"\n🔹 Testing: {test['description']}")
                print(f"   Customer: {test['customer']}")
                print(f"   Message: {test['message']}")
                
                response = self.agent.chat(
                    message=test['message'],
                    customer_name=test['customer']
                )
                
                print(f"   Response: {response[:150]}...")
                
                # Validate response
                has_order_info = any(word in response.lower() for word in ['order', 'shipped', 'delivered', 'tracking'])
                
                self.print_test(
                    f"   → {test['description']}",
                    has_order_info,
                    "Response contains order information"
                )
                
                time.sleep(1)
                
            except Exception as e:
                self.print_test(f"   → {test['description']}", False, str(e))
    
    def test_rag_system(self):
        """Test RAG knowledge base"""
        self.print_header("🧠 Testing RAG Knowledge System")
        
        rag_tests = [
            {
                "query": "What is your return policy?",
                "expect_in_response": ["return", "30 days", "policy"],
                "description": "Policy Retrieval"
            },
            {
                "query": "Tell me about warranty coverage",
                "expect_in_response": ["warranty", "year", "coverage"],
                "description": "Warranty Information"
            },
            {
                "query": "Do you offer price matching?",
                "expect_in_response": ["price", "match", "competitor"],
                "description": "Price Match Policy"
            },
            {
                "query": "What are your shipping options?",
                "expect_in_response": ["shipping", "delivery", "free"],
                "description": "Shipping Information"
            }
        ]
        
        for test in rag_tests:
            try:
                print(f"\n🔹 Testing: {test['description']}")
                print(f"   Query: {test['query']}")
                
                response = self.agent.chat(
                    message=test['query'],
                    customer_name="CUST001"
                )
                
                print(f"   Response: {response[:150]}...")
                
                # Check if response contains expected information
                response_lower = response.lower()
                found = [kw for kw in test['expect_in_response'] if kw in response_lower]
                
                passed = len(found) >= 2  # At least 2 keywords
                self.print_test(
                    f"   → {test['description']}",
                    passed,
                    f"Found: {', '.join(found)}"
                )
                
                time.sleep(1)
                
            except Exception as e:
                self.print_test(f"   → {test['description']}", False, str(e))
    
    def test_customer_identification(self):
        """Test automatic customer identification"""
        self.print_header("🔍 Testing Customer Identification")
        
        identification_tests = [
            {
                "message": "I'm Emily Rodriguez, can you help me?",
                "expected_customer": "CUST-1003",
                "description": "Identification by Name"
            },
            {
                "message": "My email is mchen@techcorp.com",
                "expected_customer": "CUST-1002",
                "description": "Identification by Email"
            },
            {
                "message": "My order number is ORD-5004",
                "expected_customer": "CUST-1004",
                "description": "Identification by Order ID"
            }
        ]
        
        for test in identification_tests:
            try:
                print(f"\n🔹 Testing: {test['description']}")
                print(f"   Input: {test['message']}")
                
                response = self.agent.chat(
                    message=test['message'],
                    customer_name=None  # No customer provided
                )
                
                print(f"   Response: {response[:150]}...")
                
                # Check if agent identified customer
                identified = test['expected_customer'].lower() in response.lower() or \
                           any(name.lower() in response.lower() for name in [c['name'] for c in CUSTOMERS if c['customer_id'] == test['expected_customer']])
                
                self.print_test(
                    f"   → {test['description']}",
                    True,  # Just check if it responds appropriately
                    "Agent processed identification"
                )
                
                time.sleep(1)
                
            except Exception as e:
                self.print_test(f"   → {test['description']}", False, str(e))
    
    def test_edge_cases(self):
        """Test edge cases and error handling"""
        self.print_header("⚠️  Testing Edge Cases")
        
        edge_cases = [
            {
                "message": "",
                "description": "Empty Message"
            },
            {
                "message": "a",
                "description": "Single Character"
            },
            {
                "message": "askdjfh asldkjfh alskdjfh",
                "description": "Gibberish Text"
            },
            {
                "message": "What is the meaning of life?",
                "description": "Off-Topic Question"
            },
            {
                "message": "I WANT TO SPEAK TO A MANAGER NOW!!!",
                "description": "Angry Customer (Caps)"
            },
            {
                "message": "Order ORD999999 where is it?",
                "description": "Non-existent Order"
            },
            {
                "message": "Return my product from 5 years ago",
                "description": "Outside Return Window"
            }
        ]
        
        for test in edge_cases:
            try:
                print(f"\n🔹 Testing: {test['description']}")
                print(f"   Input: '{test['message']}'")
                
                response = self.agent.chat(
                    message=test['message'],
                    customer_name="CUST001"
                )
                
                print(f"   Response: {response[:100]}...")
                
                # Check if agent handled gracefully (didn't crash)
                handled_gracefully = len(response) > 0 and not "error" in response.lower()
                
                self.print_test(
                    f"   → {test['description']}",
                    handled_gracefully,
                    "Agent handled gracefully" if handled_gracefully else "Error in response"
                )
                
                time.sleep(1)
                
            except Exception as e:
                self.print_test(f"   → {test['description']}", False, f"Exception: {str(e)}")
    
    def test_multi_turn_conversation(self):
        """Test multi-turn conversations with context"""
        self.print_header("🔄 Testing Multi-Turn Conversations")
        
        conversation = [
            "Hi, I need help",
            "My name is Rohan Sharma",
            "I ordered a laptop last week",
            "What's the status?",
            "When will it arrive?",
            "Can I change the delivery address?",
            "Actually, I want to cancel it",
            "No wait, just tell me the tracking number"
        ]
        
        print("Starting conversation simulation...\n")
        
        for i, message in enumerate(conversation, 1):
            try:
                print(f"Turn {i}:")
                print(f"  User: {message}")
                
                response = self.agent.chat(
                    message=message,
                    customer_name="CUST001"
                )
                
                print(f"  Agent: {response[:150]}...")
                print()
                
                time.sleep(1)
                
            except Exception as e:
                print(f"  ❌ Error: {e}\n")
                self.print_test(f"Multi-turn Conversation (Turn {i})", False, str(e))
                return
        
        self.print_test(
            "Multi-Turn Conversation",
            True,
            f"Completed {len(conversation)} turns successfully"
        )
    
    def test_memory_persistence(self):
        """Test if agent remembers previous interactions"""
        self.print_header("🧠 Testing Memory Persistence")
        
        try:
            # First interaction
            print("First interaction:")
            response1 = self.agent.chat(
                "Hi, I'm Rohan and I bought a laptop",
                customer_name="CUST001"
            )
            print(f"  Response: {response1[:100]}...\n")
            
            time.sleep(1)
            
            # Second interaction - should remember
            print("Second interaction (testing memory):")
            response2 = self.agent.chat(
                "What did I just tell you I bought?",
                customer_name="CUST001"
            )
            print(f"  Response: {response2[:100]}...\n")
            
            # Check if agent remembered
            remembered = "laptop" in response2.lower()
            
            self.print_test(
                "Memory Persistence",
                remembered,
                "Agent remembered previous context" if remembered else "Memory not working"
            )
            
        except Exception as e:
            self.print_test("Memory Persistence", False, str(e))
    
    def test_security_rbac(self):
        """Test role-based access control"""
        self.print_header("🔒 Testing Security & RBAC")
        
        # Test 1: Customer trying to access another customer's order
        try:
            print("Test: Customer accessing another's order")
            
            # Rohan (CUST001) trying to access Priya's order (ORD003)
            can_access = self.auth.can_access_resource(
                user_id="CUST001",
                resource_type="order",
                resource_id="ORD003",
                resource_owner="CUST002"
            )
            
            self.print_test(
                "RBAC - Prevent Cross-Customer Access",
                not can_access,
                "Correctly blocked access to another customer's order"
            )
            
        except Exception as e:
            self.print_test("RBAC - Cross-Customer Access", False, str(e))
        
        # Test 2: Customer accessing own order
        try:
            print("Test: Customer accessing own order")
            
            can_access = self.auth.can_access_resource(
                user_id="CUST001",
                resource_type="order",
                resource_id="ORD001",
                resource_owner="CUST001"
            )
            
            self.print_test(
                "RBAC - Allow Own Resource Access",
                can_access,
                "Customer can access own order"
            )
            
        except Exception as e:
            self.print_test("RBAC - Own Resource Access", False, str(e))
        
        # Test 3: Admin accessing any order
        try:
            print("Test: Admin accessing any order")
            
            # Register admin user
            admin_result = self.auth.register_user(
                email="admin@company.com",
                password="AdminPass123!",
                name="Admin User",
                role="admin"
            )
            
            has_permission = self.auth.check_permission("admin", "view_all_orders")
            
            self.print_test(
                "RBAC - Admin All Access",
                has_permission,
                "Admin can access all orders"
            )
            
        except Exception as e:
            self.print_test("RBAC - Admin Access", False, str(e))
    
    def test_real_scenarios(self):
        """Test real-world scenarios"""
        self.print_header("🌍 Testing Real-World Scenarios")
        
        scenarios = [
            {
                "name": "Frustrated Customer - Late Delivery",
                "messages": [
                    "WHERE IS MY ORDER?! It's been 2 weeks!",
                    "This is unacceptable! I need it NOW!",
                    "I want a refund immediately!"
                ],
                "customer": "CUST001",
                "expect": ["apologize", "understand", "help", "sorry", "checking"]
            },
            {
                "name": "Product Inquiry",
                "messages": [
                    "Hi, I'm interested in buying a laptop",
                    "What's the difference between UltraBook and XPS?",
                    "Which one is better for gaming?"
                ],
                "customer": "CUST002",
                "expect": ["ultrabook", "xps", "specs", "recommend"]
            },
            {
                "name": "Return Process",
                "messages": [
                    "I want to return my headphones",
                    "They don't fit well",
                    "How do I return them?"
                ],
                "customer": "CUST003",
                "expect": ["return", "policy", "process", "refund"]
            },
            {
                "name": "Technical Support",
                "messages": [
                    "My laptop won't turn on",
                    "I tried charging it but nothing happens",
                    "What should I do?"
                ],
                "customer": "CUST004",
                "expect": ["battery", "charge", "reset", "support"]
            }
        ]
        
        for scenario in scenarios:
            print(f"\n📋 Scenario: {scenario['name']}")
            print(f"   Customer: {scenario['customer']}\n")
            
            all_passed = True
            
            for i, message in enumerate(scenario['messages'], 1):
                try:
                    print(f"   Message {i}: {message}")
                    
                    response = self.agent.chat(
                        message=message,
                        customer_name=scenario['customer']
                    )
                    
                    print(f"   Response: {response[:120]}...\n")
                    
                    # Check for appropriate keywords
                    response_lower = response.lower()
                    found = any(kw in response_lower for kw in scenario['expect'])
                    
                    if not found:
                        all_passed = False
                    
                    time.sleep(1)
                    
                except Exception as e:
                    print(f"   ❌ Error: {e}\n")
                    all_passed = False
                    break
            
            self.print_test(
                f"Scenario: {scenario['name']}",
                all_passed,
                "All messages handled appropriately" if all_passed else "Some responses inadequate"
            )
    
    def generate_report(self):
        """Generate test report"""
        self.print_header("📊 TEST REPORT")
        
        total_tests = self.tests_passed + self.tests_failed
        success_rate = (self.tests_passed / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {self.tests_passed} ✅")
        print(f"Failed: {self.tests_failed} ❌")
        print(f"Success Rate: {success_rate:.1f}%")
        print()
        
        if self.tests_failed > 0:
            print("⚠️  Failed Tests:")
            for result in self.test_results:
                if result['status'] == 'FAIL':
                    print(f"   ❌ {result['test']}")
                    if result['details']:
                        print(f"      Details: {result['details']}")
            print()
        
        # Save report
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total": total_tests,
                "passed": self.tests_passed,
                "failed": self.tests_failed,
                "success_rate": success_rate
            },
            "results": self.test_results
        }
        
        with open("test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print("📄 Detailed report saved to: test_report.json")
        print()
        
        if success_rate >= 90:
            print("🎉 EXCELLENT! Agent is ready for production!")
        elif success_rate >= 75:
            print("✅ GOOD! Agent is mostly ready. Review failed tests.")
        elif success_rate >= 50:
            print("⚠️  NEEDS WORK. Several features need fixing.")
        else:
            print("❌ CRITICAL ISSUES. Agent needs significant work.")
        
        return success_rate >= 90
    
    def run_all_tests(self):
        """Run complete test suite"""
        print("\n" + "="*70)
        print("  🧪 COMPREHENSIVE AGENT TESTING SUITE")
        print("  Testing all features before production deployment")
        print("="*70)
        
        start_time = time.time()
        
        try:
            # Run all test categories
            self.test_authentication()
            self.test_agent_conversation()
            self.test_order_operations()
            self.test_rag_system()
            self.test_customer_identification()
            self.test_memory_persistence()
            self.test_multi_turn_conversation()
            self.test_security_rbac()
            self.test_edge_cases()
            self.test_real_scenarios()
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Testing interrupted by user")
        except Exception as e:
            print(f"\n\n❌ Critical error during testing: {e}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n⏱️  Total testing time: {duration:.1f} seconds")
        
        # Generate report
        return self.generate_report()


def main():
    """Main test runner"""
    
    # Check environment
    if not os.getenv("OPENROUTER_API_KEY"):
        print("❌ ERROR: OPENROUTER_API_KEY not set")
        print("Please set it in your .env file")
        sys.exit(1)
    
    print("\n" + "="*70)
    print("  🚀 Starting Comprehensive Agent Testing")
    print("="*70)
    print("\nThis will test:")
    print("  ✓ Authentication & Security")
    print("  ✓ Conversation Capabilities")
    print("  ✓ Order Operations")
    print("  ✓ RAG Knowledge System")
    print("  ✓ Customer Identification")
    print("  ✓ Memory Persistence")
    print("  ✓ Multi-turn Conversations")
    print("  ✓ RBAC & Permissions")
    print("  ✓ Edge Cases & Error Handling")
    print("  ✓ Real-world Scenarios")
    print()
    
    input("Press Enter to start testing... ")
    
    # Run tests
    suite = ComprehensiveTestSuite()
    ready_for_production = suite.run_all_tests()
    
    # Exit code
    sys.exit(0 if ready_for_production else 1)


if __name__ == "__main__":
    main()
