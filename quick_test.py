"""
Quick Comprehensive Test - Tests all major features
"""

import os
from dotenv import load_dotenv

# Load environment
load_dotenv()

from agentic_ai import AgenticAI
from auth_system import AuthSystem

print("="*70)
print("  🧪 COMPREHENSIVE AGENT TEST")
print("="*70)
print()

# Initialize
api_key = os.getenv("OPENROUTER_API_KEY")
if not api_key:
    print("❌ OPENROUTER_API_KEY not found in .env file")
    exit(1)

print("✅ API key found")
print("✅ Initializing agent...")

agent = AgenticAI(api_key)
auth = AuthSystem()

print("✅ Agent initialized")
print()

# Test counter
passed = 0
failed = 0

def test(name, func):
    """Run a test"""
    global passed, failed
    try:
        print(f"\n🔹 Testing: {name}")
        result = func()
        if result:
            print(f"   ✅ PASS")
            passed += 1
        else:
            print(f"   ❌ FAIL")
            failed += 1
        return result
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
        failed += 1
        return False

# ============================================================================
# TEST 1: Authentication
# ============================================================================

print("\n" + "="*70)
print("  🔐 AUTHENTICATION TESTS")
print("="*70)

def test_registration():
    result = auth.register_user(
        email="test@example.com",
        password="Test123!",
        name="Test User",
        role="customer"
    )
    print(f"   Registration: {result['success']}")
    return result['success']

def test_login():
    result = auth.login(
        email="test@example.com",
        password="Test123!",
        ip_address="127.0.0.1"
    )
    print(f"   Login: {result['success']}")
    if result['success']:
        print(f"   Token: {result['token'][:20]}...")
    return result['success']

def test_wrong_password():
    result = auth.login(
        email="test@example.com",
        password="WrongPass",
        ip_address="127.0.0.1"
    )
    # Should fail
    print(f"   Wrong password rejected: {not result['success']}")
    return not result['success']

test("User Registration", test_registration)
test("Valid Login", test_login)
test("Invalid Password Rejection", test_wrong_password)

# ============================================================================
# TEST 2: Basic Conversation
# ============================================================================

print("\n" + "="*70)
print("  💬 CONVERSATION TESTS")
print("="*70)

def test_greeting():
    response = agent.chat("Hello", customer_name="CUST-1001")
    print(f"   Response: {response[:80]}...")
    return len(response) > 0 and any(word in response.lower() for word in ['hello', 'hi', 'help'])

def test_introduction():
    response = agent.chat("My name is Sarah", customer_name="CUST-1001")
    print(f"   Response: {response[:80]}...")
    return len(response) > 0

def test_order_inquiry():
    response = agent.chat("Where is my order?", customer_name="CUST-1001")
    print(f"   Response: {response[:80]}...")
    return len(response) > 0 and 'order' in response.lower()

test("Greeting", test_greeting)
test("Introduction", test_introduction)
test("Order Inquiry", test_order_inquiry)

# ============================================================================
# TEST 3: RAG System
# ============================================================================

print("\n" + "="*70)
print("  🧠 RAG KNOWLEDGE TESTS")
print("="*70)

def test_policy_query():
    response = agent.chat("What is your return policy?", customer_name="CUST-1001")
    print(f"   Response: {response[:80]}...")
    return 'return' in response.lower() or 'policy' in response.lower()

def test_warranty_query():
    response = agent.chat("Tell me about warranty", customer_name="CUST-1001")
    print(f"   Response: {response[:80]}...")
    return 'warranty' in response.lower()

def test_product_query():
    response = agent.chat("Tell me about UltraBook", customer_name="CUST-1001")
    print(f"   Response: {response[:80]}...")
    return 'laptop' in response.lower() or 'ultrabook' in response.lower()

test("Policy Query", test_policy_query)
test("Warranty Query", test_warranty_query)
test("Product Query", test_product_query)

# ============================================================================
# TEST 4: Edge Cases
# ============================================================================

print("\n" + "="*70)
print("  ⚠️  EDGE CASE TESTS")
print("="*70)

def test_empty_message():
    try:
        response = agent.chat("", customer_name="CUST-1001")
        print(f"   Handled empty message: {len(response) > 0}")
        return len(response) > 0
    except:
        return False

def test_long_message():
    long_msg = "Can you help me? " * 50
    response = agent.chat(long_msg, customer_name="CUST-1001")
    print(f"   Handled long message: {len(response) > 0}")
    return len(response) > 0

def test_gibberish():
    response = agent.chat("asdfghjkl qwerty", customer_name="CUST-1001")
    print(f"   Handled gibberish: {len(response) > 0}")
    return len(response) > 0

test("Empty Message", test_empty_message)
test("Long Message", test_long_message)
test("Gibberish Input", test_gibberish)

# ============================================================================
# TEST 5: Multi-turn Conversation
# ============================================================================

print("\n" + "="*70)
print("  🔄 MULTI-TURN CONVERSATION TEST")
print("="*70)

def test_multi_turn():
    print()
    messages = [
        "Hi, I need help",
        "I ordered a laptop",
        "What's the status?",
        "When will it arrive?"
    ]
    
    all_valid = True
    for i, msg in enumerate(messages, 1):
        print(f"   Turn {i}: {msg}")
        response = agent.chat(msg, customer_name="CUST-1001")
        print(f"   Response: {response[:60]}...")
        if len(response) == 0:
            all_valid = False
        print()
    
    return all_valid

test("Multi-turn Conversation", test_multi_turn)

# ============================================================================
# TEST 6: Real Scenarios
# ============================================================================

print("\n" + "="*70)
print("  🌍 REAL-WORLD SCENARIO TESTS")
print("="*70)

def test_frustrated_customer():
    print()
    response = agent.chat(
        "I'M VERY ANGRY! My order is late!",
        customer_name="CUST-1001"
    )
    print(f"   Response: {response[:100]}...")
    # Should have empathetic response
    return any(word in response.lower() for word in ['sorry', 'apologize', 'understand', 'help'])

def test_return_request():
    print()
    response = agent.chat(
        "I want to return my product",
        customer_name="CUST-1001"
    )
    print(f"   Response: {response[:100]}...")
    return 'return' in response.lower()

def test_technical_issue():
    print()
    response = agent.chat(
        "My device is not working properly",
        customer_name="CUST-1001"
    )
    print(f"   Response: {response[:100]}...")
    return any(word in response.lower() for word in ['help', 'support', 'issue', 'troubleshoot'])

test("Frustrated Customer", test_frustrated_customer)
test("Return Request", test_return_request)
test("Technical Issue", test_technical_issue)

# ============================================================================
# TEST 7: Security & RBAC
# ============================================================================

print("\n" + "="*70)
print("  🔒 SECURITY & RBAC TESTS")
print("="*70)

def test_rbac_customer():
    can_view_own = auth.check_permission("customer", "view", "own_orders")
    cannot_manage_users = not auth.check_permission("customer", "delete", "users")
    print(f"   Customer permissions: view_own={can_view_own}, manage_users={not cannot_manage_users}")
    return can_view_own and cannot_manage_users

def test_rbac_admin():
    can_view_all = auth.check_permission("admin", "view", "orders")
    can_manage = auth.check_permission("admin", "create", "users")
    print(f"   Admin permissions: view_all={can_view_all}, manage_users={can_manage}")
    return can_view_all and can_manage

def test_access_control():
    # Customer trying to access another customer's data
    user_info = {"role": "customer", "customer_id": "CUST-1001"}
    can_access = auth.can_access_resource(user_info, "CUST-1002")
    print(f"   Cross-customer access blocked: {not can_access}")
    return not can_access

test("RBAC - Customer Permissions", test_rbac_customer)
test("RBAC - Admin Permissions", test_rbac_admin)
test("Access Control", test_access_control)

# ============================================================================
# FINAL REPORT
# ============================================================================

print("\n" + "="*70)
print("  📊 TEST REPORT")
print("="*70)
print()

total = passed + failed
success_rate = (passed / total * 100) if total > 0 else 0

print(f"Total Tests: {total}")
print(f"Passed: {passed} ✅")
print(f"Failed: {failed} ❌")
print(f"Success Rate: {success_rate:.1f}%")
print()

if success_rate >= 90:
    print("🎉 EXCELLENT! Agent is production-ready!")
    print("   All systems working perfectly.")
elif success_rate >= 75:
    print("✅ GOOD! Agent is mostly ready.")
    print("   Minor issues to review.")
elif success_rate >= 50:
    print("⚠️  NEEDS WORK. Several features need attention.")
else:
    print("❌ CRITICAL ISSUES. Major fixes required.")

print()
print("="*70)

# Exit with appropriate code
exit(0 if success_rate >= 90 else 1)
