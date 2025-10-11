"""
Test Website Connection
Quick script to verify your website integration is working
"""

import os
import sys
from website_integration import init_website_integration
from load_env import load_env

# Load environment variables
load_env()

def test_connection():
    """Test website data fetching"""
    
    print("🔧 Testing Website Integration\n")
    print("=" * 60)
    
    # Get integration type from environment
    integration_type = os.getenv("INTEGRATION_TYPE", "api")
    print(f"📡 Integration Type: {integration_type.upper()}")
    print("=" * 60)
    
    # Initialize fetcher
    try:
        print("\n1️⃣ Initializing connection...")
        fetcher = init_website_integration(integration_type)
        print("   ✅ Connection initialized!")
    except Exception as e:
        print(f"   ❌ Failed to initialize: {e}")
        return False
    
    # Test 1: Fetch customer by email
    print("\n2️⃣ Testing customer fetch by email...")
    test_email = input("   Enter customer email to test (or press Enter for default): ").strip()
    if not test_email:
        test_email = "customer@example.com"
    
    try:
        customer = fetcher.get_customer_by_email(test_email)
        if customer:
            print(f"   ✅ Customer found!")
            print(f"   • ID: {customer.get('customer_id')}")
            print(f"   • Name: {customer.get('name')}")
            print(f"   • Email: {customer.get('email')}")
            print(f"   • Phone: {customer.get('phone')}")
            print(f"   • Total Orders: {customer.get('total_orders')}")
            print(f"   • Lifetime Value: ${customer.get('lifetime_value', 0):.2f}")
            
            # Test 2: Fetch orders
            print("\n3️⃣ Testing order fetch...")
            try:
                orders = fetcher.get_customer_orders(customer['customer_id'])
                print(f"   ✅ Found {len(orders)} orders")
                
                if orders:
                    latest = orders[0]
                    print(f"\n   Latest Order:")
                    print(f"   • Order ID: {latest.get('order_id')}")
                    print(f"   • Date: {latest.get('date')}")
                    print(f"   • Status: {latest.get('status')}")
                    print(f"   • Total: ${latest.get('total', 0):.2f}")
                    print(f"   • Items: {len(latest.get('items', []))}")
                    
                    # Test 3: Fetch specific order
                    print("\n4️⃣ Testing specific order fetch...")
                    order = fetcher.get_order_by_id(latest['order_id'])
                    if order:
                        print(f"   ✅ Order details retrieved")
                        print(f"   • Shipping: {order.get('shipping', {}).get('method')}")
                        print(f"   • Tracking: {order.get('shipping', {}).get('tracking')}")
                    else:
                        print(f"   ⚠️ Order not found")
                else:
                    print("   ℹ️ Customer has no orders")
                    
            except Exception as e:
                print(f"   ❌ Failed to fetch orders: {e}")
        else:
            print(f"   ⚠️ Customer not found with email: {test_email}")
            print(f"   💡 Make sure the email exists in your database/system")
            return False
            
    except Exception as e:
        print(f"   ❌ Failed to fetch customer: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 4: Fetch by phone (for WhatsApp)
    print("\n5️⃣ Testing customer fetch by phone...")
    test_phone = input("   Enter phone number to test (or press Enter to skip): ").strip()
    if test_phone:
        try:
            customer = fetcher.get_customer_by_phone(test_phone)
            if customer:
                print(f"   ✅ Customer found by phone!")
                print(f"   • Name: {customer.get('name')}")
                print(f"   • Email: {customer.get('email')}")
            else:
                print(f"   ⚠️ No customer found with phone: {test_phone}")
        except Exception as e:
            print(f"   ❌ Failed: {e}")
    else:
        print("   ⏭️ Skipped phone test")
    
    print("\n" + "=" * 60)
    print("✅ INTEGRATION TEST COMPLETE!")
    print("=" * 60)
    print("\n💡 Next Steps:")
    print("   1. Update agentic_ai.py to use website_integration")
    print("   2. Update api_server.py to use website_integration")
    print("   3. Test with chat_widget.html")
    print("   4. Deploy to production!")
    
    return True


def show_config_help():
    """Show configuration help"""
    print("\n" + "=" * 60)
    print("⚙️ CONFIGURATION HELP")
    print("=" * 60)
    
    integration_type = os.getenv("INTEGRATION_TYPE", "api")
    
    print(f"\nCurrent Integration: {integration_type.upper()}")
    
    if integration_type == "database":
        print("\n📊 Database Configuration:")
        print(f"   • Type: {os.getenv('WEBSITE_DB_TYPE', 'NOT SET')}")
        print(f"   • Host: {os.getenv('WEBSITE_DB_HOST', 'NOT SET')}")
        print(f"   • Port: {os.getenv('WEBSITE_DB_PORT', 'NOT SET')}")
        print(f"   • Database: {os.getenv('WEBSITE_DB_NAME', 'NOT SET')}")
        print(f"   • User: {os.getenv('WEBSITE_DB_USER', 'NOT SET')}")
        print(f"   • Password: {'SET' if os.getenv('WEBSITE_DB_PASSWORD') else 'NOT SET'}")
        
    elif integration_type == "api":
        print("\n🔌 API Configuration:")
        print(f"   • URL: {os.getenv('WEBSITE_API_URL', 'NOT SET')}")
        print(f"   • API Key: {'SET' if os.getenv('WEBSITE_API_KEY') else 'NOT SET'}")
        
    elif integration_type == "woocommerce":
        print("\n🛒 WooCommerce Configuration:")
        print(f"   • URL: {os.getenv('WOO_URL', 'NOT SET')}")
        print(f"   • Consumer Key: {'SET' if os.getenv('WOO_CONSUMER_KEY') else 'NOT SET'}")
        print(f"   • Consumer Secret: {'SET' if os.getenv('WOO_CONSUMER_SECRET') else 'NOT SET'}")
        
    elif integration_type == "shopify":
        print("\n🛍️ Shopify Configuration:")
        print(f"   • Shop URL: {os.getenv('SHOPIFY_SHOP_URL', 'NOT SET')}")
        print(f"   • Access Token: {'SET' if os.getenv('SHOPIFY_ACCESS_TOKEN') else 'NOT SET'}")
    
    print("\n💡 To configure, add these to your .env file:")
    print("   See WEBSITE_INTEGRATION_GUIDE.md for details")
    print("=" * 60)


if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║         🌐 WEBSITE INTEGRATION TEST                        ║
    ║                                                            ║
    ║  This script tests your website connection                 ║
    ║  Make sure you've configured your .env file first!         ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    # Check if configuration exists
    if not os.getenv("INTEGRATION_TYPE"):
        print("⚠️  WARNING: INTEGRATION_TYPE not set in .env")
        print("   Add this line to .env: INTEGRATION_TYPE=database")
        print("   (or api, woocommerce, shopify)")
        print()
    
    # Show current config
    show_config_help()
    
    # Ask to continue
    response = input("\n🚀 Ready to test connection? (y/n): ").strip().lower()
    
    if response == 'y':
        try:
            success = test_connection()
            if success:
                print("\n🎉 Your website integration is working!")
            else:
                print("\n⚠️ Integration test failed. Check configuration.")
                print("   See WEBSITE_INTEGRATION_GUIDE.md for help")
        except KeyboardInterrupt:
            print("\n\n⏹️ Test cancelled by user")
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("\n👋 Test cancelled. Configure your .env file and try again!")
        print("   See WEBSITE_INTEGRATION_GUIDE.md for setup instructions")
