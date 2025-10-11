"""
Test Runner for Enhanced Customer Support Agent
Runs realistic test scenarios and validates agent capabilities
"""

import os
from enhanced_agent import EnhancedCustomerSupportAgent
from test_data import TEST_SCENARIOS, get_customer_profile
from datetime import datetime


def run_single_scenario(agent, scenario):
    """Run a single test scenario"""
    print("\n" + "="*80)
    print(f"TEST SCENARIO: {scenario['scenario_name']}")
    print("="*80)
    
    customer_id = scenario['customer_id']
    customer_name = scenario['customer_name']
    
    profile = get_customer_profile(customer_id)
    if profile:
        print(f"\n👤 Customer: {customer_name}")
        print(f"   Loyalty Tier: {profile['loyalty_tier']}")
        print(f"   Total Orders: {profile['total_orders']}")
        print(f"   Sentiment History: {profile['sentiment_history']}")
    
    print("\n" + "-"*80)
    
    for turn_num, turn in enumerate(scenario['conversation'], 1):
        print(f"\n[Turn {turn_num}]")
        print(f"👨 Customer: {turn['customer']}")
        
        if turn.get('sentiment'):
            print(f"   😠 Sentiment: {turn['sentiment']}")
        
        # Get agent response
        response = agent.chat(customer_id, turn['customer'])
        print(f"\n🤖 Agent: {response}")
        
        # Show expected actions
        if turn.get('expected_actions'):
            print(f"\n   ✓ Expected actions: {', '.join(turn['expected_actions'])}")
        
        if turn.get('expected_topics'):
            print(f"   ✓ Expected topics: {', '.join(turn['expected_topics'])}")
        
        print("\n" + "-"*80)
        
        # Pause between turns
        input("\nPress Enter to continue to next turn...")
    
    print(f"\n✅ Scenario '{scenario['scenario_name']}' completed!")
    print("="*80)


def run_all_scenarios(agent):
    """Run all test scenarios"""
    print("\n" + "="*80)
    print("RUNNING ALL TEST SCENARIOS")
    print("="*80)
    
    for i, scenario in enumerate(TEST_SCENARIOS, 1):
        print(f"\n\n{'#'*80}")
        print(f"# Scenario {i} of {len(TEST_SCENARIOS)}")
        print(f"{'#'*80}")
        
        run_single_scenario(agent, scenario)
        
        if i < len(TEST_SCENARIOS):
            cont = input("\nContinue to next scenario? (y/n): ")
            if cont.lower() != 'y':
                break
    
    print("\n\n" + "="*80)
    print("ALL SCENARIOS COMPLETED!")
    print("="*80)


def interactive_scenario_selector(agent):
    """Interactive scenario selection"""
    while True:
        print("\n" + "="*80)
        print("TEST SCENARIO SELECTOR")
        print("="*80)
        
        print("\nAvailable test scenarios:")
        for i, scenario in enumerate(TEST_SCENARIOS, 1):
            print(f"  {i}. {scenario['scenario_name']}")
        print(f"  {len(TEST_SCENARIOS) + 1}. Run ALL scenarios")
        print("  0. Exit")
        
        choice = input("\nSelect scenario number: ").strip()
        
        if choice == '0':
            break
        
        if choice == str(len(TEST_SCENARIOS) + 1):
            run_all_scenarios(agent)
        else:
            try:
                scenario_idx = int(choice) - 1
                if 0 <= scenario_idx < len(TEST_SCENARIOS):
                    run_single_scenario(agent, TEST_SCENARIOS[scenario_idx])
                else:
                    print("❌ Invalid selection!")
            except ValueError:
                print("❌ Please enter a valid number!")


def quick_feature_test(agent):
    """Quick test of key features"""
    print("\n" + "="*80)
    print("QUICK FEATURE TEST")
    print("="*80)
    
    tests = [
        {
            "name": "RAG Policy Search",
            "customer_id": "CUST-1001",
            "message": "What's your return policy?"
        },
        {
            "name": "Order Status Check",
            "customer_id": "CUST-1001",
            "message": "Check status of order ORD-20251001-001"
        },
        {
            "name": "Known Issues Check",
            "customer_id": "CUST-1001",
            "message": "I just got a SmartHome Hub. Any known issues I should know about?"
        },
        {
            "name": "Loyalty Benefits",
            "customer_id": "CUST-1002",
            "message": "What benefits do I get as a Platinum member?"
        },
        {
            "name": "Multi-part Question",
            "customer_id": "CUST-1004",
            "message": "Can you check my order ORD-20250930-004 status, tell me about the warranty on Smart Thermostats, and see if I have any loyalty discounts?"
        }
    ]
    
    for test in tests:
        print(f"\n{'─'*80}")
        print(f"Test: {test['name']}")
        print(f"Customer: {test['customer_id']}")
        print(f"{'─'*80}")
        print(f"\n👨 Customer: {test['message']}")
        
        response = agent.chat(test['customer_id'], test['message'])
        print(f"\n🤖 Agent: {response}")
        
        input("\nPress Enter for next test...")
    
    print("\n✅ All quick tests completed!")


def main():
    """Main test runner"""
    print("="*80)
    print("ENHANCED CUSTOMER SUPPORT AGENT - TEST RUNNER")
    print("="*80)
    
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("\n❌ Error: OPENROUTER_API_KEY not set!")
        print("Please set your API key in the .env file")
        return
    
    print("\n✓ API Key loaded")
    print("✓ Initializing agent...")
    
    agent = EnhancedCustomerSupportAgent(
        api_key=api_key,
        site_url="http://localhost:3000",
        site_name="Dealer Shop Support"
    )
    
    print("✓ Agent initialized successfully!")
    
    while True:
        print("\n" + "="*80)
        print("TEST OPTIONS")
        print("="*80)
        print("\n1. Run interactive test scenarios")
        print("2. Quick feature test")
        print("3. Free chat mode")
        print("0. Exit")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '0':
            print("\n👋 Goodbye!")
            break
        elif choice == '1':
            interactive_scenario_selector(agent)
        elif choice == '2':
            quick_feature_test(agent)
        elif choice == '3':
            print("\n" + "="*80)
            print("FREE CHAT MODE")
            print("="*80)
            customer_id = input("\nEnter customer ID (or press Enter for CUST-1001): ").strip() or "CUST-1001"
            profile = get_customer_profile(customer_id)
            
            if profile:
                print(f"\n👤 {profile['name']} ({profile['loyalty_tier']})")
            
            print("\nType 'back' to return to menu\n")
            
            while True:
                msg = input(f"{profile.get('name', 'Customer') if profile else 'Customer'}: ").strip()
                if msg.lower() == 'back':
                    break
                if msg:
                    response = agent.chat(customer_id, msg)
                    print(f"\n🤖 Agent: {response}\n")
        else:
            print("❌ Invalid option!")


if __name__ == "__main__":
    main()
