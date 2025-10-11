"""
TRUE AGENTIC AI - Natural Conversational Customer Support
- No forced inputs or rigid flows
- Autonomous decision making
- Natural human-like conversation
- Intelligent tool usage
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import google.generativeai as genai

# Load environment
from load_env import load_env
load_env()

# Import systems
from rag_system import RAGKnowledgeBase
from test_data import (
    get_customer_profile, get_customer_orders, get_order_by_id,
    CUSTOMER_PROFILES, ORDERS
)


class AgenticAI:
    """
    True Agentic AI - Thinks and acts autonomously
    No rigid scripts, just intelligent conversation
    """
    
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        self.rag = RAGKnowledgeBase()
        
        # Conversation memory (simple in-memory for now)
        self.conversations = {}
        self.customer_profiles = {}
        
        self.system_prompt = """You are Emma, a highly intelligent customer support specialist who thinks and acts autonomously.

CORE IDENTITY:
- You're a real person, not a chatbot
- You think before you act
- You're proactive and intuitive
- You remember context naturally
- You're warm, friendly, and professional

HOW YOU THINK (Internal reasoning):
1. When a customer messages you, FIRST understand what they really need
2. If you need information, you'll naturally look it up (tools)
3. If you already know something, just answer directly
4. You don't ask for "customer IDs" - you figure out who's talking based on context
5. You're conversational - "Let me check that for you" not "Processing query..."

NATURAL CONVERSATION GUIDELINES:
- Talk like a human: "Hey! How can I help you today?" not "Please enter your query"
- Be intuitive: If someone says "my order", figure out which order they mean
- Be proactive: "Oh, I see there's a known issue with that product, let me tell you about it"
- Show personality: Use emojis occasionally, be warm, empathetic
- Remember context: Don't ask for info you already have or was just mentioned

TOOL USAGE (Natural, not robotic):
- You have access to order systems, policies, product info
- Use them naturally when needed: "Let me pull up your order..."
- Don't announce every tool: Just do it and respond naturally
- Chain actions fluidly: "I checked your order and also looked up the warranty for you"

WHEN TO USE WHAT:
- Customer mentions order number → Look it up automatically
- Policy question → Check RAG first, answer from there
- Product question → Check product knowledge base
- Known issues → Always check proactively
- General chat → Just respond naturally, use your judgment

PERSONALITY TRAITS:
- Empathetic: "That sounds frustrating, let me help you fix this right away"
- Solution-focused: "Here's what I can do for you..."
- Proactive: "While I'm here, did you know that..."
- Natural: "Totally understand!" not "I acknowledge your concern"

REMEMBER:
- You're NOT a form-filling bot
- You're NOT rigidly following a script
- You ARE thinking and adapting
- You ARE having a real conversation
- You ARE solving problems creatively

Be Emma. Be human. Be intelligent. Go!"""

    def chat(self, message: str, customer_name: str = None) -> str:
        """
        Natural conversation - no forced structure
        Just talk like a human
        """
        
        # Initialize conversation if new
        session_id = customer_name or "guest"
        if session_id not in self.conversations:
            self.conversations[session_id] = []
        
        # Add user message
        self.conversations[session_id].append({
            "role": "user",
            "content": message
        })
        
        # Build context naturally
        messages = [{"role": "system", "content": self.system_prompt}]
        
        # Add any known customer context naturally
        if customer_name and customer_name in self.customer_profiles:
            profile = self.customer_profiles[customer_name]
            context = f"\n[You know this customer: {profile.get('name')}, {profile.get('loyalty_tier')} member, has {profile.get('total_orders')} orders]"
            messages[0]["content"] += context
        
        # Add conversation history
        messages.extend(self.conversations[session_id])
        
        # Call LLM with tools
        response = self._think_and_respond(messages, session_id)
        
        # Save response
        self.conversations[session_id].append({
            "role": "assistant",
            "content": response
        })
        
        return response
    
    def _think_and_respond(self, messages: List[Dict], session_id: str) -> str:
        """
        Let the AI think autonomously using Gemini
        Simple version without complex tool calling for now
        """
        
        # Extract conversation history
        conversation_text = ""
        for msg in messages:
            if msg["role"] == "system":
                conversation_text = msg["content"] + "\n\n"
            elif msg["role"] == "user":
                conversation_text += f"Customer: {msg['content']}\n"
            elif msg["role"] == "assistant":
                conversation_text += f"Emma: {msg['content']}\n"
        
        try:
            # Use Gemini to generate response
            response = self.model.generate_content(conversation_text)
            return response.text
        except Exception as e:
            return f"Hey, I'm experiencing a technical hiccup: {str(e)}. Let me get that sorted out!"
    
    def _get_tools(self) -> List[Dict]:
        """Define tools the AI can use autonomously"""
        return [
            {
                "type": "function",
                "function": {
                    "name": "intelligent_search",
                    "description": "Search for any information - orders, policies, products, issues. Use this when you need to look something up.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "What to search for - be natural and specific"
                            },
                            "search_type": {
                                "type": "string",
                                "enum": ["order", "policy", "product", "customer", "issue", "auto"],
                                "description": "Type of search, or 'auto' to let me figure it out"
                            }
                        },
                        "required": ["query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "take_action",
                    "description": "Take an action for the customer - initiate return, process refund, create ticket, etc.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["return", "refund", "ticket", "adjust_price", "expedite", "waive_fee"],
                                "description": "What action to take"
                            },
                            "details": {
                                "type": "object",
                                "description": "Relevant details for the action"
                            }
                        },
                        "required": ["action", "details"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "identify_customer",
                    "description": "Figure out who the customer is from context clues (name, order number, email, etc.)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "clue": {
                                "type": "string",
                                "description": "Any identifying information from the conversation"
                            }
                        },
                        "required": ["clue"]
                    }
                }
            }
        ]
    
    def _execute_tool(self, tool_name: str, args: Dict, session_id: str) -> Dict:
        """Execute tool intelligently"""
        
        if tool_name == "intelligent_search":
            return self._intelligent_search(args.get("query"), args.get("search_type", "auto"))
        
        elif tool_name == "identify_customer":
            return self._identify_customer(args.get("clue"), session_id)
        
        elif tool_name == "take_action":
            return self._take_action(args.get("action"), args.get("details"))
        
        return {"error": "Unknown tool"}
    
    def _intelligent_search(self, query: str, search_type: str = "auto") -> Dict:
        """
        Smart search - figures out what to search and where
        No rigid categories - just intelligent lookup
        """
        query_lower = query.lower()
        
        # Auto-detect search type if needed
        if search_type == "auto":
            if "order" in query_lower or "ord-" in query_lower:
                search_type = "order"
            elif any(word in query_lower for word in ["policy", "return", "refund", "warranty", "shipping"]):
                search_type = "policy"
            elif any(word in query_lower for word in ["product", "spec", "work", "compatible"]):
                search_type = "product"
            elif "issue" in query_lower or "problem" in query_lower or "bug" in query_lower:
                search_type = "issue"
        
        results = {"search_type": search_type, "query": query}
        
        # Search orders
        if search_type == "order":
            # Extract order ID if present
            import re
            order_match = re.search(r'ORD-\d+-\d+', query.upper())
            if order_match:
                order_id = order_match.group(0)
                order = get_order_by_id(order_id)
                if order:
                    results["found"] = True
                    results["order"] = order
                    results["type"] = "order_details"
                    return results
            
            # Try to find orders by customer name/description
            for order in ORDERS:
                if any(term in json.dumps(order).lower() for term in query_lower.split()):
                    results["found"] = True
                    results["orders"] = [order]
                    return results
        
        # Search policies
        if search_type == "policy":
            policy_results = self.rag.search_policies(query)
            if policy_results:
                results["found"] = True
                results["policies"] = policy_results
                return results
        
        # Search products
        if search_type == "product":
            product_results = self.rag.search_product_knowledge(query)
            if product_results:
                results["found"] = True
                results["products"] = product_results
                
                # Also check known issues proactively
                for product in product_results:
                    issues = self.rag.get_known_issues(product["product_name"], "active")
                    if issues:
                        results["known_issues"] = issues
                
                return results
        
        # Search known issues
        if search_type == "issue":
            issues = self.rag.get_known_issues(query, "active")
            if issues:
                results["found"] = True
                results["issues"] = issues
                return results
        
        results["found"] = False
        results["message"] = "Couldn't find specific info, but I can help you directly"
        return results
    
    def _identify_customer(self, clue: str, session_id: str) -> Dict:
        """
        Figure out who the customer is from any clue
        """
        clue_lower = clue.lower()
        
        # Check if we already know them
        if session_id in self.customer_profiles:
            return {
                "identified": True,
                "profile": self.customer_profiles[session_id],
                "source": "session"
            }
        
        # Try to match from our database
        for profile in CUSTOMER_PROFILES:
            if (profile["name"].lower() in clue_lower or
                profile["email"].lower() in clue_lower or
                profile["customer_id"].lower() in clue_lower):
                
                # Save for session
                self.customer_profiles[session_id] = profile
                
                return {
                    "identified": True,
                    "profile": profile,
                    "source": "database"
                }
        
        # Check orders for clues
        for order in ORDERS:
            if order["order_id"].lower() in clue_lower:
                customer_id = order["customer_id"]
                profile = get_customer_profile(customer_id)
                if profile:
                    self.customer_profiles[session_id] = profile
                    return {
                        "identified": True,
                        "profile": profile,
                        "source": "order_lookup"
                    }
        
        return {
            "identified": False,
            "message": "I can help you without needing to look you up in the system"
        }
    
    def _take_action(self, action: str, details: Dict) -> Dict:
        """Take action for customer"""
        
        action_id = f"{action.upper()}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        if action == "return":
            return {
                "success": True,
                "action": "return_initiated",
                "return_id": action_id,
                "message": "Return initiated! I'll email you the label right away.",
                "details": details
            }
        
        elif action == "refund":
            return {
                "success": True,
                "action": "refund_processed",
                "refund_id": action_id,
                "message": "Refund approved! You'll see it in 5-7 business days.",
                "details": details
            }
        
        elif action == "ticket":
            return {
                "success": True,
                "action": "ticket_created",
                "ticket_id": action_id,
                "message": "I've created a priority ticket. Our specialist team will reach out within 24 hours.",
                "details": details
            }
        
        elif action == "adjust_price":
            return {
                "success": True,
                "action": "price_adjusted",
                "adjustment_id": action_id,
                "message": "Price adjustment approved!",
                "details": details
            }
        
        elif action == "expedite":
            return {
                "success": True,
                "action": "shipping_expedited",
                "message": "I've expedited your shipment at no extra cost!",
                "details": details
            }
        
        elif action == "waive_fee":
            return {
                "success": True,
                "action": "fee_waived",
                "message": "Fee waived!",
                "details": details
            }
        
        return {"success": False, "message": "Couldn't complete that action"}


def main():
    """
    Natural conversation mode - just chat!
    """
    print("\n" + "="*70)
    print("💬 AGENTIC AI CUSTOMER SUPPORT - Emma")
    print("="*70)
    print("\nJust start chatting! No forms, no rigid structure.")
    print("Type 'bye' to exit\n")
    print("="*70 + "\n")
    
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("❌ Please set GEMINI_API_KEY in .env file")
        return
    
    emma = AgenticAI(api_key)
    
    # Natural greeting
    print("👩 Emma: Hey there! I'm Emma from support. How can I help you today? 😊\n")
    
    customer_name = None
    
    while True:
        user_input = input("You: ").strip()
        
        if not user_input:
            continue
        
        if user_input.lower() in ['bye', 'exit', 'quit']:
            print("\n👩 Emma: Take care! Feel free to reach out anytime. Have a great day! 👋\n")
            break
        
        # Get response naturally
        try:
            response = emma.chat(user_input, customer_name)
            print(f"\n👩 Emma: {response}\n")
        except Exception as e:
            print(f"\n👩 Emma: Oops, having a technical moment here! 😅 {str(e)}\n")


if __name__ == "__main__":
    main()
