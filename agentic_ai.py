"""
TRUE AGENTIC AI - Natural Conversational Customer Support
- No forced inputs or rigid flows
- Autonomous decision making
- Natural human-like conversation
- Intelligent tool usage
"""

import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import google.generativeai as genai

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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
        
        # Configuration constants
        self.MAX_CONVERSATION_HISTORY = 10  # Only keep last 10 messages for context
        self.MAX_CONVERSATION_LENGTH = 50   # Max total messages before cleanup
        
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
            logger.info(f"New conversation started for session: {session_id}")
        
        # Cleanup old conversations if too long (prevent memory issues)
        if len(self.conversations[session_id]) > self.MAX_CONVERSATION_LENGTH:
            # Keep only the most recent messages
            logger.info(f"Cleaning up conversation for {session_id}: {len(self.conversations[session_id])} messages")
            self.conversations[session_id] = self.conversations[session_id][-self.MAX_CONVERSATION_LENGTH:]
        
        # Add user message
        self.conversations[session_id].append({
            "role": "user",
            "content": message
        })
        logger.debug(f"User message added for {session_id}: {message[:50]}...")
        
        # Build context naturally
        messages = [{"role": "system", "content": self.system_prompt}]
        
        # Add any known customer context naturally
        if customer_name and customer_name in self.customer_profiles:
            profile = self.customer_profiles[customer_name]
            context = f"\n[You know this customer: {profile.get('name')}, {profile.get('loyalty_tier')} member, has {profile.get('total_orders')} orders]"
            messages[0]["content"] += context
            logger.debug(f"Customer profile added for {customer_name}")
        
        # Add conversation history (only recent messages to save tokens)
        recent_conversation = self.conversations[session_id][-self.MAX_CONVERSATION_HISTORY:]
        messages.extend(recent_conversation)
        logger.debug(f"Using {len(recent_conversation)} messages for context")
        
        # Call LLM with tools
        response = self._think_and_respond(messages, session_id)
        
        # Save response
        self.conversations[session_id].append({
            "role": "assistant",
            "content": response
        })
        logger.info(f"Response generated for {session_id}")
        
        return response
    
    def _think_and_respond(self, messages: List[Dict], session_id: str) -> str:
        """
        Let the AI think autonomously using Gemini
        Improved error handling and safety checks
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
            logger.debug(f"Calling Gemini API for session {session_id}")
            # Use Gemini to generate response with safety settings
            response = self.model.generate_content(
                conversation_text,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.7,
                    max_output_tokens=1024,
                ),
            )
            
            # Check if response is valid
            if response and hasattr(response, 'text') and response.text:
                logger.debug(f"Successfully got response from Gemini for {session_id}")
                return response.text
            elif response and response.candidates:
                # Try to extract text from candidates
                logger.debug(f"Extracting text from candidates for {session_id}")
                return response.candidates[0].content.parts[0].text
            else:
                logger.warning(f"Empty response from Gemini for {session_id}")
                return "I'm having trouble processing that right now. Could you rephrase your question?"
                
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Gemini API error for {session_id}: {error_msg}")
            # Better error messages for common issues
            if "API_KEY" in error_msg or "authentication" in error_msg.lower():
                logger.error("Authentication error with Gemini API")
                return "I'm having authentication issues. Please contact support."
            elif "quota" in error_msg.lower() or "rate" in error_msg.lower():
                logger.warning("Rate limit or quota exceeded")
                return "I'm a bit overwhelmed right now. Can you try again in a moment?"
            else:
                return f"Hey, I'm experiencing a technical hiccup. Let me get that sorted out!"


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
