"""
WhatsApp Integration via Twilio
- Webhook receiver for WhatsApp messages
- Session management
- Natural conversation via phone number
"""

from fastapi import FastAPI, Request, HTTPException
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client
import os
from datetime import datetime, timedelta
import json

from agentic_ai import AgenticAI
from auth_system import AuthSystem

# Initialize
app = FastAPI(title="WhatsApp Integration")
auth_system = AuthSystem()

# Twilio credentials (set in .env)
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_NUMBER = os.getenv("TWILIO_WHATSAPP_NUMBER", "whatsapp:+14155238886")

# Initialize Twilio client
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) if TWILIO_ACCOUNT_SID else None

# Initialize AI
api_key = os.getenv("OPENROUTER_API_KEY")
emma = AgenticAI(api_key) if api_key else None


# ============================================================================
# Session Management for WhatsApp Users
# ============================================================================

class WhatsAppSessionManager:
    """Manage WhatsApp chat sessions"""
    
    def __init__(self):
        self.sessions = {}  # phone_number: {customer_id, last_activity, context}
    
    def get_or_create_session(self, phone_number: str):
        """Get existing session or create new one"""
        
        # Clean up old sessions (> 30 minutes inactive)
        self._cleanup_old_sessions()
        
        if phone_number not in self.sessions:
            # Try to identify customer by phone
            customer_id = self._identify_customer_by_phone(phone_number)
            
            self.sessions[phone_number] = {
                "customer_id": customer_id,
                "phone_number": phone_number,
                "last_activity": datetime.now(),
                "message_count": 0,
                "context": {},
                "authenticated": customer_id is not None
            }
        
        # Update last activity
        self.sessions[phone_number]["last_activity"] = datetime.now()
        self.sessions[phone_number]["message_count"] += 1
        
        return self.sessions[phone_number]
    
    def _identify_customer_by_phone(self, phone_number: str) -> str:
        """
        Try to identify customer by phone number
        In production, this would query your customer database
        """
        # For demo, map some test phone numbers
        phone_map = {
            "+919876543210": "CUST001",  # Rohan Sharma
            "+919876543211": "CUST002",  # Priya Patel
            "+919876543212": "CUST003",  # Amit Kumar
            "+919876543213": "CUST004",  # Sneha Reddy
            "+919876543214": "CUST005",  # Vikram Singh
        }
        
        # Clean phone number (remove whatsapp: prefix)
        clean_phone = phone_number.replace("whatsapp:", "").strip()
        
        return phone_map.get(clean_phone)
    
    def _cleanup_old_sessions(self):
        """Remove sessions inactive for > 30 minutes"""
        timeout = datetime.now() - timedelta(minutes=30)
        
        expired = [
            phone for phone, session in self.sessions.items()
            if session["last_activity"] < timeout
        ]
        
        for phone in expired:
            del self.sessions[phone]
    
    def end_session(self, phone_number: str):
        """End a session"""
        if phone_number in self.sessions:
            del self.sessions[phone_number]


session_manager = WhatsAppSessionManager()


# ============================================================================
# WhatsApp Webhook Handler
# ============================================================================

@app.post("/whatsapp/webhook")
async def whatsapp_webhook(request: Request):
    """
    Twilio WhatsApp webhook handler
    Receives incoming messages from WhatsApp users
    
    Setup in Twilio Console:
    1. Go to WhatsApp Sandbox settings
    2. Set webhook URL: https://your-domain.com/whatsapp/webhook
    3. Set HTTP method: POST
    """
    
    # Parse form data from Twilio
    form_data = await request.form()
    
    # Extract message details
    from_number = form_data.get("From")  # Format: whatsapp:+1234567890
    to_number = form_data.get("To")  # Your Twilio number
    message_body = form_data.get("Body")
    message_sid = form_data.get("MessageSid")
    
    print(f"\n{'='*70}")
    print(f"📱 WhatsApp Message Received")
    print(f"{'='*70}")
    print(f"From: {from_number}")
    print(f"Message: {message_body}")
    print(f"SID: {message_sid}")
    print(f"{'='*70}\n")
    
    # Get or create session
    session = session_manager.get_or_create_session(from_number)
    
    # Check if AI agent is available
    if not emma:
        response_text = "Sorry, the support system is currently unavailable. Please try again later."
        return _send_whatsapp_response(response_text)
    
    # Special commands
    if message_body.lower() in ["/start", "/hello", "hi", "hello"]:
        customer_id = session.get("customer_id")
        
        if customer_id:
            response_text = (
                f"👋 Welcome back! I'm Emma, your customer support assistant.\n\n"
                f"I can help you with:\n"
                f"• Order status & tracking\n"
                f"• Returns & exchanges\n"
                f"• Product information\n"
                f"• Technical support\n"
                f"• And much more!\n\n"
                f"Just tell me what you need help with! 😊"
            )
        else:
            response_text = (
                f"👋 Hello! I'm Emma, your customer support assistant.\n\n"
                f"I couldn't automatically identify your account. Could you please provide:\n"
                f"• Your order number, or\n"
                f"• Your email address, or\n"
                f"• Your customer ID\n\n"
                f"This will help me assist you better!"
            )
        
        return _send_whatsapp_response(response_text)
    
    elif message_body.lower() == "/end":
        session_manager.end_session(from_number)
        response_text = "👋 Thanks for chatting! Feel free to message anytime you need help."
        return _send_whatsapp_response(response_text)
    
    elif message_body.lower() == "/help":
        response_text = (
            "🤖 **Available Commands:**\n\n"
            "/start - Start conversation\n"
            "/end - End conversation\n"
            "/help - Show this help\n\n"
            "Or just ask me anything!"
        )
        return _send_whatsapp_response(response_text)
    
    # Process message with AI
    try:
        # Get AI response
        ai_response = emma.chat(
            message=message_body,
            customer_name=session.get("customer_id")
        )
        
        # Log the interaction
        _log_whatsapp_interaction(
            phone_number=from_number,
            customer_id=session.get("customer_id"),
            message=message_body,
            response=ai_response,
            success=True
        )
        
        # Send response via Twilio
        return _send_whatsapp_response(ai_response)
    
    except Exception as e:
        print(f"❌ Error processing message: {e}")
        
        # Log error
        _log_whatsapp_interaction(
            phone_number=from_number,
            customer_id=session.get("customer_id"),
            message=message_body,
            response=str(e),
            success=False
        )
        
        error_response = (
            "😓 Sorry, I encountered an error processing your message. "
            "Please try again or contact support directly."
        )
        return _send_whatsapp_response(error_response)


def _send_whatsapp_response(message: str) -> str:
    """
    Create Twilio WhatsApp response
    Returns TwiML response
    """
    response = MessagingResponse()
    response.message(message)
    return str(response)


def _log_whatsapp_interaction(
    phone_number: str,
    customer_id: str,
    message: str,
    response: str,
    success: bool
):
    """Log WhatsApp interaction"""
    try:
        import sqlite3
        conn = sqlite3.connect("customer_memory.db")
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, resource_type, resource_id, success, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            customer_id or "unknown",
            "whatsapp_message",
            "whatsapp",
            phone_number,
            success,
            json.dumps({
                "message": message[:100],
                "response": response[:100]
            }),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging interaction: {e}")


# ============================================================================
# Webhook Verification (Twilio GET request)
# ============================================================================

@app.get("/whatsapp/webhook")
async def whatsapp_webhook_verify():
    """
    Twilio webhook verification endpoint
    """
    return {"status": "active", "service": "WhatsApp Integration"}


# ============================================================================
# Status & Testing Endpoints
# ============================================================================

@app.get("/")
def root():
    """Health check"""
    return {
        "status": "online",
        "service": "WhatsApp Integration",
        "twilio_configured": twilio_client is not None,
        "ai_configured": emma is not None,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/whatsapp/sessions")
def get_active_sessions():
    """Get active WhatsApp sessions (for monitoring)"""
    sessions = []
    
    for phone, session_data in session_manager.sessions.items():
        sessions.append({
            "phone": phone[-4:] + "****",  # Masked for privacy
            "customer_id": session_data.get("customer_id"),
            "authenticated": session_data.get("authenticated"),
            "message_count": session_data.get("message_count"),
            "last_activity": session_data["last_activity"].isoformat()
        })
    
    return {
        "active_sessions": len(sessions),
        "sessions": sessions
    }


@app.post("/whatsapp/send")
async def send_whatsapp_message(
    to_phone: str,
    message: str
):
    """
    Send outbound WhatsApp message (for notifications)
    
    Example:
    POST /whatsapp/send
    {
        "to_phone": "+919876543210",
        "message": "Your order has been shipped!"
    }
    """
    
    if not twilio_client:
        raise HTTPException(status_code=503, detail="Twilio not configured")
    
    try:
        # Format phone number
        if not to_phone.startswith("whatsapp:"):
            to_phone = f"whatsapp:{to_phone}"
        
        # Send message
        message = twilio_client.messages.create(
            from_=TWILIO_WHATSAPP_NUMBER,
            to=to_phone,
            body=message
        )
        
        return {
            "success": True,
            "message_sid": message.sid,
            "status": message.status
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Run Server
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("="*70)
    print("📱 Starting WhatsApp Integration Server")
    print("="*70)
    print("\n⚙️  Configuration:")
    print(f"   Twilio Configured: {twilio_client is not None}")
    print(f"   AI Agent Ready: {emma is not None}")
    print(f"   WhatsApp Number: {TWILIO_WHATSAPP_NUMBER}")
    print("\n📍 Endpoints:")
    print("   - POST /whatsapp/webhook - Receive messages")
    print("   - GET /whatsapp/webhook - Webhook verification")
    print("   - GET /whatsapp/sessions - Active sessions")
    print("   - POST /whatsapp/send - Send message")
    print("\n🔧 Setup Instructions:")
    print("   1. Set environment variables in .env:")
    print("      TWILIO_ACCOUNT_SID=your_account_sid")
    print("      TWILIO_AUTH_TOKEN=your_auth_token")
    print("      TWILIO_WHATSAPP_NUMBER=whatsapp:+14155238886")
    print("   2. Configure webhook in Twilio Console:")
    print("      https://your-domain.com/whatsapp/webhook")
    print("   3. Test in WhatsApp Sandbox first")
    print("\n" + "="*70 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8001)
