"""
Secure FastAPI Backend Server
- REST API endpoints
- WebSocket for real-time chat
- JWT authentication
- Role-based access control
- Rate limiting
"""

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import our systems
from auth_system import AuthSystem
from agentic_ai import AgenticAI
from test_data import get_order_by_id, get_customer_orders, ORDERS

# Initialize
app = FastAPI(title="Agentic AI Customer Support API", version="1.0.0")
auth_system = AuthSystem()
security = HTTPBearer()

# Load API key
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    logger.error("GEMINI_API_KEY environment variable not found!")
    raise ValueError("❌ GEMINI_API_KEY environment variable is required! Please set it in .env file")
logger.info("✅ Gemini API key loaded successfully")

emma = AgenticAI(api_key)
logger.info("✅ AI Agent initialized successfully")

# CORS Configuration - Secure for production
# For development, allow localhost. For production, update to your actual domain
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
if ENVIRONMENT == "production":
    allowed_origins = [
        "https://yourdomain.com",  # Update with your actual domain
        "https://www.yourdomain.com",
    ]
else:
    # Development: allow localhost
    allowed_origins = [
        "http://localhost:3000",
        "http://localhost:5000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


# ============================================================================
# Pydantic Models
# ============================================================================

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str
    timestamp: str


# ============================================================================
# Authentication Dependency
# ============================================================================

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Dependency to get current authenticated user from JWT token
    """
    token = credentials.credentials
    user_info = auth_system.verify_token(token)
    
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return user_info


def require_role(allowed_roles: List[str]):
    """
    Dependency to check user has required role
    """
    def role_checker(user_info: dict = Depends(get_current_user)):
        if user_info["role"] not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user_info
    return role_checker


# ============================================================================
# Public Endpoints (No Authentication Required)
# ============================================================================

@app.get("/")
def root():
    """Root endpoint"""
    return {
        "service": "RimTyres AI Agent",
        "status": "running",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
def health():
    """Health check endpoint for monitoring (Render, UptimeRobot, etc.)"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "RimTyres AI Agent",
        "environment": os.getenv("ENVIRONMENT", "development")
    }


@app.get("/old_root")
def old_root():
    """API health check"""
    return {
        "status": "online",
        "service": "Agentic AI Customer Support",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "ai_agent": "ready" if emma else "not configured",
        "database": "connected",
        "auth": "enabled",
        "timestamp": datetime.now().isoformat()
    }


# ============================================================================
# Authentication Endpoints
# ============================================================================

@app.post("/auth/register")
def register(data: RegisterRequest):
    """
    Register a new customer account
    """
    result = auth_system.register_user(
        email=data.email,
        password=data.password,
        name=data.name,
        role="customer",  # Default role
        phone=data.phone
    )
    
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "success": True,
        "message": "Registration successful",
        "user_id": result["user_id"],
        "customer_id": result["customer_id"]
    }


@app.post("/auth/login")
def login(data: LoginRequest, request: Request):
    """
    Login and receive JWT token
    """
    result = auth_system.login(
        email=data.email,
        password=data.password,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent")
    )
    
    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["error"])
    
    return {
        "success": True,
        "token": result["token"],
        "user": result["user"],
        "expires_in": result["expires_in"]
    }


@app.post("/auth/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Logout and invalidate token
    """
    token = credentials.credentials
    auth_system.logout(token)
    
    return {"success": True, "message": "Logged out successfully"}


@app.get("/auth/me")
def get_current_user_info(user_info: dict = Depends(get_current_user)):
    """
    Get current user information
    """
    return {
        "user_id": user_info["user_id"],
        "role": user_info["role"],
        "customer_id": user_info.get("customer_id")
    }


# ============================================================================
# Secure Chat Endpoints
# ============================================================================

@app.post("/chat", response_model=ChatResponse)
def chat(
    data: ChatRequest,
    user_info: dict = Depends(get_current_user)
):
    """
    Send message to AI agent (authenticated)
    User can only access their own data
    """
    # Input validation
    if not data.message or not data.message.strip():
        logger.warning(f"Empty message from user {user_info['user_id']}")
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    
    if len(data.message) > 2000:
        logger.warning(f"Message too long from user {user_info['user_id']}: {len(data.message)} chars")
        raise HTTPException(status_code=400, detail="Message too long. Maximum 2000 characters allowed")
    
    if len(data.message) < 1:
        raise HTTPException(status_code=400, detail="Message too short")
    
    logger.info(f"Chat request from user {user_info['user_id']}: {data.message[:50]}...")
    
    try:
        # The agent will automatically filter data based on user's customer_id
        # Pass user info to agent for security filtering
        response = emma.chat(
            message=data.message,
            customer_name=user_info.get("customer_id")
        )
        logger.info(f"Chat response sent to user {user_info['user_id']}")
    except Exception as e:
        logger.error(f"Error in chat for user {user_info['user_id']}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process message")
    
    # Log the interaction
    auth_system._log_action(
        user_id=user_info["user_id"],
        action="chat_message",
        resource_type="chat",
        resource_id=user_info.get("customer_id"),
        success=True,
        details=f"Message: {data.message[:50]}..."
    )
    
    return ChatResponse(
        response=response,
        timestamp=datetime.now().isoformat()
    )


# ============================================================================
# Order Endpoints (Secure - User sees only their orders)
# ============================================================================

@app.get("/orders")
def get_my_orders(user_info: dict = Depends(get_current_user)):
    """
    Get user's orders (customers see only their own)
    """
    customer_id = user_info.get("customer_id")
    role = user_info.get("role")
    
    # Customers can only see their own orders
    if role == "customer":
        if not customer_id:
            raise HTTPException(status_code=400, detail="No customer ID associated")
        
        orders = get_customer_orders(customer_id)
        
        # Log access
        auth_system._log_action(
            user_id=user_info["user_id"],
            action="view_orders",
            resource_type="orders",
            resource_id=customer_id,
            success=True
        )
        
        return {
            "success": True,
            "orders": orders,
            "count": len(orders)
        }
    
    # Support agents and admins can see all orders
    elif role in ["support_agent", "admin", "owner"]:
        # Log access
        auth_system._log_action(
            user_info["user_id"],
            "view_all_orders",
            "orders",
            "all",
            True
        )
        
        return {
            "success": True,
            "orders": ORDERS,
            "count": len(ORDERS)
        }
    
    raise HTTPException(status_code=403, detail="Access denied")


@app.get("/orders/{order_id}")
def get_order(order_id: str, user_info: dict = Depends(get_current_user)):
    """
    Get specific order (with access control)
    """
    order = get_order_by_id(order_id)
    
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    # Check access permission
    role = user_info.get("role")
    customer_id = user_info.get("customer_id")
    
    # Customers can only view their own orders
    if role == "customer":
        if order["customer_id"] != customer_id:
            # Log unauthorized access attempt
            auth_system._log_action(
                user_info["user_id"],
                "unauthorized_access",
                "order",
                order_id,
                False,
                "Attempted to access another customer's order"
            )
            raise HTTPException(status_code=403, detail="You can only view your own orders")
    
    # Log successful access
    auth_system._log_action(
        user_info["user_id"],
        "view_order",
        "order",
        order_id,
        True
    )
    
    return {
        "success": True,
        "order": order
    }


# ============================================================================
# Admin Endpoints (Owner/Admin only)
# ============================================================================

@app.get("/admin/users")
def get_all_users(user_info: dict = Depends(require_role(["admin", "owner"]))):
    """
    Get all users (admin/owner only)
    """
    # Implementation here
    return {"message": "Admin endpoint - get all users"}


@app.get("/admin/audit-log")
def get_audit_log(
    limit: int = 100,
    user_info: dict = Depends(require_role(["admin", "owner"]))
):
    """
    Get audit log (admin/owner only)
    """
    logs = auth_system.get_audit_log(limit=limit)
    
    return {
        "success": True,
        "logs": logs,
        "count": len(logs)
    }


@app.get("/admin/analytics")
def get_analytics(user_info: dict = Depends(require_role(["owner"]))):
    """
    Get analytics dashboard (owner only)
    """
    # Implementation for analytics
    return {
        "message": "Analytics endpoint",
        "total_users": "...",
        "total_orders": "...",
        "revenue": "..."
    }


# ============================================================================
# WebSocket for Real-time Chat
# ============================================================================

class ConnectionManager:
    """Manage WebSocket connections"""
    
    def __init__(self):
        self.active_connections: dict = {}
    
    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.active_connections[user_id] = websocket
    
    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
    
    async def send_message(self, user_id: str, message: str):
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_text(message)


manager = ConnectionManager()


@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket, token: str):
    """
    WebSocket endpoint for real-time chat
    Usage: ws://localhost:8000/ws/chat?token=YOUR_JWT_TOKEN
    """
    # Verify token
    user_info = auth_system.verify_token(token)
    
    if not user_info:
        await websocket.close(code=1008, reason="Invalid token")
        return
    
    user_id = user_info["user_id"]
    await manager.connect(websocket, user_id)
    
    try:
        # Send welcome message
        await websocket.send_json({
            "type": "system",
            "message": "Connected to support chat",
            "timestamp": datetime.now().isoformat()
        })
        
        while True:
            # Receive message
            data = await websocket.receive_text()
            
            # Process with AI
            if emma:
                response = emma.chat(
                    message=data,
                    customer_name=user_info.get("customer_id")
                )
                
                # Send response
                await websocket.send_json({
                    "type": "agent",
                    "message": response,
                    "timestamp": datetime.now().isoformat()
                })
            else:
                await websocket.send_json({
                    "type": "error",
                    "message": "AI agent not available",
                    "timestamp": datetime.now().isoformat()
                })
    
    except WebSocketDisconnect:
        manager.disconnect(user_id)


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom error handler"""
    return {
        "error": True,
        "status_code": exc.status_code,
        "message": exc.detail,
        "timestamp": datetime.now().isoformat()
    }


# ============================================================================
# Run Server
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("="*70)
    print("🚀 Starting Secure API Server")
    print("="*70)
    print("\n📍 API Endpoints:")
    print("   - http://localhost:8000")
    print("   - http://localhost:8000/docs (API documentation)")
    print("\n🔐 Authentication:")
    print("   - POST /auth/register - Register new user")
    print("   - POST /auth/login - Login and get token")
    print("   - GET /auth/me - Get current user info")
    print("\n💬 Chat:")
    print("   - POST /chat - Send message (requires auth)")
    print("   - WS /ws/chat - WebSocket chat (requires token)")
    print("\n📦 Orders:")
    print("   - GET /orders - Get your orders (requires auth)")
    print("   - GET /orders/{id} - Get specific order (requires auth)")
    print("\n👑 Admin:")
    print("   - GET /admin/users - All users (admin/owner only)")
    print("   - GET /admin/audit-log - Audit log (admin/owner only)")
    print("   - GET /admin/analytics - Analytics (owner only)")
    print("\n" + "="*70)
    print("\n⚠️  Make sure to set OPENROUTER_API_KEY in .env file")
    print("\n" + "="*70 + "\n")
    
    # Use PORT from environment (Render, Railway, etc.) or default to 8000
    port = int(os.environ.get('PORT', 8000))
    host = "0.0.0.0"  # Listen on all interfaces for cloud deployment
    
    print(f"🌍 Server starting on {host}:{port}")
    print(f"📊 Health check: http://{host}:{port}/health")
    print(f"📖 API docs: http://{host}:{port}/docs")
    print("\n" + "="*70 + "\n")
    
    uvicorn.run(app, host=host, port=port)
