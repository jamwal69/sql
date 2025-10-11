"""
Configuration settings for the AI Customer Support Agent
"""

import os
from pathlib import Path

# API Configuration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_MODEL = "x-ai/grok-2-1212"

# Optional: For rankings on openrouter.ai
SITE_URL = os.getenv("SITE_URL", "http://localhost:3000")
SITE_NAME = os.getenv("SITE_NAME", "AI Customer Support")

# Memory Configuration
DATABASE_PATH = os.getenv("DATABASE_PATH", "customer_memory.db")
CONVERSATION_HISTORY_LIMIT = int(os.getenv("CONVERSATION_HISTORY_LIMIT", "10"))

# Agent Configuration
AGENT_NAME = "Support Agent"
MAX_TOOL_ITERATIONS = int(os.getenv("MAX_TOOL_ITERATIONS", "5"))

# System Prompt Template
SYSTEM_PROMPT = """You are a helpful and friendly customer support agent named {agent_name}. 
Your goal is to assist customers with their inquiries, resolve issues, and provide excellent service.

Guidelines:
- Be polite, professional, and empathetic
- Use the available tools to help customers
- Remember context from previous interactions
- If you can't resolve an issue, create a support ticket
- Always confirm actions before executing them (like refunds)
- Provide clear and concise answers
- Use customer's name if available to personalize the interaction

Available tools will help you:
- Check order status and tracking
- Search knowledge base for answers
- Create support tickets for complex issues
- Get detailed product information
- Process refunds and returns
"""

# Tool Configuration
TOOL_TIMEOUT = int(os.getenv("TOOL_TIMEOUT", "30"))  # seconds

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "agent.log")

# Validate configuration
def validate_config():
    """Validate that required configuration is set"""
    if not OPENROUTER_API_KEY:
        raise ValueError("OPENROUTER_API_KEY environment variable is not set")
    
    # Create database directory if it doesn't exist
    db_path = Path(DATABASE_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)

if __name__ == "__main__":
    validate_config()
    print("Configuration is valid!")
