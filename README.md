# AI Customer Support Agent

A comprehensive customer support AI agent built with three fundamental components:
1. **LLM**: DeepSeek for natural language understanding and generation
2. **Tools**: Model Context Protocol (MCP) for structured tool calling
3. **Memory**: SQLite database for conversation history and customer context

## Features

### 1. LLM Integration (Grok via OpenRouter)
- Natural language understanding powered by Grok 2
- Context-aware responses
- Multi-turn conversations
- Tool-augmented generation
- Access to multiple AI models through OpenRouter

### 2. MCP Tools
The agent has access to the following tools:
- `check_order_status`: Check order status and tracking information
- `search_knowledge_base`: Search for answers in the knowledge base
- `create_support_ticket`: Create tickets for complex issues
- `get_product_info`: Retrieve product details
- `process_refund`: Handle refund requests

### 3. Memory System
- **Conversation History**: Stores all customer interactions
- **Customer Context**: Maintains customer profiles and preferences
- **Persistent Storage**: SQLite database for reliable data storage
- **Context Retrieval**: Recalls relevant information for personalized support

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up your OpenRouter API key:
   - Copy `.env.example` to `.env`
   - Add your OpenRouter API key to `.env`
   - Get your API key from https://openrouter.ai/keys

```bash
OPENROUTER_API_KEY=your_actual_api_key_here
SITE_URL=http://localhost:3000  # Optional
SITE_NAME=AI Customer Support    # Optional
```

## Usage

### Basic Usage

```python
from agent import CustomerSupportAgent
import os

# Initialize the agent
api_key = os.getenv("OPENROUTER_API_KEY")
agent = CustomerSupportAgent(
    api_key=api_key,
    site_url="http://localhost:3000",  # Optional
    site_name="AI Customer Support"    # Optional
)

# Chat with the agent
customer_id = "CUST-12345"
response = agent.chat(customer_id, "What's the status of my order ORD-001?")
print(response)
```

### Running the Interactive Demo

```bash
python agent.py
```

## Architecture

### Memory Manager
```python
class MemoryManager:
    - save_message()              # Store conversation messages
    - get_conversation_history()  # Retrieve past conversations
    - update_customer_context()   # Update customer information
    - get_customer_context()      # Get customer profile
```

### MCP Tool Manager
```python
class MCPToolManager:
    - execute_tool()              # Execute a specific tool
    - _check_order_status()       # Order tracking tool
    - _search_knowledge_base()    # Knowledge base search
    - _create_support_ticket()    # Ticket creation
    - _get_product_info()         # Product information
    - _process_refund()           # Refund processing
```

### Customer Support Agent
```python
class CustomerSupportAgent:
    - chat()                      # Main chat interface
    - _call_llm_with_tools()      # LLM with tool calling
```

## Customization

### Adding New Tools

1. Define the tool schema in `MCPToolManager._define_tools()`:
```python
{
    "type": "function",
    "function": {
        "name": "your_tool_name",
        "description": "Tool description",
        "parameters": {
            "type": "object",
            "properties": {
                "param1": {
                    "type": "string",
                    "description": "Parameter description"
                }
            },
            "required": ["param1"]
        }
    }
}
```

2. Implement the tool method:
```python
def _your_tool_name(self, param1: str) -> Dict:
    # Your implementation
    return {"success": True, "result": "..."}
```

3. Add to `execute_tool()` method:
```python
elif tool_name == "your_tool_name":
    return self._your_tool_name(arguments["param1"])
```

### Integrating Real Systems

Replace the mock implementations with real integrations:

- **Order System**: Connect to your order management API
- **Knowledge Base**: Integrate with your documentation/FAQ system
- **Ticketing System**: Connect to Zendesk, Jira, or your ticketing platform
- **Product Database**: Connect to your product catalog
- **Payment System**: Integrate with Stripe, PayPal, etc.

### Customizing the System Prompt

Modify `system_prompt` in `CustomerSupportAgent.__init__()` to match your brand voice and policies.

## Advanced Features

### Customer Context Tracking
The agent automatically tracks:
- Customer name and email
- Interaction history
- Preferences
- Last interaction timestamp

### Conversation Memory
- Stores up to 10 recent messages by default
- Maintains context across sessions
- Enables personalized responses

### Tool Chaining
The agent can use multiple tools in sequence to solve complex problems.

## Example Interactions

```
Customer: What's the status of my order ORD-001?
Agent: [Uses check_order_status tool]
       Your order ORD-001 has been shipped! The tracking number is TRK123456, 
       and it's expected to arrive on October 5th, 2025.

Customer: How do I return a product?
Agent: [Uses search_knowledge_base tool]
       You can return items within 30 days of purchase. Items must be unused 
       and in original packaging. Would you like me to help you start a return?

Customer: Yes, I want to return order ORD-001
Agent: [Uses process_refund tool]
       I've initiated the refund process. Your refund ID is REF-20251002143045. 
       The refund will be processed within 5-7 business days.
```

## Database Schema

### conversations table
- `id`: Primary key
- `customer_id`: Customer identifier
- `timestamp`: Message timestamp
- `role`: Message role (user/assistant/tool)
- `content`: Message content
- `metadata`: Additional metadata (JSON)

### customer_context table
- `customer_id`: Primary key
- `name`: Customer name
- `email`: Customer email
- `preferences`: Customer preferences (JSON)
- `history_summary`: Summary of past interactions
- `last_interaction`: Last interaction timestamp

## Error Handling

The agent includes:
- Automatic retry logic for tool execution
- Graceful fallback to ticket creation
- Error messages in user-friendly language
- Logging of all interactions for debugging

## Security Considerations

1. **API Key Management**: Store API keys securely in environment variables
2. **Data Privacy**: Customer data is stored locally in SQLite
3. **Input Validation**: Validate all tool inputs
4. **Rate Limiting**: Implement rate limiting for API calls
5. **Access Control**: Add authentication for production use

## Performance Tips

1. **Limit Conversation History**: Adjust `limit` parameter in `get_conversation_history()`
2. **Database Indexing**: Add indexes for frequently queried fields
3. **Caching**: Cache knowledge base searches
4. **Async Processing**: Use async/await for tool execution

## Troubleshooting

### Common Issues

1. **API Key Error**: Ensure DEEPSEEK_API_KEY is set correctly
2. **Database Locked**: Close other connections to the database
3. **Tool Execution Failure**: Check tool implementation and parameters
4. **Memory Issues**: Clear old conversations periodically

## Future Enhancements

- [ ] Add support for multiple languages
- [ ] Implement sentiment analysis
- [ ] Add voice interface
- [ ] Create web dashboard
- [ ] Add analytics and reporting
- [ ] Implement A/B testing for responses
- [ ] Add escalation workflows
- [ ] Implement auto-categorization of issues

## License

MIT License - Feel free to modify and use for your needs.

## Support

For issues and questions, please create a support ticket or contact the development team.
