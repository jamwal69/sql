# 🚀 Quick Start Guide

Complete guide to deploy your AI Customer Support system with website and WhatsApp integration.

---

## 📋 Prerequisites

- Python 3.11+
- Docker & Docker Compose (for production)
- OpenRouter API Key (for AI)
- Twilio Account (for WhatsApp)
- Domain name (optional, for production)

---

## ⚡ Quick Setup (5 Minutes)

### 1. Install Dependencies

```powershell
# Install Python packages
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Create `.env` file:

```env
# AI Configuration
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Security
JWT_SECRET=your_super_secret_jwt_key_change_this_in_production

# Twilio (for WhatsApp)
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_WHATSAPP_NUMBER=whatsapp:+14155238886
```

### 3. Initialize Database

```powershell
# Run migration to set up database
python migrate_db.py
```

### 4. Test the Agent (Optional)

```powershell
# Test the agentic AI locally
python agentic_ai.py
```

---

## 🌐 Method 1: Website Integration (FastAPI)

### Start the API Server

```powershell
# Start main API server
python api_server.py
```

Server will run at: `http://localhost:8000`

### Open the Chat Widget

1. Open `chat_widget.html` in your browser
2. Or visit: `http://localhost:8000` (when integrated)

### Test the API

```powershell
# Health check
curl http://localhost:8000/health

# Register user
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "rohan@example.com",
    "password": "securepassword",
    "name": "Rohan Sharma",
    "phone": "+919876543210"
  }'

# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "rohan@example.com",
    "password": "securepassword"
  }'

# Chat (use token from login response)
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"message": "Where is my order?"}'
```

### API Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/health` | GET | Health check | No |
| `/auth/register` | POST | Register user | No |
| `/auth/login` | POST | Login | No |
| `/auth/me` | GET | Current user | Yes |
| `/chat` | POST | Send message | Yes |
| `/ws/chat` | WS | WebSocket chat | Yes (token param) |
| `/orders` | GET | Get your orders | Yes |
| `/orders/{id}` | GET | Get specific order | Yes |
| `/admin/audit-log` | GET | Audit log | Admin only |

---

## 📱 Method 2: WhatsApp Integration

### Setup Twilio

1. **Create Twilio Account**: https://www.twilio.com/try-twilio
2. **Get WhatsApp Sandbox**: Console → Messaging → Try it out → WhatsApp
3. **Save credentials** in `.env` file

### Start WhatsApp Server

```powershell
python whatsapp_integration.py
```

Server will run at: `http://localhost:8001`

### Configure Webhook

1. **Expose local server** (for testing):
   ```powershell
   # Using ngrok
   ngrok http 8001
   ```

2. **Set webhook in Twilio**:
   - Go to: Console → Messaging → Settings → WhatsApp Sandbox Settings
   - Webhook URL: `https://your-ngrok-url.ngrok.io/whatsapp/webhook`
   - Method: POST

### Test WhatsApp

1. **Join sandbox**: Send code to Twilio WhatsApp number
2. **Start chatting**: 
   ```
   Hi
   Where is my order?
   I want to return my product
   ```

### WhatsApp Commands

- `/start` - Start conversation
- `/end` - End conversation
- `/help` - Show help
- Any natural message - Talk to AI

---

## 🐳 Method 3: Docker Deployment (Production)

### Build and Run

```powershell
# Build and start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Services

- **API Server**: http://localhost:8000
- **WhatsApp Server**: http://localhost:8001
- **Nginx (Frontend)**: http://localhost:80
- **Chat Widget**: http://localhost/

### Docker Commands

```powershell
# Rebuild after code changes
docker-compose up -d --build

# View specific service logs
docker-compose logs -f api-server

# Restart service
docker-compose restart api-server

# Execute command in container
docker-compose exec api-server python migrate_db.py
```

---

## 🔒 Security Features

### Authentication

- **JWT Tokens**: 24-hour expiry
- **Bcrypt Password Hashing**: Industry-standard encryption
- **Session Management**: Track all active sessions

### Role-Based Access Control (RBAC)

| Role | Permissions |
|------|-------------|
| **Customer** | View own orders, chat with AI |
| **Support Agent** | View all customer data, manage tickets |
| **Admin** | All support agent permissions + user management |
| **Owner** | Full system access, analytics |

### Data Access Control

```python
# Customers can only see their own data
GET /orders → Only Rohan's orders (if logged in as Rohan)

# Attempting to access other's orders
GET /orders/ORD002 → 403 Forbidden (if not Rohan's order)

# Admins see everything
GET /orders → All orders (if logged in as admin)
```

### Security Best Practices

1. **Environment Variables**: Never commit `.env` file
2. **HTTPS**: Use SSL certificates in production
3. **Rate Limiting**: Prevent API abuse (configured in nginx.conf)
4. **Input Validation**: All inputs validated with Pydantic
5. **Audit Logging**: All actions logged to database

---

## 🧪 Testing

### Test User Accounts

Create test accounts:

```powershell
# Rohan (Customer)
POST /auth/register
{
  "email": "rohan@example.com",
  "password": "test123",
  "name": "Rohan Sharma",
  "phone": "+919876543210"
}

# Priya (Customer)
POST /auth/register
{
  "email": "priya@example.com",
  "password": "test123",
  "name": "Priya Patel",
  "phone": "+919876543211"
}
```

### Test Scenarios

1. **Login as Rohan**: Should see only Rohan's orders
2. **Login as Priya**: Should see only Priya's orders
3. **Try to access Rohan's order as Priya**: Should get 403 Forbidden
4. **Chat**: Both can chat with AI agent

### Run Automated Tests

```powershell
# Run test scenarios
python test_runner.py
```

---

## 🌍 Production Deployment

### Option 1: Cloud VPS (DigitalOcean, AWS, Azure)

1. **Set up server**:
   ```bash
   # Update system
   sudo apt update && sudo apt upgrade -y
   
   # Install Docker
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   
   # Install Docker Compose
   sudo apt install docker-compose -y
   ```

2. **Upload code**:
   ```bash
   scp -r . user@your-server:/app
   ```

3. **Configure domain**:
   - Point DNS to your server IP
   - Update nginx.conf with your domain

4. **Get SSL certificate** (Let's Encrypt):
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d yourdomain.com
   ```

5. **Start services**:
   ```bash
   cd /app
   docker-compose up -d
   ```

### Option 2: Cloud Functions (Serverless)

1. **AWS Lambda + API Gateway**
2. **Google Cloud Functions**
3. **Azure Functions**

### Option 3: Platform-as-a-Service

1. **Heroku**: Deploy with git push
2. **Railway**: Connect GitHub repo
3. **Render**: Auto-deploy from GitHub

---

## 🔧 Configuration

### Customize AI Agent

Edit `agentic_ai.py`:

```python
# Change AI model
self.model = "x-ai/grok-beta"  # Different model

# Change temperature (creativity)
temperature=0.7  # Default

# Add more tools
def _new_tool(self, query):
    # Your custom tool
    pass
```

### Customize Chat Widget

Edit `chat_widget.html`:

```javascript
// Change colors
background: linear-gradient(135deg, #YOUR_COLOR 0%, #YOUR_COLOR 100%);

// Change API URL
const API_BASE_URL = 'https://your-domain.com';

// Add custom features
```

### Add More Policies

Edit `rag_system.py`:

```python
# Add new policy
conn.execute("""
    INSERT INTO policies VALUES (?, ?, ?, ?)
""", (
    "POL011",
    "Your New Policy",
    "Policy description...",
    "full_text"
))
```

---

## 📊 Monitoring

### View Audit Logs

```powershell
# Via API (as admin)
curl http://localhost:8000/admin/audit-log \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

### Check Active Sessions

```powershell
# WhatsApp sessions
curl http://localhost:8001/whatsapp/sessions
```

### Database Queries

```powershell
# Connect to database
sqlite3 customer_memory.db

# View recent conversations
SELECT * FROM conversations ORDER BY timestamp DESC LIMIT 10;

# View audit log
SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 20;

# View user activity
SELECT user_id, COUNT(*) as actions 
FROM audit_log 
GROUP BY user_id 
ORDER BY actions DESC;
```

---

## 🐛 Troubleshooting

### Issue: "Module not found"

```powershell
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Issue: "Database locked"

```powershell
# Close all connections and restart
rm customer_memory.db
python migrate_db.py
```

### Issue: "WebSocket connection failed"

- Check if server is running: `http://localhost:8000/health`
- Check browser console for errors
- Verify token is valid: `GET /auth/me`

### Issue: "WhatsApp webhook not receiving messages"

1. Check ngrok is running: `ngrok http 8001`
2. Verify webhook URL in Twilio console
3. Check server logs: `docker-compose logs -f whatsapp-server`
4. Test webhook manually:
   ```powershell
   curl -X POST http://localhost:8001/whatsapp/webhook \
     -d "From=whatsapp:+1234567890" \
     -d "Body=Test message"
   ```

### Issue: "401 Unauthorized"

- Token expired: Login again
- Invalid token: Check Authorization header format
- No token: Include `Authorization: Bearer YOUR_TOKEN`

---

## 📚 Next Steps

1. **Add more test data**: Edit `test_data.py`
2. **Customize policies**: Edit `rag_system.py`
3. **Add analytics**: Create dashboard
4. **Integrate payment**: Add payment processing tools
5. **Multi-language**: Add translation support
6. **Voice support**: Add speech-to-text
7. **Mobile app**: Create React Native app

---

## 💡 Tips

### Performance

- Use Redis for caching (add to docker-compose.yml)
- Use PostgreSQL instead of SQLite for production
- Enable CDN for static files
- Use load balancer for multiple instances

### Scalability

- Horizontal scaling with Kubernetes
- Message queue (RabbitMQ/Redis) for async tasks
- Separate read/write database replicas
- Microservices architecture

### Cost Optimization

- Use free-tier services initially
- Monitor API usage (OpenRouter)
- Implement caching to reduce AI calls
- Use reserved instances for predictable workload

---

## 📞 Support

### Documentation

- `README.md` - Overview
- `DEPLOYMENT_GUIDE.md` - Detailed deployment
- `MEMORY_EXPLAINED.md` - Memory system explanation
- `AGENTIC_EXPLAINED.md` - Agentic AI concepts

### Testing

- `test_runner.py` - Interactive test scenarios
- `test_data.py` - Test data and scenarios
- `example_usage.py` - Basic usage examples

### Need Help?

- Check logs: `docker-compose logs -f`
- Review audit log: `GET /admin/audit-log`
- Test health: `GET /health`

---

## ✅ Success Checklist

- [ ] Installed all dependencies
- [ ] Created `.env` file with API keys
- [ ] Ran database migration
- [ ] Tested API server (`http://localhost:8000/health`)
- [ ] Tested chat widget in browser
- [ ] Registered test user accounts
- [ ] Verified RBAC (Rohan sees only his data)
- [ ] Set up Twilio WhatsApp sandbox
- [ ] Tested WhatsApp integration
- [ ] Deployed to production (optional)
- [ ] Configured SSL certificates (production)
- [ ] Set up monitoring and alerts (production)

---

**🎉 Congratulations! Your AI Customer Support system is ready!**

Your customers can now:
- Chat via website (chat_widget.html)
- Chat via WhatsApp (Twilio integration)
- Securely access only their own data
- Get instant AI-powered support 24/7

Your staff can:
- Monitor all conversations
- Access customer history
- View audit logs
- Manage system settings
