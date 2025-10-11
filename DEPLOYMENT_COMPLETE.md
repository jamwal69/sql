# ✅ RENDER DEPLOYMENT CHECKLIST - RIMTYRES AI

Use this checklist to deploy your RimTyres AI to Render step-by-step.

---

## 📋 PRE-DEPLOYMENT CHECKLIST

### 1. Test Locally First ✅

```powershell
# Test production config
python production_config.py
# Expected: ✅ Configuration loaded from env_file

# Test Wix connection
python test_wix_connection.py
# Expected: ✅ Wix connection successful!

# Test API server
python api_server.py
# Then visit: http://localhost:8000/health
# Expected: {"status": "healthy"}
```

- [ ] production_config.py works
- [ ] test_wix_connection.py passes
- [ ] api_server.py starts without errors
- [ ] /health endpoint returns "healthy"

---

### 2. Get Wix API Credentials ✅

Go to: **https://dev.wix.com**

1. Sign in with your Wix account
2. Click **"Create App"** or **"My Apps"**
3. Create new app: **"RimTyres AI Agent"**
4. Go to **"API Keys"** tab
5. Copy these 3 values:

- [ ] **API Key** (long JWT token starting with JWS.eyJ...)
- [ ] **Site ID** (your website ID)
- [ ] **Account ID** (your account ID)

**Important**: Set permissions to **READ-ONLY**:
- ✅ Contacts (Read)
- ✅ Orders (Read)
- ✅ Products (Read)
- ❌ NO Write permissions
- ❌ NO Delete permissions

---

### 3. Prepare GitHub Repository ✅

```powershell
# Check .gitignore includes:
# .env
# __pycache__/
# *.pyc

# If not already on GitHub:
git init
git add .
git commit -m "Initial commit - RimTyres AI"

# Create PRIVATE repository on GitHub
# Go to: https://github.com/new
# Name: rimtyres-ai-agent
# Visibility: PRIVATE ⚠️

git remote add origin https://github.com/YOUR-USERNAME/rimtyres-ai-agent.git
git branch -M main
git push -u origin main
```

- [ ] .env is in .gitignore
- [ ] Repository is PRIVATE
- [ ] Code pushed to GitHub

---

## 🚀 DEPLOYMENT STEPS

### Step 1: Create Render Account

1. Go to: **https://render.com**
2. Click **"Get Started for Free"**
3. Sign up with GitHub (recommended)

- [ ] Render account created
- [ ] GitHub connected to Render

---

### Step 2: Create Web Service

1. **Render Dashboard**: https://dashboard.render.com
2. Click **"New +"** → **"Web Service"**
3. Click **"Connect a repository"**
4. Authorize Render (first time)
5. Select: **rimtyres-ai-agent**
6. Click **"Connect"**

- [ ] Repository connected to Render

---

### Step 3: Configure Service

Fill in these settings:

| Field | Value |
|-------|-------|
| **Name** | `rimtyres-ai-agent` |
| **Region** | Choose closest (e.g., Oregon US West) |
| **Branch** | `main` |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `python api_server.py` |
| **Instance Type** | `Free` |

- [ ] All fields configured correctly

---

### Step 4: Add Environment Variables 🔒

**CRITICAL**: Add these 3 environment variables:

Click **"Add Environment Variable"** for each:

#### Variable 1: WIX_API_KEY
```
Key:   WIX_API_KEY
Value: [paste your Wix API key here]
```
⚠️ **Click the LOCK icon** to mark as SECRET!

#### Variable 2: WIX_SITE_ID
```
Key:   WIX_SITE_ID
Value: [paste your Wix site ID here]
```

#### Variable 3: WIX_ACCOUNT_ID
```
Key:   WIX_ACCOUNT_ID
Value: [paste your Wix account ID here]
```

#### Variable 4: ENVIRONMENT (optional)
```
Key:   ENVIRONMENT
Value: production
```

**Double-check**:
- [ ] WIX_API_KEY is marked as **SECRET** (lock icon)
- [ ] All 3 credentials are correct (no spaces, no quotes)
- [ ] Variables saved

---

### Step 5: Configure Advanced Settings

Click **"Advanced"** button:

| Setting | Value |
|---------|-------|
| **Health Check Path** | `/health` |
| **Auto-Deploy** | `Yes` ✅ |

- [ ] Health check path set to `/health`
- [ ] Auto-deploy enabled

---

### Step 6: Deploy! 🚀

1. Click **"Create Web Service"** (bottom of page)
2. Wait 2-3 minutes...
3. Watch deployment logs

**Expected logs**:
```
==> Cloning from https://github.com/...
==> Installing dependencies...
==> Starting service...
✅ Configuration loaded from environment variables
� Server starting on 0.0.0.0:10000
📊 Health check: http://0.0.0.0:10000/health
```

- [ ] Deployment successful (green checkmark)
- [ ] No errors in logs
- [ ] Service shows "Live" status

---

### Step 7: Test Deployment ✅

Your app is now live at: `https://rimtyres-ai-agent.onrender.com`

**Test health endpoint**:

```powershell
# Method 1: Browser
# Open: https://rimtyres-ai-agent.onrender.com/health

# Method 2: PowerShell
curl https://rimtyres-ai-agent.onrender.com/health
```

**Expected response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-10-11T14:30:00",
  "service": "RimTyres AI Agent",
  "environment": "production"
}
```

- [ ] /health endpoint returns "healthy"
- [ ] Response includes correct timestamp
- [ ] No errors in Render logs

---

## 📱 WHATSAPP INTEGRATION

### Step 8: Connect Twilio Webhook

1. Go to: **https://console.twilio.com**
2. Navigate: **Messaging** → **Try it out** → **WhatsApp**
3. Select your WhatsApp number
4. Set **"When a message comes in"**:
   ```
   https://rimtyres-ai-agent.onrender.com/webhook
   ```
5. Method: **POST**
6. Click **"Save"**

- [ ] Webhook URL set to your Render URL
- [ ] Method is POST
- [ ] Configuration saved

---

### Step 9: Test WhatsApp End-to-End ✅

**Test with your own phone**:

1. Send WhatsApp to your Twilio number
2. Check Render logs for processing
3. Should get reply with real Wix data!

- [ ] WhatsApp message received
- [ ] AI responds correctly
- [ ] Real Wix data is used

---

## 📊 MONITORING SETUP

### Step 10: Set Up UptimeRobot (Free)

1. Go to: **https://uptimerobot.com**
2. Sign up (free)
3. Add monitor: `https://rimtyres-ai-agent.onrender.com/health`
4. Interval: 5 minutes

- [ ] UptimeRobot monitor created
- [ ] Alert contact added

---

## 🔒 SECURITY VERIFICATION

- [ ] ✅ WIX_API_KEY marked as "Secret"
- [ ] ✅ .env NOT in Git
- [ ] ✅ Repository is PRIVATE
- [ ] ✅ Wix API key is READ-ONLY
- [ ] ✅ HTTPS enabled
- [ ] ✅ Health check works

---

## 🎊 YOU'RE LIVE!

**Your RimTyres AI is now deployed to Render!** 🎉

**Next**: Read RENDER_DEPLOYMENT.md for complete guide.

---

# 🎉 ORIGINAL DEPLOYMENT COMPLETE NOTE

Your **Agentic AI Customer Support System** is ready for production deployment!

---

## ✅ What Has Been Created

### 🤖 Core AI System
- ✅ `agentic_ai.py` - True agentic AI with natural conversation
- ✅ `rag_system.py` - RAG knowledge base with policies & product info
- ✅ `test_data.py` - Realistic test data (5 customers, 5 orders, 8 scenarios)
- ✅ `auth_system.py` - JWT authentication with RBAC

### 🌐 Web Integration
- ✅ `api_server.py` - FastAPI backend with secure endpoints
- ✅ `chat_widget.html` - Beautiful chat widget for website
- ✅ WebSocket support for real-time chat
- ✅ REST API with authentication

### 📱 WhatsApp Integration
- ✅ `whatsapp_integration.py` - Twilio WhatsApp webhook handler
- ✅ Session management for WhatsApp users
- ✅ Natural conversation via WhatsApp
- ✅ Phone number-based identification

### 🐳 Production Deployment
- ✅ `Dockerfile` - Container image for deployment
- ✅ `docker-compose.yml` - Multi-service orchestration
- ✅ `nginx.conf` - Reverse proxy with rate limiting
- ✅ `.dockerignore` - Optimized build

### 📚 Documentation
- ✅ `QUICKSTART.md` - Quick start guide (5 minutes)
- ✅ `DEPLOYMENT_GUIDE.md` - Comprehensive deployment guide
- ✅ `MEMORY_EXPLAINED.md` - Memory system explanation
- ✅ `AGENTIC_EXPLAINED.md` - Agentic AI concepts
- ✅ `README_ENHANCED.md` - Complete documentation

### 🔧 Utilities
- ✅ `start.ps1` - One-click startup script
- ✅ `migrate_db.py` - Database migration tool
- ✅ `test_runner.py` - Interactive test scenarios
- ✅ `requirements.txt` - All dependencies

---

## 🚀 Quick Start (Choose Your Method)

### Method 1: Local Development (Fastest) ⚡

```powershell
# 1. Install dependencies (already done!)
pip install -r requirements.txt

# 2. Create .env file
# Add your API keys

# 3. Start all services
.\start.ps1

# 4. Open chat widget
# Open chat_widget.html in browser
```

**Result**: Chat interface at http://localhost:8000

### Method 2: Docker (Production-Ready) 🐳

```powershell
# 1. Build and start
docker-compose up -d

# 2. Check status
docker-compose ps

# 3. View logs
docker-compose logs -f
```

**Result**: Full stack with Nginx at http://localhost

### Method 3: Manual Control 🎮

```powershell
# Terminal 1: API Server
python api_server.py

# Terminal 2: WhatsApp Integration
python whatsapp_integration.py

# Terminal 3: Test
python test_runner.py
```

---

## 🔑 Required Configuration

Create `.env` file with:

```env
# AI Configuration (Required)
OPENROUTER_API_KEY=sk-or-v1-xxxxx

# Security (Required)
JWT_SECRET=change_this_super_secret_key_in_production

# WhatsApp (Optional - for WhatsApp integration)
TWILIO_ACCOUNT_SID=ACxxxxx
TWILIO_AUTH_TOKEN=xxxxx
TWILIO_WHATSAPP_NUMBER=whatsapp:+14155238886
```

---

## 🔒 Security Features

### ✅ Authentication
- JWT tokens with 24-hour expiry
- Bcrypt password hashing
- Session management

### ✅ Authorization (RBAC)
- **Customer**: See only own data
- **Support Agent**: See all customer data
- **Admin**: User management
- **Owner**: Full system access

### ✅ Data Access Control
```javascript
// Example: Rohan can only see Rohan's orders
GET /orders → [ORD001, ORD002]  // Only Rohan's orders
GET /orders/ORD003 → 403 Forbidden  // Not Rohan's order
```

### ✅ Audit Logging
Every action is logged:
- User authentication
- Data access attempts
- Unauthorized access attempts
- WhatsApp messages

---

## 📱 Features

### Website Chat
- ✅ Beautiful chat interface
- ✅ Real-time WebSocket communication
- ✅ User authentication
- ✅ Message history
- ✅ Typing indicators

### WhatsApp Integration
- ✅ Natural conversation
- ✅ Session management
- ✅ Automatic customer identification
- ✅ Order tracking
- ✅ Returns & support

### AI Capabilities
- ✅ Order status checking
- ✅ Return processing
- ✅ Policy search (RAG)
- ✅ Product knowledge
- ✅ Known issues database
- ✅ Intelligent customer identification
- ✅ Proactive actions

---

## 🧪 Testing

### Test the API

```powershell
# Health check
curl http://localhost:8000/health

# Register user
curl -X POST http://localhost:8000/auth/register `
  -H "Content-Type: application/json" `
  -d '{"email": "rohan@example.com", "password": "test123", "name": "Rohan Sharma"}'

# Login
curl -X POST http://localhost:8000/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email": "rohan@example.com", "password": "test123"}'
```

### Test WhatsApp

1. Configure Twilio webhook
2. Join WhatsApp sandbox
3. Send: "Hi, where is my order?"

### Run Automated Tests

```powershell
python test_runner.py
```

---

## 📊 API Endpoints

### Public
- `GET /` - API info
- `GET /health` - Health check
- `POST /auth/register` - Register
- `POST /auth/login` - Login

### Authenticated
- `GET /auth/me` - Current user
- `POST /chat` - Send message
- `WS /ws/chat` - WebSocket chat
- `GET /orders` - Your orders
- `GET /orders/{id}` - Specific order

### Admin Only
- `GET /admin/users` - All users
- `GET /admin/audit-log` - Audit log
- `GET /admin/analytics` - Analytics

---

## 🌍 Production Deployment Options

### Cloud VPS
- **DigitalOcean**: $6/month droplet
- **AWS EC2**: t3.micro instance
- **Azure**: B1s VM
- **Linode**: Shared CPU instance

### Platform-as-a-Service
- **Heroku**: Easy git push deployment
- **Railway**: Auto-deploy from GitHub
- **Render**: Free tier available
- **Fly.io**: Global edge deployment

### Serverless
- **AWS Lambda + API Gateway**
- **Google Cloud Functions**
- **Azure Functions**

---

## 📈 Next Steps

### Immediate (Production Ready)
1. ✅ Get domain name
2. ✅ Configure SSL certificate (Let's Encrypt)
3. ✅ Deploy to cloud VPS
4. ✅ Set up monitoring
5. ✅ Configure backups

### Short Term (Enhancements)
1. Add more test data
2. Customize chat widget branding
3. Add more policies to RAG
4. Implement analytics dashboard
5. Add email notifications

### Long Term (Scaling)
1. Move to PostgreSQL
2. Add Redis caching
3. Implement load balancer
4. Add CDN for static files
5. Create mobile app
6. Multi-language support
7. Voice call support

---

## 🎯 Your System Can Now

### For Customers
✅ Chat on website with beautiful interface  
✅ Chat on WhatsApp  
✅ Check order status  
✅ Initiate returns  
✅ Get instant support 24/7  
✅ Natural conversation (no robotic menus!)  

### For Support Team
✅ View all customer conversations  
✅ Access customer history  
✅ Monitor AI responses  
✅ Review audit logs  
✅ Manage customer issues  

### For You (Owner)
✅ Full system visibility  
✅ Analytics and insights  
✅ User management  
✅ Security audit logs  
✅ Scalable infrastructure  

---

## 🛠️ Troubleshooting

### Server won't start?
```powershell
# Check if port is in use
netstat -ano | findstr :8000

# Kill process using port
taskkill /PID <PID> /F
```

### Database issues?
```powershell
# Recreate database
rm customer_memory.db
python migrate_db.py
```

### WebSocket not connecting?
- Check server is running: `http://localhost:8000/health`
- Verify token is valid: `GET /auth/me`
- Check browser console for errors

### WhatsApp not working?
- Verify Twilio credentials in `.env`
- Check webhook URL in Twilio console
- Test webhook: `curl -X POST http://localhost:8001/whatsapp/webhook`

---

## 📞 Support Resources

### Documentation Files
- `QUICKSTART.md` - Quick start (5 min)
- `DEPLOYMENT_GUIDE.md` - Full deployment
- `MEMORY_EXPLAINED.md` - Memory system
- `AGENTIC_EXPLAINED.md` - Agentic AI
- `README_ENHANCED.md` - Complete docs

### Test & Debug
- `test_runner.py` - Interactive tests
- `test_data.py` - Test scenarios
- `GET /admin/audit-log` - View logs
- `docker-compose logs -f` - View logs

---

## 💡 Pro Tips

### Performance
- Use PostgreSQL for production
- Add Redis for caching
- Enable CDN for static files
- Use connection pooling

### Security
- Change JWT_SECRET immediately
- Use HTTPS in production
- Enable rate limiting
- Regular security audits
- Keep dependencies updated

### Cost Optimization
- Start with free tier services
- Monitor API usage
- Implement caching
- Use reserved instances

### Monitoring
- Set up uptime monitoring
- Configure error alerts
- Track response times
- Monitor database size

---

## 🎉 Success!

You now have a **complete, production-ready AI customer support system** with:

✅ **Website integration** - Beautiful chat widget  
✅ **WhatsApp integration** - Reach customers where they are  
✅ **Security** - JWT auth, RBAC, audit logs  
✅ **Scalability** - Docker, microservices ready  
✅ **Natural AI** - True agentic conversation  
✅ **RAG Knowledge** - Smart policy & product search  
✅ **24/7 Support** - Always-on AI assistant  

---

## 📧 What Customers Will Experience

**On Your Website:**
1. Click chat bubble
2. Login/Register
3. "Hi, where is my order?"
4. Get instant response with tracking

**On WhatsApp:**
1. Send message to your WhatsApp number
2. "Hi, I want to return my product"
3. AI helps with return process
4. Seamless, natural conversation

**Security:**
- Rohan sees only Rohan's orders ✅
- Priya sees only Priya's orders ✅
- Support agents see all data ✅
- Complete audit trail ✅

---

## 🚀 Ready to Launch!

Your AI customer support agent **Emma** is ready to:
- Handle unlimited simultaneous conversations
- Provide 24/7 support
- Access customer history
- Understand context
- Take actions autonomously
- Maintain conversation flow
- Respect user permissions

**Just start the servers and go live!** 🎉

```powershell
# Start everything with one command
.\start.ps1

# Or use Docker for production
docker-compose up -d
```

---

**Need help?** Check the documentation files or review the code comments.

**Ready to scale?** The system is designed for growth - just deploy more instances!

**Want to customize?** All code is well-documented and modular.

---

**🎊 Congratulations on your new AI-powered customer support system!** 🎊
