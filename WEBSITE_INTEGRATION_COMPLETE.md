# 🌐 WEBSITE INTEGRATION - COMPLETE SETUP

## ✅ What's Been Created

I've created a **complete website integration system** that connects your AI agent to your actual website to fetch real customer data!

### 📦 New Files Created:

1. **`website_integration.py`** - Main integration module
   - Supports 5 integration methods
   - Database (MySQL, PostgreSQL)
   - REST API
   - WooCommerce
   - Shopify
   - Custom

2. **`WEBSITE_INTEGRATION_GUIDE.md`** - Complete setup guide
   - Step-by-step instructions
   - Configuration examples
   - Troubleshooting tips

3. **`test_website_connection.py`** - Connection tester
   - Verifies your setup works
   - Tests customer fetch
   - Tests order fetch
   - Interactive testing

4. **`.env.website.example`** - Configuration template
   - All integration options
   - Easy copy-paste setup

---

## 🚀 Quick Start (3 Steps!)

### Step 1: Choose Your Integration

Pick the method that matches your website:

**🗄️ Option A: MySQL Database** (Direct, Fastest)
```powershell
# Add to .env file:
INTEGRATION_TYPE=database
WEBSITE_DB_TYPE=mysql
WEBSITE_DB_HOST=localhost
WEBSITE_DB_PORT=3306
WEBSITE_DB_NAME=your_shop_database
WEBSITE_DB_USER=your_user
WEBSITE_DB_PASSWORD=your_password

# Install package:
pip install mysql-connector-python
```

**🔌 Option B: REST API** (Most Flexible)
```powershell
# Add to .env file:
INTEGRATION_TYPE=api
WEBSITE_API_URL=https://yourwebsite.com/api
WEBSITE_API_KEY=your_api_key
WEBSITE_API_SECRET=your_secret

# Install package:
pip install requests
```

**🛒 Option C: WooCommerce** (WordPress Sites)
```powershell
# Add to .env file:
INTEGRATION_TYPE=woocommerce
WOO_URL=https://yourstore.com
WOO_CONSUMER_KEY=ck_xxxxxxxxxxxx
WOO_CONSUMER_SECRET=cs_xxxxxxxxxxxx

# Install package:
pip install woocommerce requests
```

**🛍️ Option D: Shopify** (Shopify Stores)
```powershell
# Add to .env file:
INTEGRATION_TYPE=shopify
SHOPIFY_SHOP_URL=https://yourstore.myshopify.com
SHOPIFY_ACCESS_TOKEN=shpat_xxxxxxxxxxxx

# Install package:
pip install requests
```

---

### Step 2: Install Required Package

Based on your choice above:

```powershell
# For MySQL:
pip install mysql-connector-python

# For PostgreSQL:
pip install psycopg2-binary

# For WooCommerce:
pip install woocommerce

# For API/Shopify:
pip install requests
```

---

### Step 3: Test Connection

```powershell
python test_website_connection.py
```

This will:
- ✅ Verify your configuration
- ✅ Test customer fetch
- ✅ Test order fetch
- ✅ Show you sample data

---

## 🔧 How It Works

### Current Setup (Test Data):
```
Agent → test_data.py → Fake customer data
```

### New Setup (Real Data):
```
Agent → website_integration.py → Your Website Database/API → Real customer data
```

### What Changes:

**In `agentic_ai.py`:**
```python
# OLD:
from test_data import get_customer_profile, get_customer_orders

# NEW:
from website_integration import get_customer_profile, get_customer_orders, init_website_integration

# Add in __init__:
init_website_integration(os.getenv("INTEGRATION_TYPE", "api"))
```

**In `api_server.py`:**
```python
# OLD:
from test_data import get_order_by_id, get_customer_orders

# NEW:
from website_integration import get_order_by_id, get_customer_orders, init_website_integration

# After imports:
init_website_integration(os.getenv("INTEGRATION_TYPE", "database"))
```

---

## 📊 What Data Gets Fetched

Your agent will automatically fetch:

### Customer Information:
- ✅ Customer ID
- ✅ Name
- ✅ Email address
- ✅ Phone number
- ✅ Member since date
- ✅ Loyalty tier
- ✅ Total orders
- ✅ Lifetime value
- ✅ Preferences
- ✅ Notes

### Order Information:
- ✅ Order ID
- ✅ Order date
- ✅ Order status
- ✅ Items ordered
- ✅ Quantities
- ✅ Prices
- ✅ Shipping method
- ✅ Tracking number
- ✅ Delivery date

---

## 🎯 Customer Identification

### Website Chat:
- Customer logs in → Email known → Agent fetches profile automatically

### WhatsApp:
- Customer messages → Phone number known → Agent fetches profile automatically

### No Manual Entry Needed! 🎉

---

## 💡 Examples

### Example 1: Database Integration

**Your `.env` file:**
```env
INTEGRATION_TYPE=database
WEBSITE_DB_TYPE=mysql
WEBSITE_DB_HOST=localhost
WEBSITE_DB_PORT=3306
WEBSITE_DB_NAME=shop_db
WEBSITE_DB_USER=shop_user
WEBSITE_DB_PASSWORD=SecurePass123
```

**Install & Test:**
```powershell
pip install mysql-connector-python
python test_website_connection.py
```

**Expected Output:**
```
🔧 Testing Website Integration
============================================================
📡 Integration Type: DATABASE
============================================================

1️⃣ Initializing connection...
   ✅ Connection initialized!

2️⃣ Testing customer fetch by email...
   Enter customer email: john@example.com
   ✅ Customer found!
   • ID: CUST-1001
   • Name: John Doe
   • Email: john@example.com
   • Phone: +1234567890
   • Total Orders: 5
   • Lifetime Value: $1,250.00

3️⃣ Testing order fetch...
   ✅ Found 5 orders
   
   Latest Order:
   • Order ID: ORD-2025-001
   • Date: 2025-10-01
   • Status: shipped
   • Total: $299.99
   • Items: 2

✅ INTEGRATION TEST COMPLETE!
```

---

### Example 2: WooCommerce Integration

**Get API Keys:**
1. Go to WooCommerce → Settings → Advanced → REST API
2. Click "Add Key"
3. Copy Consumer Key and Consumer Secret

**Your `.env` file:**
```env
INTEGRATION_TYPE=woocommerce
WOO_URL=https://mystore.com
WOO_CONSUMER_KEY=ck_abc123def456...
WOO_CONSUMER_SECRET=cs_xyz789uvw012...
```

**Install & Test:**
```powershell
pip install woocommerce
python test_website_connection.py
```

---

### Example 3: REST API Integration

**Your `.env` file:**
```env
INTEGRATION_TYPE=api
WEBSITE_API_URL=https://mywebsite.com/api/v1
WEBSITE_API_KEY=your_api_key_here
```

**Your API should have:**
- `GET /customers/{id}`
- `GET /customers?email={email}`
- `GET /customers/{id}/orders`
- `GET /orders/{id}`

**Install & Test:**
```powershell
pip install requests
python test_website_connection.py
```

---

## 🔒 Security Notes

### Best Practices:

1. **Use Read-Only Access**
   - Database: Create read-only user
   - API: Generate read-only token
   - WooCommerce: Set permissions to "Read"

2. **Protect Credentials**
   - Never commit `.env` to git
   - Use environment variables in production
   - Rotate keys regularly

3. **Limit Access**
   - Only allow needed tables/endpoints
   - Use firewall rules
   - Enable SSL/TLS

---

## 🚨 Common Issues & Solutions

### Issue 1: "Cannot import mysql.connector"
**Solution:**
```powershell
pip install mysql-connector-python
```

### Issue 2: "Connection refused"
**Solution:**
- Check database is running
- Verify host and port
- Check firewall settings

### Issue 3: "Customer not found"
**Solution:**
- Verify customer exists in database
- Check email format matches exactly
- Try with different customer email

### Issue 4: "API returns 401"
**Solution:**
- Verify API key is correct
- Check API key hasn't expired
- Ensure correct authorization header format

---

## 📖 Complete Documentation

See **`WEBSITE_INTEGRATION_GUIDE.md`** for:
- Detailed setup instructions
- Database schema requirements
- API endpoint specifications
- WooCommerce setup guide
- Shopify setup guide
- Complete troubleshooting
- Security best practices

---

## ✅ Testing Checklist

Before going live with real data:

- [ ] Configuration added to `.env`
- [ ] Required packages installed
- [ ] Connection test passes
- [ ] Customer fetch works
- [ ] Order fetch works
- [ ] Phone number fetch works (for WhatsApp)
- [ ] Multiple customers tested
- [ ] Edge cases tested (no orders, etc.)
- [ ] Error handling verified
- [ ] Security reviewed

---

## 🎯 Next Steps

### Step 1: Configure (5 minutes)
```powershell
# Copy example config
copy .env.website.example .env

# Edit .env with your credentials
notepad .env
```

### Step 2: Install (1 minute)
```powershell
# Choose based on your integration:
pip install mysql-connector-python  # For MySQL
pip install woocommerce             # For WooCommerce
pip install requests                # For API/Shopify
```

### Step 3: Test (2 minutes)
```powershell
python test_website_connection.py
```

### Step 4: Update Code (5 minutes)
- Update `agentic_ai.py` imports
- Update `api_server.py` imports
- Add `init_website_integration()` call

### Step 5: Test with Agent (10 minutes)
```powershell
# Start server
python api_server.py

# Open chat widget
# Test with real customer email
```

### Step 6: Deploy! 🚀
```powershell
docker-compose up -d
```

---

## 🎉 What You Get

With website integration, your AI agent will:

1. **Automatically Identify Customers**
   - By email (website chat)
   - By phone (WhatsApp)
   - No manual input needed!

2. **Access Real Data**
   - Current order status
   - Order history
   - Customer preferences
   - Accurate information

3. **Provide Better Support**
   - "Your order #12345 is out for delivery"
   - "I see you've ordered from us 5 times before"
   - "Your UltraBook laptop will arrive tomorrow"

4. **Work Across Channels**
   - Same data on website chat
   - Same data on WhatsApp
   - Consistent experience

---

## 💬 Example Conversations

### Before (Test Data):
```
Customer: Where is my order?
Agent: I'd love to help! Can you tell me your order number?
Customer: ORD-12345
Agent: Let me look that up...
```

### After (Real Data):
```
Customer: Where is my order?
Agent: Hey Sarah! I can see your order #12345 for the UltraBook 
       laptop. Great news - it's out for delivery and should 
       arrive tomorrow by 5 PM! 📦
```

---

## 🆘 Need Help?

1. **Configuration Issues**: See `.env.website.example`
2. **Connection Problems**: Run `python test_website_connection.py`
3. **Database Setup**: See `WEBSITE_INTEGRATION_GUIDE.md`
4. **API Integration**: Check API documentation
5. **General Issues**: See `TROUBLESHOOTING.md`

---

## 🎊 Summary

You now have:
- ✅ Complete website integration module
- ✅ Support for 5 integration methods
- ✅ Database, API, WooCommerce, Shopify, Custom
- ✅ Automatic customer identification
- ✅ Real-time data fetching
- ✅ Testing tools
- ✅ Complete documentation
- ✅ Ready to deploy!

**Just configure, test, and go live!** 🚀

---

**Files to Review:**
1. `WEBSITE_INTEGRATION_GUIDE.md` - Full setup guide
2. `website_integration.py` - Integration code
3. `test_website_connection.py` - Test script
4. `.env.website.example` - Config template

**Commands to Run:**
```powershell
# 1. Install packages
pip install mysql-connector-python  # or woocommerce, or requests

# 2. Configure .env
notepad .env

# 3. Test connection
python test_website_connection.py

# 4. Update code (see guide)

# 5. Test with agent
python api_server.py
```

**You're all set!** 🎉
