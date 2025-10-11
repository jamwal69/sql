# 🌐 WEBSITE INTEGRATION GUIDE

## 🎯 Connect Your Agent to Your Website

This guide shows you how to connect your AI agent to your actual website to fetch **real customer data** instead of test data.

---

## 📋 Integration Options

Your agent supports **5 integration methods**:

1. **Direct Database** - Connect directly to your website's database (MySQL, PostgreSQL)
2. **REST API** - Connect to your website's API endpoints
3. **WooCommerce** - Built-in WooCommerce integration
4. **Shopify** - Built-in Shopify integration
5. **Custom** - Create custom integration for any platform

---

## 🚀 Quick Start

### Step 1: Choose Your Integration Method

**Option A: Direct Database Connection** (Fastest)
```env
WEBSITE_DB_TYPE=mysql
WEBSITE_DB_HOST=localhost
WEBSITE_DB_PORT=3306
WEBSITE_DB_NAME=your_ecommerce_db
WEBSITE_DB_USER=your_user
WEBSITE_DB_PASSWORD=your_password
```

**Option B: REST API** (Most flexible)
```env
WEBSITE_API_URL=https://yourwebsite.com/api
WEBSITE_API_KEY=your_api_key
WEBSITE_API_SECRET=your_api_secret
```

**Option C: WooCommerce** (WordPress sites)
```env
WOO_URL=https://yourstore.com
WOO_CONSUMER_KEY=ck_xxxxxxxxxxxxx
WOO_CONSUMER_SECRET=cs_xxxxxxxxxxxxx
```

**Option D: Shopify** (Shopify stores)
```env
SHOPIFY_SHOP_URL=https://yourstore.myshopify.com
SHOPIFY_ACCESS_TOKEN=shpat_xxxxxxxxxxxxx
```

---

## 📦 Step 2: Install Required Dependencies

### For Database Integration (MySQL):
```powershell
pip install mysql-connector-python
```

### For Database Integration (PostgreSQL):
```powershell
pip install psycopg2-binary
```

### For WooCommerce:
```powershell
pip install woocommerce
```

### For All Integrations:
```powershell
pip install requests
```

---

## ⚙️ Step 3: Configure Your Integration

### Update `.env` File

Add these lines to your `.env` file based on your choice:

#### Example 1: MySQL Database
```env
# Website Database Integration
WEBSITE_DB_TYPE=mysql
WEBSITE_DB_HOST=localhost
WEBSITE_DB_PORT=3306
WEBSITE_DB_NAME=shop_database
WEBSITE_DB_USER=shop_user
WEBSITE_DB_PASSWORD=SecurePassword123

# Use database integration
INTEGRATION_TYPE=database
```

#### Example 2: REST API
```env
# Website API Integration
WEBSITE_API_URL=https://yourwebsite.com/api/v1
WEBSITE_API_KEY=your_secret_api_key
WEBSITE_API_SECRET=your_api_secret

# Use API integration
INTEGRATION_TYPE=api
```

#### Example 3: WooCommerce
```env
# WooCommerce Integration
WOO_URL=https://yourstore.com
WOO_CONSUMER_KEY=ck_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
WOO_CONSUMER_SECRET=cs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Use WooCommerce integration
INTEGRATION_TYPE=woocommerce
```

---

## 🔧 Step 4: Update Your Code

### Option A: Modify `agentic_ai.py` (Recommended)

Replace the test_data import:

```python
# OLD (test data)
from test_data import get_customer_profile, get_customer_orders, get_order_by_id

# NEW (real website data)
from website_integration import get_customer_profile, get_customer_orders, get_order_by_id, init_website_integration

# Initialize at startup
init_website_integration("database")  # or "api", "woocommerce", "shopify"
```

### Option B: Modify `api_server.py`

```python
# OLD
from test_data import get_order_by_id, get_customer_orders, ORDERS

# NEW
from website_integration import (
    get_order_by_id, 
    get_customer_orders, 
    init_website_integration
)

# Initialize before app starts
init_website_integration("database")  # Choose your type
```

---

## 🗄️ Database Schema Requirements

If using **direct database connection**, your database should have these tables:

### Customers Table
```sql
CREATE TABLE customers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    customer_id VARCHAR(50) UNIQUE,
    name VARCHAR(255),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(50),
    phone_number VARCHAR(50),
    created_at DATETIME,
    date_created DATETIME,
    member_since DATETIME,
    loyalty_tier VARCHAR(50),
    orders_count INT DEFAULT 0,
    total_orders INT DEFAULT 0,
    total_spent DECIMAL(10,2) DEFAULT 0,
    lifetime_value DECIMAL(10,2) DEFAULT 0,
    preferences JSON,
    notes TEXT
);
```

### Orders Table
```sql
CREATE TABLE orders (
    id INT PRIMARY KEY AUTO_INCREMENT,
    order_id VARCHAR(50) UNIQUE,
    order_number VARCHAR(50),
    customer_id VARCHAR(50),
    date_created DATETIME,
    created_at DATETIME,
    status VARCHAR(50),
    total DECIMAL(10,2),
    shipping_method VARCHAR(100),
    tracking_number VARCHAR(100),
    tracking VARCHAR(100),
    shipping_carrier VARCHAR(100),
    carrier VARCHAR(100),
    delivery_date DATE,
    estimated_delivery DATE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);
```

### Order Items Table
```sql
CREATE TABLE order_items (
    id INT PRIMARY KEY AUTO_INCREMENT,
    order_id INT,
    product_name VARCHAR(255),
    sku VARCHAR(100),
    quantity INT,
    price DECIMAL(10,2),
    FOREIGN KEY (order_id) REFERENCES orders(id)
);
```

**Note**: The integration is flexible - it will try multiple column names to find the data!

---

## 🔌 API Endpoint Requirements

If using **REST API integration**, your API should have these endpoints:

### Customer Endpoints
```
GET /api/customers/{customer_id}
GET /api/customers?email={email}
GET /api/customers?phone={phone}
```

**Response Format**:
```json
{
    "id": "CUST-1001",
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "+1234567890",
    "created_at": "2024-01-15T10:30:00Z",
    "orders_count": 5,
    "total_spent": 1250.00
}
```

### Order Endpoints
```
GET /api/customers/{customer_id}/orders
GET /api/orders/{order_id}
```

**Response Format**:
```json
{
    "id": "ORD-2025-001",
    "customer_id": "CUST-1001",
    "date_created": "2025-10-01T14:20:00Z",
    "status": "shipped",
    "total": 299.99,
    "items": [
        {
            "name": "Product Name",
            "quantity": 1,
            "price": 299.99,
            "sku": "SKU-123"
        }
    ]
}
```

---

## 🛒 WooCommerce Setup

### 1. Get API Keys

1. Go to **WooCommerce → Settings → Advanced → REST API**
2. Click **Add Key**
3. Set **Description**: "AI Agent"
4. Set **User**: Admin user
5. Set **Permissions**: Read
6. Click **Generate API Key**
7. Copy **Consumer Key** and **Consumer Secret**

### 2. Configure `.env`
```env
WOO_URL=https://yourstore.com
WOO_CONSUMER_KEY=ck_your_consumer_key_here
WOO_CONSUMER_SECRET=cs_your_consumer_secret_here
INTEGRATION_TYPE=woocommerce
```

### 3. Test Connection
```powershell
python -c "from website_integration import init_website_integration; f = init_website_integration('woocommerce'); print(f.get_customer_by_email('customer@example.com'))"
```

---

## 🛍️ Shopify Setup

### 1. Create Private App

1. Go to **Settings → Apps and sales channels → Develop apps**
2. Click **Create an app**
3. Name it "AI Customer Support"
4. Click **Configure Admin API scopes**
5. Enable: `read_customers`, `read_orders`
6. Click **Install app**
7. Copy **Admin API access token**

### 2. Configure `.env`
```env
SHOPIFY_SHOP_URL=https://yourstore.myshopify.com
SHOPIFY_ACCESS_TOKEN=shpat_your_access_token_here
INTEGRATION_TYPE=shopify
```

### 3. Test Connection
```powershell
python -c "from website_integration import init_website_integration; f = init_website_integration('shopify'); print(f.get_customer_by_email('customer@example.com'))"
```

---

## ✅ Step 5: Test Your Integration

Create a test script `test_website_connection.py`:

```python
from website_integration import init_website_integration

# Initialize (choose: "database", "api", "woocommerce", or "shopify")
fetcher = init_website_integration("database")

# Test customer fetch
print("Testing customer fetch...")
customer = fetcher.get_customer_by_email("your_customer_email@example.com")
print(f"Customer: {customer}")

# Test orders fetch
if customer:
    print("\nTesting orders fetch...")
    orders = fetcher.get_customer_orders(customer['customer_id'])
    print(f"Orders: {len(orders)} found")
    if orders:
        print(f"Latest order: {orders[0]}")

print("\n✅ Integration test complete!")
```

Run it:
```powershell
python test_website_connection.py
```

---

## 🔄 Switch from Test Data to Real Data

### Update `agentic_ai.py`:

```python
# At the top, replace:
# from test_data import get_customer_profile, get_customer_orders, get_order_by_id

# With:
from website_integration import (
    get_customer_profile, 
    get_customer_orders, 
    get_order_by_id,
    init_website_integration
)

# In __init__ method, add:
def __init__(self, api_key: str):
    # ... existing code ...
    
    # Initialize website integration
    integration_type = os.getenv("INTEGRATION_TYPE", "api")
    init_website_integration(integration_type)
```

### Update `api_server.py`:

```python
# Replace import
from website_integration import (
    get_order_by_id, 
    get_customer_orders,
    init_website_integration
)

# After app initialization
integration_type = os.getenv("INTEGRATION_TYPE", "database")
init_website_integration(integration_type)
```

---

## 🔒 Security Best Practices

### 1. Database Security
- ✅ Use **read-only** database user
- ✅ Restrict access to only needed tables
- ✅ Use **SSL/TLS** for database connections
- ✅ Never expose credentials in code

### 2. API Security
- ✅ Use **API keys** with limited permissions
- ✅ Enable **rate limiting**
- ✅ Use **HTTPS** only
- ✅ Rotate keys regularly

### 3. WooCommerce/Shopify
- ✅ Use **read-only** permissions
- ✅ Create dedicated API user/app
- ✅ Monitor API usage
- ✅ Revoke unused keys

---

## 🐛 Troubleshooting

### Problem: "Cannot connect to database"
**Solution**:
1. Check database credentials in `.env`
2. Verify database is running: `mysql -u your_user -p`
3. Check firewall allows connections
4. Test connection: `telnet localhost 3306`

### Problem: "API returns 401 Unauthorized"
**Solution**:
1. Verify API key in `.env`
2. Check API key hasn't expired
3. Ensure correct API URL format
4. Test with curl: `curl -H "Authorization: Bearer YOUR_KEY" https://yourapi.com/customers`

### Problem: "WooCommerce API not found"
**Solution**:
1. Install WooCommerce library: `pip install woocommerce`
2. Verify WooCommerce is enabled on site
3. Check REST API is enabled in WooCommerce settings
4. Test keys with WooCommerce REST API tester

### Problem: "No customer found"
**Solution**:
1. Check customer actually exists in database
2. Verify email/phone format matches
3. Check table/column names match your schema
4. Add debug prints to see what's being queried

---

## 📊 Data Mapping Guide

The integration automatically maps your website data to agent format:

| Agent Field | Database Columns | API Fields | WooCommerce | Shopify |
|------------|------------------|------------|-------------|---------|
| customer_id | id, customer_id | id, customer_id | id | id |
| name | name, first_name+last_name | name | first_name+last_name | first_name+last_name |
| email | email | email | email | email |
| phone | phone, phone_number | phone | billing.phone | phone, default_address.phone |
| total_orders | orders_count, total_orders | orders_count | orders_count | orders_count |
| lifetime_value | total_spent, lifetime_value | total_spent | total_spent | total_spent |

**Don't worry!** The integration tries multiple column names automatically.

---

## 🎯 Next Steps

1. ✅ Choose your integration method
2. ✅ Install required packages
3. ✅ Configure `.env` file
4. ✅ Test connection
5. ✅ Update code to use website data
6. ✅ Test with real customers
7. ✅ Deploy to production!

---

## 💡 Examples

### Example 1: MySQL Integration
```python
from website_integration import init_website_integration

# Initialize
fetcher = init_website_integration("database")

# Fetch customer by email (for website chat)
customer = fetcher.get_customer_by_email("john@example.com")

# Fetch customer by phone (for WhatsApp)
customer = fetcher.get_customer_by_phone("+1234567890")

# Get their orders
orders = fetcher.get_customer_orders(customer['customer_id'])

# Get specific order
order = fetcher.get_order_by_id("ORD-123")
```

### Example 2: API Integration
```python
from website_integration import init_website_integration

# Initialize with API
fetcher = init_website_integration("api")

# Everything else works the same!
customer = fetcher.get_customer_by_email("jane@example.com")
orders = fetcher.get_customer_orders(customer['customer_id'])
```

---

## 🆘 Need Help?

**Database Issues**: Check `TROUBLESHOOTING.md`
**API Issues**: Review API documentation
**WooCommerce**: See WooCommerce REST API docs
**Shopify**: See Shopify Admin API docs

---

## ✨ You're All Set!

Your AI agent can now fetch **real customer data** from your website! 🎉

The agent will:
- ✅ Automatically identify customers by email or phone
- ✅ Fetch their order history
- ✅ Get real-time order status
- ✅ Access all customer information
- ✅ Provide accurate support based on real data

**Test it thoroughly before going live!**
