# 🔒 SECURITY GUIDE FOR RIMTYRES

## ⚠️ Your Concern is Valid!

You're handling:
- 💰 Real payments daily
- 👥 Customer personal data
- 📦 Order information
- 🏦 Payment gateway data
- 📱 WhatsApp conversations

**Storing API keys in `.env` file CAN be risky if not done properly!**

---

## 🛡️ SOLUTION: Multi-Layer Security

I'll show you **5 security layers** from basic to enterprise-level:

---

## 🔐 LAYER 1: Basic Security (Minimum Required)

### ✅ What You MUST Do:

#### 1. **Protect .env File**
```powershell
# Add to .gitignore (CRITICAL!)
echo ".env" >> .gitignore
echo "*.env" >> .gitignore
echo ".env.*" >> .gitignore
```

**Why?** Prevents accidentally uploading API keys to GitHub/Git.

#### 2. **File Permissions**
```powershell
# Windows: Set file to read-only for system only
icacls .env /inheritance:r /grant:r "%USERNAME%:R"

# Or right-click .env → Properties → Security → Advanced
# Remove all users except your account (Read only)
```

#### 3. **Read-Only API Keys in Wix**

When creating Wix API keys:
- ✅ **Enable**: Contacts (Read), Orders (Read), Products (Read)
- ❌ **Disable**: Write, Delete, Manage permissions
- ✅ **Scope**: Only what's needed

**Result**: Even if key is stolen, attacker can't modify/delete data.

---

## 🔐 LAYER 2: Environment Variables (Better)

Instead of `.env` file, use **system environment variables**:

### Windows (Production Server):

```powershell
# Set permanent environment variables
[System.Environment]::SetEnvironmentVariable('WIX_SITE_ID', 'your_site_id', 'User')
[System.Environment]::SetEnvironmentVariable('WIX_API_KEY', 'your_api_key', 'User')
[System.Environment]::SetEnvironmentVariable('WIX_ACCOUNT_ID', 'your_account_id', 'User')

# Verify
$env:WIX_API_KEY
```

### Benefits:
- ✅ No `.env` file to steal
- ✅ Encrypted by Windows
- ✅ Only accessible by your user account
- ✅ Survives server restarts

---

## 🔐 LAYER 3: Encrypted Secrets (Recommended for RimTyres)

Use **encrypted storage** for sensitive data:

### Option A: Windows Credential Manager

```python
# Install package
pip install keyring

# Store API key securely (one time)
import keyring
keyring.set_password("rimtyres_wix", "api_key", "your_actual_api_key")
keyring.set_password("rimtyres_wix", "site_id", "your_site_id")
keyring.set_password("rimtyres_wix", "account_id", "your_account_id")

# Retrieve in your code
api_key = keyring.get_password("rimtyres_wix", "api_key")
```

### Option B: Azure Key Vault (Cloud)

```python
# Install
pip install azure-keyvault-secrets azure-identity

# Use
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://rimtyres-vault.vault.azure.net/", credential=credential)

api_key = client.get_secret("wix-api-key").value
```

**Benefits**:
- ✅ Keys encrypted at rest
- ✅ Access logged
- ✅ Can rotate keys easily
- ✅ Enterprise-grade security

---

## 🔐 LAYER 4: API Key Rotation (Best Practice)

Regularly change your API keys:

### Setup:
1. Create 2 API keys in Wix (Primary + Backup)
2. Use Primary in production
3. Rotate every 30-90 days

### Rotation Script:
```python
# api_key_manager.py
import os
from datetime import datetime, timedelta

class APIKeyManager:
    def __init__(self):
        self.primary_key = os.getenv("WIX_API_KEY_PRIMARY")
        self.backup_key = os.getenv("WIX_API_KEY_BACKUP")
        self.last_rotation = os.getenv("KEY_ROTATION_DATE")
    
    def get_active_key(self):
        """Get current active API key"""
        # Check if rotation needed
        if self._needs_rotation():
            print("⚠️ API key rotation recommended!")
        return self.primary_key
    
    def _needs_rotation(self):
        """Check if key is older than 90 days"""
        if not self.last_rotation:
            return True
        last = datetime.fromisoformat(self.last_rotation)
        return datetime.now() - last > timedelta(days=90)
    
    def rotate_keys(self):
        """Swap primary and backup keys"""
        # Swap keys
        self.primary_key, self.backup_key = self.backup_key, self.primary_key
        # Update rotation date
        os.environ["KEY_ROTATION_DATE"] = datetime.now().isoformat()
        print("✅ API keys rotated successfully")
```

---

## 🔐 LAYER 5: Rate Limiting & Monitoring (Enterprise)

Protect against abuse even if key is compromised:

### A. Rate Limiting

```python
# rate_limiter.py
from datetime import datetime, timedelta
from collections import defaultdict

class RateLimiter:
    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
    
    def allow_request(self, identifier):
        """Check if request should be allowed"""
        now = datetime.now()
        window_start = now - timedelta(seconds=self.window_seconds)
        
        # Clean old requests
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if req_time > window_start
        ]
        
        # Check limit
        if len(self.requests[identifier]) >= self.max_requests:
            return False
        
        # Allow request
        self.requests[identifier].append(now)
        return True

# Usage
limiter = RateLimiter(max_requests=100, window_seconds=60)
if not limiter.allow_request(phone_number):
    return "Too many requests, please try again later"
```

### B. API Call Monitoring

```python
# api_monitor.py
import logging
from datetime import datetime

class APIMonitor:
    def __init__(self):
        self.logger = logging.getLogger("rimtyres_api")
        self.suspicious_threshold = 50  # requests per minute
    
    def log_api_call(self, endpoint, phone_number, response_code):
        """Log all API calls"""
        self.logger.info(f"{datetime.now()} | {endpoint} | {phone_number} | {response_code}")
        
        # Check for suspicious activity
        if self._is_suspicious(phone_number):
            self.logger.warning(f"⚠️ Suspicious activity from {phone_number}")
            # Send alert (email, SMS, etc.)
            self._send_alert(phone_number)
    
    def _is_suspicious(self, phone_number):
        """Detect unusual patterns"""
        # Check request frequency
        # Check unusual times (3am?)
        # Check multiple failed attempts
        return False  # Implement your logic
    
    def _send_alert(self, phone_number):
        """Alert admin of suspicious activity"""
        # Send email/SMS to admin
        pass
```

---

## 🔐 LAYER 6: IP Whitelisting (Production Server)

Restrict API access to your server only:

### Wix Dashboard:
1. Go to API settings
2. Enable IP restrictions
3. Add your server's IP address
4. Block all other IPs

**Result**: Even if API key leaks, only YOUR server can use it.

---

## 🎯 RECOMMENDED SECURITY SETUP FOR RIMTYRES

### For Development (Your Computer):
```
✅ Use .env file (in .gitignore)
✅ File permissions set to read-only
✅ Read-only API permissions
```

### For Production (Server):
```
✅ Windows Credential Manager (encrypted)
✅ OR Azure Key Vault (cloud)
✅ Read-only API permissions
✅ API key rotation (90 days)
✅ Rate limiting
✅ API call logging
✅ IP whitelisting
✅ HTTPS only
```

---

## 📝 IMPLEMENTATION: Secure Wix Integration

Let me create a **secure version** for you:

### File: `secure_wix_integration.py`

```python
"""
Secure Wix Integration for RimTyres
Uses encrypted credential storage
"""

import os
import keyring
import logging
from datetime import datetime
from wix_integration import WixIntegration

# Setup logging
logging.basicConfig(
    filename='rimtyres_api.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

class SecureWixIntegration(WixIntegration):
    """
    Enhanced Wix integration with security features
    """
    
    def __init__(self, use_keyring=True):
        """
        Initialize with secure credential storage
        
        Args:
            use_keyring: Use Windows Credential Manager (True) or env vars (False)
        """
        self.use_keyring = use_keyring
        self.logger = logging.getLogger("rimtyres_secure")
        
        # Load credentials securely
        self.config = self._load_secure_config()
        
        # Initialize parent
        super().__init__()
    
    def _load_secure_config(self):
        """Load credentials from secure storage"""
        if self.use_keyring:
            # Load from Windows Credential Manager
            return {
                "wix_site_id": keyring.get_password("rimtyres_wix", "site_id"),
                "wix_api_key": keyring.get_password("rimtyres_wix", "api_key"),
                "wix_account_id": keyring.get_password("rimtyres_wix", "account_id")
            }
        else:
            # Load from environment variables (fallback)
            return {
                "wix_site_id": os.getenv("WIX_SITE_ID"),
                "wix_api_key": os.getenv("WIX_API_KEY"),
                "wix_account_id": os.getenv("WIX_ACCOUNT_ID")
            }
    
    def get_customer_by_phone(self, phone: str):
        """Override with logging and security"""
        # Log request
        self.logger.info(f"Customer lookup: {phone[-4:]}")  # Only log last 4 digits
        
        try:
            # Call parent method
            result = super().get_customer_by_phone(phone)
            
            # Log success
            self.logger.info(f"Customer found: {result.get('customer_id') if result else 'None'}")
            
            return result
            
        except Exception as e:
            # Log error
            self.logger.error(f"Customer lookup failed: {e}")
            raise
    
    def get_customer_orders(self, customer_id: str):
        """Override with logging"""
        self.logger.info(f"Orders request: {customer_id}")
        
        try:
            result = super().get_customer_orders(customer_id)
            self.logger.info(f"Orders found: {len(result)}")
            return result
        except Exception as e:
            self.logger.error(f"Orders fetch failed: {e}")
            raise

# Setup script
def setup_secure_credentials():
    """
    One-time setup to store credentials securely
    Run this once, then delete the code
    """
    print("🔐 Secure Credential Setup for RimTyres\n")
    
    site_id = input("Enter WIX_SITE_ID: ").strip()
    api_key = input("Enter WIX_API_KEY: ").strip()
    account_id = input("Enter WIX_ACCOUNT_ID: ").strip()
    
    # Store in Windows Credential Manager
    keyring.set_password("rimtyres_wix", "site_id", site_id)
    keyring.set_password("rimtyres_wix", "api_key", api_key)
    keyring.set_password("rimtyres_wix", "account_id", account_id)
    
    print("\n✅ Credentials stored securely in Windows Credential Manager")
    print("✅ They are encrypted and only accessible by your user account")
    print("\n⚠️  You can now DELETE the .env file for extra security!")
    print("\n💡 To view/edit: Control Panel → Credential Manager → Windows Credentials")

if __name__ == "__main__":
    setup_secure_credentials()
```

---

## 🚀 QUICK SETUP: Secure RimTyres

### Step 1: Install Security Package
```powershell
pip install keyring
```

### Step 2: Store Credentials Securely (One Time)
```powershell
python -c "from secure_wix_integration import setup_secure_credentials; setup_secure_credentials()"
```

This will:
1. Ask for your Wix credentials
2. Store them encrypted in Windows Credential Manager
3. Delete need for `.env` file

### Step 3: Update Your Code
```python
# In whatsapp_integration.py
from secure_wix_integration import SecureWixIntegration

# Initialize
wix = SecureWixIntegration(use_keyring=True)
```

### Step 4: Delete .env File (Optional)
```powershell
# Credentials now stored securely, .env no longer needed
del .env
```

---

## ✅ SECURITY CHECKLIST FOR RIMTYRES

Before going live:

- [ ] API keys are read-only (no write/delete)
- [ ] `.env` in `.gitignore`
- [ ] File permissions restricted
- [ ] Using encrypted credential storage (keyring/Azure)
- [ ] API call logging enabled
- [ ] Rate limiting implemented
- [ ] Monitoring for suspicious activity
- [ ] HTTPS only (no HTTP)
- [ ] Regular security audits
- [ ] Backup authentication method
- [ ] Admin alerts configured
- [ ] IP whitelisting (production)
- [ ] API key rotation schedule

---

## 🆘 IF API KEY IS COMPROMISED

### Immediate Actions:

1. **Revoke Old Key**
   - Go to dev.wix.com
   - Delete compromised key

2. **Generate New Key**
   - Create new API key
   - Update encrypted storage

3. **Check Logs**
   - Review `rimtyres_api.log`
   - Look for suspicious activity

4. **Notify Customers** (if data accessed)
   - GDPR compliance
   - Transparency

---

## 💡 ADDITIONAL SECURITY TIPS

### 1. Separate Keys for Dev/Prod
```
Development: WIX_API_KEY_DEV (test store)
Production: WIX_API_KEY_PROD (real store)
```

### 2. Enable 2FA on Wix Account
- Extra protection for your Wix account
- Even if password stolen, can't access

### 3. Regular Backups
- Backup Wix data monthly
- Store securely offline
- Test restore process

### 4. Security Headers
```python
# In FastAPI
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Specific domain only
    allow_credentials=True,
    allow_methods=["POST"],  # Only what's needed
    allow_headers=["Content-Type", "Authorization"],
)
```

### 5. Input Validation
```python
# Validate phone numbers
import re

def validate_phone(phone: str) -> bool:
    # Must be valid format
    pattern = r'^\+?1?\d{9,15}$'
    return bool(re.match(pattern, phone.replace(' ', '')))

# Validate before API call
if not validate_phone(phone):
    return "Invalid phone number"
```

---

## 📊 COST vs SECURITY

| Solution | Cost | Security Level | Setup Time |
|----------|------|----------------|------------|
| .env file + .gitignore | Free | ⭐⭐ Basic | 1 min |
| System env vars | Free | ⭐⭐⭐ Good | 5 min |
| Windows Credential Manager | Free | ⭐⭐⭐⭐ Great | 10 min |
| Azure Key Vault | $0.03/10k ops | ⭐⭐⭐⭐⭐ Enterprise | 30 min |

**Recommendation for RimTyres**: Windows Credential Manager (Free + Great security)

---

## 🎯 BOTTOM LINE

### For RimTyres (Real Business with Daily Payments):

**DO THIS**:
1. ✅ Install keyring: `pip install keyring`
2. ✅ Store credentials encrypted (one-time setup)
3. ✅ Use read-only API keys
4. ✅ Enable logging
5. ✅ Monitor daily
6. ✅ Rotate keys every 90 days

**DON'T DO THIS**:
- ❌ Commit `.env` to GitHub
- ❌ Share API keys in messages/email
- ❌ Use admin/write permissions
- ❌ Skip logging
- ❌ Ignore suspicious activity

---

**Your concern is valid! But with proper security, API keys in production are safe.** 🔒

**For a business like RimTyres handling real payments, use encrypted storage (Windows Credential Manager) - it's free and very secure!** 🛡️

See `SECURITY_IMPLEMENTATION.md` for code examples!
