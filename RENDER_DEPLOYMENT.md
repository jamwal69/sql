# 🎨 RENDER DEPLOYMENT GUIDE - RIMTYRES AI

**Platform**: Render  
**Cost**: FREE (750 hours/month - enough for 24/7!)  
**Time**: 10 minutes  
**Difficulty**: Easy ⭐⭐

---

## ✅ WHY RENDER IS GREAT

- 🆓 **FREE tier** (750 hours/month)
- 🔒 **Secure environment variables** (encrypted)
- 🚀 **Auto-deploy** from Git
- 🌐 **Free SSL/HTTPS**
- 📊 **Built-in monitoring**
- ⚡ **Fast deployment**

---

## 🚀 STEP-BY-STEP DEPLOYMENT

### Step 1: Prepare Your Code (2 minutes)

First, let's make sure everything is ready:

```powershell
# 1. Test locally first
python production_config.py

# Should show:
# ✅ Configuration loaded from env_file
# ✅ All tests passed!

# 2. Test Wix connection
python test_wix_connection.py

# Should show:
# ✅ Wix connection successful!
```

### Step 2: Create Render Account (2 minutes)

1. Go to: **https://render.com**
2. Click **"Get Started for Free"**
3. Sign up with:
   - **GitHub** (recommended - for auto-deploy)
   - Email
   - Google

### Step 3: Push to GitHub (if not already) (3 minutes)

```powershell
# If you haven't pushed to GitHub yet:

# 1. Create new repository on GitHub
# Go to: https://github.com/new
# Name: rimtyres-ai-agent
# Make it PRIVATE (your business code!)

# 2. Initialize and push
git init
git add .
git commit -m "Initial commit - RimTyres AI Agent"
git remote add origin https://github.com/YOUR-USERNAME/rimtyres-ai-agent.git
git branch -M main
git push -u origin main
```

**IMPORTANT**: Make sure `.env` is in `.gitignore`! ✅

### Step 4: Create Web Service on Render (5 minutes)

#### 4.1 Create New Web Service

1. Go to Render Dashboard: https://dashboard.render.com
2. Click **"New +"** button (top right)
3. Select **"Web Service"**

#### 4.2 Connect Repository

1. Click **"Connect a repository"**
2. If first time: Authorize Render to access GitHub
3. Find your repository: **rimtyres-ai-agent**
4. Click **"Connect"**

#### 4.3 Configure Service

Fill in the following:

**Name**: `rimtyres-ai-agent`

**Region**: Choose closest to your customers
- `Oregon (US West)` - Good for North America
- `Frankfurt (EU)` - Good for Europe
- `Singapore (AP)` - Good for Asia

**Branch**: `main`

**Runtime**: `Python 3`

**Build Command**:
```bash
pip install -r requirements.txt
```

**Start Command**:
```bash
python api_server.py
```

**Instance Type**: `Free` ✅

#### 4.4 Add Environment Variables (CRITICAL! 🔒)

Scroll down to **"Environment Variables"** section.

Click **"Add Environment Variable"** and add these **3 variables**:

1. **WIX_API_KEY**
   - Key: `WIX_API_KEY`
   - Value: `your-wix-api-key-here`
   - ⚠️ Click the **"lock" icon** to mark as SECRET

2. **WIX_SITE_ID**
   - Key: `WIX_SITE_ID`
   - Value: `your-wix-site-id-here`

3. **WIX_ACCOUNT_ID**
   - Key: `WIX_ACCOUNT_ID`
   - Value: `your-wix-account-id-here`

4. **ENVIRONMENT** (optional)
   - Key: `ENVIRONMENT`
   - Value: `production`

**Example**:
```
WIX_API_KEY      = JWS.eyJraWQiOiJQb... (SECRET - click lock icon!)
WIX_SITE_ID      = abc123def456
WIX_ACCOUNT_ID   = xyz789uvw012
ENVIRONMENT      = production
```

#### 4.5 Advanced Settings (Optional but Recommended)

Click **"Advanced"** and set:

**Health Check Path**: `/health`

**Auto-Deploy**: `Yes` ✅ (deploy automatically on Git push)

### Step 5: Deploy! 🚀

1. Click **"Create Web Service"** button (bottom)
2. Render will now:
   - Clone your repository
   - Install dependencies
   - Start your application
   - Give you a public URL

**Wait 2-3 minutes for first deployment...**

You'll see logs like:
```
==> Cloning from https://github.com/YOUR-USERNAME/rimtyres-ai-agent...
==> Installing dependencies...
==> Successfully installed requests-2.31.0 flask-3.0.0 ...
==> Starting service...
✅ Configuration loaded from environment variables
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
```

### Step 6: Test Your Deployment ✅

Once deployed, you'll get a URL like:
```
https://rimtyres-ai-agent.onrender.com
```

**Test it**:

```powershell
# 1. Test health endpoint
curl https://rimtyres-ai-agent.onrender.com/health

# Should return:
# {"status": "healthy", "timestamp": "...", "wix_connection": "ok"}

# 2. Test in browser
# Open: https://rimtyres-ai-agent.onrender.com/health
```

If you see ✅ **"healthy"**, you're LIVE! 🎉

---

## 📱 STEP 7: CONNECT WHATSAPP (5 minutes)

### Update Twilio Webhook

1. Go to **Twilio Console**: https://console.twilio.com
2. Navigate to: **Messaging** → **Try it out** → **WhatsApp**
3. Find your WhatsApp number
4. Set **"When a message comes in"** webhook to:
   ```
   https://rimtyres-ai-agent.onrender.com/webhook
   ```
5. Method: `POST`
6. Click **"Save"**

### Test WhatsApp Integration

1. Send a WhatsApp message to your Twilio number:
   ```
   Hey! Where is my order?
   ```

2. Check Render logs (Dashboard → Logs tab):
   ```
   Received WhatsApp message from +1234567890
   Fetching customer data from Wix...
   ✅ Customer found: John Doe
   ✅ Order found: #12345
   Sending response...
   ```

3. You should get a reply with real order info! 🎉

---

## 🔍 MONITORING YOUR APP

### View Logs

**Render Dashboard** → Your Service → **"Logs"** tab

See real-time logs:
```
2025-10-11 14:30:45 | INFO | Webhook received from WhatsApp
2025-10-11 14:30:46 | INFO | Fetching customer by phone: ****7890
2025-10-11 14:30:47 | INFO | Customer found: cust_abc123
2025-10-11 14:30:48 | INFO | Sending response
```

### Check Metrics

**Render Dashboard** → Your Service → **"Metrics"** tab

Monitor:
- **CPU Usage** (should be low for WhatsApp bot)
- **Memory Usage** (should stay under 512MB on free tier)
- **Response Time**
- **Request Count**

### Set Up Alerts

1. Go to: **Settings** → **Notifications**
2. Add your email
3. Get notified if:
   - Service goes down
   - Deploy fails
   - High error rate

---

## 🔒 SECURITY CHECKLIST

After deployment, verify:

- [ ] ✅ WIX_API_KEY is marked as "Secret" (lock icon)
- [ ] ✅ .env file is NOT in Git (check `.gitignore`)
- [ ] ✅ Repository is PRIVATE on GitHub
- [ ] ✅ Wix API key has READ-ONLY permissions
- [ ] ✅ HTTPS is enabled (automatic on Render)
- [ ] ✅ Health check endpoint works
- [ ] ✅ WhatsApp webhook uses HTTPS URL

---

## 💰 FREE TIER LIMITS

Render Free tier includes:
- ✅ **750 hours/month** (31 days × 24 hours = 744 hours - perfect!)
- ✅ **512 MB RAM** (enough for WhatsApp bot)
- ✅ **Free SSL**
- ✅ **Automatic deploys**
- ⚠️ **Spins down after 15 min of inactivity**
  - First request after spin-down takes ~30 seconds
  - Solution: Upgrade to paid tier ($7/mo) for always-on

**For RimTyres**: Free tier is great to start! Upgrade if you get lots of customers.

---

## 🔄 AUTO-DEPLOY (Already Enabled!)

Now whenever you update code:

```powershell
# 1. Make changes to your code
# Edit files...

# 2. Commit and push
git add .
git commit -m "Updated WhatsApp responses"
git push

# 3. Render automatically redeploys! 🚀
# Check Render dashboard to see deployment progress
```

**No manual deployment needed!** ✅

---

## 🆙 UPGRADE PATH

### When to Upgrade to Paid Tier ($7/month)?

Upgrade if you need:
- ✅ **Always-on** (no spin down after inactivity)
- ✅ **Faster response** (no cold start delay)
- ✅ **More RAM** (1GB instead of 512MB)
- ✅ **Custom domain** (your-domain.com)

### How to Upgrade:

1. Render Dashboard → Your Service
2. Click **"Upgrade"** button
3. Choose **"Starter"** plan ($7/month)
4. Add payment method
5. Done! Instant upgrade, no downtime ✅

---

## 🛠️ TROUBLESHOOTING

### Problem: "Deploy failed - No module named 'dotenv'"

**Solution**: Make sure `requirements.txt` includes:
```
python-dotenv
requests
flask
twilio
```

Then commit and push:
```powershell
git add requirements.txt
git commit -m "Updated requirements"
git push
```

### Problem: "Port already in use"

**Solution**: Update `api_server.py` to use Render's PORT:

```python
import os

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
```

### Problem: "Health check failed"

**Solution**: 
1. Check logs in Render dashboard
2. Make sure `/health` endpoint exists:

```python
@app.route('/health')
def health():
    return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}
```

3. Make sure app is running on `0.0.0.0`, not `127.0.0.1`

### Problem: "Service unavailable / Spin down"

**Cause**: Free tier spins down after 15 minutes of inactivity.

**Solutions**:
1. **Upgrade to Starter** ($7/mo) - always on
2. **Use cron job** to ping your app every 10 minutes (free):
   - Use UptimeRobot: https://uptimerobot.com
   - Ping: https://rimtyres-ai-agent.onrender.com/health
   - Every 10 minutes

### Problem: "Can't connect to Wix API"

**Solution**:
1. Check environment variables are set correctly
2. Test locally first: `python test_wix_connection.py`
3. Check Render logs for error messages
4. Verify Wix API credentials are correct

---

## 📊 UPTIME MONITORING (FREE)

Set up UptimeRobot to:
- Keep your app alive (prevent spin down)
- Alert you if it goes down

### Setup (5 minutes):

1. Go to: **https://uptimerobot.com**
2. Sign up (free)
3. Click **"Add New Monitor"**
4. Configure:
   - **Monitor Type**: HTTP(s)
   - **Friendly Name**: RimTyres AI Health
   - **URL**: `https://rimtyres-ai-agent.onrender.com/health`
   - **Monitoring Interval**: 5 minutes (free tier)
5. Click **"Create Monitor"**
6. Add **Alert Contacts** (your email/SMS)

**Benefits**:
- ✅ Keeps app alive (pings every 5 min)
- ✅ Alerts you if down
- ✅ Free!

---

## 🎯 PRODUCTION CHECKLIST

Before announcing to customers:

### Pre-Launch:
- [ ] Deployed to Render successfully
- [ ] All environment variables set (and WIX_API_KEY is secret)
- [ ] Health check endpoint works
- [ ] Wix API connection tested
- [ ] WhatsApp webhook connected to Render URL
- [ ] Test WhatsApp conversation works end-to-end
- [ ] Logs are clean (no errors)
- [ ] UptimeRobot monitoring set up

### Security:
- [ ] Repository is PRIVATE on GitHub
- [ ] .env file NOT in Git
- [ ] Wix API key is READ-ONLY
- [ ] HTTPS enabled (automatic)
- [ ] Secrets marked as "Secret" in Render

### Monitoring:
- [ ] Email alerts configured in Render
- [ ] UptimeRobot pinging /health endpoint
- [ ] Know how to check logs (Render dashboard)
- [ ] Know how to check metrics (CPU/Memory)

### Documentation:
- [ ] Saved Render URL somewhere safe
- [ ] Saved Wix API credentials in password manager
- [ ] Know how to rotate API keys
- [ ] Have rollback plan (Git revert + redeploy)

---

## 🔄 UPDATING YOUR APP

### Deploy New Changes:

```powershell
# 1. Make changes
# Edit your code...

# 2. Test locally
python api_server.py
# Test at: http://localhost:5000

# 3. Commit and push
git add .
git commit -m "Added new feature"
git push

# 4. Render auto-deploys! ✅
# Watch logs in dashboard
```

### Rollback if Needed:

```powershell
# If new deployment breaks something:

# 1. Find last working commit
git log --oneline

# 2. Revert
git revert HEAD
git push

# 3. Render redeploys previous version
```

---

## 💡 PRO TIPS

### 1. Use Environment-Specific Settings

```python
# In your code:
import os

ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')

if ENVIRONMENT == 'production':
    DEBUG = False
    LOG_LEVEL = 'INFO'
else:
    DEBUG = True
    LOG_LEVEL = 'DEBUG'
```

### 2. Add Request Logging

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

@app.route('/webhook', methods=['POST'])
def webhook():
    logging.info(f"Webhook received from {request.remote_addr}")
    # ... your code
```

### 3. Set Up Staging Environment (Optional)

Create a second Render service for testing:
- `rimtyres-ai-agent-staging`
- Connected to `develop` Git branch
- Use test Wix credentials
- Test new features before production

### 4. Monitor Wix API Usage

Check your API usage in Wix:
1. Go to dev.wix.com
2. Dashboard → Your App
3. Check API call count
4. Make sure you're within limits

---

## 📈 SCALING YOUR APP

### When You Need to Scale:

If you're getting lots of customers:

1. **Upgrade Render plan**: Starter → Standard
   - More CPU/RAM
   - Better performance
   
2. **Optimize your code**:
   - Cache Wix API responses
   - Use async/await for API calls
   - Add request queuing

3. **Add database** (if needed):
   - Render offers PostgreSQL (free tier!)
   - Store conversation history
   - Cache customer data

---

## 🎊 YOU'RE LIVE!

Congratulations! Your RimTyres AI is now:

- ✅ **Deployed** on Render
- ✅ **Secure** (encrypted env vars)
- ✅ **Free** (750 hours/month)
- ✅ **Auto-deploying** from Git
- ✅ **Monitored** (alerts if down)
- ✅ **Connected** to WhatsApp
- ✅ **Fetching real data** from Wix

**Your customers can now chat with your AI 24/7!** 🎉

---

## 📞 NEXT STEPS

1. **Test with your own phone**:
   - Send WhatsApp: "Where is my order?"
   - Verify AI responds with real data

2. **Soft launch**:
   - Tell a few trusted customers
   - Get feedback
   - Fix any issues

3. **Full launch**:
   - Update website with WhatsApp number
   - Announce on social media
   - Monitor logs daily (first week)

4. **Monitor & improve**:
   - Check logs regularly
   - Optimize responses based on customer questions
   - Add more features

---

## 🆘 NEED HELP?

### Render Resources:
- Docs: https://render.com/docs
- Status: https://status.render.com
- Support: https://render.com/support

### Your Setup:
- **Render Dashboard**: https://dashboard.render.com
- **Your Service URL**: `https://rimtyres-ai-agent.onrender.com`
- **GitHub Repo**: Your private repository
- **Wix Dashboard**: dev.wix.com

---

## 🎯 SUMMARY

**What You Did**:
1. ✅ Created Render account
2. ✅ Connected GitHub repository
3. ✅ Added environment variables (secure!)
4. ✅ Deployed to Render
5. ✅ Connected WhatsApp webhook
6. ✅ Set up monitoring

**What You Have Now**:
- 🚀 Production AI agent running 24/7
- 🔒 Secure credential management
- 🆓 Free hosting (750 hrs/month)
- 📊 Monitoring & alerts
- 🔄 Auto-deploy from Git

**Total Cost**: $0/month (free tier!) 💰

**Total Time**: ~15 minutes ⚡

---

**Your RimTyres AI is LIVE! Time to help customers! 🎉**
