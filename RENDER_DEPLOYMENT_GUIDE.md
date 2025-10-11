# 🚀 Render Deployment Guide - Agentic AI Agent

Complete guide to deploy your AI agent on Render's free tier.

---

## 📋 Prerequisites

1. ✅ Your AI agent is working locally with Gemini API
2. ✅ GitHub repository with your code
3. ✅ Gemini API key from https://makersuite.google.com/app/apikey
4. ✅ Render account (free): https://render.com

---

## 🎯 Step-by-Step Deployment

### Step 1: Push Code to GitHub

```bash
# If not already initialized
git init
git add .
git commit -m "Initial commit - Agentic AI with Gemini"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

### Step 2: Create New Web Service on Render

1. Go to https://dashboard.render.com
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository
4. Select your `sql` repository

### Step 3: Configure Service

Fill in these settings:

| Setting | Value |
|---------|-------|
| **Name** | `agentic-ai-agent` (or your choice) |
| **Region** | Choose closest to you |
| **Branch** | `main` |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `python api_server.py` |
| **Plan** | `Free` |

### Step 4: Add Environment Variables

Click **"Advanced"** and add these environment variables:

```
GEMINI_API_KEY=<your-gemini-api-key>
ENVIRONMENT=production
PORT=10000
```

**Important:** 
- Replace `<your-gemini-api-key>` with your actual Gemini API key
- Port 10000 is Render's default for free tier

### Step 5: Deploy!

1. Click **"Create Web Service"**
2. Render will automatically:
   - Clone your repository
   - Install dependencies
   - Start your server
3. Wait 2-5 minutes for deployment

---

## ✅ Verify Deployment

Once deployed, you'll get a URL like: `https://agentic-ai-agent.onrender.com`

### Test Endpoints:

1. **Health Check:**
   ```
   https://your-app.onrender.com/health
   ```
   Should return: `{"status": "healthy"}`

2. **API Documentation:**
   ```
   https://your-app.onrender.com/docs
   ```
   Interactive API documentation (Swagger UI)

3. **Chat Endpoint:**
   ```bash
   curl -X POST https://your-app.onrender.com/chat \
     -H "Content-Type: application/json" \
     -d '{"message": "Hello Emma!", "customer_name": "Test User"}'
   ```

---

## 🎨 What You Get with Free Tier

✅ **Included:**
- 750 hours/month of runtime (enough for 24/7 if only one service)
- Automatic HTTPS
- Auto-deploy on git push
- Custom domain support
- 512 MB RAM
- Shared CPU

⚠️ **Limitations:**
- Service sleeps after 15 minutes of inactivity
- First request after sleep takes ~30 seconds (cold start)
- 512 MB RAM limit

---

## 🔧 Troubleshooting

### Service Won't Start

**Check logs:**
1. Go to Render dashboard
2. Click your service
3. Click "Logs" tab
4. Look for errors

**Common issues:**
- Missing `GEMINI_API_KEY` environment variable
- Wrong Python version (should use Python 3.11+)
- Missing dependencies in `requirements.txt`

### Cold Starts (Service Sleeping)

Free tier services sleep after 15 minutes. Solutions:

1. **Accept it** - First request takes 30 seconds
2. **Upgrade to paid** - $7/month for always-on
3. **Use a ping service** - Keep alive with cron jobs (but uses your free hours)

### API Errors

Check these:
```bash
# Test locally first
python api_server.py

# Check if Gemini API key works
python agentic_ai.py
```

---

## 📊 Monitoring

### View Logs
```
Render Dashboard → Your Service → Logs
```

### View Metrics
```
Render Dashboard → Your Service → Metrics
```

Shows:
- CPU usage
- Memory usage
- Request count
- Response times

---

## 🔄 Auto-Deploy Updates

Every time you push to GitHub, Render automatically redeploys:

```bash
git add .
git commit -m "Update AI agent"
git push
```

Render will:
1. Detect the push
2. Build new version
3. Deploy automatically
4. Keep old version running until new one is ready (zero downtime)

---

## 🌐 Custom Domain (Optional)

1. Go to your service settings
2. Click "Custom Domain"
3. Add your domain (e.g., `ai.yourdomain.com`)
4. Follow DNS setup instructions
5. Render provides free SSL automatically

---

## 💰 Cost Estimate

**Free Tier:**
- ✅ $0/month
- ✅ Perfect for testing and small projects
- ⚠️ Service sleeps after 15 min

**Paid Tier ($7/month):**
- ✅ Always-on (no sleeping)
- ✅ 2 GB RAM
- ✅ Faster CPU
- ✅ Better for production

**Gemini API Costs:**
- Gemini 2.5 Flash: Very affordable
- Pay per token usage
- Free tier available: 15 requests/minute

---

## 🎯 Next Steps After Deployment

1. **Test all endpoints** using `/docs`
2. **Integrate with frontend** (chat widget, website)
3. **Set up monitoring** (Render metrics + external)
4. **Configure custom domain** (if needed)
5. **Add more features** (database, analytics, etc.)

---

## 📞 Support

- **Render Docs:** https://render.com/docs
- **Render Community:** https://community.render.com
- **Your AI Agent Docs:** See `proper_docs.html`

---

## 🎉 You're Live!

Your AI agent is now accessible worldwide at:
```
https://your-app-name.onrender.com
```

Test it, share it, and scale it! 🚀

---

**Last Updated:** October 2025
