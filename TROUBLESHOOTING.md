# 🔧 Troubleshooting Guide

Common issues and solutions for your AI Customer Support system.

---

## 🚨 Common Issues

### 1. "Module not found" Error

**Problem**: Python can't find required packages

**Solution**:
```powershell
# Reinstall all dependencies
pip install -r requirements.txt --force-reinstall

# If specific module is missing (e.g., PyJWT)
pip install PyJWT

# Check installed packages
pip list
```

---

### 2. "Port already in use" Error

**Problem**: Server can't start because port 8000 or 8001 is already in use

**Solution**:
```powershell
# Find process using port 8000
netstat -ano | findstr :8000

# Kill the process (replace <PID> with actual process ID)
taskkill /PID <PID> /F

# Or use different port
python api_server.py --port 8080
```

---

### 3. Database Errors

#### "No such table" Error

**Problem**: Database tables don't exist

**Solution**:
```powershell
# Run database migration
python migrate_db.py
```

#### "Database is locked" Error

**Problem**: Another process is using the database

**Solution**:
```powershell
# Close all Python processes
# Delete database and recreate
rm customer_memory.db
python migrate_db.py
```

#### "Column not found" Error

**Problem**: Database schema is outdated

**Solution**:
```powershell
# Run migration to update schema
python migrate_db.py
```

---

### 4. Authentication Issues

#### "Invalid or expired token" Error

**Problem**: JWT token is expired or invalid

**Solution**:
1. Login again to get new token
2. Check JWT_SECRET is set in .env
3. Verify token format: `Authorization: Bearer YOUR_TOKEN`

#### "403 Forbidden" Error

**Problem**: User doesn't have permission

**Solution**:
- Check user role: `GET /auth/me`
- Verify user has permission for the resource
- Customers can only access their own data
- Use admin account for testing

---

### 5. API Connection Issues

#### "Connection refused" Error

**Problem**: Server is not running

**Solution**:
```powershell
# Check if server is running
curl http://localhost:8000/health

# If not, start the server
python api_server.py
```

#### "CORS Error" in Browser

**Problem**: Browser blocking cross-origin requests

**Solution**:
1. In `api_server.py`, update CORS settings:
```python
allow_origins=["http://localhost:3000", "https://yourdomain.com"]
```

2. Or temporarily allow all (development only):
```python
allow_origins=["*"]
```

---

### 6. WhatsApp Integration Issues

#### Messages Not Received

**Problem**: Twilio webhook not configured

**Solution**:
1. Check webhook URL in Twilio console
2. Make sure server is publicly accessible (use ngrok for testing)
3. Verify webhook format: `https://your-domain.com/whatsapp/webhook`
4. Check server logs: `docker-compose logs -f whatsapp-server`

#### "Twilio not configured" Error

**Problem**: Missing Twilio credentials

**Solution**:
```env
# Add to .env file
TWILIO_ACCOUNT_SID=ACxxxxx
TWILIO_AUTH_TOKEN=xxxxx
TWILIO_WHATSAPP_NUMBER=whatsapp:+14155238886
```

#### Webhook Test

**Test webhook manually**:
```powershell
curl -X POST http://localhost:8001/whatsapp/webhook `
  -d "From=whatsapp:+1234567890" `
  -d "Body=Test message"
```

---

### 7. WebSocket Issues

#### WebSocket Won't Connect

**Problem**: WebSocket connection failed

**Solution**:
1. Check server is running: `http://localhost:8000/health`
2. Verify token is valid: `GET /auth/me`
3. Check browser console for errors
4. Use correct URL: `ws://localhost:8000/ws/chat?token=YOUR_TOKEN`
5. For HTTPS, use `wss://` instead of `ws://`

#### Connection Drops

**Problem**: WebSocket disconnects frequently

**Solution**:
- Increase timeout in nginx.conf
- Check network stability
- Implement auto-reconnect (already in chat_widget.html)

---

### 8. Docker Issues

#### "Cannot start service" Error

**Problem**: Docker container won't start

**Solution**:
```powershell
# Check logs
docker-compose logs

# Rebuild containers
docker-compose up -d --build

# Remove old containers and rebuild
docker-compose down
docker-compose up -d --build
```

#### "No space left on device" Error

**Problem**: Disk is full

**Solution**:
```powershell
# Clean up Docker
docker system prune -a

# Remove unused volumes
docker volume prune
```

---

### 9. AI/LLM Issues

#### "AI agent not configured" Error

**Problem**: OPENROUTER_API_KEY not set

**Solution**:
```env
# Add to .env file
OPENROUTER_API_KEY=sk-or-v1-your-key-here
```

#### AI Responses Are Slow

**Problem**: Model is slow or API rate limited

**Solution**:
1. Check API usage at https://openrouter.ai/
2. Try different model (faster but less capable):
```python
model="anthropic/claude-instant-v1"
```
3. Implement caching for common queries

#### AI Gives Wrong Information

**Problem**: RAG database needs updating

**Solution**:
Edit `rag_system.py` to add/update policies and products

---

### 10. Chat Widget Issues

#### Widget Not Loading

**Problem**: JavaScript errors or incorrect API URL

**Solution**:
1. Open browser DevTools (F12)
2. Check Console for errors
3. Verify API_BASE_URL in chat_widget.html:
```javascript
const API_BASE_URL = 'http://localhost:8000';
```
4. Check if CORS is configured

#### Can't Login

**Problem**: Authentication endpoint not responding

**Solution**:
1. Check API server is running
2. Test login endpoint:
```powershell
curl -X POST http://localhost:8000/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email": "test@example.com", "password": "test123"}'
```
3. Check browser console for errors

---

## 🔍 Debugging Tips

### Check Server Status

```powershell
# API Server
curl http://localhost:8000/health

# WhatsApp Server
curl http://localhost:8001/
```

### View Logs

```powershell
# Docker logs
docker-compose logs -f

# Specific service
docker-compose logs -f api-server

# Python script logs
python api_server.py
# Look for error messages in console
```

### Check Database

```powershell
# Open database
sqlite3 customer_memory.db

# List tables
.tables

# View users
SELECT * FROM users;

# View recent conversations
SELECT * FROM conversations ORDER BY timestamp DESC LIMIT 10;

# View audit log
SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 20;

# Exit
.quit
```

### Test API Endpoints

```powershell
# Health check
curl http://localhost:8000/health

# Register user
curl -X POST http://localhost:8000/auth/register `
  -H "Content-Type: application/json" `
  -d '{"email": "test@example.com", "password": "test123", "name": "Test User"}'

# Login
curl -X POST http://localhost:8000/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email": "test@example.com", "password": "test123"}'

# Get current user (replace TOKEN)
curl http://localhost:8000/auth/me `
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Check Environment Variables

```powershell
# Windows
cat .env

# Check if variable is loaded
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print(os.getenv('OPENROUTER_API_KEY'))"
```

---

## 🛠️ Advanced Debugging

### Enable Debug Mode

In Python scripts, add at top:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Monitor Network Traffic

Use browser DevTools → Network tab to see:
- API requests
- Response status codes
- Request/response bodies
- WebSocket messages

### Check Python Version

```powershell
python --version
# Should be 3.11 or higher
```

### Verify Dependencies

```powershell
# Check installed packages
pip list

# Check specific package
pip show fastapi

# Compare with requirements.txt
pip install -r requirements.txt --dry-run
```

---

## 🆘 Still Having Issues?

### Checklist

- [ ] Python 3.11+ installed
- [ ] All dependencies installed (`pip install -r requirements.txt`)
- [ ] `.env` file exists with correct values
- [ ] Database migrated (`python migrate_db.py`)
- [ ] Server running (`python api_server.py`)
- [ ] Port not in use (`netstat -ano | findstr :8000`)
- [ ] API key is valid (test at https://openrouter.ai/)
- [ ] Firewall allows connections

### Fresh Start

If all else fails, start from scratch:

```powershell
# 1. Stop all servers
# Press Ctrl+C in all terminal windows

# 2. Delete database
rm customer_memory.db

# 3. Reinstall dependencies
pip uninstall -y -r requirements.txt
pip install -r requirements.txt

# 4. Recreate database
python migrate_db.py

# 5. Restart servers
.\start.ps1
```

### Get Help

1. **Check Documentation**:
   - `QUICKSTART.md` - Quick setup
   - `DEPLOYMENT_GUIDE.md` - Deployment details
   - `README_ENHANCED.md` - Full documentation

2. **Review Logs**:
   - Console output when running servers
   - Browser DevTools console
   - Docker logs: `docker-compose logs`

3. **Test Components**:
   - Test AI directly: `python agentic_ai.py`
   - Test data: `python test_runner.py`
   - Test API: Use curl commands above

---

## 📝 Common Error Messages

### Import Errors

```
ImportError: No module named 'fastapi'
```
**Fix**: `pip install fastapi`

```
ImportError: No module named 'jwt'
```
**Fix**: `pip install PyJWT`

### Database Errors

```
sqlite3.OperationalError: no such table: users
```
**Fix**: `python migrate_db.py`

```
sqlite3.OperationalError: database is locked
```
**Fix**: Close all connections, restart

### API Errors

```
401 Unauthorized
```
**Fix**: Login to get valid token

```
403 Forbidden
```
**Fix**: Check user has permission for resource

```
404 Not Found
```
**Fix**: Check endpoint URL is correct

```
500 Internal Server Error
```
**Fix**: Check server logs for details

### Network Errors

```
Connection refused
```
**Fix**: Start the server

```
CORS error
```
**Fix**: Update CORS settings in api_server.py

```
WebSocket connection failed
```
**Fix**: Check server running, verify token

---

## 💡 Pro Tips

1. **Always check logs first** - Most issues show up in logs
2. **Test one component at a time** - Isolate the problem
3. **Use curl to test API** - Bypasses frontend issues
4. **Check environment variables** - Missing config is common
5. **Start simple** - Get basic working before adding features

---

## ✅ Verification Commands

Run these to verify everything works:

```powershell
# 1. Check Python
python --version

# 2. Check dependencies
pip install -r requirements.txt --dry-run

# 3. Check database
sqlite3 customer_memory.db ".tables"

# 4. Check API server
curl http://localhost:8000/health

# 5. Check WhatsApp server
curl http://localhost:8001/

# 6. Test authentication
curl -X POST http://localhost:8000/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email": "test@example.com", "password": "test123"}'
```

If all these work, your system is healthy! ✅

---

**Still stuck? The error message is your friend - read it carefully!** 🔍
