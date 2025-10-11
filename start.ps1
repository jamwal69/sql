# 🚀 Start All Services
# This script starts the API server and WhatsApp integration

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  🤖 Agentic AI Customer Support System" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

# Check if .env file exists
if (-Not (Test-Path ".env")) {
    Write-Host "❌ Error: .env file not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please create .env file with:" -ForegroundColor Yellow
    Write-Host "  OPENROUTER_API_KEY=your_key_here" -ForegroundColor Yellow
    Write-Host "  JWT_SECRET=your_secret_here" -ForegroundColor Yellow
    Write-Host "  TWILIO_ACCOUNT_SID=your_sid_here" -ForegroundColor Yellow
    Write-Host "  TWILIO_AUTH_TOKEN=your_token_here" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Check if database exists
if (-Not (Test-Path "customer_memory.db")) {
    Write-Host "⚠️  Database not found. Running migration..." -ForegroundColor Yellow
    python migrate_db.py
    Write-Host "✅ Database initialized" -ForegroundColor Green
    Write-Host ""
}

Write-Host "🔧 Starting services..." -ForegroundColor Yellow
Write-Host ""

# Start API Server in background
Write-Host "📡 Starting API Server (port 8000)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "python api_server.py"
Start-Sleep -Seconds 2

# Start WhatsApp Integration in background
Write-Host "📱 Starting WhatsApp Integration (port 8001)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "python whatsapp_integration.py"
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "  ✅ All Services Started!" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "📍 Access Points:" -ForegroundColor Cyan
Write-Host "   🌐 API Server:      http://localhost:8000" -ForegroundColor White
Write-Host "   📚 API Docs:        http://localhost:8000/docs" -ForegroundColor White
Write-Host "   💬 Chat Widget:     Open chat_widget.html in browser" -ForegroundColor White
Write-Host "   📱 WhatsApp Server: http://localhost:8001" -ForegroundColor White
Write-Host ""
Write-Host "🔐 First Steps:" -ForegroundColor Cyan
Write-Host "   1. Open chat_widget.html in your browser" -ForegroundColor White
Write-Host "   2. Register a new account" -ForegroundColor White
Write-Host "   3. Start chatting with Emma!" -ForegroundColor White
Write-Host ""
Write-Host "🧪 Test API:" -ForegroundColor Cyan
Write-Host '   curl http://localhost:8000/health' -ForegroundColor White
Write-Host ""
Write-Host "📖 Need help? Check QUICKSTART.md" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C in service windows to stop" -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Green
